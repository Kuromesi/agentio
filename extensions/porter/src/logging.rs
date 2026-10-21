// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

//! JSON logging contract: Istio-style envelope, flat event fields and scoped context.

use std::{fmt, io};

use serde::{Serialize, Serializer, ser::SerializeMap};
use tracing::{Event, Subscriber};
use tracing_log::NormalizeEvent;
use tracing_serde::SerdeMapVisitor;
use tracing_subscriber::{
    fmt::{
        FmtContext, FormatEvent, FormattedFields,
        format::{JsonFields, Writer},
        time::{FormatTime, SystemTime},
    },
    registry::LookupSpan,
};

/// Matches ztunnel's time/level/scope envelope. Event fields must not use these
/// reserved names or `spans`. Span context is kept separate from event fields.
pub struct JsonFormat;

impl<S> FormatEvent<S, JsonFields> for JsonFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, JsonFields>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let normalized = event.normalized_metadata();
        let meta = normalized.as_ref().unwrap_or_else(|| event.metadata());
        let mut write = || -> anyhow::Result<()> {
            let mut time = String::with_capacity(32);
            SystemTime.format_time(&mut Writer::new(&mut time))?;
            let mut serializer = serde_json::Serializer::new(JsonWriter(&mut writer));
            let mut object = serializer.serialize_map(None)?;
            object.serialize_entry("time", &time)?;
            object.serialize_entry("level", &meta.level().as_str().to_ascii_lowercase())?;
            object.serialize_entry("scope", meta.target())?;
            let mut visitor = SerdeMapVisitor::new(object);
            event.record(&mut visitor);
            let mut object = visitor.take_serializer()?;
            if let Some(scope) = ctx.event_scope() {
                let mut spans = Vec::new();
                for span in scope.from_root() {
                    let extensions = span.extensions();
                    let fields = extensions
                        .get::<FormattedFields<JsonFields>>()
                        .expect("fmt layer records JSON span fields");
                    spans.push(Span {
                        name: span.metadata().name(),
                        fields: serde_json::from_str(fields.as_str())?,
                    });
                }
                object.serialize_entry("spans", &spans)?;
            }
            object.end()?;
            Ok(())
        };
        write().map_err(|_| fmt::Error)?;
        writeln!(writer)
    }
}

#[derive(Serialize)]
struct Span {
    name: &'static str,
    fields: serde_json::Value,
}

// serde_json writes UTF-8 bytes; tracing supplies a fmt::Write destination.
struct JsonWriter<'a, 'b>(&'a mut Writer<'b>);

impl io::Write for JsonWriter<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let text = std::str::from_utf8(bytes).map_err(io::Error::other)?;
        fmt::Write::write_str(self.0, text).map_err(io::Error::other)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek};

    #[test]
    fn json_preserves_types_escaping_and_updated_span_context() {
        let mut output = tempfile::tempfile().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .fmt_fields(JsonFields::default())
            .event_format(JsonFormat)
            .with_writer(output.try_clone().unwrap())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "agentio_porter::app", enabled = true, count = 7u64, "ready\n\"你好\"");
            let root = tracing::info_span!("xds", connection_id = 1u64, address = "agentiod:15012");
            let _entered = root.enter();
            root.record("connection_id", 2u64);
            let child = tracing::info_span!("xds", retry = false);
            let _child = child.enter();
            tracing::warn!(target: "agentio_porter::discovery",
                retry_ms = std::time::Duration::from_millis(100).as_millis() as u64,
                error = "connection reset",
                "ADS disconnected"
            );
        });
        output.rewind().unwrap();
        let mut text = String::new();
        output.read_to_string(&mut text).unwrap();
        let events: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(events.len(), 2);
        let ready = &events[0];
        assert!(ready["time"].as_str().unwrap().ends_with('Z'));
        assert_eq!(ready["level"], "info");
        assert_eq!(ready["scope"], "agentio_porter::app");
        assert_eq!(ready["enabled"], true);
        assert_eq!(ready["count"], 7);
        assert_eq!(ready["message"], "ready\n\"你好\"");
        assert!(ready.get("fields").is_none());
        assert!(ready.get("spans").is_none());
        let disconnected = &events[1];
        assert_eq!(disconnected["level"], "warn");
        assert_eq!(disconnected["retry_ms"], 100);
        assert_eq!(disconnected["error"], "connection reset");
        let spans = disconnected["spans"].as_array().unwrap();
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0]["name"], "xds");
        assert_eq!(spans[0]["fields"]["connection_id"], 2);
        assert_eq!(spans[0]["fields"]["address"], "agentiod:15012");
        assert_eq!(spans[1]["name"], "xds");
        assert_eq!(spans[1]["fields"]["retry"], false);
    }
}
