// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail};
use axum::{
    extract::{ConnectInfo, Query, State},
    http::{Method, StatusCode},
};
use std::{collections::HashMap, net::SocketAddr, str::FromStr};
use tracing_subscriber::{
    Registry, filter::Targets, layer::SubscriberExt, reload, util::SubscriberInitExt,
};

pub struct Config {
    filter: Targets,
    format: Format,
}

enum Format {
    Text,
    Json,
}

impl Config {
    pub fn new(level: &str, format: &str) -> Result<Self> {
        let filter = parse_filter(level)?;
        let format = match format {
            "text" => Format::Text,
            "json" => Format::Json,
            _ => bail!("AGENTIO_LOG_FORMAT must be text or json"),
        };
        Ok(Self { filter, format })
    }
}

fn parse_filter(level: &str) -> Result<Targets> {
    let level = if level == "none" { "off" } else { level };
    if !valid_level(level) {
        bail!("invalid AGENTIO_LOG_LEVEL");
    }
    Targets::from_str(level).context("invalid AGENTIO_LOG_LEVEL")
}

#[derive(Clone)]
pub struct Logging {
    handle: reload::Handle<Targets, Registry>,
    startup: Targets,
}

pub fn init(config: &Config) -> Logging {
    let writer = std::io::stderr;
    let (filter, handle) = reload::Layer::new(config.filter.clone());
    let subscriber = tracing_subscriber::registry().with(filter);
    match config.format {
        Format::Json => subscriber
            .with(
                tracing_subscriber::fmt::layer()
                    .fmt_fields(tracing_subscriber::fmt::format::JsonFields::default())
                    .event_format(agentio_porter::logging::JsonFormat)
                    .with_writer(writer),
            )
            .init(),
        Format::Text => subscriber
            .with(tracing_subscriber::fmt::layer().with_writer(writer))
            .init(),
    }
    Logging {
        handle,
        startup: config.filter.clone(),
    }
}

const HELP: &str = "
usage: POST /logging                                     (To list current level)
usage: POST /logging?level=<level>                       (To change global levels)
usage: POST /logging?level={mod1}={level1},{mod2}={level2} (To change specific mods' logging level)

hint: loglevel: error|warn|info|debug|trace|off
hint: mod_name: the module name, i.e. agentio_porter::policy
";

pub fn router(logging: Logging) -> axum::Router {
    axum::Router::new()
        .route("/logging", axum::routing::any(change_level))
        .with_state(logging)
}

async fn change_level(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(logging): State<Logging>,
    Query(query): Query<HashMap<String, String>>,
    method: Method,
) -> Result<String, (StatusCode, String)> {
    if !peer.ip().to_canonical().is_loopback() {
        return Err((
            StatusCode::FORBIDDEN,
            "logging control is localhost-only\n".into(),
        ));
    }
    if method != Method::POST {
        return Err((
            StatusCode::METHOD_NOT_ALLOWED,
            format!("Invalid HTTP method\n {HELP}"),
        ));
    }
    let level = query.get("level").map(String::as_str).unwrap_or_default();
    let reset = query.contains_key("reset");
    if !level.is_empty() && !valid_level(level) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Invalid level provided: {level}\n{HELP}"),
        ));
    }
    if reset || !level.is_empty() {
        let mut previous_filter = String::new();
        let mut current_filter = String::new();
        // Read and replace under the reload lock so concurrent requests merge
        // against the actual current filter and record the correct predecessor.
        logging
            .handle
            .modify(|active| {
                previous_filter = active.to_string();
                let base = if reset {
                    logging.startup.to_string()
                } else {
                    previous_filter.clone()
                };
                let directives = if level.is_empty() {
                    base
                } else {
                    format!("{base},{level}")
                };
                *active = Targets::from_str(&directives).expect("validated log directives");
                current_filter = active.to_string();
            })
            .map_err(|error| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Failed to set new level: reload failure: {error}\n{HELP}"),
                )
            })?;
        if previous_filter != current_filter {
            tracing::info!(
                event = "log_level_changed",
                previous_filter,
                current_filter,
                source_address = %peer,
                reset,
                "Log level changed"
            );
        }
    }
    logging
        .handle
        .with_current(|filter| format!("current log level is {filter}\n"))
        .map_err(internal_error)
}

fn valid_level(level: &str) -> bool {
    level.split(',').all(|clause| match clause {
        "off" | "error" | "warn" | "info" | "debug" | "trace" => true,
        s if s.contains('=') => Targets::from_str(s).is_ok(),
        _ => false,
    })
}

fn internal_error(error: reload::Error) -> (StatusCode, String) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("failed to get the log level: reload failure: {error}\n {HELP}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_agentio_log_options() {
        let config = Config::new("none", "json").unwrap();
        assert_eq!(config.filter.to_string(), "off");
        assert!(matches!(config.format, Format::Json));
        assert!(Config::new("debug", "text").is_ok());
        assert!(Config::new("invalid", "text").is_err());
        assert!(Config::new("agentio_porter=invalid", "text").is_err());
    }
    #[tokio::test]
    async fn logging_matches_ztunnel_update_semantics() {
        let startup = Targets::from_str("info").unwrap();
        let (layer, handle) = reload::Layer::new(startup.clone());
        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        assert!(!tracing::enabled!(target: "agentio_porter::policy", tracing::Level::DEBUG));
        let logging = Logging { handle, startup };
        async fn request(
            logging: &Logging,
            params: &[(&str, &str)],
        ) -> Result<String, (StatusCode, String)> {
            change_level(
                ConnectInfo("127.0.0.1:12345".parse().unwrap()),
                State(logging.clone()),
                Query(
                    params
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect(),
                ),
                Method::POST,
            )
            .await
        }
        assert_eq!(
            request(&logging, &[]).await.unwrap(),
            "current log level is info\n"
        );
        let result = request(&logging, &[("level", "agentio_porter::policy=debug")])
            .await
            .unwrap();
        assert!(result.contains("agentio_porter::policy=debug"));
        assert!(tracing::enabled!(target: "agentio_porter::policy", tracing::Level::DEBUG));
        let result = request(&logging, &[("level", "warn")]).await.unwrap();
        assert!(result.contains("agentio_porter::policy=debug"));
        assert!(tracing::enabled!(target: "agentio_porter::policy", tracing::Level::DEBUG));
        assert!(result.contains("warn"));
        assert_eq!(
            request(&logging, &[("level", "invalid")])
                .await
                .unwrap_err()
                .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(request(&logging, &[]).await.unwrap(), result);
        assert_eq!(request(&logging, &[("level", "")]).await.unwrap(), result);
        assert_eq!(
            request(&logging, &[("unknown", "ignored")]).await.unwrap(),
            result
        );
        assert_eq!(
            request(&logging, &[("reset", ""), ("level", "debug")])
                .await
                .unwrap(),
            "current log level is debug\n"
        );
        assert_eq!(
            request(&logging, &[("reset", "false")]).await.unwrap(),
            "current log level is info\n"
        );
        assert!(!tracing::enabled!(target: "agentio_porter::policy", tracing::Level::DEBUG));
        let error = change_level(
            ConnectInfo("127.0.0.1:12345".parse().unwrap()),
            State(logging.clone()),
            Query(HashMap::new()),
            Method::GET,
        )
        .await
        .unwrap_err();
        assert_eq!(error.0, StatusCode::METHOD_NOT_ALLOWED);
        let error = change_level(
            ConnectInfo("10.0.0.1:12345".parse().unwrap()),
            State(logging),
            Query(HashMap::new()),
            Method::POST,
        )
        .await
        .unwrap_err();
        assert_eq!(error.0, StatusCode::FORBIDDEN);
    }
    #[tokio::test]
    async fn successful_level_changes_are_structured_and_use_the_new_filter() {
        use std::io::{Read, Seek};
        let mut output = tempfile::tempfile().unwrap();
        let startup = Targets::from_str("warn").unwrap();
        let (layer, handle) = reload::Layer::new(startup.clone());
        let subscriber = tracing_subscriber::registry().with(layer).with(
            tracing_subscriber::fmt::layer()
                .fmt_fields(tracing_subscriber::fmt::format::JsonFields::default())
                .event_format(agentio_porter::logging::JsonFormat)
                .with_writer(output.try_clone().unwrap()),
        );
        let _guard = tracing::subscriber::set_default(subscriber);
        let logging = Logging { handle, startup };
        for (level, status) in [
            ("info", StatusCode::OK),
            ("invalid", StatusCode::BAD_REQUEST),
            ("info", StatusCode::OK),
            ("warn", StatusCode::OK),
        ] {
            let result = change_level(
                ConnectInfo("127.0.0.1:12345".parse().unwrap()),
                State(logging.clone()),
                Query(HashMap::from([("level".into(), level.into())])),
                Method::POST,
            )
            .await;
            assert_eq!(
                result
                    .map(|_| StatusCode::OK)
                    .unwrap_or_else(|(status, _)| status),
                status
            );
        }
        assert_eq!(
            logging.handle.with_current(ToString::to_string).unwrap(),
            "warn"
        );
        output.rewind().unwrap();
        let mut text = String::new();
        output.read_to_string(&mut text).unwrap();
        let events: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        // warn -> info is visible; invalid/no-op updates emit nothing; info -> warn filters INFO out.
        assert_eq!(events.len(), 1, "{text}");
        let event = &events[0];
        assert_eq!(event["event"], "log_level_changed");
        assert_eq!(event["level"], "info");
        assert_eq!(event["previous_filter"], "warn");
        assert_eq!(event["current_filter"], "info");
        assert_eq!(event["source_address"], "127.0.0.1:12345");
        assert_eq!(event["reset"], false);
    }
}
