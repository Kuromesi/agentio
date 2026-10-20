// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use std::{net::TcpListener, time::Duration};

#[tokio::test]
async fn runtime_failure_is_one_structured_error_with_nonzero_exit() {
    let occupied = TcpListener::bind("0.0.0.0:0").unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_agentio-porter"));
    command
        .kill_on_drop(true)
        .env("POD_NAME", "logging-test")
        .env("POD_NAMESPACE", "default")
        .env("TOKIO_WORKER_THREADS", "1")
        .env("AGENTIO_LOG_FORMAT", "json")
        .env("AGENTIO_LOG_LEVEL", "info")
        .args([
            "--xds-address=127.0.0.1:1",
            "--grpc-port=0",
            "--grpc-health-port=0",
            "--request-timeout=1250ms",
            "--xds-cache-idle-ttl=0",
        ])
        .arg(format!(
            "--metrics-port={}",
            occupied.local_addr().unwrap().port()
        ))
        .arg("--xds-root-path")
        .arg(directory.path().join("missing-root.pem"));
    let output = tokio::time::timeout(Duration::from_secs(10), command.output())
        .await
        .expect("failed service must stop the process")
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    let events: Vec<serde_json::Value> = stderr
        .lines()
        .map(|line| serde_json::from_str(line).expect("no unstructured runtime error"))
        .collect();
    let errors: Vec<_> = events
        .iter()
        .filter(|event| event["level"] == "error")
        .collect();
    assert_eq!(errors.len(), 1, "{stderr}");
    assert_eq!(errors[0]["event"], "porter_failed");
    assert!(
        errors[0]["error"]
            .as_str()
            .unwrap()
            .contains("task metrics failed")
    );
    assert!(
        errors[0]["error"]
            .as_str()
            .unwrap()
            .contains("bind metrics listener")
    );
    let startup = events
        .iter()
        .find(|event| event["message"] == "starting Porter")
        .unwrap();
    assert_eq!(startup["request_timeout_seconds"], 1.25);
    assert_eq!(startup["cache_idle_ttl_seconds"], 0.0);
    assert!(startup.get("request_timeout").is_none());
    assert!(startup.get("cache_idle_ttl").is_none());
}
