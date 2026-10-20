// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

mod app;
mod config;
mod telemetry;

use anyhow::{Context, Result};
use std::process::ExitCode;

// Linux deployments use jemalloc to reclaim fragmented allocation bursts after ADS resync.
#[cfg(target_os = "linux")]
#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn main() -> Result<ExitCode> {
    let config = config::parse()?;
    let logging = telemetry::init(&config.logging);
    let result: Result<()> = (|| {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(config.worker_threads)
            .enable_all()
            .build()
            .context("build Porter runtime")?;
        runtime.block_on(app::run(config, logging))
    })();
    match result {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => {
            tracing::error!(event = "porter_failed", error = %format_args!("{error:#}"), "Porter failed");
            Ok(ExitCode::FAILURE)
        }
    }
}
