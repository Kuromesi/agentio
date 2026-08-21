// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use agentio_multi_tenant_egress_poc::config::parse_and_validate_yaml;
use agentio_multi_tenant_egress_poc::render::render_config_map;

fn main() {
    if let Err(error) = run() {
        eprintln!("render multi-tenant egress POC: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os().skip(1);
    let config_path = PathBuf::from(
        args.next()
            .ok_or("usage: render <tenants.yaml> <router.wasm> [output.yaml]")?,
    );
    let wasm_path = PathBuf::from(
        args.next()
            .ok_or("usage: render <tenants.yaml> <router.wasm> [output.yaml]")?,
    );
    let output_path = args.next().map(PathBuf::from);
    if args.next().is_some() {
        return Err("usage: render <tenants.yaml> <router.wasm> [output.yaml]".into());
    }

    let config_source = fs::read_to_string(&config_path)?;
    let config = parse_and_validate_yaml(&config_source)?;
    let wasm = fs::read(&wasm_path)?;
    let rendered = render_config_map(&config, &wasm)?;
    if let Some(output_path) = output_path {
        fs::write(output_path, rendered)?;
    } else {
        io::stdout().write_all(rendered.as_bytes())?;
    }
    Ok(())
}
