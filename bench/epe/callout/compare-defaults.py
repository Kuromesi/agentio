#!/usr/bin/env python3
# Copyright 2026 The Kruise Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#	http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Run beside callout.test on the benchmark host; retain failing overload results."""
import argparse
import json
import os
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--prefix', default='', help='run only case names with this prefix')
parser.add_argument('--output', default='default-results')
options = parser.parse_args()
out = root / options.output
out.mkdir(exist_ok=True)
base = [str(root / 'callout.test'), '-test.v', '-test.run=^TestEnvoyLoad$',
        '-test.timeout=3m', '-envoy-image=envoyproxy/envoy:v1.39.4',
        '-callout-isolated', '-callout-forward-headers',
        '-callout-path=/request/continue/closed', '-callout-body=1024',
        '-callout-max-streams=250', '-callout-connection-window=4194304']
cases = []
# Fixed arrival rate; latency includes backlog in the load generator.
for delay, rate, concurrency, timeout in [
    (5, 1000, 32, ''), (5, 10000, 128, ''),
    (50, 1000, 128, ''), (50, 2000, 256, ''),
    (200, 400, 128, ''), (200, 1000, 512, ''),
    (500, 1000, 1024, '2s'),
]:
    for protocol in ['http1', 'http2']:
        cases.append(dict(name=f'rate-{delay}ms-{rate}-{protocol}', protocol=protocol,
                          delay=delay, rate=rate, concurrency=concurrency,
                          timeout=timeout, requests=min(30000, max(2048, rate*6))))
# Closed-loop saturation and cold-to-warm rounds, including above the new H2 cap.
for concurrency in [64, 256, 512, 1024, 1536]:
    for protocol in ['http1', 'http2']:
        cases.append(dict(name=f'closed-200ms-c{concurrency}-{protocol}', protocol=protocol,
                          delay=200, rate=0, concurrency=concurrency, timeout='2s', requests=4096))
for trial in range(3):
    for old in [False, True]:
        cases.append(dict(name=f'burst-{trial}-' + ('old' if old else 'new'), protocol='http2',
                          delay=50, rate=0, concurrency=1536, timeout='2s', requests=6144,
                          rounds=3, old=old))
for rate in [1500, 2500]:
    for old in [False, True]:
        cases.append(dict(name=f'capacity-500ms-{rate}-' + ('old' if old else 'new'), protocol='http2',
                          delay=500, rate=rate, concurrency=2048, timeout='2s', requests=rate*8, old=old))
records = []
for case in cases:
    if not case['name'].startswith(options.prefix):
        continue
    args = base + [f'-callout-response-delay={case["delay"]}ms',
                   f'-callout-rate={case["rate"]}', f'-callout-concurrency={case["concurrency"]}',
                   f'-callout-timeout={case["timeout"]}', f'-callout-requests={case["requests"]}',
                   f'-callout-rounds={case.get("rounds", 1)}']
    if case['protocol'] == 'http2':
        args.append('-callout-http2')
    if case.get('old'):
        args += ['-callout-max-connections=128', '-callout-max-idle=64']
    logpath = out / (case['name'] + '.log')
    with logpath.open('w') as log:
        result = subprocess.run(args, stdout=log, stderr=subprocess.STDOUT,
                                env={**os.environ, 'GOMAXPROCS': '4'})
    rows = [json.loads(line.split('RESULT ', 1)[1]) for line in logpath.read_text().splitlines()
            if 'RESULT ' in line]
    if not rows:
        raise RuntimeError(f'No measurement: {logpath}')
    record = dict(case=case, exit_code=result.returncode, rounds=rows)
    records.append(record)
    (out / 'summary.json').write_text(json.dumps(records, indent=2) + '\n')
    for row in rows:
        r, t = row['result'], row['transport']
        print(case['name'], row['round'], round(r['ops_per_second'], 1),
              'p99', round(r['p99_ms'], 1), 'errors', r['errors'],
              'connections', t['peak_connections'], 'refused', t['refused_streams'], flush=True)
    # Overload failures are measurements, never silently counted as passing tests.
    if result.returncode and not any(row['result']['errors'] for row in rows):
        raise RuntimeError(f'Unexpected failure: {logpath}')
