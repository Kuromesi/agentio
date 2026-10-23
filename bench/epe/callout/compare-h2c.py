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

import argparse, json, os, pathlib, subprocess
parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()
group.add_argument('--stream-sweep', action='store_true', help='compare HTTP/1.1 with h2c stream limits 16/32/64/100/250')
group.add_argument('--slow-sweep', action='store_true', help='compare connection limits with 200ms endpoint latency')
options = parser.parse_args()
root = pathlib.Path(__file__).resolve().parent
results = root / ('slow-results' if options.slow_sweep else 'stream-results' if options.stream_sweep else 'results')
results.mkdir(exist_ok=True)
records = []
scenarios = [
 ('headers-1k', 'headers', 1024, 100000, 64),
 ('body-1k', 'request', 1024, 100000, 64),
 ('body-64k', 'request', 65536, 30000, 64),
 ('headers-1m', 'headers', 1048576, 10000, 64),
 ('body-1m', 'request', 1048576, 10000, 64),
 ('response-1m', 'response', 1048576, 10000, 64),
 ('body-1k-c256', 'request', 1024, 100000, 256),
 ('body-1m-c256', 'request', 1048576, 10000, 256),
]
if options.stream_sweep:
 scenarios = [s for s in scenarios if s[0] in ('body-1k', 'body-1m', 'body-1k-c256', 'body-1m-c256')]
variants = [('http1', 0)] + [('h2c', limit) for limit in (16, 32, 64, 100, 250)] if options.stream_sweep else [('http1', 0), ('h2c', 0)]
if options.slow_sweep:
 scenarios = [(f'slow-200ms-c{c}', 'request', 1024, 4096, c) for c in (64, 128, 256, 512)]
 variants = [('http1', 0), ('h2c', 250), ('http1-wide', 0)]
for trial in range(1, 4):
 for name, phase, size, count, concurrency in scenarios:
  if options.stream_sweep or options.slow_sweep:
   offset = (trial - 1) * (1 if options.slow_sweep else 2)
   order = variants[offset:] + variants[:offset]
  else:
   order = variants if trial % 2 else variants[::-1]
  for mode, limit in order:
   label = f'{mode}-s{limit}' if options.stream_sweep or options.slow_sweep else mode
   path = results / f'{name}-{label}-{trial}.log'
   args = [str(root / 'callout.test'), '-test.v', '-test.run=^TestEnvoyLoad$', '-test.timeout=15m',
    '-envoy-image=envoyproxy/envoy:v1.39.4', '-callout-isolated', '-callout-forward-headers',
    f'-callout-path=/{phase}/continue/closed', f'-callout-body={size}', f'-callout-requests={count}',
    f'-callout-concurrency={concurrency}', f'-callout-max-streams={limit}',
    f'-callout-client-streams={limit or 32}', f'-callout-max-connections={512 if mode=="http1-wide" else 128}']
   if mode == 'h2c': args.append('-callout-http2')
   if options.slow_sweep: args.append('-callout-response-delay=200ms')
   with path.open('w') as log:
    completed = subprocess.run(args, stdout=log, stderr=subprocess.STDOUT, env={**os.environ, 'GOMAXPROCS':'4'}, timeout=900)
   if completed.returncode:
    raise RuntimeError(f'{path}: exit {completed.returncode}: '+path.read_text()[-4000:])
   lines = [line.split('RESULT ',1)[1] for line in path.read_text().splitlines() if 'RESULT ' in line]
   assert len(lines)==1, path
   record=json.loads(lines[0])
   stats=record['transport']
   assert stats['http2_requests' if mode=='h2c' else 'http1_requests']==count, stats
   assert stats['http1_requests' if mode=='h2c' else 'http2_requests']==0, stats
   assert record['result']['errors']==0 and record['active_callouts']==0, record
   assert stats['refused_streams']==0, stats
   if options.stream_sweep or options.slow_sweep:
    assert 0 < stats['peak_handlers_per_connection'] <= (limit if mode=='h2c' else 1), stats
   if options.slow_sweep:
    if mode == 'http1':
     assert stats['peak_connections'] <= 128 and stats['peak_handlers_total'] <= 128, stats
     if concurrency >= 256: assert stats['peak_handlers_total'] == 128, stats
    elif concurrency >= 256: assert stats['peak_handlers_total'] > 128, stats
   record.update(scenario=name, phase=phase, body_bytes=size, trial=trial, mode=mode, max_streams=limit, concurrency=concurrency)
   if options.slow_sweep: record.update(response_delay_ms=200, max_connections=512 if mode=='http1-wide' else 128)
   records.append(record)
   (results/'summary.json').write_text(json.dumps(records,indent=2)+'\n')
   print(f'{name} {label} trial={trial} rps={record["result"]["ops_per_second"]:.1f} p99={record["result"]["p99_ms"]:.2f} connections={stats["connections"]}',flush=True)
print(f'PASS {len(records)} runs; {sum(r["result"]["operations"] for r in records)} requests',flush=True)
