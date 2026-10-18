#!/usr/bin/env python3
"""Summarize recorded load results and cumulative resource samples, without credentials."""
import argparse
import collections
import json
from pathlib import Path
import re

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('directory', type=Path)
parser.add_argument('--namespace', default='sandbox-scale-system')
args = parser.parse_args()
root = args.directory
loads = {}
for path in root.glob('*.json'):
    record = json.loads(path.read_text())
    if record.get('action') == 'traffic' and record.get('result'):
        loads[path.stem] = record['result']['load']
        loads[path.stem]['action_error'] = record.get('error')
records = [json.loads(line) for line in (root / 'resources.jsonl').open()]


def role(pod, container):
    if pod['podRef']['namespace'] != args.namespace:
        return None
    name = container['name']
    return {'discovery': 'control-plane', 'agentio-porter': 'porter',
            'agentio-proxy': 'envoy', 'epe': 'epe',
            'agentio-sandbox-bench': 'backend'}.get(name)


def resources(start, end):
    previous = {}
    cpu_seconds = collections.defaultdict(float)
    peaks = collections.defaultdict(int)
    rss = collections.defaultdict(int)
    samples = [r for r in records if start <= r['time'] <= end]
    for sample in samples:
        memory = collections.defaultdict(int)
        rss_memory = collections.defaultdict(int)
        for pod in sample['stats']['pods']:
            for container in pod['containers']:
                component = role(pod, container)
                if component is None:
                    continue
                key = (pod['podRef']['uid'], container['name'])
                cpu = container.get('cpu', {}).get('usageCoreNanoSeconds')
                if cpu is not None:
                    if key in previous and cpu >= previous[key]:
                        cpu_seconds[component] += (cpu-previous[key])/1e9
                    previous[key] = cpu
                memory[component] += container.get('memory', {}).get('workingSetBytes', 0)
                rss_memory[component] += container.get('memory', {}).get('rssBytes', 0)
        for component, value in memory.items():
            peaks[component] = max(peaks[component], value)
            rss[component] = max(rss[component], rss_memory[component])
    duration = samples[-1]['time']-samples[0]['time'] if len(samples) > 1 else 0
    return {component: {'mean_cpu_cores': seconds/duration if duration else None,
                        'peak_working_set_mib': peaks[component]/1048576,
                        'peak_rss_mib': rss[component]/1048576}
            for component, seconds in cpu_seconds.items()}


def control_plane_metrics():
    counters = ['agentio_compile_failures_total', 'agentio_xds_pushes_total',
                'agentio_xds_nacks_total', 'agentio_xds_push_failures_total',
                'agentio_xds_request_rejections_total']
    histograms = ['agentio_compile_duration_seconds', 'agentio_publish_duration_seconds',
                  'agentio_xds_push_duration_seconds', 'agentio_xds_queue_duration_seconds',
                  'agentio_xds_convergence_duration_seconds']
    selected = counters + [h+s for h in histograms for s in ['_bucket', '_count', '_sum']]

    def read(path):
        values = collections.defaultdict(float)
        for line in path.read_text().splitlines():
            if not line or line.startswith('#'):
                continue
            series, value = line.rsplit(' ', 1)
            name = series.split('{', 1)[0]
            if name in selected:
                bucket = re.search(r'le="([^"]+)"', series)
                values[(name, bucket.group(1) if bucket else None)] += float(value)
        return values

    totals = collections.defaultdict(float)
    paired, unpaired, reset = [], [], []
    for after in root.glob('after-mutations-agentiod-*-15014.prom'):
        before = root / after.name.replace('after-mutations-', 'before-', 1)
        if not before.exists():
            unpaired.append(after.name)
            continue
        old, new = read(before), read(after)
        delta = {key: value-old.get(key, 0) for key, value in new.items()}
        if any(value < 0 for value in delta.values()):
            reset.append(after.name)
            continue
        paired.append(after.name)
        for key, value in delta.items():
            totals[key] += value
    output = {'paired_pods': paired, 'unpaired_pods': unpaired, 'counter_resets': reset}
    if not paired or unpaired or reset:
        return output
    output['counters'] = {name: totals[(name, None)] for name in counters}
    output['histograms'] = {}
    for name in histograms:
        count = totals[(name+'_count', None)]
        buckets = sorted((float(bound), value) for (metric, bound), value in totals.items()
                         if metric == name+'_bucket')
        upper = next((bound for bound, value in buckets if count and value >= count*.99), None)
        output['histograms'][name] = {
            'count': count,
            'mean_seconds': totals[(name+'_sum', None)]/count if count else None,
            'p99_bucket_upper_seconds': '+Inf' if upper == float('inf') else upper,
        }
    return output


def control_plane_cpu_quota():
    paths = [root / f'{phase}-cadvisor.prom' for phase in ['before', 'after-mutations']]
    if not all(path.exists() for path in paths):
        return {'available': False}
    metrics = ['container_cpu_cfs_periods_total', 'container_cpu_cfs_throttled_periods_total',
               'container_cpu_cfs_throttled_seconds_total']
    snapshots = []
    for path in paths:
        values = {}
        for line in path.read_text().splitlines():
            if (not line.startswith(tuple(metrics)) or
                f'namespace="{args.namespace}"' not in line or 'container="discovery"' not in line):
                continue
            # cAdvisor includes an optional sample timestamp after the value.
            series, value, *_ = line.split()
            values[series] = float(value)
        snapshots.append(values)
    before, after = snapshots
    unmatched = set(before) ^ set(after)
    if unmatched:
        return {'available': False, 'unmatched_series': len(unmatched)}
    totals = collections.defaultdict(float)
    for series, value in after.items():
        delta = value-before[series]
        if delta < 0:
            return {'available': False, 'counter_reset': True}
        totals[series.split('{', 1)[0]] += delta
    periods = totals[metrics[0]]
    return {'available': bool(after), 'delta': totals,
            'throttled_period_fraction': totals[metrics[1]]/periods if periods else None}


output = {'loads': {}, 'cache': {}}
for name, result in loads.items():
    output['loads'][name] = {key: result[key] for key in [
        'operations', 'errors', 'ops_per_second', 'p50_ms', 'p95_ms', 'p99_ms', 'max_ms',
        'unique_attempted', 'offered_rate', 'action_error', 'first_error']}
    output['loads'][name]['resources'] = resources(result['started_unix'], result['finished_unix'])
    output['loads'][name]['error_seconds'] = {key: value['error'] for key, value in result['seconds_bins'].items() if value['error']}
after_cache_files = list(root.glob('after-mutations-egress-gateway-*-9004.prom'))
paired_pods = {p.name.removeprefix('after-mutations-') for p in after_cache_files
               if (root / p.name.replace('after-mutations-', 'before-', 1)).exists()}
output['cache']['unpaired_pods'] = [p.name for p in after_cache_files
                                  if p.name.removeprefix('after-mutations-') not in paired_pods]
for phase in ['before', 'after-mutations']:
    totals = collections.defaultdict(float)
    for suffix in paired_pods:
        path = root / f'{phase}-{suffix}'
        for line in path.read_text().splitlines():
            if not line or line.startswith('#'):
                continue
            metric, value = line.rsplit(' ', 1)
            if metric.startswith('agentio_porter_demand_cache_lookups_total'):
                key = re.search(r'result="([^"]+)"', metric).group(1)
                totals[key] += float(value)
            elif metric.startswith('agentio_porter_demand_cache_evictions_total'):
                key = re.search(r'reason="([^"]+)"', metric).group(1)
                totals['eviction_'+key] += float(value)
    output['cache'][phase] = totals
if paired_pods and not output['cache']['unpaired_pods']:
    output['cache']['delta'] = {key: value-output['cache']['before'].get(key, 0)
                               for key, value in output['cache']['after-mutations'].items()}
output['control_plane'] = control_plane_metrics()
output['control_plane_cpu_quota'] = control_plane_cpu_quota()
output['events'] = [json.loads(line) for line in (root/'events.jsonl').open()]
print(json.dumps(output, indent=2))
