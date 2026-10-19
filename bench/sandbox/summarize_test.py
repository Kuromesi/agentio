"""Counter deltas must not combine old terminating Pods with replacement Pods."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class CounterIdentityTest(unittest.TestCase):
    def test_cadvisor_timestamp_is_not_a_counter_value(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'resources.jsonl').write_text('')
            (root / 'events.jsonl').write_text('')
            labels = '{container="discovery",id="container-a",namespace="sandbox-scale-system"}'
            for phase, periods, throttled in [('before', 100, 2), ('after-mutations', 200, 7)]:
                (root / f'{phase}-cadvisor.prom').write_text(
                    f'container_cpu_cfs_periods_total{labels} {periods} 1792305823829\n'
                    f'container_cpu_cfs_throttled_periods_total{labels} {throttled} 1792305823829\n')
            result = subprocess.check_output([
                sys.executable, str(Path(__file__).with_name('summarize.py')), str(root),
            ], text=True)
            quota = json.loads(result)['control_plane_cpu_quota']
            self.assertTrue(quota['available'])
            self.assertEqual(quota['throttled_period_fraction'], .05)

    def test_histograms_merge_interval_buckets_before_percentiles(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'resources.jsonl').write_text('')
            (root / 'events.jsonl').write_text('')
            prefix = 'agentio_xds_queue_duration_seconds'
            for pod, fast, slow in [('a', 98, 0), ('b', 0, 2)]:
                before = (f'{prefix}_bucket{{le="0.1"}} 100\n'
                          f'{prefix}_bucket{{le="1"}} 100\n'
                          f'{prefix}_bucket{{le="+Inf"}} 100\n'
                          f'{prefix}_count{{}} 100\n{prefix}_sum{{}} 1\n')
                after = (f'{prefix}_bucket{{le="0.1"}} {100+fast}\n'
                         f'{prefix}_bucket{{le="1"}} {100+fast+slow}\n'
                         f'{prefix}_bucket{{le="+Inf"}} {100+fast+slow}\n'
                         f'{prefix}_count{{}} {100+fast+slow}\n{prefix}_sum{{}} 2\n')
                (root / f'before-agentiod-{pod}-15014.prom').write_text(before)
                (root / f'after-mutations-agentiod-{pod}-15014.prom').write_text(after)
            result = subprocess.check_output([
                sys.executable, str(Path(__file__).with_name('summarize.py')), str(root),
            ], text=True)
            histogram = json.loads(result)['control_plane']['histograms'][prefix]
            self.assertEqual(histogram['count'], 100)
            self.assertEqual(histogram['p99_bucket_upper_seconds'], 1)
            self.assertEqual(histogram['mean_seconds'], .02)

    def test_retired_pod_does_not_subtract_from_new_pod(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'resources.jsonl').write_text('')
            (root / 'events.jsonl').write_text('')
            metric = 'agentio_porter_demand_cache_lookups_total{result="hit"} '
            (root / 'before-egress-gateway-retired-9004.prom').write_text(metric + '100\n')
            # Prometheus has not instantiated any counter series on the new Pod yet.
            (root / 'before-egress-gateway-current-9004.prom').write_text('# counter\n')
            (root / 'after-mutations-egress-gateway-current-9004.prom').write_text(metric + '7\n')
            result = subprocess.check_output([
                sys.executable, str(Path(__file__).with_name('summarize.py')), str(root),
            ], text=True)
            self.assertEqual(json.loads(result)['cache']['delta'], {'hit': 7.0})


if __name__ == '__main__':
    unittest.main()
