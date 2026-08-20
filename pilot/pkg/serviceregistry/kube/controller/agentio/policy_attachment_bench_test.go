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

package agentio

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/test"
)

const (
	policyAttachmentBenchWorkloadsEnv = "AGENTIO_BENCH_WORKLOADS"
	policyAttachmentBenchPoliciesEnv  = "AGENTIO_BENCH_POLICIES"
)

func policyAttachmentBenchWorkloads(b *testing.B) int {
	b.Helper()
	const defaultWorkloads = 1000
	value := os.Getenv(policyAttachmentBenchWorkloadsEnv)
	if value == "" {
		return defaultWorkloads
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		b.Fatalf("%s must be a positive integer, got %q", policyAttachmentBenchWorkloadsEnv, value)
	}
	return parsed
}

func policyAttachmentBenchPolicies(b *testing.B) int {
	b.Helper()
	const defaultPolicies = 100
	value := os.Getenv(policyAttachmentBenchPoliciesEnv)
	if value == "" {
		return defaultPolicies
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		b.Fatalf("%s must be a positive integer, got %q", policyAttachmentBenchPoliciesEnv, value)
	}
	return parsed
}

func benchmarkWorkloads(count int) []model.WorkloadInfo {
	workloads := make([]model.WorkloadInfo, 0, count)
	for i := 0; i < count; i++ {
		workloads = append(workloads, sniTestWorkload(
			fmt.Sprintf("pod-%d", i), "bench", map[string]string{"app": "agent"},
		))
	}
	return workloads
}

func benchmarkRulesPolicy(host string) BindablePolicy {
	policy := sniBindablePolicy("bench", "policy", 1, nil)
	policy.Resource = &extensions.SniTrafficPolicy{Rules: []*extensions.SniRule{
		sniRule(extensions.SniAction_SNI_ACTION_TLS_TERMINATION, host),
	}}
	return policy
}

func benchmarkWaitForRecomputes(b *testing.B, recomputes *atomic.Int64, want int64) {
	b.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for recomputes.Load() < want {
		if time.Now().After(deadline) {
			b.Fatalf("timed out waiting for binding recomputes: got %d, want %d", recomputes.Load(), want)
		}
		runtime.Gosched()
	}
	if got := recomputes.Load(); got != want {
		b.Fatalf("unexpected binding recomputes: got %d, want %d", got, want)
	}
}

func benchmarkOldPolicyRefs(
	ctx krt.HandlerContext,
	policies krt.Collection[BindablePolicy],
	policiesByNamespace krt.Index[string, BindablePolicy],
	workloadNamespace string,
	workloadLabels map[string]string,
) map[string]*extensions.PolicyReference {
	selectorFilter := krt.FilterGeneric(func(a any) bool {
		return a.(BindablePolicy).Selects(workloadNamespace, workloadLabels)
	})
	matched := krt.Fetch(ctx, policies,
		krt.FilterIndex(policiesByNamespace, workloadNamespace), selectorFilter)
	if workloadNamespace != "" {
		matched = append(matched, krt.Fetch(ctx, policies,
			krt.FilterIndex(policiesByNamespace, ""), selectorFilter)...)
	}

	byType := make(map[string][]PolicyRef)
	for _, policy := range matched {
		if policy.TypeURL == "" || policy.Name == "" || policy.Resource == nil {
			continue
		}
		byType[policy.TypeURL] = append(byType[policy.TypeURL], PolicyRef{
			ResourceName:    policy.XDSResourceName(),
			Priority:        policy.Priority,
			CreationTime:    policy.CreationTime,
			SourceName:      policy.SourceName,
			SourceNamespace: policy.SourceNamespace,
		})
	}
	result := make(map[string]*extensions.PolicyReference, len(byType))
	for typeURL, refs := range byType {
		result[typeURL] = &extensions.PolicyReference{ResourceNames: sortPolicyRefs(refs)}
	}
	return result
}

func benchmarkOldPolicyBindingTransformation(
	policies krt.Collection[BindablePolicy],
	policiesByNamespace krt.Index[string, BindablePolicy],
	recomputes *atomic.Int64,
) krt.TransformationMulti[model.WorkloadInfo, model.PolicyBinding] {
	return func(ctx krt.HandlerContext, workload model.WorkloadInfo) []model.PolicyBinding {
		recomputes.Add(1)
		namespace, name := workload.Workload.GetNamespace(), workload.Workload.GetName()
		binding := &extensions.PolicyBinding{
			TargetRef: &extensions.PolicyBinding_Workload{
				Workload: &extensions.WorkloadReference{Namespace: namespace, Name: name},
			},
			PolicyRefs: benchmarkOldPolicyRefs(ctx, policies, policiesByNamespace, namespace, workload.Labels),
		}
		return []model.PolicyBinding{{Name: model.PolicyBindingResourceName(namespace, name), Binding: binding}}
	}
}

// BenchmarkPolicyBindingRulesOnlyUpdate measures the fanout caused by changing
// only a policy protobuf while a catch-all selector matches many workloads.
//
// Run the 10k workload case explicitly with one benchmark iteration to avoid
// queuing an unbounded number of intentionally expensive baseline recomputes:
//
//	AGENTIO_BENCH_WORKLOADS=10000 go test ./pilot/pkg/serviceregistry/kube/controller/agentio \
//	  -run '^$' -bench '^BenchmarkPolicyBindingRulesOnlyUpdate$' -benchtime=1x -benchmem
//
// The primary signal is binding_recomputes/op: direct-bindable should equal the
// workload count, while policy-attachment should remain zero.
func BenchmarkPolicyBindingRulesOnlyUpdate(b *testing.B) {
	workloadCount := policyAttachmentBenchWorkloads(b)
	workloads := benchmarkWorkloads(workloadCount)
	policyA := benchmarkRulesPolicy("a.example.com")
	policyB := benchmarkRulesPolicy("b.example.com")

	for _, benchmark := range []struct {
		name  string
		setup func(*testing.B, krt.StaticCollection[model.WorkloadInfo], krt.StaticCollection[BindablePolicy], krt.OptionsBuilder, *atomic.Int64) krt.Collection[model.PolicyBinding]
	}{
		{
			name: "direct-bindable-baseline",
			setup: func(
				_ *testing.B,
				workloadSource krt.StaticCollection[model.WorkloadInfo],
				policySource krt.StaticCollection[BindablePolicy],
				opts krt.OptionsBuilder,
				recomputes *atomic.Int64,
			) krt.Collection[model.PolicyBinding] {
				byNamespace := krt.NewIndex(policySource, "benchmarkBindablePoliciesByNamespace", func(policy BindablePolicy) []string {
					return []string{policy.Namespace}
				})
				return krt.NewManyCollection(workloadSource,
					benchmarkOldPolicyBindingTransformation(policySource, byNamespace, recomputes),
					opts.WithName("BenchmarkDirectPolicyBindings")...)
			},
		},
		{
			name: "policy-attachment",
			setup: func(
				_ *testing.B,
				workloadSource krt.StaticCollection[model.WorkloadInfo],
				policySource krt.StaticCollection[BindablePolicy],
				opts krt.OptionsBuilder,
				recomputes *atomic.Int64,
			) krt.Collection[model.PolicyBinding] {
				attachments := newPolicyAttachmentsCollection(policySource, opts)
				byNamespace := krt.NewIndex(attachments, "benchmarkPolicyAttachmentsByNamespace", func(policy PolicyAttachment) []string {
					return []string{policy.Namespace}
				})
				productionTransform := policyBindingTransformation(attachments, byNamespace)
				return krt.NewManyCollection(workloadSource,
					func(ctx krt.HandlerContext, workload model.WorkloadInfo) []model.PolicyBinding {
						recomputes.Add(1)
						return productionTransform(ctx, workload)
					}, opts.WithName("BenchmarkAttachmentPolicyBindings")...)
			},
		},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			stop := test.NewStop(b)
			opts := krt.NewOptionsBuilder(stop, benchmark.name, krt.GlobalDebugHandler)
			workloadSource := krt.NewStaticCollection(nil, workloads, opts.WithName("Workloads")...)
			policySource := krt.NewStaticCollection(nil, []BindablePolicy{policyA}, opts.WithName("BindablePolicies")...)
			var recomputes atomic.Int64
			bindings := benchmark.setup(b, workloadSource, policySource, opts, &recomputes)
			if !bindings.WaitUntilSynced(stop) {
				b.Fatal("policy bindings did not sync")
			}
			benchmarkWaitForRecomputes(b, &recomputes, int64(workloadCount))
			recomputes.Store(0)

			b.ReportMetric(float64(workloadCount), "workloads")
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if i%2 == 0 {
					policySource.UpdateObject(policyB)
				} else {
					policySource.UpdateObject(policyA)
				}
			}
			barrier := policyA
			barrier.Priority++
			policySource.UpdateObject(barrier)

			barrierRecomputes := int64(workloadCount)
			want := barrierRecomputes
			if benchmark.name == "direct-bindable-baseline" {
				want += int64(b.N * workloadCount)
			}
			benchmarkWaitForRecomputes(b, &recomputes, want)
			b.StopTimer()

			rulesOnlyRecomputes := recomputes.Load() - barrierRecomputes
			b.ReportMetric(float64(rulesOnlyRecomputes)/float64(b.N), "binding_recomputes/op")
		})
	}
}

// BenchmarkPolicyBindingCreateStorm measures the real production path for a
// burst of selector-based policies that all match the same workloads.
//
// Run the 10k-policy case with one iteration:
//
//	AGENTIO_BENCH_POLICIES=10000 AGENTIO_BENCH_WORKLOADS=4 \
//	  go test ./pilot/pkg/serviceregistry/kube/controller/agentio \
//	  -run '^$' -bench '^BenchmarkPolicyBindingCreateStorm$' -benchtime=1x -benchmem
//
// The primary signal is binding_recomputes/op. The debounced case uses the
// chart defaults (200ms quiet window, 10s maximum delay).
func BenchmarkPolicyBindingCreateStorm(b *testing.B) {
	workloadCount := policyAttachmentBenchWorkloads(b)
	policyCount := policyAttachmentBenchPolicies(b)
	workloads := benchmarkWorkloads(workloadCount)

	for _, benchmark := range []struct {
		name     string
		debounce time.Duration
		maxDelay time.Duration
	}{
		{name: "baseline"},
		{name: "debounce-200ms", debounce: 200 * time.Millisecond, maxDelay: 10 * time.Second},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			oldDebounce, oldMaxDebounce := features.KrtEventDistributeDebounce, features.KrtEventDistributeDebounceMax
			features.KrtEventDistributeDebounce = benchmark.debounce
			features.KrtEventDistributeDebounceMax = benchmark.maxDelay
			b.Cleanup(func() {
				features.KrtEventDistributeDebounce = oldDebounce
				features.KrtEventDistributeDebounceMax = oldMaxDebounce
			})

			stop := test.NewStop(b)
			opts := krt.NewOptionsBuilder(stop, benchmark.name, krt.GlobalDebugHandler)
			workloadSource := krt.NewStaticCollection(nil, workloads, opts.WithName("Workloads")...)
			seed := sniBindablePolicy("bench", "seed", 1, map[string]string{"app": "agent"})
			policySource := krt.NewStaticCollection(nil, []BindablePolicy{seed}, opts.WithName("BindablePolicies")...)
			attachments := newPolicyAttachmentsCollection(policySource, opts)
			byNamespace := krt.NewIndex(attachments, "benchmarkPolicyAttachmentsByNamespace", func(policy PolicyAttachment) []string {
				return []string{policy.Namespace}
			})
			productionTransform := policyBindingTransformation(attachments, byNamespace)
			var recomputes atomic.Int64
			bindings := krt.NewManyCollection(workloadSource,
				func(ctx krt.HandlerContext, workload model.WorkloadInfo) []model.PolicyBinding {
					recomputes.Add(1)
					return productionTransform(ctx, workload)
				}, opts.WithName("PolicyBindings")...)
			if !bindings.WaitUntilSynced(stop) {
				b.Fatal("policy bindings did not sync")
			}
			benchmarkWaitForRecomputes(b, &recomputes, int64(workloadCount))
			recomputes.Store(0)

			b.ReportMetric(float64(workloadCount), "workloads")
			b.ReportMetric(float64(policyCount), "policies/op")
			wantPolicies := 1
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				for i := 0; i < policyCount; i++ {
					policySource.UpdateObject(sniBindablePolicy(
						"bench", fmt.Sprintf("policy-%d-%d", n, i), 1, map[string]string{"app": "agent"},
					))
				}
				wantPolicies += policyCount
				deadline := time.Now().Add(10 * time.Minute)
				for {
					converged := len(bindings.List()) == workloadCount
					if converged {
						for _, binding := range bindings.List() {
							refs := binding.Binding.GetPolicyRefs()[seed.TypeURL]
							if refs == nil || len(refs.ResourceNames) != wantPolicies {
								converged = false
								break
							}
						}
					}
					if converged {
						break
					}
					if time.Now().After(deadline) {
						b.Fatalf("timed out waiting for %d policy references", wantPolicies)
					}
					time.Sleep(10 * time.Millisecond)
				}
			}

			// Visible convergence may precede late redundant queue entries. Wait
			// until the recompute counter is quiet before reporting it.
			for {
				before := recomputes.Load()
				time.Sleep(100 * time.Millisecond)
				if recomputes.Load() == before {
					break
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(recomputes.Load())/float64(b.N), "binding_recomputes/op")
		})
	}
}
