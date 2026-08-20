// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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

package model

import "testing"

func TestWorkloadConfigType(t *testing.T) {
	const want = "type.googleapis.com/kruise.networking.extensions.v1.WorkloadConfig"
	if WorkloadConfigType != want {
		t.Fatalf("unexpected WCDS resource type: got %q, want %q", WorkloadConfigType, want)
	}
}

func TestPolicyBindingType(t *testing.T) {
	const want = "type.googleapis.com/kruise.networking.extensions.v1.PolicyBinding"
	if PolicyBindingType != want {
		t.Fatalf("unexpected PBDS resource type: got %q, want %q", PolicyBindingType, want)
	}
}

func TestSniTrafficPolicyType(t *testing.T) {
	const want = "type.googleapis.com/kruise.networking.extensions.v1.SniTrafficPolicy"
	if SniTrafficPolicyType != want {
		t.Fatalf("unexpected STPDS resource type: got %q, want %q", SniTrafficPolicyType, want)
	}
}

func TestPolicyTypeShortAndMetricTypes(t *testing.T) {
	cases := []struct {
		typeURL    string
		shortType  string
		metricType string
	}{
		{typeURL: PolicyBindingType, shortType: "PBDS", metricType: "pbds"},
		{typeURL: SniTrafficPolicyType, shortType: "STPDS", metricType: "stpds"},
	}

	for _, tc := range cases {
		t.Run(tc.shortType, func(t *testing.T) {
			if got := GetShortType(tc.typeURL); got != tc.shortType {
				t.Errorf("unexpected short type: got %q, want %q", got, tc.shortType)
			}
			if got := GetMetricType(tc.typeURL); got != tc.metricType {
				t.Errorf("unexpected metric type: got %q, want %q", got, tc.metricType)
			}
			if got := GetResourceType(tc.shortType); got != tc.typeURL {
				t.Errorf("unexpected resource type: got %q, want %q", got, tc.typeURL)
			}
			if got := GetResourceType(tc.metricType); got != tc.typeURL {
				t.Errorf("unexpected resource type for lowercase short form: got %q, want %q", got, tc.typeURL)
			}
		})
	}
}
