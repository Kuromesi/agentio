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

package compiler

import (
	"testing"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

func TestValidatedDomainInputsRejectsMultipleActiveAttestersForSandbox(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	workloads := krt.NewStaticCollection(nil, []model.Workload{
		validationTestWorkload("workload-a", "sandbox-a"),
		validationTestWorkload("workload-b", "sandbox-a"),
	}, options...)
	failures := newFailureRecorder()

	validated := validatedDomainInputs(Inputs{Workloads: workloads}, failures,
		func(name string) []krt.CollectionOption {
			return []krt.CollectionOption{krt.WithStop(stop), krt.WithName(name)}
		})
	if !validated.Workloads.WaitUntilSynced(stop) {
		t.Fatal("validated Workloads did not sync")
	}
	if got := validated.Workloads.List(); len(got) != 0 {
		t.Fatalf("validated Workloads = %+v, want both conflicting attesters omitted", got)
	}
	if got := len(failures.snapshot()); got != 2 {
		t.Fatalf("failures = %v, want one per conflicting Workload", failures.snapshot())
	}
}

func TestValidateDiscoveredWorkload(t *testing.T) {
	valid := validationTestWorkload("workload-a", "sandbox-a")
	valid.Principal = model.Principal{}
	tests := []struct {
		name    string
		mutate  func(*model.Workload)
		wantErr bool
	}{
		{name: "absent principal"},
		{name: "empty service-account identity", mutate: func(workload *model.Workload) {
			workload.Principal = model.Principal{Kind: model.PrincipalServiceAccount}
		}},
		{name: "empty UID", mutate: func(workload *model.Workload) {
			workload.UID = ""
		}, wantErr: true},
		{name: "invalid tunnel", mutate: func(workload *model.Workload) {
			workload.TunnelProtocol = "invalid"
		}, wantErr: true},
		{name: "empty binding", mutate: func(workload *model.Workload) {
			workload.SandboxBindings = []model.SandboxBinding{{}}
		}, wantErr: true},
		{name: "duplicate binding", mutate: func(workload *model.Workload) {
			workload.SandboxBindings = append(workload.SandboxBindings, workload.SandboxBindings[0])
		}, wantErr: true},
		{name: "identity fields without kind", mutate: func(workload *model.Workload) {
			workload.Principal = model.Principal{TrustDomain: "cluster.local"}
		}, wantErr: true},
		{name: "unknown identity kind", mutate: func(workload *model.Workload) {
			workload.Principal = model.Principal{Kind: "unsupported"}
		}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			workload := valid
			if test.mutate != nil {
				test.mutate(&workload)
			}
			err := validateDiscoveredWorkload(workload)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateDiscoveredWorkload() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func validationTestWorkload(uid, sandboxUID string) model.Workload {
	return model.Workload{
		UID:       uid,
		Namespace: "demo",
		SandboxBindings: []model.SandboxBinding{
			{
				SandboxUID: sandboxUID,
			},
		},
		Principal: model.Principal{
			Kind:        model.PrincipalServiceAccount,
			TrustDomain: "cluster.local",
			ServiceAccount: model.ServiceAccountRef{
				Namespace:      "demo",
				ServiceAccount: "client",
			},
		},
	}
}
