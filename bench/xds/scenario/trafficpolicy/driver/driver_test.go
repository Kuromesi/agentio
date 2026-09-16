// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package driver

import (
	"encoding/json"
	"testing"

	"github.com/openkruise/agentio/bench/xds/loadapi"
	"github.com/openkruise/agentio/bench/xds/scenario/trafficpolicy"
)

func TestRoundsDoNotShareMarkersBetweenRuns(t *testing.T) {
	a, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	x, err := a.Rounds(2)
	if err != nil {
		t.Fatal(err)
	}
	y, err := b.Rounds(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(x) != 4 || string(x[0]) != string(y[0]) {
		t.Fatal("runs share state or payload sizes missing")
	}
	z, err := a.Rounds(1)
	if err != nil {
		t.Fatal(err)
	}
	var last, next trafficpolicy.Round
	if err = json.Unmarshal(x[len(x)-1], &last); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(z[0], &next); err != nil {
		t.Fatal(err)
	}
	if next.Marker <= last.Marker {
		t.Fatal("markers repeated between stages")
	}
}

func TestCheckRequiresConsistentPoliciesWithoutSandboxPushes(t *testing.T) {
	d, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	before := []loadapi.Status{{}, {}}
	for _, corruption := range []string{"", "version", "size", "sandbox"} {
		t.Run(corruption, func(t *testing.T) {
			after := []loadapi.Status{{Samples: []loadapi.Sample{{Version: "v1", Bytes: 10}}}, {Samples: []loadapi.Sample{{Version: "v1", Bytes: 10}}}}
			switch corruption {
			case "version":
				after[1].Samples[0].Version = "v2"
			case "size":
				after[1].Samples[0].Bytes = 11
			case "sandbox":
				after[1].ResponsesByType = map[string]int64{trafficpolicy.SandboxType: 1}
			}
			checks, err := d.Check(nil, before, after)
			if corruption == "" {
				if err != nil || checks["version"] != "v1" {
					t.Fatalf("checks=%v err=%v", checks, err)
				}
			} else if err == nil {
				t.Fatal("invalid round accepted")
			}
		})
	}
}
