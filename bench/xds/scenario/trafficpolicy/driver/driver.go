// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package driver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openkruise/agentio/bench/xds/loadapi"
	"github.com/openkruise/agentio/bench/xds/scenario"
	"github.com/openkruise/agentio/bench/xds/scenario/driver"
	"github.com/openkruise/agentio/bench/xds/scenario/trafficpolicy"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

var sandboxGVR = schema.GroupVersionResource{Group: "agents.kruise.io", Version: "v1alpha1", Resource: "sandboxes"}
var policyGVR = schema.GroupVersionResource{Group: "agents.kruise.io", Version: "v1alpha1", Resource: "globaltrafficpolicies"}

type Options struct {
	Rules        int   `json:"rules"`
	PortsPerRule []int `json:"ports_per_rule"`
}
type policyDriver struct {
	cfg    Options
	marker int
}

func New(raw json.RawMessage) (driver.Driver, error) {
	cfg := Options{Rules: 50, PortsPerRule: []int{1, 20}}
	if err := scenario.Decode(raw, &cfg); err != nil {
		return nil, err
	}
	if cfg.Rules < 2 || cfg.Rules > 50001 || len(cfg.PortsPerRule) == 0 {
		return nil, errors.New("invalid rules/ports_per_rule")
	}
	for _, ports := range cfg.PortsPerRule {
		if ports < 1 || ports > 50000/(cfg.Rules-1) {
			return nil, errors.New("require (rules-1)*ports <= 50000")
		}
	}
	return &policyDriver{cfg: cfg, marker: 10000}, nil
}
func (d *policyDriver) ClientConfig(namespace, pod string) (json.RawMessage, error) {
	return json.Marshal(trafficpolicy.ClientOptions{PolicyName: "trafficPolicies/" + namespace, SandboxID: namespace + "--" + pod})
}
func (d *policyDriver) Prepare(ctx context.Context, e driver.Environment) error {
	for _, name := range e.Pods {
		sb := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "agents.kruise.io/v1alpha1", "kind": "Sandbox", "metadata": map[string]any{"name": name, "namespace": e.Namespace, "labels": map[string]any{driver.RunLabel: e.Namespace}}, "spec": map[string]any{}}}
		sb, err := e.Dynamic.Resource(sandboxGVR).Namespace(e.Namespace).Create(ctx, sb, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		p, err := e.Kube.CoreV1().Pods(e.Namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		owner := map[string]any{"metadata": map[string]any{"ownerReferences": []metav1.OwnerReference{{APIVersion: "agents.kruise.io/v1alpha1", Kind: "Sandbox", Name: name, UID: sb.GetUID(), Controller: ptr.To(true)}}}}
		data, err := json.Marshal(owner)
		if err != nil {
			return err
		}
		if _, err = e.Kube.CoreV1().Pods(e.Namespace).Patch(ctx, name, types.MergePatchType, data, metav1.PatchOptions{}); err != nil {
			return err
		}
		status := map[string]any{"status": map[string]any{"phase": "Running", "observedGeneration": sb.GetGeneration(), "podInfo": map[string]any{"podUID": string(p.UID)}}}
		data, err = json.Marshal(status)
		if err != nil {
			return err
		}
		if _, err = e.Dynamic.Resource(sandboxGVR).Namespace(e.Namespace).Patch(ctx, name, types.MergePatchType, data, metav1.PatchOptions{}, "status"); err != nil {
			return err
		}
	}
	e.Track(driver.Resource{GVR: policyGVR, Name: e.Namespace})
	_, err := e.Dynamic.Resource(policyGVR).Create(ctx, policy(e.Namespace, trafficpolicy.Round{Marker: uint32(d.marker), RuleCount: d.cfg.Rules, Ports: d.cfg.PortsPerRule[0]}), metav1.CreateOptions{})
	return err
}
func (d *policyDriver) Rounds(repeats int) ([]json.RawMessage, error) {
	if repeats < 1 || repeats > (65535-d.marker)/len(d.cfg.PortsPerRule) {
		return nil, errors.New("too many rounds for unique port markers")
	}
	var rounds []json.RawMessage
	for _, ports := range d.cfg.PortsPerRule {
		for i := 0; i < repeats; i++ {
			d.marker++
			r := trafficpolicy.Round{Marker: uint32(d.marker), Action: int32(d.marker % 2), RuleCount: d.cfg.Rules, Ports: ports}
			raw, err := json.Marshal(r)
			if err != nil {
				return nil, err
			}
			rounds = append(rounds, raw)
		}
	}
	return rounds, nil
}
func (d *policyDriver) Trigger(ctx context.Context, e driver.Environment, raw json.RawMessage) error {
	var r trafficpolicy.Round
	if err := scenario.Decode(raw, &r); err != nil {
		return err
	}
	if err := r.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(map[string]any{"spec": policy(e.Namespace, r).Object["spec"]})
	if err != nil {
		return err
	}
	_, err = e.Dynamic.Resource(policyGVR).Patch(ctx, e.Namespace, types.MergePatchType, data, metav1.PatchOptions{})
	return err
}
func (d *policyDriver) Check(_ json.RawMessage, before, after []loadapi.Status) (map[string]any, error) {
	if len(before) != len(after) {
		return nil, errors.New("missing client statuses")
	}
	delta := int64(0)
	version := ""
	size := 0
	for i, s := range after {
		delta += s.ResponsesByType[trafficpolicy.SandboxType] - before[i].ResponsesByType[trafficpolicy.SandboxType]
		for _, sample := range s.Samples {
			if sample.Version == "" || sample.Bytes <= 0 {
				return nil, errors.New("unversioned/empty policy sample")
			}
			if version == "" {
				version = sample.Version
				size = sample.Bytes
			}
			if sample.Version != version || sample.Bytes != size {
				return nil, errors.New("inconsistent resource versions or sizes")
			}
		}
	}
	if delta != 0 {
		return nil, fmt.Errorf("shared policy update sent %d unexpected Sandbox responses", delta)
	}
	if version == "" {
		return nil, errors.New("missing policy samples")
	}
	return map[string]any{"version": version, "policy_bytes": size, "sandbox_responses_delta": delta}, nil
}

func policy(name string, r trafficpolicy.Round) *unstructured.Unstructured {
	entries := make([]any, 0, r.RuleCount)
	// Egress rules require explicit destination peers to configure the direction.
	targets := []any{map[string]any{"cidr": "0.0.0.0/0"}, map[string]any{"cidr": "::/0"}}
	for i := 0; i < r.RuleCount-1; i++ {
		matches := make([]any, 0, r.Ports)
		for j := 0; j < r.Ports; j++ {
			p := 12000 + i*r.Ports + j
			if i == 0 && j == 0 {
				p = int(r.Marker)
			}
			matches = append(matches, map[string]any{"protocol": "UDP", "port": int64(p)})
		}
		entries = append(entries, map[string]any{"action": "reject", "ports": matches, "to": targets})
	}
	action := "allow"
	if r.Action == 1 {
		action = "reject"
	}
	entries = append(entries, map[string]any{"action": action, "to": targets})
	return &unstructured.Unstructured{Object: map[string]any{"apiVersion": "agents.kruise.io/v1alpha1", "kind": "GlobalTrafficPolicy", "metadata": map[string]any{"name": name, "labels": map[string]any{driver.RunLabel: name}}, "spec": map[string]any{"priority": int64(10), "selector": map[string]any{"matchLabels": map[string]any{driver.RunLabel: name}}, "egress": map[string]any{"rules": entries}}}}
}
