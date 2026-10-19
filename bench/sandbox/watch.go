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

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/types/known/structpb"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/bench/xds/fakeclient"
	"github.com/openkruise/agentio/pkg/model"
)

type watchStats struct {
	mu         sync.Mutex
	Connected  int
	Responses  int
	Reconnects int
	LastError  string
	Resources  map[int]map[string]map[string]string
}

func (r *runner) watch(ctx context.Context) (any, error) {
	cm, err := r.kube.CoreV1().ConfigMaps(r.System).Get(ctx, "sandbox-scale-ca-root-cert", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(cm.Data["root-cert.pem"])) {
		return nil, fmt.Errorf("empty roots")
	}
	_, err = r.kube.CoreV1().
		ServiceAccounts(r.System).
		Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "ztunnel"}}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, r.Duration)
	defer cancel()
	stats := &watchStats{Resources: map[int]map[string]map[string]string{}}
	prepare := *r
	prepare.Count = (r.Count + 99) / 100
	prepare.Offset = 0
	if err := prepare.parallel(ctx, func(ctx context.Context, i int) error {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("node-proxy-%04d", i),
				Namespace: r.System,
				Labels:    map[string]string{"bench.agentio.io/run": r.Prefix},
			},
			Spec: corev1.PodSpec{
				NodeName:           r.node(i * 100),
				ServiceAccountName: "ztunnel",
				Containers:         []corev1.Container{{Name: "ztunnel", Image: "registry.k8s.io/pause:3.10"}},
				Tolerations: []corev1.Toleration{
					{
						Key:      "kwok.x-k8s.io/node",
						Operator: corev1.TolerationOpExists,
						Effect:   corev1.TaintEffectNoSchedule,
					},
				},
			},
		}
		_, e := r.kube.CoreV1().Pods(r.System).Create(ctx, pod, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(e) {
			return nil
		}
		return e
	}); err != nil {
		return nil, err
	}
	var workers sync.WaitGroup
	for i := range prepare.Count {
		workers.Go(func() { r.watchNode(ctx, i, roots, stats) })
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	defer func() {
		cancel()
		workers.Wait()
	}()
	for {
		select {
		case <-ctx.Done():
			return r.watchSnapshot(stats), nil
		case <-ticker.C:
			value := r.watchSnapshot(stats)
			data, e := json.Marshal(value)
			if e != nil {
				return nil, e
			}
			fmt.Println(string(data))
			if r.Output != "" {
				if e = os.WriteFile(r.Output+".tmp", append(data, '\n'), 0600); e != nil {
					cancel()
					return nil, e
				}
				if e = os.Rename(r.Output+".tmp", r.Output+".live"); e != nil {
					return nil, e
				}
			}
		}
	}
}

func (r *runner) watchSnapshot(stats *watchStats) any {
	stats.mu.Lock()
	defer stats.mu.Unlock()
	counts := map[string]int{}
	versions := map[string]int{}
	ready := 0
	for _, types := range stats.Resources {
		if len(types) == 3 {
			ready++
		}
		for typ, resources := range types {
			counts[typ] += len(resources)
			if typ == model.TrafficPolicyType {
				for _, version := range resources {
					versions[version]++
				}
			}
		}
	}
	return map[string]any{
		"time":            time.Now(),
		"connected":       stats.Connected,
		"ready":           ready,
		"responses":       stats.Responses,
		"reconnects":      stats.Reconnects,
		"resources":       counts,
		"policy_versions": versions,
		"last_error":      stats.LastError,
	}
}

func (r *runner) watchNode(ctx context.Context, i int, roots *x509.CertPool, stats *watchStats) {
	for ctx.Err() == nil {
		err := r.watchStream(ctx, i, roots, stats)
		if ctx.Err() != nil {
			return
		}
		stats.mu.Lock()
		stats.Reconnects++
		stats.LastError = err.Error()
		stats.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func (r *runner) watchStream(ctx context.Context, i int, roots *x509.CertPool, stats *watchStats) error {
	name := fmt.Sprintf("node-proxy-%04d", i)
	pod, err := r.kube.CoreV1().Pods(r.System).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	token, err := r.kube.CoreV1().
		ServiceAccounts(r.System).
		CreateToken(ctx, "ztunnel", &authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{Audiences: []string{"agentio-ca"}, BoundObjectRef: &authenticationv1.BoundObjectReference{APIVersion: "v1", Kind: "Pod", Name: name, UID: pod.UID}}}, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	nodeMeta, err := structpb.NewStruct(
		map[string]any{"POD_NAMESPACE": r.System, "POD_NAME": name, "NODE_NAME": r.node(i * 100)},
	)
	if err != nil {
		return err
	}
	client, err := fakeclient.Open(
		ctx,
		fakeclient.Config{
			Target: r.CA,
			Node: &core.Node{
				Id:       "ztunnel~10.223.0.1~" + name + "." + r.System + "~" + r.System + ".svc.cluster.local",
				Metadata: nodeMeta,
			},
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    roots,
				ServerName: "agentiod." + r.System + ".svc",
			},
			Token: func(context.Context) (string, error) { return token.Status.Token, nil },
		},
	)
	if err != nil {
		return err
	}
	defer closeResource(client)
	stats.mu.Lock()
	stats.Connected++
	stats.Resources[i] = map[string]map[string]string{}
	stats.mu.Unlock()
	defer func() {
		stats.mu.Lock()
		stats.Connected--
		delete(stats.Resources, i)
		stats.mu.Unlock()
	}()
	for _, typ := range []string{model.AddressType, model.SandboxType, model.TrafficPolicyType} {
		if err := client.Subscribe(typ, "*"); err != nil {
			return err
		}
	}
	for {
		response, err := client.Recv()
		if err != nil {
			return err
		}
		stats.mu.Lock()
		types := stats.Resources[i]
		resources := types[response.TypeUrl]
		if resources == nil {
			resources = map[string]string{}
			types[response.TypeUrl] = resources
		}
		for _, resource := range response.Resources {
			resources[resource.Name] = resource.Version
		}
		for _, name := range response.RemovedResources {
			delete(resources, name)
		}
		stats.Responses++
		stats.mu.Unlock()
		if err := client.ACK(response); err != nil {
			return err
		}
	}
}
