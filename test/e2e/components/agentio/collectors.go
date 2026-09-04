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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/artifacts"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
)

func Collectors(config Config) []e2e.Collector {
	ztunnel := podCollector{
		name:              "ztunnel",
		namespaceSelector: DataplaneModeLabel + "=" + ProfileSidecar,
		requiredContainer: "agentio-proxy",
	}
	if config.Profile == ProfileAmbient {
		ztunnel.namespace = config.Namespace
		ztunnel.selector = "app.kubernetes.io/name=ztunnel"
		ztunnel.namespaceSelector = ""
		ztunnel.requiredContainer = ""
	}
	return []e2e.Collector{
		podCollector{name: "agentiod", namespace: config.Namespace, selector: "app=agentiod"},
		podCollector{name: "egress-gateway", namespace: config.Namespace, selector: "gateway.networking.k8s.io/gateway-name=egress-gateway"},
		podCollector{name: "agentio-epe", namespace: config.Namespace, selector: "app.kubernetes.io/name=agentio-epe"},
		ztunnel,
		resourceCollector{
			name: "xds-config",
			gvr:  schema.GroupVersionResource{Group: "agents.kruise.io", Version: "v1alpha1", Resource: "trafficpolicies"},
		},
	}
}

type podCollector struct {
	name, namespace, selector, namespaceSelector, requiredContainer string
}

func (p podCollector) Name() string { return p.name }

func (p podCollector) Collect(ctx context.Context, environment *e2e.Environment, writer artifacts.Writer) error {
	if environment == nil || environment.Cluster == nil || environment.Cluster.Kube == nil || environment.Kube == nil {
		return errors.New("typed Kubernetes client is required")
	}
	pods, err := p.listPods(ctx, environment.Cluster.Kube)
	if err != nil {
		return err
	}
	if err := writeJSON(writer, filepath.Join("setup", "agentio", p.name, "inventory.json"), pods); err != nil {
		return err
	}
	var errs []error
	for _, pod := range pods.Items {
		for _, container := range pod.Spec.Containers {
			logs, logErr := environment.Kube.Logs(ctx, pod.Namespace, pod.Name, container.Name, nil)
			if logErr != nil {
				errs = append(errs, logErr)
				logs = logErr.Error()
			}
			file, err := writer.Writer("setup", "agentio", p.name, "pods", pod.Namespace, pod.Name, container.Name+".log")
			if err != nil {
				errs = append(errs, err)
				continue
			}
			_, writeErr := file.Write([]byte(logs))
			errs = append(errs, writeErr, file.Close())
		}
	}
	return errors.Join(errs...)
}

func (p podCollector) listPods(ctx context.Context, client kubernetes.Interface) (*corev1.PodList, error) {
	namespaces := []string{p.namespace}
	if p.namespaceSelector != "" {
		matched, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{LabelSelector: p.namespaceSelector})
		if err != nil {
			return nil, fmt.Errorf("list namespaces for collector %q: %w", p.name, err)
		}
		namespaces = make([]string, 0, len(matched.Items))
		for _, item := range matched.Items {
			namespaces = append(namespaces, item.Name)
		}
	}

	result := &corev1.PodList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PodList"}}
	for _, namespace := range namespaces {
		pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: p.selector})
		if err != nil {
			return nil, fmt.Errorf("list Pods in namespace %q for collector %q: %w", namespace, p.name, err)
		}
		for _, pod := range pods.Items {
			if p.requiredContainer != "" && !podHasContainer(pod, p.requiredContainer) {
				continue
			}
			result.Items = append(result.Items, pod)
		}
	}
	return result, nil
}

func podHasContainer(pod corev1.Pod, name string) bool {
	for _, container := range pod.Spec.Containers {
		if container.Name == name {
			return true
		}
	}
	return false
}

type resourceCollector struct {
	name string
	gvr  schema.GroupVersionResource
}

func (r resourceCollector) Name() string { return r.name }

func (r resourceCollector) Collect(ctx context.Context, environment *e2e.Environment, writer artifacts.Writer) error {
	if environment == nil || environment.Cluster == nil || environment.Cluster.Dynamic == nil {
		return errors.New("dynamic Kubernetes client is required")
	}
	objects, err := environment.Cluster.Dynamic.Resource(r.gvr).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	return writeJSON(writer, filepath.Join("setup", "agentio", r.name, "inventory.json"), objects)
}

func writeJSON(writer artifacts.Writer, path string, value any) error {
	file, err := writer.Writer(path)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encodeErr := encoder.Encode(value)
	if err := errors.Join(encodeErr, file.Close()); err != nil {
		return fmt.Errorf("write collector artifact %q: %w", path, err)
	}
	return nil
}
