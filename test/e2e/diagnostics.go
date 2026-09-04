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

package e2e

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (s *Suite) collectFailure(ctx context.Context, environment *Environment, artifactPath string, cause error) error {
	if environment == nil || environment.Artifacts == nil {
		return nil
	}
	writer, err := environment.Artifacts.Writer(artifactPath, "failure.txt")
	if err != nil {
		return err
	}
	_, writeErr := fmt.Fprintf(writer, "%v\n", cause)
	closeErr := writer.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	var errs []error
	if err := collectFastDiagnostics(ctx, environment, artifactPath); err != nil {
		errs = append(errs, fmt.Errorf("fast diagnostics: %w", err))
	}
	if !s.config.Diagnostics.FullOnFailure || s.config.Diagnostics.MaxFullDumps <= 0 {
		return errors.Join(errs...)
	}
	for {
		current := s.fullDumps.Load()
		if current >= int64(s.config.Diagnostics.MaxFullDumps) {
			return errors.Join(errs...)
		}
		if s.fullDumps.CompareAndSwap(current, current+1) {
			break
		}
	}
	for _, collector := range s.collectors {
		if err := collector.Collect(ctx, environment, environment.Artifacts); err != nil {
			errs = append(errs, fmt.Errorf("collector %q: %w", collector.Name(), err))
		}
	}
	if err := writeDiagnosticErrors(environment, artifactPath, errs); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func collectFastDiagnostics(ctx context.Context, environment *Environment, artifactPath string) error {
	if environment.Cluster == nil || environment.Cluster.Kube == nil || environment.Kube == nil {
		return nil
	}
	namespaces := make(map[string]bool)
	for _, record := range environment.Kube.Ledger().Snapshot() {
		if record.Namespace != "" {
			namespaces[record.Namespace] = true
		}
	}
	ordered := make([]string, 0, len(namespaces))
	for namespace := range namespaces {
		ordered = append(ordered, namespace)
	}
	sort.Strings(ordered)
	for _, namespace := range ordered {
		pods, podErr := environment.Cluster.Kube.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
		events, eventErr := environment.Cluster.Kube.CoreV1().Events(namespace).List(ctx, metav1.ListOptions{})
		if podErr != nil || eventErr != nil {
			return errors.Join(podErr, eventErr)
		}
		if err := writeYAMLArtifact(environment, filepath.Join(artifactPath, namespace, "pods.yaml"), pods); err != nil {
			return err
		}
		if err := writeYAMLArtifact(environment, filepath.Join(artifactPath, namespace, "events.yaml"), events); err != nil {
			return err
		}
		for _, pod := range pods.Items {
			for _, container := range pod.Spec.Containers {
				logs, err := environment.Kube.Logs(ctx, namespace, pod.Name, container.Name, nil)
				if err != nil {
					logs = err.Error()
				}
				writer, err := environment.Artifacts.Writer(artifactPath, namespace, "pods", pod.Name, container.Name+".log")
				if err != nil {
					return err
				}
				_, writeErr := writer.Write([]byte(logs))
				if err := errors.Join(writeErr, writer.Close()); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func writeYAMLArtifact(environment *Environment, path string, value any) error {
	data, err := yaml.Marshal(value)
	if err != nil {
		return err
	}
	writer, err := environment.Artifacts.Writer(path)
	if err != nil {
		return err
	}
	_, writeErr := writer.Write(data)
	return errors.Join(writeErr, writer.Close())
}

func writeDiagnosticErrors(environment *Environment, artifactPath string, errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	parts := make([]string, 0, len(errs))
	for _, err := range errs {
		if err != nil {
			parts = append(parts, err.Error())
		}
	}
	writer, err := environment.Artifacts.Writer(artifactPath, "diagnostics-errors.txt")
	if err != nil {
		return err
	}
	_, writeErr := writer.Write([]byte(strings.Join(parts, "\n") + "\n"))
	return errors.Join(writeErr, writer.Close())
}
