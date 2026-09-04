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

package kube

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/openkruise/agentio/test/e2e/retry"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

// ReadyPods returns Pods matching selector that report Ready and have a Pod IP.
func (c *Client) ReadyPods(ctx context.Context, namespace, selector string) ([]corev1.Pod, error) {
	if c == nil || c.kube == nil {
		return nil, errors.New("Kubernetes client is required for ready Pod lookup")
	}
	pods, err := c.kube.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, fmt.Errorf("list ready Pods in namespace %s: %w", namespace, err)
	}
	ready := make([]corev1.Pod, 0, len(pods.Items))
	for _, pod := range pods.Items {
		if pod.Status.PodIP == "" || !podReady(&pod) {
			continue
		}
		ready = append(ready, pod)
	}
	sort.Slice(ready, func(i, j int) bool { return ready[i].Name < ready[j].Name })
	return ready, nil
}

// WaitReadyPods polls until at least minimum matching Pods are Ready.
func (c *Client) WaitReadyPods(ctx context.Context, namespace, selector string, minimum int) ([]corev1.Pod, error) {
	if c == nil || c.kube == nil {
		return nil, errors.New("Kubernetes client is required for ready Pod lookup")
	}
	if minimum < 1 {
		return nil, errors.New("minimum ready Pod count must be at least 1")
	}
	var ready []corev1.Pod
	err := retry.UntilSuccess(ctx, retry.Policy{
		NoTimeout: true,
		Delay:     200 * time.Millisecond,
		Backoff:   1,
		MaxDelay:  200 * time.Millisecond,
	}, func() error {
		pods, err := c.ReadyPods(ctx, namespace, selector)
		if err != nil {
			return err
		}
		ready = pods
		if len(pods) < minimum {
			return fmt.Errorf("found %d ready Pods, need %d", len(pods), minimum)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ready, nil
}

func podReady(pod *corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func (c *Client) Logs(
	ctx context.Context,
	namespace, pod, container string,
	tailLines *int64,
) (string, error) {
	if c.kube == nil {
		return "", errors.New("Kubernetes client is required for Pod logs")
	}
	data, err := c.kube.CoreV1().Pods(namespace).GetLogs(pod, &corev1.PodLogOptions{
		Container: container,
		TailLines: tailLines,
	}).DoRaw(ctx)
	if err != nil {
		return "", fmt.Errorf("read logs for pod %s/%s container %s: %w", namespace, pod, container, err)
	}
	return string(data), nil
}

func (c *Client) Exec(
	ctx context.Context,
	namespace, pod, container string,
	command []string,
	stdin io.Reader,
) (string, string, error) {
	if c.kube == nil || c.restConfig == nil {
		return "", "", errors.New("Kubernetes client and REST config are required for Pod exec")
	}
	request := c.kube.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: container,
			Command:   append([]string(nil), command...),
			Stdin:     stdin != nil,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, scheme.ParameterCodec)
	executor, err := remotecommand.NewSPDYExecutor(c.restConfig, "POST", request.URL())
	if err != nil {
		return "", "", fmt.Errorf("create exec stream for pod %s/%s: %w", namespace, pod, err)
	}
	var stdout, stderr bytes.Buffer
	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:  stdin,
		Stdout: &stdout,
		Stderr: &stderr,
		Tty:    false,
	})
	if err != nil {
		return stdout.String(), stderr.String(), fmt.Errorf("exec pod %s/%s container %s: %w", namespace, pod, container, err)
	}
	return stdout.String(), stderr.String(), nil
}
