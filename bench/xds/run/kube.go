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
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"

	"github.com/openkruise/agentio/bench/xds/scenario/driver"
)

const runLabel = driver.RunLabel

var metricsGVR = schema.GroupVersionResource{Group: "metrics.k8s.io", Version: "v1beta1", Resource: "pods"}

func clients(c config) (*rest.Config, kubernetes.Interface, dynamic.Interface, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = c.Kubeconfig
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: c.Context}).
		ClientConfig()
	if err != nil {
		return nil, nil, nil, err
	}
	cfg.Timeout = 30 * time.Second
	cfg.UserAgent = "agentio-xds-bench"
	k, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	d, err := dynamic.NewForConfig(cfg)
	return cfg, k, d, err
}

func (r *runner) pod(name string) (*corev1.Pod, error) {
	c := r.cfg
	parameters, err := r.scenario.ClientConfig(r.id, name)
	if err != nil {
		return nil, err
	}
	args := []string{
		"--target=" + c.XDSAddress,
		"--server-name=" + c.ServerName,
		"--listen=0.0.0.0:8088",
		"--scenario=" + c.Scenario,
		"--scenario-config=" + string(parameters),
		"--ack-delay=" + c.AckDelay,
		"--ready-timeout=" + c.timeout().
			String(),
		"--max-connections=" + strconv.Itoa(targetFor(c.Stages[len(c.Stages)-1], c.Pods, 0)),
	}
	var env []corev1.EnvVar
	for _, kv := range [][2]string{{"POD_NAME", "metadata.name"}, {"POD_NAMESPACE", "metadata.namespace"}, {"POD_UID", "metadata.uid"}, {"NODE_NAME", "spec.nodeName"}, {"POD_IP", "status.podIP"}} {
		env = append(
			env,
			corev1.EnvVar{
				Name:      kv[0],
				ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: kv[1]}},
			},
		)
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   r.id,
			Labels:      map[string]string{runLabel: r.id},
			Annotations: map[string]string{"sidecar.istio.io/inject": "false"},
		},
		Spec: corev1.PodSpec{
			TerminationGracePeriodSeconds: new(int64(10)),
			Containers: []corev1.Container{
				{
					Name:            "load",
					Image:           c.Image,
					ImagePullPolicy: corev1.PullPolicy(c.ImagePullPolicy),
					Args:            args,
					Env:             env,
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("100m"),
							corev1.ResourceMemory: resource.MustParse("128Mi"),
						},
						Limits: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse(c.CPULimit),
							corev1.ResourceMemory: resource.MustParse(c.MemoryLimit),
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{Name: "token", MountPath: "/var/run/ads", ReadOnly: true},
						{Name: "ca", MountPath: "/var/run/ads/ca", ReadOnly: true},
					},
					ReadinessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{Path: "/status", Port: intstr.FromInt32(8088)},
						},
						PeriodSeconds: 2,
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "token",
					VolumeSource: corev1.VolumeSource{
						Projected: &corev1.ProjectedVolumeSource{
							Sources: []corev1.VolumeProjection{
								{
									ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
										Audience:          c.TokenAudience,
										ExpirationSeconds: new(int64(3600)),
										Path:              "token",
									},
								},
							},
						},
					},
				},
				{
					Name: "ca",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: "ads-ca"},
						},
					},
				},
			},
		},
	}, nil
}

func (r *runner) setup(ctx context.Context) error {
	ca, err := r.kube.CoreV1().ConfigMaps(r.cfg.CANamespace).Get(ctx, r.cfg.CAConfigMap, metav1.GetOptions{})
	if err != nil {
		return err
	}
	pem, ok := ca.Data[r.cfg.CAKey]
	if !ok || pem == "" {
		return fmt.Errorf("CA ConfigMap missing %q", r.cfg.CAKey)
	}
	// Mark intent before Create: a canceled request may still have persisted the object.
	// Cleanup verifies the run label and uses a UID precondition before deleting it.
	r.namespaceAttempted = true
	_, err = r.kube.CoreV1().
		Namespaces().
		Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: r.id, Labels: map[string]string{runLabel: r.id}}}, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	_, err = r.kube.CoreV1().
		ConfigMaps(r.id).
		Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "ads-ca", Namespace: r.id}, Data: map[string]string{"root-cert.pem": pem}}, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	for _, name := range r.pods {
		pod, err := r.pod(name)
		if err != nil {
			return err
		}
		if _, err = r.kube.CoreV1().Pods(r.id).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
			return err
		}
	}
	if err = waitFor(ctx, r.cfg.timeout(), func(ctx context.Context) (bool, error) {
		pods, err := r.kube.CoreV1().Pods(r.id).List(ctx, metav1.ListOptions{LabelSelector: runLabel + "=" + r.id})
		if err != nil {
			return false, err
		}
		ready := 0
		for _, p := range pods.Items {
			for _, c := range p.Status.Conditions {
				if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
					ready++
				}
			}
		}
		return ready == len(r.pods), nil
	}); err != nil {
		return fmt.Errorf("wait for load Pods: %w", err)
	}
	if err = r.scenario.Prepare(ctx, r.environment()); err != nil {
		return err
	}
	for _, pod := range r.pods {
		if err = r.forward(ctx, pod); err != nil {
			return err
		}
	}
	return r.snapshot(ctx, "initial")
}

func (r *runner) snapshot(ctx context.Context, label string) error {
	pods, err := r.kube.CoreV1().Pods(r.id).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	if err = r.save(label+"-pods.json", pods); err != nil {
		return err
	}
	namespaces := []string{r.id}
	if r.cfg.ControlPlane != "" {
		parts := strings.SplitN(r.cfg.ControlPlane, "/", 2)
		namespaces = append(namespaces, parts[0])
		d, err := r.kube.AppsV1().Deployments(parts[0]).Get(ctx, parts[1], metav1.GetOptions{})
		if err != nil {
			return err
		}
		if err = r.save(label+"-control-plane.json", d); err != nil {
			return err
		}
	}
	for _, ns := range namespaces {
		metrics, err := r.dynamic.Resource(metricsGVR).Namespace(ns).List(ctx, metav1.ListOptions{})
		var data any = metrics
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			data = map[string]string{"error": err.Error()}
		}
		if err = r.save(label+"-usage-"+ns+".json", data); err != nil {
			return err
		}
	}
	return nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type forwardHandle struct {
	cancel context.CancelFunc
	done   <-chan error
}

func (r *runner) forward(parent context.Context, pod string) error {
	ctx, cancel := context.WithCancel(parent)
	cfg := rest.CopyConfig(r.rest)
	cfg.Timeout = 0
	// Bind upgrade requests to the run context too; client-go's Dial interface has no context.
	cfg.Wrap(func(rt http.RoundTripper) http.RoundTripper {
		return roundTripperFunc(
			func(req *http.Request) (*http.Response, error) { return rt.RoundTrip(req.WithContext(ctx)) },
		)
	})
	u := r.kube.CoreV1().RESTClient().Post().Namespace(r.id).Resource("pods").Name(pod).SubResource("portforward").URL()
	rt, upgrader, err := spdy.RoundTripperFor(cfg)
	if err != nil {
		cancel()
		return err
	}
	ws, err := portforward.NewSPDYOverWebsocketDialer(u, cfg)
	if err != nil {
		cancel()
		return err
	}
	fallback := spdy.NewDialer(upgrader, &http.Client{Transport: rt}, http.MethodPost, u)
	dialer := portforward.NewFallbackDialer(
		ws,
		fallback,
		func(err error) bool { return httpstream.IsUpgradeFailure(err) || httpstream.IsHTTPSProxyError(err) },
	)
	log, err := os.Create(filepath.Join(r.out, pod+"-forward.log"))
	if err != nil {
		cancel()
		return err
	}
	ready := make(chan struct{})
	done := make(chan error, 1)
	pf, err := portforward.NewOnAddresses(
		dialer,
		[]string{"127.0.0.1"},
		[]string{"0:8088"},
		ctx.Done(),
		ready,
		log,
		log,
	)
	if err != nil {
		cancel()
		return errors.Join(err, log.Close())
	}
	r.forwards = append(r.forwards, forwardHandle{cancel: cancel, done: done})
	go func() {
		defer close(done)
		err := pf.ForwardPorts()
		done <- errors.Join(err, log.Close())
	}()
	timer := time.NewTimer(r.cfg.timeout())
	defer timer.Stop()
	select {
	case <-parent.Done():
		cancel()
		return parent.Err()
	case <-timer.C:
		cancel()
		return fmt.Errorf("port-forward %s readiness timed out", pod)
	case err := <-done:
		cancel()
		if err == nil {
			return fmt.Errorf("port-forward %s exited before ready", pod)
		}
		return fmt.Errorf("port-forward %s exited before ready: %w", pod, err)
	case <-ready:
	}
	ports, err := pf.GetPorts()
	if err != nil {
		cancel()
		return err
	}
	r.urls = append(r.urls, fmt.Sprintf("http://127.0.0.1:%d", ports[0].Local))
	return nil
}

func (r *runner) cleanup(ctx context.Context) error {
	for _, f := range r.forwards {
		f.cancel()
	}
	var errs []error
	if !r.cfg.KeepResources {
		if r.namespaceAttempted {
			ns, err := r.kube.CoreV1().Namespaces().Get(ctx, r.id, metav1.GetOptions{})
			if err == nil {
				if ns.Labels[runLabel] != r.id {
					err = errors.New("refusing to delete namespace not owned by this run")
				} else {
					err = r.kube.CoreV1().
						Namespaces().
						Delete(ctx, r.id, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &ns.UID}})
				}
			}
			if err != nil && !apierrors.IsNotFound(err) {
				errs = append(errs, err)
			}
		}
		for _, resource := range r.resources {
			api := r.dynamic.Resource(resource.GVR).Namespace(resource.Namespace)
			p, err := api.Get(ctx, resource.Name, metav1.GetOptions{})
			if err == nil {
				if p.GetLabels()[runLabel] != r.id {
					err = fmt.Errorf("refusing to delete resource %s not owned by this run", resource.Name)
				} else {
					uid := p.GetUID()
					err = api.Delete(
						ctx,
						resource.Name,
						metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}},
					)
				}
			}
			if err != nil && !apierrors.IsNotFound(err) {
				errs = append(errs, err)
			}
		}
	}
	for _, f := range r.forwards {
		select {
		case <-f.done:
		case <-ctx.Done():
			errs = append(errs, ctx.Err())
		}
	}
	return errors.Join(errs...)
}
