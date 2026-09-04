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

package inject

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"text/template"

	jsonpatch "gomodules.xyz/jsonpatch/v2"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	klabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/mergepatch"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"sigs.k8s.io/yaml"

	"istio.io/api/annotation"
	"istio.io/api/label"
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/kube/kclient"
)

var (
	runtimeScheme = func() *runtime.Scheme {
		s := runtime.NewScheme()
		_ = corev1.AddToScheme(s)
		_ = admissionv1.AddToScheme(s)
		return s
	}()
	codecs       = serializer.NewCodecFactory(runtimeScheme)
	deserializer = codecs.UniversalDeserializer()

	URLParameterToEnv = map[string]string{
		"cluster": "ISTIO_META_CLUSTER_ID",
		"net":     "ISTIO_META_NETWORK",
	}
)

const (
	// prometheus will convert annotation to this format
	// `prometheus.io/scrape` `prometheus.io.scrape` `prometheus-io/scrape` have the same meaning in Prometheus
	prometheusScrapeAnnotation = "prometheus_io_scrape"
	prometheusPortAnnotation   = "prometheus_io_port"
	prometheusPathAnnotation   = "prometheus_io_path"

	// maxRequestBody bounds admission request reads.
	maxRequestBody = 10 * 1024 * 1024
)

const (
	InitContainers = "initContainers"

	Containers = "containers"
)

// NativeSidecarMode controls native sidecar enablement.
type NativeSidecarMode string

const (
	NativeSidecarModeDisabled NativeSidecarMode = "false"
	NativeSidecarModeEnabled  NativeSidecarMode = "true"
	NativeSidecarModeAuto     NativeSidecarMode = "auto"
)

// Webhook implements a mutating webhook for automatic proxy injection.
type Webhook struct {
	mu               sync.RWMutex
	config           *Config
	settings         InjectionSettings
	valuesConfig     ValuesConfig
	discoveryAddress string

	nodes             kclient.Reader[*corev1.Node]
	nativeSidecarMode NativeSidecarMode
}

// WebhookParameters configures parameters for the ztunnel injection webhook.
type WebhookParameters struct {
	// Nodes optionally provides cached Node reads for native-sidecar
	// auto-detection. Nil disables detection: auto behaves as disabled.
	Nodes kclient.Reader[*corev1.Node]

	NativeSidecarMode NativeSidecarMode

	// Mux to register /inject on.
	Mux *http.ServeMux

	// DiscoveryAddress is the process-derived Agentio xDS/CA endpoint used
	// when the injector values do not provide an explicit address.
	DiscoveryAddress string
}

// NewWebhook creates a mutating webhook for automatic ztunnel injection.
// UpdateConfig installs the ztunnel template and its Agentio-native settings;
// until it arrives, requests are rejected so a half-configured injector cannot
// silently admit pods uninjected under failurePolicy Fail.
func NewWebhook(p WebhookParameters) (*Webhook, error) {
	if p.Mux == nil {
		return nil, fmt.Errorf("expected mux to be passed, but was not passed")
	}
	mode := p.NativeSidecarMode
	if mode == "" {
		mode = NativeSidecarModeAuto
	}
	wh := &Webhook{
		nodes:             p.Nodes,
		nativeSidecarMode: mode,
		discoveryAddress:  p.DiscoveryAddress,
		settings:          defaultInjectionSettings(p.DiscoveryAddress),
	}
	p.Mux.HandleFunc("/inject", wh.serveInject)
	p.Mux.HandleFunc("/inject/", wh.serveInject)
	return wh, nil
}

// UpdateConfig installs a new injection Config and values document.
func (wh *Webhook) UpdateConfig(sidecarConfig *Config, valuesConfig string) error {
	vc, err := NewValuesConfig(valuesConfig)
	if err != nil {
		return fmt.Errorf("failed to create new values config: %v", err)
	}
	wh.mu.Lock()
	wh.config = sidecarConfig
	wh.valuesConfig = vc
	wh.settings = injectionSettingsFromValues(vc, wh.discoveryAddress)
	wh.mu.Unlock()
	return nil
}

type ContainerReorder int

const (
	MoveFirst ContainerReorder = iota
	MoveLast
	Remove
)

func moveContainer(from, to []corev1.Container, name string) ([]corev1.Container, []corev1.Container) {
	var container *corev1.Container
	for i, c := range from {
		if from[i].Name == name {
			from = slices.Delete(from, i)
			container = &c
			break
		}
	}
	if container != nil {
		to = append(to, *container)
	}
	return from, to
}

func modifyContainers(cl []corev1.Container, name string, modifier ContainerReorder) []corev1.Container {
	containers := []corev1.Container{}
	var match *corev1.Container
	for _, c := range cl {
		if c.Name != name {
			containers = append(containers, c)
		} else {
			match = &c
		}
	}
	if match == nil {
		return containers
	}
	switch modifier {
	case MoveFirst:
		return append([]corev1.Container{*match}, containers...)
	case MoveLast:
		return append(containers, *match)
	case Remove:
		return containers
	default:
		return cl
	}
}

func hasContainer(cl []corev1.Container, name string) bool {
	for _, c := range cl {
		if c.Name == name {
			return true
		}
	}
	return false
}

func enablePrometheusMerge(configured bool, anno map[string]string) bool {
	// If annotation is present, we look there first
	if val, f := anno[annotation.PrometheusMergeMetrics.Name]; f {
		bval, err := strconv.ParseBool(val)
		if err != nil {
			// This shouldn't happen since we validate earlier in the code
			log.Warn("invalid annotation", "annotation", annotation.PrometheusMergeMetrics.Name, "value", bval)
		} else {
			return bval
		}
	}
	return configured
}

func toAdmissionResponse(err error) *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{Result: &metav1.Status{Message: err.Error()}}
}

// ParsedContainers holds the unmarshalled containers and initContainers
type ParsedContainers struct {
	Containers     []corev1.Container `json:"containers,omitempty"`
	InitContainers []corev1.Container `json:"initContainers,omitempty"`
}

func (p ParsedContainers) AllContainers() []corev1.Container {
	return append(slices.Clone(p.Containers), p.InitContainers...)
}

type InjectionParameters struct {
	pod                 *corev1.Pod
	deployMeta          types.NamespacedName
	nativeSidecar       bool
	typeMeta            metav1.TypeMeta
	templates           map[string]*template.Template
	defaultTemplate     []string
	aliases             map[string][]string
	settings            InjectionSettings
	valuesConfig        ValuesConfig
	proxyEnvs           map[string]string
	injectedAnnotations map[string]string
}

func checkPreconditions(params InjectionParameters) {
	spec := params.pod.Spec
	metadata := params.pod.ObjectMeta
	// If DNSPolicy is not ClusterFirst, the sidecar may not able to connect to the control plane.
	if spec.DNSPolicy != "" && spec.DNSPolicy != corev1.DNSClusterFirst {
		podName := potentialPodName(metadata)
		log.Warn("pod DNS policy may prevent the proxy from connecting to the control plane",
			"pod", metadata.Namespace+"/"+podName, "dns_policy", spec.DNSPolicy,
			"recommended_dns_policy", corev1.DNSClusterFirst)
	}
}

func getInjectionStatus(podSpec corev1.PodSpec) string {
	stat := &SidecarInjectionStatus{}
	for _, c := range podSpec.InitContainers {
		stat.InitContainers = append(stat.InitContainers, c.Name)
	}
	for _, c := range podSpec.Containers {
		stat.Containers = append(stat.Containers, c.Name)
	}
	for _, c := range podSpec.Volumes {
		stat.Volumes = append(stat.Volumes, c.Name)
	}
	for _, c := range podSpec.ImagePullSecrets {
		stat.ImagePullSecrets = append(stat.ImagePullSecrets, c.Name)
	}
	statusAnnotationValue, err := json.Marshal(stat)
	if err != nil {
		return "{}"
	}
	return string(statusAnnotationValue)
}

// injectPod is the core of the injection logic. This takes a pod and injection
// template, as well as some inputs to the injection template, and produces a
// JSON patch.
func injectPod(req InjectionParameters) ([]byte, error) {
	checkPreconditions(req)

	// The patch will be built relative to the initial pod, capture its current state
	originalPodSpec, err := json.Marshal(req.pod)
	if err != nil {
		return nil, err
	}

	// Run the injection template, giving us a partial pod spec
	mergedPod, injectedPodData, err := RunTemplate(req)
	if err != nil {
		return nil, fmt.Errorf("failed to run injection template: %v", err)
	}

	mergedPod, err = reapplyOverwrittenContainers(mergedPod, req.pod, injectedPodData, &req.settings.Proxy)
	if err != nil {
		return nil, fmt.Errorf("failed to re apply container: %v", err)
	}

	// Apply some additional transformations to the pod
	if err := postProcessPod(mergedPod, *injectedPodData, req); err != nil {
		return nil, fmt.Errorf("failed to process pod: %v", err)
	}

	patch, err := createPatch(mergedPod, originalPodSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to create patch: %v", err)
	}

	log.Debug("generated admission response", "patch", string(patch))
	return patch, nil
}

// reapplyOverwrittenContainers enables users to provide container level overrides for settings in the injection template
// * originalPod: the pod before injection. If needed, we will apply some configurations from this pod on top of the final pod
// * templatePod: the rendered injection template. This is needed only to see what containers we injected
// * finalPod: the current result of injection, roughly equivalent to the merging of originalPod and templatePod
// There are essentially three cases we cover here:
//  1. There is no overlap in containers in original and template pod. We will do nothing.
//  2. There is an overlap (both define the proxy), but that is because the pod is being re-injected.
//     In this case we do nothing, since we want to apply the new settings
//  3. There is an overlap. We will re-apply the original container.
//
// Where "overlap" is a container defined in both the original and template pod. Typically, this would mean
// the user has defined a proxy container in their own pod spec.
func reapplyOverwrittenContainers(finalPod *corev1.Pod, originalPod *corev1.Pod, templatePod *corev1.Pod,
	proxyConfig *ProxyConfig,
) (*corev1.Pod, error) {
	overrides := ParsedContainers{}
	existingOverrides := ParsedContainers{}
	if annotationOverrides, f := originalPod.Annotations[annotation.ProxyOverrides.Name]; f {
		if err := json.Unmarshal([]byte(annotationOverrides), &existingOverrides); err != nil {
			return nil, err
		}
	}
	parsedInjectedStatus := ParsedContainers{}
	status, alreadyInjected := originalPod.Annotations[annotation.SidecarStatus.Name]
	if alreadyInjected {
		parsedInjectedStatus = parseStatus(status)
	}
	for _, c := range templatePod.Spec.Containers {
		// sidecarStatus annotation is added on the pod by webhook. We should use new container template
		// instead of restoring what may be previously injected. Doing this ensures we are correctly calculating
		// env variables like ISTIO_META_APP_CONTAINERS and ISTIO_META_POD_PORTS.
		if match := FindContainer(c.Name, parsedInjectedStatus.Containers); match != nil {
			continue
		}
		match := FindContainer(c.Name, existingOverrides.Containers)
		if match == nil {
			match = FindContainer(c.Name, originalPod.Spec.Containers)
		}
		if match == nil {
			continue
		}
		overlay := *match.DeepCopy()
		if overlay.Image == AutoImage {
			overlay.Image = ""
		}

		overrides.Containers = append(overrides.Containers, overlay)
		newMergedPod, err := applyContainer(finalPod, overlay)
		if err != nil {
			return nil, fmt.Errorf("failed to apply sidecar container: %v", err)
		}
		finalPod = newMergedPod
	}
	for _, c := range templatePod.Spec.InitContainers {
		if match := FindContainer(c.Name, parsedInjectedStatus.InitContainers); match != nil {
			continue
		}
		match := FindContainer(c.Name, existingOverrides.InitContainers)
		if match == nil {
			match = FindContainerFromPod(c.Name, originalPod)
		}
		if match == nil {
			continue
		}
		overlay := *match.DeepCopy()
		if overlay.Image == AutoImage {
			overlay.Image = ""
		}

		overrides.InitContainers = append(overrides.InitContainers, overlay)
		newMergedPod, err := applyInitContainer(finalPod, overlay)
		if err != nil {
			return nil, fmt.Errorf("failed to apply sidecar init container: %v", err)
		}
		finalPod = newMergedPod
	}

	if !alreadyInjected && (len(overrides.Containers) > 0 || len(overrides.InitContainers) > 0) {
		// We found any overrides. Put them in the pod annotation so we can re-apply them on re-injection
		js, err := json.Marshal(overrides)
		if err != nil {
			return nil, err
		}
		if finalPod.Annotations == nil {
			finalPod.Annotations = map[string]string{}
		}
		finalPod.Annotations[annotation.ProxyOverrides.Name] = string(js)
	}

	adjustInitContainerUser(finalPod, originalPod, proxyConfig)

	return finalPod, nil
}

// adjustInitContainerUser adjusts the RunAsUser/Group fields and iptables parameter "-u <uid>"
// in the init/validation container so that they match the value of SecurityContext.RunAsUser/Group
// when it is present in the custom proxy container supplied by the user.
func adjustInitContainerUser(finalPod *corev1.Pod, originalPod *corev1.Pod, proxyConfig *ProxyConfig) {
	userContainer := FindSidecar(originalPod)
	if userContainer == nil {
		// If the user does not override the proxy container, there is nothing to do.
		return
	}

	if userContainer.SecurityContext == nil || (userContainer.SecurityContext.RunAsUser == nil && userContainer.SecurityContext.RunAsGroup == nil) {
		// if user doesn't override SecurityContext.RunAsUser/Group, there's nothing to do
		return
	}

	// Locate the agentio-init or agentio-validation container
	var initContainer *corev1.Container
	for _, name := range []string{InitContainerName, ValidationContainerName} {
		if container := FindContainer(name, finalPod.Spec.InitContainers); container != nil {
			initContainer = container
			break
		}
	}
	if initContainer == nil {
		// should not happen
		log.Warn("could not find either agentio-init or agentio-validation container")
		return
	}

	// Overriding RunAsUser is not allowed in TPROXY mode, it must always run with uid=0
	tproxy := false
	if proxyConfig.InterceptionMode == "TPROXY" {
		tproxy = true
	} else if mode, found := finalPod.Annotations[annotation.SidecarInterceptionMode.Name]; found && mode == "TPROXY" {
		tproxy = true
	}

	// RunAsUser cannot be overridden (ie, must remain 0) in TPROXY mode
	if tproxy && userContainer.SecurityContext.RunAsUser != nil {
		sidecar := FindSidecar(finalPod)
		if sidecar == nil {
			// Should not happen
			log.Warn("could not find the proxy container")
			return
		}
		*sidecar.SecurityContext.RunAsUser = 0
	}

	// Make sure the validation container runs with the same uid/gid as the proxy (init container is untouched, it must run with 0)
	if !tproxy && initContainer.Name == ValidationContainerName {
		if initContainer.SecurityContext == nil {
			initContainer.SecurityContext = &corev1.SecurityContext{}
		}
		if userContainer.SecurityContext.RunAsUser != nil {
			initContainer.SecurityContext.RunAsUser = userContainer.SecurityContext.RunAsUser
		}
		if userContainer.SecurityContext.RunAsGroup != nil {
			initContainer.SecurityContext.RunAsGroup = userContainer.SecurityContext.RunAsGroup
		}
	}

	// Find the "-u <uid>" parameter in the init container and replace it with the userid from SecurityContext.RunAsUser
	// but only if it's not 0. iptables --uid-owner argument must not be 0.
	if userContainer.SecurityContext.RunAsUser == nil || *userContainer.SecurityContext.RunAsUser == 0 {
		return
	}
	for i := range initContainer.Args {
		if initContainer.Args[i] == "-u" {
			initContainer.Args[i+1] = fmt.Sprintf("%d", *userContainer.SecurityContext.RunAsUser)
			return
		}
	}
}

// parseStatus extracts containers from injected SidecarStatus annotation
func parseStatus(status string) ParsedContainers {
	parsedContainers := ParsedContainers{}
	var unMarshalledStatus map[string]any
	if err := json.Unmarshal([]byte(status), &unMarshalledStatus); err != nil {
		log.Error("unmarshal sidecar status annotation",
			"annotation", annotation.SidecarStatus.Name, "error", err)
		return parsedContainers
	}
	parser := func(key string, obj map[string]any) []corev1.Container {
		out := make([]corev1.Container, 0)
		if value, exist := obj[key]; exist && value != nil {
			for _, v := range value.([]any) {
				out = append(out, corev1.Container{Name: v.(string)})
			}
		}
		return out
	}
	parsedContainers.Containers = parser(Containers, unMarshalledStatus)
	parsedContainers.InitContainers = parser(InitContainers, unMarshalledStatus)

	return parsedContainers
}

// reinsertOverrides applies the containers listed in OverrideAnnotation to a pod. This is to achieve
// idempotency by handling an edge case where an injection template is modifying a container already
// present in the pod spec. In these cases, the logic to strip injected containers would remove the
// original injected parts as well, leading to the templating logic being different (for example,
// reading the .Spec.Containers field would be empty).
func reinsertOverrides(pod *corev1.Pod) (*corev1.Pod, error) {
	type podOverrides struct {
		Containers     []corev1.Container `json:"containers,omitempty"`
		InitContainers []corev1.Container `json:"initContainers,omitempty"`
	}

	existingOverrides := podOverrides{}
	if annotationOverrides, f := pod.Annotations[annotation.ProxyOverrides.Name]; f {
		if err := json.Unmarshal([]byte(annotationOverrides), &existingOverrides); err != nil {
			return nil, err
		}
	}

	pod = pod.DeepCopy()
	for _, c := range existingOverrides.Containers {
		match := FindContainer(c.Name, pod.Spec.Containers)
		if match != nil {
			continue
		}
		pod.Spec.Containers = append(pod.Spec.Containers, c)
	}

	for _, c := range existingOverrides.InitContainers {
		match := FindContainer(c.Name, pod.Spec.InitContainers)
		if match != nil {
			continue
		}
		pod.Spec.InitContainers = append(pod.Spec.InitContainers, c)
	}

	return pod, nil
}

func createPatch(pod *corev1.Pod, original []byte) ([]byte, error) {
	reinjected, err := json.Marshal(pod)
	if err != nil {
		return nil, err
	}
	p, err := jsonpatch.CreatePatch(original, reinjected)
	if err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

// postProcessPod applies additionally transformations to the pod after merging with the injected template
// This is generally things that cannot reasonably be added to the template
func postProcessPod(pod *corev1.Pod, injectedPod corev1.Pod, req InjectionParameters) error {
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	if pod.Labels == nil {
		pod.Labels = map[string]string{}
	}

	overwriteClusterInfo(pod, req)

	if err := applyPrometheusMerge(pod, req.settings); err != nil {
		return err
	}

	if err := applyRewrite(pod, req); err != nil {
		return err
	}

	applyMetadata(pod, injectedPod, req)

	if err := reorderPod(pod, req); err != nil {
		return err
	}

	return nil
}

func applyMetadata(pod *corev1.Pod, injectedPodData corev1.Pod, req InjectionParameters) {
	if nw, ok := req.proxyEnvs["ISTIO_META_NETWORK"]; ok {
		pod.Labels[label.TopologyNetwork.Name] = nw
	}
	// Add all additional injected annotations. These are overridden if needed
	pod.Annotations[annotation.SidecarStatus.Name] = getInjectionStatus(injectedPodData.Spec)

	// Deprecated; should be set directly in the template instead
	maps.Copy(pod.Annotations, req.injectedAnnotations)
}

// reorderPod ensures containers are properly ordered after merging
func reorderPod(pod *corev1.Pod, req InjectionParameters) error {
	holdPod := req.settings.HoldApplicationUntilProxyStarts

	proxyLocation := MoveLast
	// If HoldApplicationUntilProxyStarts is set, reorder the proxy location
	if holdPod {
		proxyLocation = MoveFirst
	}

	// Proxy container should be last, unless HoldApplicationUntilProxyStarts is set
	// This is to ensure `kubectl exec` and similar commands continue to default to the user's container
	proxyName := proxyContainerName(pod.Spec)
	pod.Spec.Containers = modifyContainers(pod.Spec.Containers, proxyName, proxyLocation)
	if hasContainer(pod.Spec.InitContainers, proxyName) {
		// This is using native sidecar support in Kubernetes.
		// We want istio to be first in this case, so init containers are part of the mesh
		// This is {agentio-init/agentio-validation} => proxy => rest.
		pod.Spec.InitContainers = modifyContainers(pod.Spec.InitContainers, EnableCoreDumpName, MoveFirst)
		pod.Spec.InitContainers = modifyContainers(pod.Spec.InitContainers, proxyName, MoveFirst)
		pod.Spec.InitContainers = modifyContainers(pod.Spec.InitContainers, ValidationContainerName, MoveFirst)
		pod.Spec.InitContainers = modifyContainers(pod.Spec.InitContainers, InitContainerName, MoveFirst)
	} else {
		// Else, we want iptables setup last so we do not blackhole init containers
		// This is agentio-validation => rest => agentio-init (note: only one of agentio-init or agentio-validation should be present)
		// Validation container must be first to block any user containers
		pod.Spec.InitContainers = modifyContainers(pod.Spec.InitContainers, ValidationContainerName, MoveFirst)
		// Init container must be last to allow any traffic to pass before iptables is setup
		pod.Spec.InitContainers = modifyContainers(pod.Spec.InitContainers, InitContainerName, MoveLast)
		pod.Spec.InitContainers = modifyContainers(pod.Spec.InitContainers, EnableCoreDumpName, MoveLast)
	}

	return nil
}

func applyRewrite(pod *corev1.Pod, req InjectionParameters) error {
	sidecar := FindSidecar(pod)
	if sidecar == nil {
		return nil
	}

	rewrite := ShouldRewriteAppHTTPProbers(pod.Annotations, req.valuesConfig.boolValue("sidecarInjectorWebhook", "rewriteAppHTTPProbe"))
	// We don't have to escape json encoding here when using golang libraries.
	if rewrite {
		if prober := DumpAppProbers(pod, int32(req.settings.StatusPort)); prober != "" {
			// If sidecar.istio.io/status is not present then append instead of merge.
			_, previouslyInjected := pod.Annotations[annotation.SidecarStatus.Name]
			sidecar.Env = mergeOrAppendProbers(previouslyInjected, sidecar.Env, prober)
		}
		patchRewriteProbe(pod.Annotations, pod, int32(req.settings.StatusPort))
	}
	return nil
}

// mergeOrAppendProbers ensures that if sidecar has existing ISTIO_KUBE_APP_PROBERS,
// then probers should be merged.
func mergeOrAppendProbers(previouslyInjected bool, envVars []corev1.EnvVar, newProbers string) []corev1.EnvVar {
	if !previouslyInjected {
		return append(envVars, corev1.EnvVar{Name: KubeAppProberEnvName, Value: newProbers})
	}
	for idx, env := range envVars {
		if env.Name == KubeAppProberEnvName {
			var existingKubeAppProber KubeAppProbers
			err := json.Unmarshal([]byte(env.Value), &existingKubeAppProber)
			if err != nil {
				log.Error("unmarshal existing kube app probers", "error", err)
				return envVars
			}
			var newKubeAppProber KubeAppProbers
			err = json.Unmarshal([]byte(newProbers), &newKubeAppProber)
			if err != nil {
				log.Error("unmarshal new kube app probers", "error", err)
				return envVars
			}
			// merge old and new probers.
			maps.Copy(newKubeAppProber, existingKubeAppProber)
			marshalledKubeAppProber, err := json.Marshal(newKubeAppProber)
			if err != nil {
				log.Error("serialize merged app prober configuration", "error", err)
				return envVars
			}
			// replace old env var with new value.
			envVars[idx] = corev1.EnvVar{Name: KubeAppProberEnvName, Value: string(marshalledKubeAppProber)}
			return envVars
		}
	}
	return append(envVars, corev1.EnvVar{Name: KubeAppProberEnvName, Value: newProbers})
}

var emptyScrape = PrometheusScrapeConfiguration{}

// applyPrometheusMerge configures prometheus scraping annotations for the "metrics merge" feature.
// This moves the current prometheus.io annotations into an environment variable and replaces them
// pointing to the agent.
func applyPrometheusMerge(pod *corev1.Pod, settings InjectionSettings) error {
	if getPrometheusScrape(pod) &&
		enablePrometheusMerge(settings.EnablePrometheusMerge, pod.ObjectMeta.Annotations) {
		targetPort := strconv.Itoa(settings.StatusPort)
		if cur, f := getPrometheusPort(pod); f {
			// We have already set the port, assume user is controlling this or, more likely, re-injected
			// the pod.
			if cur == targetPort {
				return nil
			}
		}
		scrape := getPrometheusScrapeConfiguration(pod)
		sidecar := FindSidecar(pod)
		if sidecar != nil && scrape != emptyScrape {
			by, err := json.Marshal(scrape)
			if err != nil {
				return err
			}
			sidecar.Env = append(sidecar.Env, corev1.EnvVar{Name: PrometheusScrapingConfigName, Value: string(by)})
		}
		if pod.Annotations == nil {
			pod.Annotations = map[string]string{}
		}
		// if a user sets `prometheus/io/path: foo`, then we add `prometheus.io/path: /stats/prometheus`
		// prometheus will pick a random one
		// need to clear out all variants and then set ours
		clearPrometheusAnnotations(pod)
		pod.Annotations["prometheus.io/port"] = targetPort
		pod.Annotations["prometheus.io/path"] = "/stats/prometheus"
		pod.Annotations["prometheus.io/scrape"] = "true"
		return nil
	}

	return nil
}

// invalidPrometheusLabelChars mirrors Prometheus strutil.SanitizeLabelName,
// which replaces every character outside [a-zA-Z0-9_] with an underscore.
var invalidPrometheusLabelChars = regexp.MustCompile(`[^a-zA-Z0-9_]`)

func sanitizeLabelName(name string) string {
	return invalidPrometheusLabelChars.ReplaceAllString(name, "_")
}

// getPrometheusScrape respect prometheus scrape config
// not to doing prometheusMerge if this return false
func getPrometheusScrape(pod *corev1.Pod) bool {
	for k, val := range pod.Annotations {
		if sanitizeLabelName(k) != prometheusScrapeAnnotation {
			continue
		}

		if scrape, err := strconv.ParseBool(val); err == nil {
			return scrape
		}
	}

	return true
}

var prometheusAnnotations = sets.New(
	prometheusPathAnnotation,
	prometheusPortAnnotation,
	prometheusScrapeAnnotation,
)

func clearPrometheusAnnotations(pod *corev1.Pod) {
	needRemovedKeys := make([]string, 0, 2)
	for k := range pod.Annotations {
		anno := sanitizeLabelName(k)
		if prometheusAnnotations.Contains(anno) {
			needRemovedKeys = append(needRemovedKeys, k)
		}
	}

	for _, k := range needRemovedKeys {
		delete(pod.Annotations, k)
	}
}

func getPrometheusScrapeConfiguration(pod *corev1.Pod) PrometheusScrapeConfiguration {
	cfg := PrometheusScrapeConfiguration{}

	for k, val := range pod.Annotations {
		anno := sanitizeLabelName(k)
		switch anno {
		case prometheusPortAnnotation:
			cfg.Port = val
		case prometheusScrapeAnnotation:
			cfg.Scrape = val
		case prometheusPathAnnotation:
			cfg.Path = val
		}
	}

	return cfg
}

func getPrometheusPort(pod *corev1.Pod) (string, bool) {
	for k, val := range pod.Annotations {
		if sanitizeLabelName(k) != prometheusPortAnnotation {
			continue
		}

		return val, true
	}

	return "", false
}

const (
	// AutoImage means the injected image wins; container.image is required,
	// so customizers must set some image.
	AutoImage = "auto"
)

// applyContainer merges a container spec on top of the provided pod
func applyContainer(target *corev1.Pod, container corev1.Container) (*corev1.Pod, error) {
	overlay := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{container}}}

	overlayJSON, err := json.Marshal(overlay)
	if err != nil {
		return nil, err
	}

	return applyOverlay(target, overlayJSON)
}

// applyInitContainer merges a container spec on top of the provided pod as an init container
func applyInitContainer(target *corev1.Pod, container corev1.Container) (*corev1.Pod, error) {
	overlay := &corev1.Pod{Spec: corev1.PodSpec{
		// We need to set containers to empty, otherwise it will marshal as "null" and delete all containers
		Containers:     []corev1.Container{},
		InitContainers: []corev1.Container{container},
	}}

	overlayJSON, err := json.Marshal(overlay)
	if err != nil {
		return nil, err
	}

	return applyOverlay(target, overlayJSON)
}

func patchHandleUnmarshal(j []byte, unmarshal func(data []byte, v any) error) (map[string]any, error) {
	if j == nil {
		j = []byte("{}")
	}

	m := map[string]any{}
	err := unmarshal(j, &m)
	if err != nil {
		return nil, mergepatch.ErrBadJSONDoc
	}
	return m, nil
}

// StrategicMergePatchYAML is a small fork of strategicpatch.StrategicMergePatch to allow YAML patches
// This avoids expensive conversion from YAML to JSON
func StrategicMergePatchYAML(originalJSON []byte, patchYAML []byte, dataStruct any) ([]byte, error) {
	schema, err := strategicpatch.NewPatchMetaFromStruct(dataStruct)
	if err != nil {
		return nil, err
	}

	originalMap, err := patchHandleUnmarshal(originalJSON, json.Unmarshal)
	if err != nil {
		return nil, err
	}
	patchMap, err := patchHandleUnmarshal(patchYAML, func(data []byte, v any) error {
		return yaml.Unmarshal(data, v)
	})
	if err != nil {
		return nil, err
	}

	result, err := strategicpatch.StrategicMergeMapPatchUsingLookupPatchMeta(originalMap, patchMap, schema)
	if err != nil {
		return nil, err
	}

	return json.Marshal(result)
}

// applyOverlayYAML merges a pod spec, provided as YAML, on top of the provided pod
func applyOverlayYAML(target *corev1.Pod, overlayYAML []byte) (*corev1.Pod, error) {
	currentJSON, err := json.Marshal(target)
	if err != nil {
		return nil, err
	}

	pod := corev1.Pod{}
	// Overlay the injected template onto the original podSpec
	patched, err := StrategicMergePatchYAML(currentJSON, overlayYAML, pod)
	if err != nil {
		return nil, fmt.Errorf("strategic merge: %v", err)
	}

	if err := json.Unmarshal(patched, &pod); err != nil {
		return nil, fmt.Errorf("unmarshal patched pod: %v", err)
	}
	return &pod, nil
}

// applyOverlay merges a pod spec, provided as JSON, on top of the provided pod
func applyOverlay(target *corev1.Pod, overlayJSON []byte) (*corev1.Pod, error) {
	currentJSON, err := json.Marshal(target)
	if err != nil {
		return nil, err
	}

	pod := corev1.Pod{}
	// Overlay the injected template onto the original podSpec
	patched, err := strategicpatch.StrategicMergePatch(currentJSON, overlayJSON, pod)
	if err != nil {
		return nil, fmt.Errorf("strategic merge: %v", err)
	}

	if err := json.Unmarshal(patched, &pod); err != nil {
		return nil, fmt.Errorf("unmarshal patched pod: %v", err)
	}
	return &pod, nil
}

func (wh *Webhook) inject(ar *admissionv1.AdmissionReview, path string) *admissionv1.AdmissionResponse {
	requestLogger := log.With("path", path)
	req := ar.Request
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		requestLogger.Error("unmarshal admission object", "error", err)
		return toAdmissionResponse(err)
	}
	// Managed fields is sometimes extremely large, leading to excessive CPU time on patch generation
	// It does not impact the injection output at all, so we can just remove it.
	pod.ManagedFields = nil

	// Deal with potential empty fields, e.g., when the pod is created by a deployment
	podName := potentialPodName(pod.ObjectMeta)
	if pod.ObjectMeta.Namespace == "" {
		pod.ObjectMeta.Namespace = req.Namespace
	}

	requestLogger = requestLogger.With("pod", pod.Namespace+"/"+podName)
	requestLogger.Info("processing injection request")

	wh.mu.RLock()
	if wh.config == nil {
		wh.mu.RUnlock()
		requestLogger.Error("injection configuration has not been loaded")
		return toAdmissionResponse(fmt.Errorf("injection config not ready"))
	}
	if !injectRequired(IgnoredNamespaces.UnsortedList(), wh.config, &pod.Spec, pod.ObjectMeta) {
		requestLogger.Info("skipping injection due to policy check")
		wh.mu.RUnlock()
		return &admissionv1.AdmissionResponse{
			Allowed: true,
		}
	}

	deploy, typeMeta := GetDeployMetaFromPod(&pod)

	params := InjectionParameters{
		pod:                 &pod,
		deployMeta:          deploy,
		typeMeta:            typeMeta,
		templates:           wh.config.Templates,
		defaultTemplate:     wh.config.DefaultTemplates,
		aliases:             wh.config.Aliases,
		settings:            wh.settings,
		valuesConfig:        wh.valuesConfig,
		injectedAnnotations: wh.config.InjectedAnnotations,
		proxyEnvs:           parseInjectEnvs(path),
	}

	params.nativeSidecar = detectNativeSidecar(wh.nodes, wh.nativeSidecarMode, pod.Spec.NodeName)

	wh.mu.RUnlock()

	patchBytes, err := injectPod(params)
	if err != nil {
		requestLogger.Error("pod injection failed", "error", err)
		return toAdmissionResponse(err)
	}

	patchType := admissionv1.PatchTypeJSONPatch
	return &admissionv1.AdmissionResponse{
		Allowed:   true,
		Patch:     patchBytes,
		PatchType: &patchType,
	}
}

// detectNativeSidecar requires every node's kubelet to be at least 1.33 in
// auto mode; otherwise native sidecars are disabled.
func detectNativeSidecar(nodes kclient.Reader[*corev1.Node], mode NativeSidecarMode, podNodeName string) bool {
	switch mode {
	case NativeSidecarModeDisabled:
		return false
	case NativeSidecarModeEnabled:
		return true
	}

	if nodes == nil {
		log.Warn("cannot auto-detect native sidecar support without a Kubernetes client")
		return false
	}

	// Native sidecars feature graduated to stable in Kubernetes 1.33
	const minVersion = 33

	checkNodeVersion := func(n *corev1.Node) bool {
		minor, err := kubeletMinorVersion(n.Status.NodeInfo.KubeletVersion)
		if err != nil {
			log.Warn("read node version", "node", n.Name,
				"kubelet_version", n.Status.NodeInfo.KubeletVersion, "error", err)
			return false
		}
		if minor < minVersion {
			log.Debug("native sidecars disabled because kubelet is below the minimum version",
				"node", n.Name, "kubelet_minor", minor, "minimum_minor", minVersion)
			return false
		}
		return true
	}

	if podNodeName != "" {
		node := nodes.Get(podNodeName, "")
		if node != nil {
			return checkNodeVersion(node)
		}
		log.Warn("pod node not found in cluster", "node", podNodeName)
	}
	// Check all nodes to see if they are eligible to support native sidecars. If any node is below the minimum version, we disable the feature.
	// This avoids issues with mixed clusters where some nodes support native sidecars and others do not.
	for _, n := range nodes.List(metav1.NamespaceAll, klabels.Everything()) {
		if !checkNodeVersion(n) {
			return false
		}
	}
	return true
}

// kubeletMinorVersion parses the minor version out of a kubelet version
// string such as "v1.33.1" or "v1.28.3+k3s1".
func kubeletMinorVersion(version string) (int, error) {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return 0, fmt.Errorf("unparseable kubelet version %q", version)
	}
	digits := parts[1]
	for i, r := range digits {
		if r < '0' || r > '9' {
			digits = digits[:i]
			break
		}
	}
	return strconv.Atoi(digits)
}

func (wh *Webhook) serveInject(w http.ResponseWriter, r *http.Request) {
	requestLogger := log.With("path", r.URL.Path)
	var body []byte
	if r.Body != nil {
		data, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
		if err != nil {
			requestLogger.Error("read admission request body", "error", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		body = data
	}
	if len(body) == 0 {
		requestLogger.Error("admission request body is empty")
		http.Error(w, "no body found", http.StatusBadRequest)
		return
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		requestLogger.Error("invalid admission request content type",
			"content_type", contentType, "expected", "application/json")
		http.Error(w, "invalid Content-Type, want `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	path := ""
	if r.URL != nil {
		path = r.URL.Path
	}

	var reviewResponse *admissionv1.AdmissionResponse
	ar := &admissionv1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, ar); err != nil {
		requestLogger.Error("decode admission request body", "error", err)
		reviewResponse = toAdmissionResponse(err)
	} else if ar.Request == nil {
		err := fmt.Errorf("admission review request is missing")
		requestLogger.Error("invalid admission review", "error", err)
		reviewResponse = toAdmissionResponse(err)
	} else {
		reviewResponse = wh.inject(ar, path)
	}

	response := admissionv1.AdmissionReview{TypeMeta: ar.TypeMeta}
	if response.APIVersion == "" {
		response.APIVersion = admissionv1.SchemeGroupVersion.String()
		response.Kind = "AdmissionReview"
	}
	response.Response = reviewResponse
	if response.Response != nil && ar.Request != nil {
		response.Response.UID = ar.Request.UID
	}
	resp, err := json.Marshal(response)
	if err != nil {
		requestLogger.Error("encode admission response", "error", err)
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
		return
	}
	if _, err := w.Write(resp); err != nil {
		requestLogger.Error("write admission response", "error", err)
	}
}

// parseInjectEnvs parse new envs from inject url path. format: /inject/k1/v1/k2/v2
// slash characters in values must be replaced by --slash-- (e.g. /inject/k1/abc--slash--def/k2/v2).
func parseInjectEnvs(path string) map[string]string {
	path = strings.TrimSuffix(path, "/")
	res := func(path string) []string {
		parts := strings.SplitN(path, "/", 3)
		var newRes []string
		if len(parts) == 3 { // If length is less than 3, then the path is simply "/inject".
			if strings.HasPrefix(parts[2], ":ENV:") {
				// Deprecated, not recommended.
				pairs := strings.Split(parts[2], ":ENV:")
				for i := 1; i < len(pairs); i++ { // skip the first part, it is a nil
					pair := strings.SplitN(pairs[i], "=", 2)
					if len(pair[0]) > 0 && len(pair) == 2 {
						newRes = append(newRes, pair...)
					}
				}
				return newRes
			}
			newRes = strings.Split(parts[2], "/")
		}
		for i, value := range newRes {
			if i%2 != 0 {
				// Replace --slash-- with / in values.
				newRes[i] = strings.ReplaceAll(value, "--slash--", "/")
			}
		}
		return newRes
	}(path)
	newEnvs := make(map[string]string)

	for i := 0; i < len(res); i += 2 {
		k := res[i]
		if i == len(res)-1 { // ignore the last key without value
			log.Warn("odd number of injection environment entries; ignoring final key", "key", k)
			break
		}

		env, found := URLParameterToEnv[k]
		if !found {
			env = strings.ToUpper(k) // if not found, use the custom env directly
		}
		if env != "" {
			newEnvs[env] = res[i+1]
		}
	}

	return newEnvs
}

// cronJobNameRegexp matches "-<8-10 digit timestamp>" suffixes on Job names.
var cronJobNameRegexp = regexp.MustCompile(`(.+)-\d{8,10}$`)

// GetDeployMetaFromPod heuristically derives deployment metadata from the pod spec.
func GetDeployMetaFromPod(pod *corev1.Pod) (types.NamespacedName, metav1.TypeMeta) {
	if pod == nil {
		return types.NamespacedName{}, metav1.TypeMeta{}
	}
	// try to capture more useful namespace/name info for deployments, etc.
	deployMeta := types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}

	typeMetadata := metav1.TypeMeta{
		Kind:       "Pod",
		APIVersion: "v1",
	}
	if len(pod.GenerateName) > 0 {
		// if the pod name was generated (or is scheduled for generation), we can begin an investigation into the controlling reference for the pod.
		var controllerRef metav1.OwnerReference
		controllerFound := false
		for _, ref := range pod.GetOwnerReferences() {
			if ref.Controller != nil && *ref.Controller {
				controllerRef = ref
				controllerFound = true
				break
			}
		}
		if controllerFound {
			typeMetadata.APIVersion = controllerRef.APIVersion
			typeMetadata.Kind = controllerRef.Kind

			// heuristic for deployment detection
			deployMeta.Name = controllerRef.Name
			if typeMetadata.Kind == "ReplicaSet" && pod.Labels["pod-template-hash"] != "" && strings.HasSuffix(controllerRef.Name, pod.Labels["pod-template-hash"]) {
				name := strings.TrimSuffix(controllerRef.Name, "-"+pod.Labels["pod-template-hash"])
				deployMeta.Name = name
				typeMetadata.Kind = "Deployment"
			} else if typeMetadata.Kind == "ReplicaSet" && pod.Labels["rollouts-pod-template-hash"] != "" &&
				strings.HasSuffix(controllerRef.Name, pod.Labels["rollouts-pod-template-hash"]) {
				// Heuristic for ArgoCD Rollout
				name := strings.TrimSuffix(controllerRef.Name, "-"+pod.Labels["rollouts-pod-template-hash"])
				deployMeta.Name = name
				typeMetadata.Kind = "Rollout"
				typeMetadata.APIVersion = "v1alpha1"
			} else if typeMetadata.Kind == "ReplicationController" && pod.Labels["deploymentconfig"] != "" {
				// If the pod is controlled by the replication controller, which is created by the DeploymentConfig resource in
				// Openshift platform, set the deploy name to the deployment config's name, and the kind to 'DeploymentConfig'.
				deployMeta.Name = pod.Labels["deploymentconfig"]
				typeMetadata.Kind = "DeploymentConfig"
			} else if typeMetadata.Kind == "Job" {
				// If job name suffixed with `-<digit-timestamp>`, where the length of digit timestamp is 8~10,
				// trim the suffix and set kind to cron job.
				if jn := cronJobNameRegexp.FindStringSubmatch(controllerRef.Name); len(jn) == 2 {
					deployMeta.Name = jn[1]
					typeMetadata.Kind = "CronJob"
					// heuristically set cron job api version to v1 as it cannot be derived from pod metadata.
					typeMetadata.APIVersion = "batch/v1"
				}
			}
		}
	}

	if deployMeta.Name == "" {
		// if we haven't been able to extract a deployment name, then just give it the pod name
		deployMeta.Name = pod.Name
	}

	return deployMeta, typeMetadata
}
