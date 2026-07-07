{{/*
Shared helpers for the sandbox chart.
*/}}

{{/* Namespace for all enhanced traffic management resources. */}}
{{- define "sandbox.namespace" -}}
{{ .Values.enhancedTrafficManagement.namespace }}
{{- end -}}

{{/* CA certificate ConfigMap name. */}}
{{- define "sandbox.caCertConfigMap" -}}
{{ .Values.enhancedTrafficManagement.global.caCertConfigMap }}
{{- end -}}

{{/* Gateway controller deployment name. */}}
{{- define "sandbox.controller.name" -}}
{{ .Values.enhancedTrafficManagement.gatewayController.name }}
{{- end -}}

{{/* Feature gate: enhanced traffic management + ambient mode. */}}
{{- define "sandbox.ambient.enabled" -}}
{{- and .Values.enhancedTrafficManagement.enabled .Values.enhancedTrafficManagement.ambient.enabled -}}
{{- end -}}

{{/*
Image helpers
*/}}

{{/* Construct a full image reference: hub/name:tag with global.hub fallback. */}}
{{- define "sandbox.image" -}}
{{- $hub := .hub | default .globalHub -}}
{{- printf "%s/%s:%s" $hub .name .tag -}}
{{- end -}}

{{/* Ztunnel image (shared by sidecar injection and ambient DaemonSet). */}}
{{- define "sandbox.ztunnelImage" -}}
{{- include "sandbox.image" (dict "hub" .Values.enhancedTrafficManagement.ztunnel.image.hub "name" .Values.enhancedTrafficManagement.ztunnel.image.name "tag" .Values.enhancedTrafficManagement.ztunnel.image.tag "globalHub" .Values.enhancedTrafficManagement.global.hub) -}}
{{- end -}}

{{/*
CNI helpers
*/}}

{{- define "sandbox.cni.name" -}}
agentio-cni
{{- end -}}

{{- define "sandbox.cni.daemonsetName" -}}
agentio-cni-node
{{- end -}}

{{- define "sandbox.cni.configName" -}}
agentio-cni-config
{{- end -}}

{{- define "sandbox.cni.selectorLabels" -}}
k8s-app: {{ include "sandbox.cni.daemonsetName" . }}
{{- end -}}

{{- define "sandbox.cni.labels" -}}
{{ include "sandbox.cni.selectorLabels" . }}
app: {{ include "sandbox.cni.name" . }}
{{- end -}}

{{/*
Ztunnel helpers
*/}}

{{- define "sandbox.ztunnel.name" -}}
agentio-tunnel
{{- end -}}

{{- define "sandbox.ztunnel.selectorLabels" -}}
app: {{ include "sandbox.ztunnel.name" . }}
{{- end -}}

{{- define "sandbox.ztunnel.labels" -}}
{{ include "sandbox.ztunnel.selectorLabels" . }}
{{- end -}}
