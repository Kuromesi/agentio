{{/*
Shared helpers for the agentio chart.
*/}}

{{/* Namespace for all agentio resources. */}}
{{- define "agentio.namespace" -}}
{{ .Values.namespace }}
{{- end -}}

{{/* CA certificate ConfigMap name. */}}
{{- define "agentio.caCertConfigMap" -}}
{{ .Values.global.caCertConfigMap }}
{{- end -}}

{{/* agentiod (control plane) deployment name. */}}
{{- define "agentio.controller.name" -}}
{{ .Values.agentiod.name }}
{{- end -}}

{{/* Ambient mode toggle. */}}
{{- define "agentio.ambient.enabled" -}}
{{- .Values.ambient.enabled -}}
{{- end -}}

{{/*
Image helpers
*/}}

{{/* Construct a full image reference: hub/name:tag with global.hub fallback. */}}
{{- define "agentio.image" -}}
{{- $hub := .hub | default .globalHub -}}
{{- printf "%s/%s:%s" $hub .name .tag -}}
{{- end -}}

{{/* Ztunnel image (shared by sidecar injection and ambient DaemonSet). */}}
{{- define "agentio.ztunnelImage" -}}
{{- include "agentio.image" (dict "hub" .Values.ztunnel.image.hub "name" .Values.ztunnel.image.name "tag" .Values.ztunnel.image.tag "globalHub" .Values.global.hub) -}}
{{- end -}}

{{/*
CNI helpers
*/}}

{{- define "agentio.cni.name" -}}
agentio-cni
{{- end -}}

{{- define "agentio.cni.daemonsetName" -}}
agentio-cni-node
{{- end -}}

{{- define "agentio.cni.configName" -}}
agentio-cni-config
{{- end -}}

{{- define "agentio.cni.selectorLabels" -}}
k8s-app: {{ include "agentio.cni.daemonsetName" . }}
{{- end -}}

{{- define "agentio.cni.labels" -}}
{{ include "agentio.cni.selectorLabels" . }}
app: {{ include "agentio.cni.name" . }}
{{- end -}}

{{/*
Ztunnel helpers
*/}}

{{- define "agentio.ztunnel.name" -}}
ztunnel
{{- end -}}

{{- define "agentio.ztunnel.selectorLabels" -}}
app: {{ include "agentio.ztunnel.name" . }}
{{- end -}}

{{- define "agentio.ztunnel.labels" -}}
{{ include "agentio.ztunnel.selectorLabels" . }}
{{- end -}}
