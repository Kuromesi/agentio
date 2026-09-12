{{- define "agentio.meshConfig.defaults" }}
ingressControllerMode: "OFF"
defaultConfig:
  discoveryAddress: {{ include "agentio.controller.name" . }}.{{ include "agentio.namespace" . }}.svc:15012
defaultProviders:
  accessLogging:
  - envoy
  metrics:
  - prometheus
extensionProviders:
- name: envoy
  envoyFileAccessLog:
    path: /dev/stdout
    omitEmptyValues: true
    logFormat:
      labels:
        scheme: '%REQ(:SCHEME)%'
        original_destination: '%DOWNSTREAM_LOCAL_ADDRESS%'
        upstream_host: '%UPSTREAM_HOST%'
        denial_reason: '%FILTER_STATE(io.kruise.egress_denial_reason:PLAIN)%'
        response_code_details: '%RESPONSE_CODE_DETAILS%'
        connection_termination_details: '%CONNECTION_TERMINATION_DETAILS%'
        log_type: '%ACCESS_LOG_TYPE%'
        authority_for: '%REQ(:AUTHORITY)%'
        bytes_received: '%BYTES_RECEIVED%'
        bytes_sent: '%BYTES_SENT%'
        downstream_address: '%DOWNSTREAM_REMOTE_ADDRESS%'
        duration: '%DURATION%'
        method: '%REQ(:METHOD)%'
        path: '%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%'
        protocol: '%PROTOCOL%'
        request_id: '%REQ(X-REQUEST-ID)%'
        # The decrypted internal hop retains SNI in shared filter state.
        # CEL prints filter-state bytes directly; Envoy disables string() conversion.
        requested_server_name: '%CEL(''io.kruise.outer_sni'' in filter_state ? filter_state[''io.kruise.outer_sni''] : connection.requested_server_name)%'
        response_code: '%RESPONSE_CODE%'
        response_flags: '%RESPONSE_FLAGS%'
        start_time: '%START_TIME%'
        trace_id: '%TRACE_ID%'
        upstream_address: '%UPSTREAM_REMOTE_ADDRESS%'
        transport_failure_reason: '%UPSTREAM_TRANSPORT_FAILURE_REASON%'
        user_agent: '%REQ(USER-AGENT)%'
        sandbox_name: '%CEL(filter_state[''downstream_peer''].name)%'
        sandbox_namespace: '%CEL(filter_state[''downstream_peer''].namespace)%'
enablePrometheusMerge: true
rootNamespace: {{ include "agentio.namespace" . }}
trustDomain: {{ .Values.global.trustDomain }}
{{- end }}
