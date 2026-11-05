{{- define "cbom-scan-node.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cbom-scan-node.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "cbom-scan-node.labels" -}}
app.kubernetes.io/name: {{ include "cbom-scan-node.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "cbom-scan-node.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion (toString .Values.image.tag)) -}}
{{- end -}}

{{- define "cbom-scan-node.secretName" -}}
{{- default (printf "%s-tokens" (include "cbom-scan-node.fullname" .)) .Values.existingSecret -}}
{{- end -}}

{{- define "cbom-scan-node.agentSecretName" -}}
{{- default (printf "%s-tokens" (include "cbom-scan-node.fullname" .)) .Values.agent.existingSecret -}}
{{- end -}}

{{/* The host directory that keeps the agents' node state: one per release unless agent.statePath is set. */}}
{{- define "cbom-scan-node.agentStatePath" -}}
{{- default (printf "/var/lib/zs-node-agent/%s.%s" .Release.Namespace .Release.Name) .Values.agent.statePath -}}
{{- end -}}

{{/* Environment shared by both workloads: the API, the proxy, extra variables. */}}
{{- define "cbom-scan-node.commonEnv" -}}
- name: ZS_API_URL
  value: {{ required "apiUrl is required (the ZeroShield API URL)" .Values.apiUrl | quote }}
- name: ZS_STATE_DIR
  value: /var/lib/zs-node
{{- if .Values.allowInsecureHttp }}
- name: ZS_ALLOW_INSECURE_HTTP
  value: "1"
{{- end }}
{{- with .Values.httpsProxy }}
- name: HTTPS_PROXY
  value: {{ . | quote }}
{{- end }}
{{- with .Values.noProxy }}
- name: NO_PROXY
  value: {{ . | quote }}
{{- end }}
{{- with .Values.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/* Ready while the heartbeat loop turns (the image HEALTHCHECK's test); a node not yet enrolled is not ready.
     Readiness only: a liveness probe would restart a node that is still waiting to enroll. */}}
{{- define "cbom-scan-node.readiness" -}}
readinessProbe:
  exec:
    command: ["python", "-c", "import os,sys,time; p=os.path.join(os.environ.get('ZS_STATE_DIR','/var/lib/zs-node'),'alive'); sys.exit(0 if os.path.exists(p) and time.time()-os.path.getmtime(p)<180 else 1)"]
  initialDelaySeconds: 10
  periodSeconds: 30
  timeoutSeconds: 5
{{- end -}}
