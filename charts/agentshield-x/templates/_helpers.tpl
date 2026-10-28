{{- define "agentshield.name" -}}agentshield-x{{- end -}}
{{- define "agentshield.labels" -}}
app.kubernetes.io/name: {{ include "agentshield.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}
{{- define "agentshield.selector" -}}
app.kubernetes.io/name: {{ include "agentshield.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
