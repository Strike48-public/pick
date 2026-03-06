{{/*
Expand the name of the chart.
*/}}
{{- define "pick-connector.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "pick-connector.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "pick-connector.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "pick-connector.labels" -}}
helm.sh/chart: {{ include "pick-connector.chart" . }}
{{ include "pick-connector.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "pick-connector.selectorLabels" -}}
app.kubernetes.io/name: {{ include "pick-connector.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use.
*/}}
{{- define "pick-connector.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "pick-connector.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Pod security context — driven by securityProfile.
*/}}
{{- define "pick-connector.podSecurityContext" -}}
{{- if eq .Values.securityProfile "full" }}
{}
{{- else }}
runAsNonRoot: true
runAsUser: 999
runAsGroup: 999
fsGroup: 999
{{- end }}
{{- end }}

{{/*
Container security context — driven by securityProfile.
  restricted: drop ALL, readOnlyRootFilesystem, no privilege escalation
  pentest:    drop ALL, add NET_RAW + NET_ADMIN, writable filesystem
  full:       root user, broad capabilities
*/}}
{{- define "pick-connector.containerSecurityContext" -}}
{{- if eq .Values.securityProfile "full" }}
runAsUser: 0
capabilities:
  drop: ["ALL"]
  add: ["SYS_PTRACE", "SYS_ADMIN", "NET_RAW", "NET_ADMIN"]
{{- else if eq .Values.securityProfile "pentest" }}
allowPrivilegeEscalation: false
capabilities:
  drop: ["ALL"]
  add: ["NET_RAW", "NET_ADMIN"]
{{- else }}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
{{- end }}
{{- end }}
