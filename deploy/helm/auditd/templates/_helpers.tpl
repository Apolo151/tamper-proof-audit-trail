{{/* Chart name, truncated to the 63-char DNS label limit. */}}
{{- define "auditd.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified app name. Collapses to the release name when it already
contains the chart name, so `helm install auditd ./auditd` yields "auditd".
*/}}
{{- define "auditd.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "auditd.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Selector labels: stable for the life of a release (selectors are immutable). */}}
{{- define "auditd.selectorLabels" -}}
app.kubernetes.io/name: {{ include "auditd.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "auditd.labels" -}}
helm.sh/chart: {{ include "auditd.chart" . }}
{{ include "auditd.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: tamper-proof-audit-trail
{{- end -}}

{{/* repository@digest when a digest is pinned (immutable), else repository:tag. */}}
{{- define "auditd.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{- define "auditd.pullPolicy" -}}
{{- if .Values.image.pullPolicy -}}
{{- .Values.image.pullPolicy -}}
{{- else if .Values.image.digest -}}
Always
{{- else -}}
IfNotPresent
{{- end -}}
{{- end -}}

{{/*
Checkov skips that are only true for a tag-addressed, locally loaded image
(kind). A digest-pinned install with pullPolicy Always needs neither, so they
are rendered only when they apply - the published chart carries no skips.
*/}}
{{- define "auditd.checkovSkips" -}}
{{- if not .Values.image.digest }}
checkov.io/skip1: CKV_K8S_43=no digest set - local kind loads the image by tag; the published chart pins sha256
{{- end }}
{{- if ne (include "auditd.pullPolicy" .) "Always" }}
checkov.io/skip2: CKV_K8S_15=IfNotPresent is required for `kind load docker-image`; digest installs default to Always
{{- end }}
{{- end -}}

{{/*
Restricted-PSS security contexts, shared by the app and the helm test pod.
Not exposed in values on purpose: the hardening is not a tunable.
*/}}
{{- define "auditd.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
fsGroup: 65532
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "auditd.containerSecurityContext" -}}
allowPrivilegeEscalation: false
privileged: false
readOnlyRootFilesystem: true
runAsNonRoot: true
capabilities:
  drop:
    - ALL
{{- end -}}
