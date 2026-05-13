{{/*
Expand the name of the chart.
*/}}
{{- define "bweso.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "bweso.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "bweso.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels.
*/}}
{{- define "bweso.labels" -}}
helm.sh/chart: {{ include "bweso.chart" . }}
{{ include "bweso.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Selector labels.
*/}}
{{- define "bweso.selectorLabels" -}}
app.kubernetes.io/name: {{ include "bweso.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Service account name.
*/}}
{{- define "bweso.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "bweso.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Container image reference.
*/}}
{{- define "bweso.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{/*
Credentials Secret name.
*/}}
{{- define "bweso.credentialsSecretName" -}}
{{- if .Values.credentials.existingSecret.name -}}
{{- .Values.credentials.existingSecret.name -}}
{{- else -}}
{{- printf "%s-credentials" (include "bweso.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Validate endpoint and credential configuration.
*/}}
{{- define "bweso.validate" -}}
{{- if and .Values.config.singleOriginUrl (or .Values.config.identityUrl .Values.config.apiUrl) -}}
{{- fail "configure either config.singleOriginUrl or both config.identityUrl and config.apiUrl, not both endpoint modes" -}}
{{- end -}}
{{- if and (not .Values.config.singleOriginUrl) (not (and .Values.config.identityUrl .Values.config.apiUrl)) -}}
{{- fail "configure config.singleOriginUrl, or both config.identityUrl and config.apiUrl" -}}
{{- end -}}
{{- if and .Values.credentials.create .Values.credentials.existingSecret.name -}}
{{- fail "configure either credentials.create or credentials.existingSecret.name, not both" -}}
{{- end -}}
{{- if and (not .Values.credentials.create) (not .Values.credentials.existingSecret.name) -}}
{{- fail "configure credentials.existingSecret.name or set credentials.create=true" -}}
{{- end -}}
{{- if and (not .Values.auth.enabled) (not .Values.auth.insecureAllowUnauthenticated) -}}
{{- fail "auth.enabled=false requires auth.insecureAllowUnauthenticated=true" -}}
{{- end -}}
{{- if and .Values.auth.enabled .Values.auth.insecureAllowUnauthenticated -}}
{{- fail "configure either auth.enabled=true or auth.insecureAllowUnauthenticated=true, not both" -}}
{{- end -}}
{{- if .Values.credentials.create -}}
{{- if not .Values.credentials.clientId -}}
{{- fail "credentials.clientId is required when credentials.create=true" -}}
{{- end -}}
{{- if not .Values.credentials.clientSecret -}}
{{- fail "credentials.clientSecret is required when credentials.create=true" -}}
{{- end -}}
{{- if not .Values.credentials.masterPassword -}}
{{- fail "credentials.masterPassword is required when credentials.create=true" -}}
{{- end -}}
{{- if and .Values.auth.enabled (not .Values.credentials.webhookToken) -}}
{{- fail "credentials.webhookToken is required when credentials.create=true and auth.enabled=true" -}}
{{- end -}}
{{- end -}}
{{- end -}}
