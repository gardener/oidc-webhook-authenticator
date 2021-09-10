{{- define "oidc-webhook-authenticator.name" -}}
oidc-webhook-authenticator
{{- end -}}

{{-  define "oidc-webhook-authenticator.webhook-kubeconfig" -}}
apiVersion: v1
kind: Config
clusters:
  - name: {{ include "oidc-webhook-authenticator.name" . }}
    cluster:
{{- if .Values.virtualGarden.enabled }}
      server: {{ printf "https://%s.%s/validate-token" (include "oidc-webhook-authenticator.name" .) (.Release.Namespace) }}
{{- else }}
      server: {{ printf "https://%s/validate-token" (include "oidc-webhook-authenticator.name" .) }}
{{- end }}
      certificate-authority-data: {{ required ".Values.webhookConfig.caBundle is required" (b64enc .Values.webhookConfig.caBundle) }}
users:
  - name: {{ include "oidc-webhook-authenticator.name" . }}
    user:
      tokenFile: /var/run/secrets/oidc-webhook-tokens/kube-apiserver-token
current-context: {{ include "oidc-webhook-authenticator.name" . }}
contexts:
  - name: {{ include "oidc-webhook-authenticator.name" . }}
    context:
      cluster: {{ include "oidc-webhook-authenticator.name" . }}
      user: {{ include "oidc-webhook-authenticator.name" . }}
{{- end }}
