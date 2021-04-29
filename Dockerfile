# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

# Build the manager binary
FROM eu.gcr.io/gardener-project/3rd/golang:1.15.5 AS builder

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY apis/ apis/
COPY controllers/ controllers/
COPY cmd/ cmd/
COPY webhook/ webhook/

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -o oidc-webhook-authenticator cmd/oidc-webhook-authenticator/authenticator.go

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static@sha256:b89b98ea1f5bc6e0b48c8be6803a155b2a3532ac6f1e9508a8bcbf99885a9152
WORKDIR /
COPY --from=builder /workspace/oidc-webhook-authenticator .
USER 65532:65532
EXPOSE 10443/tcp

LABEL org.opencontainers.image.authors="Gardener contributors"
LABEL org.opencontainers.image.description="Kubernetes Webhook Authenticator that allows for dynamic registration of OpenID Connect providers ."
LABEL org.opencontainers.image.documentation="https://github.com/gardener/oidc-webhook-authenticator"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/gardener/oidc-webhook-authenticator"
LABEL org.opencontainers.image.title="oidc webhook authenticator"
LABEL org.opencontainers.image.url="https://github.com/gardener/oidc-webhook-authenticator"
LABEL org.opencontainers.image.vendor="Gardener contributors"

ENTRYPOINT ["/oidc-webhook-authenticator"]
