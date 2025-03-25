# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

# Build the manager binary
FROM golang:1.24.1 AS builder

ARG TARGETARCH
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
COPY internal/ internal/

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH GO111MODULE=on go build -a -o oidc-webhook-authenticator cmd/oidc-webhook-authenticator/authenticator.go

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=builder /workspace/oidc-webhook-authenticator .
EXPOSE 10443/tcp

LABEL org.opencontainers.image.authors="Gardener contributors"
LABEL org.opencontainers.image.description="Kubernetes Webhook Authenticator that allows for dynamic registration of OpenID Connect providers."
LABEL org.opencontainers.image.documentation="https://github.com/gardener/oidc-webhook-authenticator"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/gardener/oidc-webhook-authenticator"
LABEL org.opencontainers.image.title="oidc webhook authenticator"
LABEL org.opencontainers.image.url="https://github.com/gardener/oidc-webhook-authenticator"
LABEL org.opencontainers.image.vendor="Gardener contributors"

ENTRYPOINT ["/oidc-webhook-authenticator"]
