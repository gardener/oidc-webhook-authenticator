# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

FROM registry.k8s.io/kube-apiserver:v1.33.2 AS kube-apiserver
FROM quay.io/coreos/etcd:v3.5.21 AS etcd
FROM golang:1.26rc2 AS tools

COPY --from=kube-apiserver /usr/local/bin/kube-apiserver /testbin/kube-apiserver
COPY --from=etcd /usr/local/bin/etcd /testbin/etcd

RUN mkdir /tools && cd /tools && go mod init tmp && go install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.18.0
ENV KUBEBUILDER_ASSETS=/testbin
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64
ENV GO111MODULE=on
WORKDIR /workspace
