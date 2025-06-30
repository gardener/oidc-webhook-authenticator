# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

FROM k8s.gcr.io/kube-apiserver:v1.22.1 AS kube-apiserver
FROM quay.io/coreos/etcd:v3.5.1 AS etcd
FROM golang:1.24.4 AS tools

COPY --from=kube-apiserver /usr/local/bin/kube-apiserver /testbin/kube-apiserver
COPY --from=etcd /usr/local/bin/etcd /testbin/etcd

RUN mkdir /tools && cd /tools && go mod init tmp && go install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.13.0
ENV KUBEBUILDER_ASSETS=/testbin
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64
ENV GO111MODULE=on
WORKDIR /workspace
