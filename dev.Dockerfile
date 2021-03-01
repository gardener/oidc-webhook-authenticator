# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

FROM k8s.gcr.io/kube-apiserver:v1.20.0 as kube-apiserver
FROM quay.io/coreos/etcd:v3.4.15 as etcd
FROM eu.gcr.io/gardener-project/3rd/golang:1.15.5 AS tools

COPY --from=kube-apiserver /usr/local/bin/kube-apiserver /testbin/kube-apiserver
COPY --from=etcd /usr/local/bin/etcd /testbin/etcd

RUN mkdir /tools && cd /tools && go mod init tmp && go get sigs.k8s.io/controller-tools/cmd/controller-gen@v0.4.1
ENV KUBEBUILDER_ASSETS=/testbin
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64
ENV GO111MODULE=on
WORKDIR /workspace
