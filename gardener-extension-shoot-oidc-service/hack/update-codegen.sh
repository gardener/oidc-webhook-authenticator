#!/bin/bash
#
# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

rm -f $GOPATH/bin/*-gen

PROJECT_ROOT=$(dirname $0)/..

bash "${PROJECT_ROOT}"/vendor/k8s.io/code-generator/generate-internal-groups.sh \
  deepcopy,defaulter \
  github.com/gardener/oidc-webhook-authenticator/gardener-extension-shoot-oidc-service/pkg/client/componentconfig \
  github.com/gardener/oidc-webhook-authenticator/gardener-extension-shoot-oidc-service/pkg/apis \
  github.com/gardener/oidc-webhook-authenticator/gardener-extension-shoot-oidc-service/pkg/apis \
  "config:v1alpha1" \
  --go-header-file "${PROJECT_ROOT}/hack/LICENSE_BOILERPLATE.txt"

bash "${PROJECT_ROOT}"/vendor/k8s.io/code-generator/generate-internal-groups.sh \
  conversion \
  github.com/gardener/oidc-webhook-authenticator/gardener-extension-shoot-oidc-service/pkg/client/componentconfig \
  github.com/gardener/oidc-webhook-authenticator/gardener-extension-shoot-oidc-service/pkg/apis \
  github.com/gardener/oidc-webhook-authenticator/gardener-extension-shoot-oidc-service/pkg/apis \
  "config:v1alpha1" \
  --extra-peer-dirs=github.com/gardener/oidc-webhook-authenticator/gardener-extension-shoot-oidc-service/pkg/apis/config,github.com/gardener/oidc-webhook-authenticator/gardener-extension-shoot-oidc-service/pkg/apis/config/v1alpha1,k8s.io/apimachinery/pkg/apis/meta/v1,k8s.io/apimachinery/pkg/conversion,k8s.io/apimachinery/pkg/runtime,github.com/gardener/gardener/extensions/pkg/controller/healthcheck/config/v1alpha1 \
  --go-header-file "${PROJECT_ROOT}/hack/LICENSE_BOILERPLATE.txt"
