
# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

# Image URL to use all building/pushing image targets
IMG ?= oidc-webhook-authenticator:latest
# Produce CRDs that work back to Kubernetes 1.11 (no version conversion)
CRD_OPTIONS ?= "crd:trivialVersions=false,preserveUnknownFields=false"
GOARCH      ?= $(shell go env GOARCH)

# Get the currently used
# install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

include hack/local/helm.mk

all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

manifests: tools-image ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	docker run --rm --name=oidc-tools -v $(shell pwd):/workspace tools:latest controller-gen rbac:roleName=manager-role webhook paths="./..." crd paths=./apis/... output:crd:artifacts:config=config/crd/bases
	cat hack/license_boilerplate.yaml.txt > charts/oidc-webhook-authenticator/charts/application/templates/authentication.gardener.cloud_openidconnects.yaml
	cat config/crd/bases/authentication.gardener.cloud_openidconnects.yaml >> charts/oidc-webhook-authenticator/charts/application/templates/authentication.gardener.cloud_openidconnects.yaml

generate: tools-image ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	docker run --rm --name=oidc-tools -v $(shell pwd):/workspace tools:latest controller-gen object:headerFile="hack/license_boilerplate.go.txt" paths="./..."

fmt: ## Run go fmt against code.
	go fmt ./...

vet: ## Run go vet against code.
	go vet ./...

start-dev-container: tools-image ## Run go vet against code.
	docker run --rm --tty --interactive --name=odic-dev-container -v $(shell pwd):/workspace --workdir /workspace tools:latest /bin/bash

build: generate fmt vet ## Build manager binary.
	GOARCH=$(GOARCH) go build -o bin/oidc-webhook-authenticator ./cmd/oidc-webhook-authenticator/authenticator.go

run: manifests generate fmt vet ## Run a controller from your host.
	go run ./cmd/oidc-webhook-authenticator/authenticator.go

docker-build: ## Build docker image with the manager.
	docker build --build-arg TARGETARCH=$(GOARCH) -t ${IMG} .

docker-push: ## Push docker image with the manager.
	docker push ${IMG}

tools-image:
	docker build --target=tools -f dev.Dockerfile -t tools:latest .

.PHONY: test
test:
	@./hack/local/run-tests.sh

.PHONY: cleanup-test-env
cleanup-test-env:
	@hack/local/cleanup-test-env.sh
