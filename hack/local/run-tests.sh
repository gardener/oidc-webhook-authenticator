#!/bin/bash

# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

if ! command -v go &> /dev/null
then
    echo "Go is not installed."
    exit 1
fi

if ! command -v setup-envtest &> /dev/null
then
    echo "setup-envtest is not installed. Please install it by running 'go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest'"
    exit 1
fi

test_env_dir=$(setup-envtest use -p path 1.20.x!)
KUBEBUILDER_ASSETS="$test_env_dir" go test ./... -v count=1
