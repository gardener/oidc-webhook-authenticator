#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

if ! command -v setup-envtest &> /dev/null
then
    echo "setup-envtest tool is not installed. Nothing to clean."
    exit
fi

setup-envtest cleanup
