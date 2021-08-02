// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

//go:generate ../../vendor/github.com/gardener/gardener/hack/generate-controller-registration.sh extension-shoot-oidc-service . ../../VERSION ../../example/controller-registration.yaml Extension:shoot-oidc-service

// Package chart enables go:generate support for generating the correct controller registration.
package chart
