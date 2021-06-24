// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package service

import "path/filepath"

const (
	ExtensionType        = "shoot-oidc-service"
	ServiceName          = ExtensionType
	ExtensionServiceName = "extension-" + ServiceName
	SeedChartName        = ServiceName + "-seed"
	ShootChartName       = ServiceName + "-shoot"

	// ImageName is the name of the oidc webhook authenticator.
	ImageName = "oidc-webhook-authenticator"

	// UserName is the name of the user  used to connect to the target cluster.
	UserName = "oidc.gardener.cloud:system:" + ServiceName

	// SecretName is the name of the secret used to store the access data for the shoot cluster.
	SecretName = ExtensionServiceName
)

// ChartsPath is the path to the charts
var ChartsPath = filepath.Join("charts", "internal")
