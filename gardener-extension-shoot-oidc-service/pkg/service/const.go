// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package service

const (
	ExtensionType        = "shoot-oidc-service"
	ServiceName          = ExtensionType
	ExtensionServiceName = "extension-" + ServiceName

	// ImageName is the name of the oidc webhook authenticator.
	ImageName = "oidc-webhook-authenticator"
	// ManagedResourceNamesSeed is the name used to describe the managed seed resources.
	ManagedResourceNamesSeed = ExtensionServiceName + "-seed"
	// ManagedResourceNamesShoot is the name used to describe the managed shoot resources.
	ManagedResourceNamesShoot = ExtensionServiceName + "-shoot"
)
