// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"time"

	controllerconfig "github.com/gardener/oidc-webhook-authenticator/gardener-extension-shoot-oidc-service/pkg/controller/config"
	"github.com/gardener/oidc-webhook-authenticator/gardener-extension-shoot-oidc-service/pkg/service"

	"github.com/gardener/gardener/extensions/pkg/controller/extension"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

const (
	// Type is the type of Extension resource.
	Type = service.ExtensionType
	// Name is the name of the lifecycle controller.
	Name = "shoot_oidc_service_lifecycle_controller"
	// FinalizerSuffix is the finalizer suffix for the OIDC Service controller.
	FinalizerSuffix = service.ExtensionType
)

// DefaultAddOptions contains configuration for the OIDC service.
var DefaultAddOptions = AddOptions{}

// AddOptions are options to apply when adding the oidc service controller to the manager.
type AddOptions struct {
	// ControllerOptions contains options for the controller.
	ControllerOptions controller.Options
	// ServiceConfig contains configuration for the shoot OIDC service.
	ServiceConfig controllerconfig.Config
	// IgnoreOperationAnnotation specifies whether to ignore the operation annotation or not.
	IgnoreOperationAnnotation bool
}

// AddToManager adds a OIDC Service Lifecycle controller to the given Controller Manager.
func AddToManager(mgr manager.Manager) error {
	return extension.Add(mgr, extension.AddArgs{
		Actuator:          NewActuator(DefaultAddOptions.ServiceConfig.Configuration),
		ControllerOptions: DefaultAddOptions.ControllerOptions,
		Name:              Name,
		FinalizerSuffix:   FinalizerSuffix,
		Resync:            60 * time.Minute,
		Predicates:        extension.DefaultPredicates(DefaultAddOptions.IgnoreOperationAnnotation),
		Type:              service.ExtensionType,
	})
}
