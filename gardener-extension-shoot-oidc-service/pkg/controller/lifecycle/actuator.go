// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"

	"github.com/gardener/oidc-webhook-authenticator/gardener-extension-shoot-oidc-service/pkg/apis/config"
	"github.com/gardener/oidc-webhook-authenticator/gardener-extension-shoot-oidc-service/pkg/service"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"

	"github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/extension"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// ActuatorName is the name of the OIDC Service actuator.
	ActuatorName = service.ServiceName + "-actuator"
	// SeedResourcesName is the name for resource describing the resources applied to the seed cluster.
	SeedResourcesName = service.ExtensionServiceName + "-seed"
	// ShootResourcesName is the name for resource describing the resources applied to the shoot cluster.
	ShootResourcesName = service.ExtensionServiceName + "-shoot"
	// TODO check if these are needed
	// KeptShootResourcesName is the name for resource describing the resources applied to the shoot cluster that should not be deleted.
	// KeptShootResourcesName = service.ExtensionServiceName + "-shoot-keep"
	// OwnerName is the name of the OIDCOwner object created for the shoot oidc service
	// OwnerName = service.ServiceName
)

// NewActuator returns an actuator responsible for Extension resources.
func NewActuator(config config.Configuration) extension.Actuator {
	return &actuator{
		logger:        log.Log.WithName(ActuatorName),
		serviceConfig: config,
	}
}

type actuator struct {
	client  client.Client
	config  *rest.Config
	decoder runtime.Decoder

	serviceConfig config.Configuration

	logger logr.Logger
}

// Reconcile the Extension resource.
func (a *actuator) Reconcile(ctx context.Context, ex *extensionsv1alpha1.Extension) error {
	namespace := ex.GetNamespace()

	cluster, err := controller.GetCluster(ctx, a.client, namespace)
	if err != nil {
		return err
	}

	// validate

	if !controller.IsHibernated(cluster) {

	}

	return nil
}

// Delete the Extension resource.
func (a *actuator) Delete(ctx context.Context, ex *extensionsv1alpha1.Extension) error {
	//namespace := ex.GetNamespace()

	return nil
}

// Restore the Extension resource.
func (a *actuator) Restore(ctx context.Context, ex *extensionsv1alpha1.Extension) error {
	return a.Reconcile(ctx, ex)
}

// Migrate the Extension resource.
func (a *actuator) Migrate(ctx context.Context, ex *extensionsv1alpha1.Extension) error {
	// Keep objects for shoot managed resources so that they are not deleted from the shoot during the migration

	return a.Delete(ctx, ex)
}

// InjectConfig injects the rest config to this actuator.
func (a *actuator) InjectConfig(config *rest.Config) error {
	a.config = config
	return nil
}

// InjectClient injects the controller runtime client into the reconciler.
func (a *actuator) InjectClient(client client.Client) error {
	a.client = client
	return nil
}

// InjectScheme injects the given scheme into the reconciler.
func (a *actuator) InjectScheme(scheme *runtime.Scheme) error {
	a.decoder = serializer.NewCodecFactory(scheme, serializer.EnableStrict).UniversalDecoder()
	return nil
}
