// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package kapiserver

import (
	"context"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gcontext "github.com/gardener/gardener/extensions/pkg/webhook/context"
	"github.com/gardener/gardener/extensions/pkg/webhook/controlplane/genericmutator"
	"github.com/gardener/oidc-webhook-authenticator/gardener-extension-shoot-oidc-service/pkg/controller/lifecycle"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"k8s.io/apimachinery/pkg/types"
)

const (
	shootKubeConfgVolumeName = "oidc-authenticator-shoot-kubeconfig"
)

type ensurer struct {
	genericmutator.NoopEnsurer
	client client.Client
	logger logr.Logger
}

// InjectClient injects the given client into the ensurer.
func (e *ensurer) InjectClient(client client.Client) error {
	e.client = client

	return nil
}

// EnsureKubeAPIServerDeployment ensures that the kube-apiserver deployment conforms to the provider requirements.
func (e *ensurer) EnsureKubeAPIServerDeployment(ctx context.Context, _ gcontext.GardenContext, new, _ *appsv1.Deployment) error {
	template := &new.Spec.Template
	ps := &template.Spec

	if c := extensionswebhook.ContainerWithName(ps.Containers, v1beta1constants.DeploymentNameKubeAPIServer); c != nil {
		namespacedName := types.NamespacedName{
			Namespace: new.Namespace,
			Name:      lifecycle.SeedResourcesName,
		}
		cfg := &corev1.ConfigMap{}

		// Skip mutating if the volume is not ready to mount
		if err := e.client.Get(ctx, namespacedName, cfg); err != nil {
			if apierrors.IsNotFound(err) {
				return nil
			} else {
				return err
			}
		}

		c.Command = extensionswebhook.EnsureStringWithPrefix(c.Command, "--authentication-token-webhook-config-file=", "/var/run/gardener/oidc-webhook/kubeconfig")
		c.Command = extensionswebhook.EnsureStringWithPrefix(c.Command, "--authentication-token-webhook-cache-ttl=", "10s")

		c.VolumeMounts = extensionswebhook.EnsureVolumeMountWithName(c.VolumeMounts, corev1.VolumeMount{
			Name:      shootKubeConfgVolumeName,
			ReadOnly:  true,
			MountPath: "/var/run/gardener/oidc-webhook",
		})

		ps.Volumes = extensionswebhook.EnsureVolumeWithName(ps.Volumes, corev1.Volume{
			Name: shootKubeConfgVolumeName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: lifecycle.SeedResourcesName,
					},
				},
			},
		})

	}

	return nil
}

// NewMutator creates a new oidc mutator.
func NewMutator(logger logr.Logger) genericmutator.Ensurer {
	return &ensurer{
		logger: logger.WithName("oidc-controlplane-ensurer"),
	}
}
