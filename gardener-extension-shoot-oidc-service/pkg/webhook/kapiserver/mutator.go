// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package kapiserver

import (
	"context"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type mutator struct {
	client client.Client
	logger logr.Logger
}

// InjectClient injects the given client into the mutator.
func (m *mutator) InjectClient(client client.Client) error {
	m.client = client
	return nil
}

// Mutate validates and if needed mutates the new object.
func (m *mutator) Mutate(ctx context.Context, new, old client.Object) error {
	switch x := new.(type) {
	case *corev1.Pod:
		if c := extensionswebhook.ContainerWithName(x.Spec.Containers, "kube-apiserver"); c != nil {
			m.logger.Info("WEBHOOK IS WORKING")

			// TODO Maybe ensure kubeconfig path
			c.Command = extensionswebhook.EnsureStringWithPrefix(c.Command, "--authentication-token-webhook-config-file=", "/oidc/webhook-kubeconfig.yaml")
			c.Command = extensionswebhook.EnsureStringWithPrefix(c.Command, "--authentication-token-webhook-cache-ttl=", "10s")
		}
	}

	return nil
}

// NewMutator creates a new oidc mutator.
func NewMutator(logger logr.Logger) extensionswebhook.Mutator {
	return &mutator{
		logger: logger.WithName("oidc-mutator"),
	}
}
