// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package kapiserver

import (
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/extensions/pkg/webhook/controlplane"
	"github.com/gardener/gardener/extensions/pkg/webhook/controlplane/genericmutator"
	"github.com/gardener/gardener/pkg/operation/botanist/component/extensions/operatingsystemconfig/original/components/kubelet"
	oscutils "github.com/gardener/gardener/pkg/operation/botanist/component/extensions/operatingsystemconfig/utils"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var logger = log.Log.WithName("oidc-kapiserver-webhook")

func New(mgr manager.Manager) (*extensionswebhook.Webhook, error) {
	logger.Info("Adding webhook to manager")

	fciCodec := oscutils.NewFileContentInlineCodec()

	webhook, err := controlplane.New(mgr, controlplane.Args{
		Kind:  controlplane.KindShoot,
		Types: []client.Object{&appsv1.Deployment{}},
		Mutator: genericmutator.NewMutator(
			NewMutator(logger),
			oscutils.NewUnitSerializer(),
			kubelet.NewConfigCodec(fciCodec),
			fciCodec,
			logger,
		),
	})

	webhook.Selector.MatchExpressions = []v1.LabelSelectorRequirement{
		{
			Key:      "shoot.gardener.cloud/authentication",
			Operator: "In",
			Values:   []string{"oidc"},
		},
	}

	// webhook.Selector.MatchLabels = map[string]string{
	// 	"app":                 "kubernetes",
	// 	"gardener.cloud/role": "controlplane",
	// 	"role":                "apiserver",
	// }

	return webhook, err
}
