// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package kapiserver

import (
	"context"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/extensions/pkg/webhook/controlplane/genericmutator"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	mockclient "github.com/gardener/gardener/pkg/mock/controller-runtime/client"
	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/runtime/inject"
)

const namespace = "test"

var _ = Describe("Mutator", func() {

	checkDeploymentIsCorrectlyMutated := func(deployment *appsv1.Deployment) {
		// Check that the kube-apiserver container still exists
		c := extensionswebhook.ContainerWithName(deployment.Spec.Template.Spec.Containers, v1beta1constants.DeploymentNameKubeAPIServer)
		Expect(c).To(Not(BeNil()))

		Expect(c.Command).To(ContainElement("--authentication-token-webhook-cache-ttl=10s"))
		Expect(c.Command).To(ContainElement("--authentication-token-webhook-config-file=/var/run/gardener/oidc-webhook/kubeconfig"))
	}

	var (
		ctrl *gomock.Controller
		ctx  = context.TODO()
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Describe("MutateKubeAPIServerDeployments", func() {
		var (
			client     *mockclient.MockClient
			deployment *appsv1.Deployment
			ensurer    genericmutator.Ensurer
		)

		BeforeEach(func() {
			deployment = &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: v1beta1constants.DeploymentNameKubeAPIServer},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name: v1beta1constants.DeploymentNameKubeAPIServer,
								},
							},
						},
					},
				},
			}

			client = mockclient.NewMockClient(ctrl)

			ensurer = NewMutator(logger)
			err := ensurer.(inject.Client).InjectClient(client)
			Expect(err).To(Not(HaveOccurred()))
		})

		It("should add missing flags to a kube-apiserver pod", func() {
			err := ensurer.EnsureKubeAPIServerDeployment(ctx, nil, deployment, nil)
			Expect(err).NotTo(HaveOccurred())
			checkDeploymentIsCorrectlyMutated(deployment)
		})

		It("should modify existing elements of a pod", func() {
			deployment.Spec.Template.Spec.Containers[0].Command = []string{
				"--authentication-token-webhook-cache-ttl=?",
				"--authentication-token-webhook-config-file=?",
			}

			err := ensurer.EnsureKubeAPIServerDeployment(ctx, nil, deployment, nil)
			Expect(err).NotTo(HaveOccurred())
			checkDeploymentIsCorrectlyMutated(deployment)
		})
	})

})
