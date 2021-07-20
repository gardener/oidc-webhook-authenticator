// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package kapiserver

import (
	"context"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	mockclient "github.com/gardener/gardener/pkg/mock/controller-runtime/client"
	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/runtime/inject"
)

const namespace = "test"

var _ = Describe("Mutator", func() {

	checkPodIsCorrectlyMutated := func(pod *corev1.Pod) {
		// Check that the kube-apiserver container still exists
		c := extensionswebhook.ContainerWithName(pod.Spec.Containers, "kube-apiserver")
		Expect(c).To(Not(BeNil()))

		Expect(c.Command).To(ContainElement("--authentication-token-webhook-cache-ttl=10s"))
		Expect(c.Command).To(ContainElement("--authentication-token-webhook-config-file=/oidc/webhook-kubeconfig.yaml"))
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

	Describe("MutateKubeAPIServerPods", func() {
		var (
			client  *mockclient.MockClient
			pod     *corev1.Pod
			mutator extensionswebhook.Mutator
		)

		BeforeEach(func() {
			pod = &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "kube-apiserver"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name: "kube-apiserver",
						},
					},
				},
			}

			client = mockclient.NewMockClient(ctrl)

			mutator = NewMutator(logger)
			err := mutator.(inject.Client).InjectClient(client)
			Expect(err).To(Not(HaveOccurred()))
		})

		It("should add missing flags to a kube-apiserver pod", func() {
			err := mutator.Mutate(ctx, pod, nil)
			Expect(err).NotTo(HaveOccurred())
			checkPodIsCorrectlyMutated(pod)
		})

		It("should modify existing elements of a pod", func() {
			pod.Spec.Containers[0].Command = []string{
				"--authentication-token-webhook-cache-ttl=?",
				"--authentication-token-webhook-config-file=?",
			}

			err := mutator.Mutate(ctx, pod, nil)
			Expect(err).NotTo(HaveOccurred())
			checkPodIsCorrectlyMutated(pod)
		})
	})

})
