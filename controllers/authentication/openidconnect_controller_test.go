// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// +kubebuilder:docs-gen:collapse=Apache License

package authentication

import (
	"context"

	authenticationv1alpha1 "github.com/gardener/oidc-webhook-authenticator/apis/authentication/v1alpha1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:docs-gen:collapse=Imports

var _ = Describe("OpenIDConnect controller", func() {

	// Define utility constants for object names and testing timeouts/durations and intervals.
	const (
		OpenIDConnectName      = "test-openidconnect-controller"
		OpenIDConnectNamespace = "default"
	)
	var userNameClaim string = "email"

	Context("When the OpenIDConnect Controller receives a request", func() {
		It("An Invalid token should fail authentication", func() {
			By("By creating a new OpenIDConnect resource")
			ctx := context.Background()
			openidconnect := &authenticationv1alpha1.OpenIDConnect{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "authentication.gardener.cloud/v1alpha1",
					Kind:       "OpenIDConnect",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      OpenIDConnectName,
					Namespace: OpenIDConnectNamespace,
				},
				Spec: authenticationv1alpha1.OIDCAuthenticationSpec{
					IssuerURL:     "https://control-plane.minikube.internal:31133",
					ClientID:      "https://control-plane.minikube.internal:31133",
					UsernameClaim: &userNameClaim,
				},
			}
			Expect(k8sClient.Create(ctx, openidconnect)).Should(Succeed())

		})
	})

})
