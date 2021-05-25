// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// +kubebuilder:docs-gen:collapse=Apache License

package authentication

import (
	"context"
	"time"

	authenticationv1alpha1 "github.com/gardener/oidc-webhook-authenticator/apis/authentication/v1alpha1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// +kubebuilder:docs-gen:collapse=Imports

var _ = Describe("OpenIDConnect controller", func() {

	// Define utility constants for object names and testing timeouts/durations and intervals.
	const (
		timeout                = time.Second * 10
		interval               = time.Millisecond * 250
		OpenIDConnectName      = "test-openidconnect-controller"
		OpenIDConnectNamespace = "default"
	)
	var userNameClaim string = "email"

	Context("New OpenIDConnect Controller resource request", func() {
		It("A new OpenIDConnect controller resource is successfully created", func() {
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

			openidconnectLookupKey := types.NamespacedName{Name: OpenIDConnectName, Namespace: OpenIDConnectNamespace}
			createdOpenIDConnect := &authenticationv1alpha1.OpenIDConnect{}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, openidconnectLookupKey, createdOpenIDConnect)
				return err == nil
			}, timeout, interval).Should(BeTrue())

			// Ensure UserNameClaim was handled correctly
			Expect(createdOpenIDConnect.Spec.UsernameClaim).Should(Equal(&userNameClaim))
		})
	})
})
