// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// +kubebuilder:docs-gen:collapse=Apache License

package integration_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	authenticationv1 "k8s.io/api/authentication/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/client"

	authenticationv1alpha1 "github.com/gardener/oidc-webhook-authenticator/apis/authentication/v1alpha1"
	mockidp "github.com/gardener/oidc-webhook-authenticator/test/integration/mock"
)

var _ = Describe("Integration", func() {
	const (
		defaultNamespaceName = "default"
		podReaderRoleName    = "pod-reader"
	)

	var (
		emailUserNameClaim = "email"
		ctx                = context.Background()
	)

	Context("Authenticating user to the kube api-server via token from a trusted identity provider", func() {
		createRoleBindingForUser := func(ctx context.Context, namespace, roleName, username string) *rbacv1.RoleBinding {
			roleBinding, err := clientset.RbacV1().RoleBindings(namespace).Create(ctx, &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      rand.String(5),
					Namespace: namespace,
				},
				Subjects: []rbacv1.Subject{{
					Kind:     "User",
					Name:     username,
					APIGroup: "rbac.authorization.k8s.io",
				}},
				RoleRef: rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Role",
					Name:     roleName,
				},
			}, metav1.CreateOptions{})

			Expect(err).NotTo(HaveOccurred())
			return roleBinding
		}

		createRoleBindingForGroup := func(ctx context.Context, namespace, roleName, groupName string) *rbacv1.RoleBinding {
			roleBinding, err := clientset.RbacV1().RoleBindings(namespace).Create(ctx, &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      rand.String(5),
					Namespace: namespace,
				},
				Subjects: []rbacv1.Subject{{
					Kind:     "Group",
					Name:     groupName,
					APIGroup: "rbac.authorization.k8s.io",
				}},
				RoleRef: rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Role",
					Name:     roleName,
				},
			}, metav1.CreateOptions{})

			Expect(err).NotTo(HaveOccurred())
			return roleBinding
		}

		deleteRoleBinding := func(ctx context.Context, roleBinding *rbacv1.RoleBinding) {
			err := clientset.RbacV1().RoleBindings(roleBinding.Namespace).Delete(ctx, roleBinding.Name, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
		}

		makeAPIServerRequestAndExpectCode := func(userToken string, expectedStatusCode int) {
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			client := &http.Client{Transport: tr}
			req, err := http.NewRequest("GET", fmt.Sprintf("https://localhost:%v/api/v1/namespaces/default/pods", apiServerSecurePort), nil)
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", userToken))

			Eventually(func() int {
				res, err := client.Do(req)
				Expect(err).NotTo(HaveOccurred())
				return res.StatusCode
			}, timeout, interval).Should(Equal(expectedStatusCode))

		}

		It("Should authenticate but not authorize user with a single registered identity provider", func() {
			idp, err := mockidp.NewIdentityServer("mytestserver", 2)
			Expect(err).NotTo(HaveOccurred())
			err = idp.Start()
			Expect(err).NotTo(HaveOccurred())

			provider := defaultOIDCProvider()
			provider.Spec.IssuerURL = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			provider.Spec.CABundle = idp.CA()
			provider.Spec.UsernameClaim = &emailUserNameClaim

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			claims := defaultClaims()
			claims["sub"] = "1231"
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			claims["email"] = "johndoe@example.com"

			signedTokenWithFirstKey, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			makeAPIServerRequestAndExpectCode(signedTokenWithFirstKey, http.StatusForbidden)

			signedTokenWithSecondKey, err := idp.Sign(1, claims)
			Expect(err).NotTo(HaveOccurred())

			makeAPIServerRequestAndExpectCode(signedTokenWithSecondKey, http.StatusForbidden)

			err = idp.Stop(ctx)
			Expect(err).NotTo(HaveOccurred())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should authenticate but not authorize user with a single registered identity provider and static jwks", func() {
			idp, err := mockidp.NewIdentityServer("offline", 2)
			Expect(err).NotTo(HaveOccurred())
			err = idp.Start()
			Expect(err).NotTo(HaveOccurred())
			keys, err := idp.PublicKeySetAsBytes()
			Expect(err).NotTo(HaveOccurred())

			provider := defaultOIDCProvider()
			provider.Name = "static"
			provider.Spec.IssuerURL = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			provider.Spec.JWKS.Keys = keys

			// stop the idp server so that we ensure that the keys will not be fetched over the network
			err = idp.Stop(ctx)
			Expect(err).NotTo(HaveOccurred())

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)
			claims := defaultClaims()
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			claims["sub"] = "my-identity"

			signedTokenWithFirstKey, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			makeAPIServerRequestAndExpectCode(signedTokenWithFirstKey, http.StatusForbidden)

			signedTokenWithSecondKey, err := idp.Sign(1, claims)
			Expect(err).NotTo(HaveOccurred())

			makeAPIServerRequestAndExpectCode(signedTokenWithSecondKey, http.StatusForbidden)

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should authenticate and authorize user with a single registered identity provider and defaulted claim to `sub`", func() {
			idp, err := mockidp.NewIdentityServer("mytestserver", 2)
			Expect(err).NotTo(HaveOccurred())
			err = idp.Start()
			Expect(err).NotTo(HaveOccurred())

			provider := defaultOIDCProvider()
			provider.Spec.IssuerURL = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			provider.Spec.CABundle = idp.CA()

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			signedTokenWithFirstKey, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			roleBinding := createRoleBindingForUser(ctx, defaultNamespaceName, podReaderRoleName, fmt.Sprintf("%s/%s", provider.Name, user))

			makeAPIServerRequestAndExpectCode(signedTokenWithFirstKey, http.StatusOK)

			err = idp.Stop(ctx)
			Expect(err).NotTo(HaveOccurred())

			deleteRoleBinding(ctx, roleBinding)

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should authenticate and authorize user with two registered identity providers", func() {
			idp, err := mockidp.NewIdentityServer("mytestserver", 1)
			Expect(err).NotTo(HaveOccurred())
			idp1, err := mockidp.NewIdentityServer("mytestserver1", 1)
			Expect(err).NotTo(HaveOccurred())
			err = idp.Start()
			Expect(err).NotTo(HaveOccurred())
			err = idp1.Start()
			Expect(err).NotTo(HaveOccurred())

			provider := defaultOIDCProvider()
			provider.Spec.IssuerURL = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			provider.Spec.CABundle = idp.CA()
			provider.Spec.UsernameClaim = &emailUserNameClaim

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			provider1 := defaultOIDCProvider()
			provider1.Spec.IssuerURL = fmt.Sprintf("https://localhost:%v", idp1.ServerSecurePort)
			provider1.Spec.CABundle = idp1.CA()
			provider1.Spec.UsernameClaim = &emailUserNameClaim

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider1)

			user := "this-is-my-fake-identity"
			email := "my.real.identity@example-something-here.com"
			claims := defaultClaims()
			claims["sub"] = user
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp1.ServerSecurePort)
			claims["email"] = email

			signedTokenFromSecondIDP, err := idp1.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			roleBinding := createRoleBindingForUser(ctx, defaultNamespaceName, podReaderRoleName, fmt.Sprintf("%s/%s", provider1.Name, email))

			makeAPIServerRequestAndExpectCode(signedTokenFromSecondIDP, http.StatusOK)

			err = idp.Stop(ctx)
			Expect(err).NotTo(HaveOccurred())
			err = idp1.Stop(ctx)
			Expect(err).NotTo(HaveOccurred())

			deleteRoleBinding(ctx, roleBinding)

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider1)
		})

		It("Should not authenticate user because of missing required claim", func() {
			idp, err := mockidp.NewIdentityServer("mytestserver", 1)
			Expect(err).NotTo(HaveOccurred())
			err = idp.Start()
			Expect(err).NotTo(HaveOccurred())

			provider := defaultOIDCProvider()
			provider.Spec.IssuerURL = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			provider.Spec.CABundle = idp.CA()
			provider.Spec.RequiredClaims = map[string]string{
				"admin": "true",
			}

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			makeAPIServerRequestAndExpectCode(token, http.StatusUnauthorized)

			err = idp.Stop(ctx)
			Expect(err).NotTo(HaveOccurred())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should authenticate user with required claim", func() {
			idp, err := mockidp.NewIdentityServer("mytestserver", 1)
			Expect(err).NotTo(HaveOccurred())
			err = idp.Start()
			Expect(err).NotTo(HaveOccurred())

			provider := defaultOIDCProvider()
			provider.Spec.IssuerURL = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			provider.Spec.CABundle = idp.CA()
			provider.Spec.RequiredClaims = map[string]string{
				"admin": "true",
			}

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			claims["admin"] = "true"

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			makeAPIServerRequestAndExpectCode(token, http.StatusForbidden)

			err = idp.Stop(ctx)
			Expect(err).NotTo(HaveOccurred())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not authenticate user because of wrong issuer", func() {
			idp, err := mockidp.NewIdentityServer("mytestserver", 1)
			Expect(err).NotTo(HaveOccurred())
			err = idp.Start()
			Expect(err).NotTo(HaveOccurred())

			provider := defaultOIDCProvider()
			provider.Spec.IssuerURL = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			provider.Spec.CABundle = idp.CA()

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["iss"] = fmt.Sprintf("https://invalid:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			makeAPIServerRequestAndExpectCode(token, http.StatusUnauthorized)

			err = idp.Stop(ctx)
			Expect(err).NotTo(HaveOccurred())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not authenticate user because of wrong audience", func() {
			idp, err := mockidp.NewIdentityServer("mytestserver", 1)
			Expect(err).NotTo(HaveOccurred())
			err = idp.Start()
			Expect(err).NotTo(HaveOccurred())

			provider := defaultOIDCProvider()
			provider.Spec.IssuerURL = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			provider.Spec.CABundle = idp.CA()

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			claims["aud"] = "invalid"

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			makeAPIServerRequestAndExpectCode(token, http.StatusUnauthorized)

			err = idp.Stop(ctx)
			Expect(err).NotTo(HaveOccurred())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not authenticate user because of expired token", func() {
			idp, err := mockidp.NewIdentityServer("mytestserver", 1)
			Expect(err).NotTo(HaveOccurred())
			err = idp.Start()
			Expect(err).NotTo(HaveOccurred())

			provider := defaultOIDCProvider()
			provider.Spec.IssuerURL = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			provider.Spec.CABundle = idp.CA()

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			claims["exp"] = time.Now().Add(time.Minute * -10).Unix()

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			makeAPIServerRequestAndExpectCode(token, http.StatusUnauthorized)

			err = idp.Stop(ctx)
			Expect(err).NotTo(HaveOccurred())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should authenticate and authorize user with custom prefix", func() {
			idp, err := mockidp.NewIdentityServer("mytestserver", 1)
			Expect(err).NotTo(HaveOccurred())
			err = idp.Start()
			Expect(err).NotTo(HaveOccurred())

			prefix := "customprefix:"
			provider := defaultOIDCProvider()
			provider.Spec.IssuerURL = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			provider.Spec.CABundle = idp.CA()
			provider.Spec.UsernamePrefix = &prefix

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			roleBinding := createRoleBindingForUser(ctx, defaultNamespaceName, podReaderRoleName, prefix+user)

			makeAPIServerRequestAndExpectCode(token, http.StatusOK)

			err = idp.Stop(ctx)
			Expect(err).NotTo(HaveOccurred())

			deleteRoleBinding(ctx, roleBinding)

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should authenticate and authorize user with custom prefix for group", func() {
			idp, err := mockidp.NewIdentityServer("mytestserver", 1)
			Expect(err).NotTo(HaveOccurred())
			err = idp.Start()
			Expect(err).NotTo(HaveOccurred())

			usernamePrefix := "customprefix:"
			groupNamePrefix := "grprefix:"
			provider := defaultOIDCProvider()
			provider.Spec.IssuerURL = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			provider.Spec.CABundle = idp.CA()
			provider.Spec.UsernamePrefix = &usernamePrefix
			provider.Spec.GroupsPrefix = &groupNamePrefix

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["groups"] = []string{"podreader1", "podreader2"}
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			roleBinding1 := createRoleBindingForGroup(ctx, defaultNamespaceName, podReaderRoleName, groupNamePrefix+"podreader1")

			makeAPIServerRequestAndExpectCode(token, http.StatusOK)

			deleteRoleBinding(ctx, roleBinding1)

			roleBinding2 := createRoleBindingForGroup(ctx, defaultNamespaceName, podReaderRoleName, groupNamePrefix+"podreader2")

			makeAPIServerRequestAndExpectCode(token, http.StatusOK)

			err = idp.Stop(ctx)
			Expect(err).NotTo(HaveOccurred())

			deleteRoleBinding(ctx, roleBinding2)

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not authenticate user with wrong audience", func() {
			idp, err := mockidp.NewIdentityServer("mytestserver", 1)
			Expect(err).NotTo(HaveOccurred())
			err = idp.Start()
			Expect(err).NotTo(HaveOccurred())

			prefix := "customprefix:"
			provider := defaultOIDCProvider()
			provider.Spec.IssuerURL = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			provider.Spec.CABundle = idp.CA()
			provider.Spec.UsernamePrefix = &prefix

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			claims["aud"] = "invalid"

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			makeAPIServerRequestAndExpectCode(token, http.StatusUnauthorized)

			err = idp.Stop(ctx)
			Expect(err).NotTo(HaveOccurred())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should correctly authenticate and authorize user with valid token from idp which is registered multiple times with different client ids", func() {
			idp, err := mockidp.NewIdentityServer("mytestserver", 1)
			Expect(err).NotTo(HaveOccurred())
			err = idp.Start()
			Expect(err).NotTo(HaveOccurred())

			prefix := "customprefix:"
			provider := defaultOIDCProvider()
			provider.Spec.IssuerURL = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			provider.Spec.CABundle = idp.CA()
			provider.Spec.UsernamePrefix = &prefix
			provider.Spec.ClientID = "123"

			prefix1 := "customprefix1:"
			provider1 := defaultOIDCProvider()
			provider1.Spec.IssuerURL = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			provider1.Spec.CABundle = idp.CA()
			provider1.Spec.UsernamePrefix = &prefix1
			provider1.Spec.ClientID = "456"

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)
			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider1)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			claims["aud"] = "123"

			// matches the first oidc resource - should authenticate but not authorize
			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			roleBinding := createRoleBindingForUser(ctx, defaultNamespaceName, podReaderRoleName, prefix1+user)
			makeAPIServerRequestAndExpectCode(token, http.StatusForbidden)

			// matches the second oidc resource - should authenticate and authorize
			claims["aud"] = "456"
			token, err = idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			makeAPIServerRequestAndExpectCode(token, http.StatusOK)

			err = idp.Stop(ctx)
			Expect(err).NotTo(HaveOccurred())

			deleteRoleBinding(ctx, roleBinding)
			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

	})

	Context("Authenticating user against the webhook authenticator via token from a trusted identity provider", func() {
		const (
			serverName = "test-server"
		)
		var (
			makeTokenReviewRequest = func(apiserverToken, userToken string, ca []byte, expectToAuthenticate bool) *authenticationv1.TokenReview {
				caCertPool := x509.NewCertPool()
				caCertPool.AppendCertsFromPEM(ca)

				review := &authenticationv1.TokenReview{
					Spec: authenticationv1.TokenReviewSpec{
						Token: userToken,
					},
				}
				tr := &http.Transport{
					TLSClientConfig: &tls.Config{RootCAs: caCertPool},
				}
				client := &http.Client{Transport: tr}
				body, err := json.Marshal(review)
				Expect(err).NotTo(HaveOccurred())
				req, err := http.NewRequest("POST", "https://localhost:10443/validate-token", bytes.NewReader(body))
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", apiserverToken))

				reviewResponse := &authenticationv1.TokenReview{}
				Eventually(func() bool {
					res, err := client.Do(req)
					Expect(err).NotTo(HaveOccurred())

					responseBytes, err := ioutil.ReadAll(res.Body)
					Expect(err).NotTo(HaveOccurred())

					err = json.Unmarshal(responseBytes, reviewResponse)
					Expect(err).NotTo(HaveOccurred())

					if expectToAuthenticate {
						return reviewResponse.Status.Authenticated
					}

					// do not retry the request
					return true
				}, timeout, interval).Should(BeTrue())
				return reviewResponse
			}
		)

		It("Should authenticate token with default prefixes for group and user", func() {
			idp, err := mockidp.NewIdentityServer(serverName, 1)
			Expect(err).NotTo(HaveOccurred())
			err = idp.Start()
			Expect(err).NotTo(HaveOccurred())

			provider := defaultOIDCProvider()
			provider.Spec.IssuerURL = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			provider.Spec.CABundle = idp.CA()

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["groups"] = []string{"employee", "admin"}
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			review := makeTokenReviewRequest(apiserverToken, token, testEnv.OIDCServerCA(), true)

			Expect(review.Status.Authenticated).To(BeTrue())
			Expect(review.Status.User.Username).To(Equal(fmt.Sprintf("%s/%s", provider.Name, user)))
			Expect(review.Status.User.Groups).To(ConsistOf(fmt.Sprintf("%s/%s", provider.Name, "admin"), fmt.Sprintf("%s/%s", provider.Name, "employee")))

			err = idp.Stop(ctx)
			Expect(err).NotTo(HaveOccurred())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should authenticate token with custom prefixes for group and user", func() {
			idp, err := mockidp.NewIdentityServer(serverName, 1)
			Expect(err).NotTo(HaveOccurred())
			err = idp.Start()
			Expect(err).NotTo(HaveOccurred())

			userPrefix := "usr:"
			groupsPrefix := "gr:"
			provider := defaultOIDCProvider()
			provider.Spec.IssuerURL = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			provider.Spec.CABundle = idp.CA()
			provider.Spec.UsernamePrefix = &userPrefix
			provider.Spec.GroupsPrefix = &groupsPrefix

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["groups"] = []string{"admin", "employee"}
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			review := makeTokenReviewRequest(apiserverToken, token, testEnv.OIDCServerCA(), true)

			Expect(review.Status.Authenticated).To(BeTrue())
			Expect(review.Status.User.Username).To(Equal(userPrefix + user))
			Expect(review.Status.User.Groups).To(ConsistOf(groupsPrefix+"admin", groupsPrefix+"employee"))

			err = idp.Stop(ctx)
			Expect(err).NotTo(HaveOccurred())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should authenticate token but not return any groups for user", func() {
			idp, err := mockidp.NewIdentityServer(serverName, 1)
			Expect(err).NotTo(HaveOccurred())
			err = idp.Start()
			Expect(err).NotTo(HaveOccurred())

			userPrefix := "usr:"
			groupsPrefix := "gr:"
			groupsClaim := "custom-groups"
			provider := defaultOIDCProvider()
			provider.Spec.IssuerURL = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			provider.Spec.CABundle = idp.CA()
			provider.Spec.GroupsClaim = &groupsClaim
			provider.Spec.UsernamePrefix = &userPrefix
			provider.Spec.GroupsPrefix = &groupsPrefix

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["groups"] = []string{"admin"}
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			review := makeTokenReviewRequest(apiserverToken, token, testEnv.OIDCServerCA(), true)

			Expect(review.Status.Authenticated).To(BeTrue())
			Expect(review.Status.User.Username).To(Equal(userPrefix + user))
			Expect(review.Status.User.Groups).To(BeEmpty())

			err = idp.Stop(ctx)
			Expect(err).NotTo(HaveOccurred())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should authenticate token and return correct user and groups", func() {
			idp, err := mockidp.NewIdentityServer(serverName, 1)
			Expect(err).NotTo(HaveOccurred())
			err = idp.Start()
			Expect(err).NotTo(HaveOccurred())

			userPrefix := "usr:"
			userClaim := "custom-sub"
			groupsPrefix := "gr:"
			groupsClaim := "custom-groups"
			provider := defaultOIDCProvider()
			provider.Spec.IssuerURL = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			provider.Spec.CABundle = idp.CA()
			provider.Spec.UsernameClaim = &userClaim
			provider.Spec.GroupsClaim = &groupsClaim
			provider.Spec.UsernamePrefix = &userPrefix
			provider.Spec.GroupsPrefix = &groupsPrefix

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			realUser := "this-is-my-real-identity"
			realGroups := []string{"real-admin"}
			claims := defaultClaims()
			claims["sub"] = user
			claims["groups"] = []string{"admin"}
			claims[groupsClaim] = realGroups
			claims[userClaim] = realUser
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			review := makeTokenReviewRequest(apiserverToken, token, testEnv.OIDCServerCA(), true)

			Expect(review.Status.Authenticated).To(BeTrue())
			Expect(review.Status.User.Username).To(Equal(userPrefix + realUser))

			prefixedGroups := []string{}
			for _, v := range realGroups {
				prefixedGroups = append(prefixedGroups, groupsPrefix+v)
			}
			Expect(review.Status.User.Groups).To(ConsistOf(prefixedGroups))

			err = idp.Stop(ctx)
			Expect(err).NotTo(HaveOccurred())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not authenticate users prefixed with `system:`", func() {
			idp, err := mockidp.NewIdentityServer(serverName, 1)
			Expect(err).NotTo(HaveOccurred())
			err = idp.Start()
			Expect(err).NotTo(HaveOccurred())

			userPrefix := "system:"
			userClaim := "custom-sub"
			provider := defaultOIDCProvider()
			provider.Spec.IssuerURL = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			provider.Spec.CABundle = idp.CA()
			provider.Spec.UsernameClaim = &userClaim
			provider.Spec.UsernamePrefix = &userPrefix

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims[userClaim] = user
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			review := makeTokenReviewRequest(apiserverToken, token, testEnv.OIDCServerCA(), false)

			Expect(review.Status.Authenticated).To(BeFalse())
			Expect(review.Status.User.Username).To(BeEmpty())
			Expect(review.Status.User.Groups).To(BeEmpty())

			err = idp.Stop(ctx)
			Expect(err).NotTo(HaveOccurred())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not authenticate users prefixed with `system:` when user prefixing is disabled", func() {
			idp, err := mockidp.NewIdentityServer(serverName, 1)
			Expect(err).NotTo(HaveOccurred())
			err = idp.Start()
			Expect(err).NotTo(HaveOccurred())

			userPrefix := "-"
			userClaim := "custom-sub"
			provider := defaultOIDCProvider()
			provider.Spec.IssuerURL = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			provider.Spec.CABundle = idp.CA()
			provider.Spec.UsernameClaim = &userClaim
			provider.Spec.UsernamePrefix = &userPrefix

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "system:this-is-my-identity"
			claims := defaultClaims()
			claims[userClaim] = user
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			review := makeTokenReviewRequest(apiserverToken, token, testEnv.OIDCServerCA(), false)

			Expect(review.Status.Authenticated).To(BeFalse())
			Expect(review.Status.User.Username).To(BeEmpty())
			Expect(review.Status.User.Groups).To(BeEmpty())

			err = idp.Stop(ctx)
			Expect(err).NotTo(HaveOccurred())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not return groups prefixed with `system:`", func() {
			idp, err := mockidp.NewIdentityServer(serverName, 1)
			Expect(err).NotTo(HaveOccurred())
			err = idp.Start()
			Expect(err).NotTo(HaveOccurred())

			userPrefix := "userpref:"
			userClaim := "custom-sub"
			groupsPrefix := "system:"
			groupsClaim := "custom-groups"
			provider := defaultOIDCProvider()
			provider.Spec.IssuerURL = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			provider.Spec.CABundle = idp.CA()
			provider.Spec.UsernameClaim = &userClaim
			provider.Spec.UsernamePrefix = &userPrefix
			provider.Spec.GroupsClaim = &groupsClaim
			provider.Spec.GroupsPrefix = &groupsPrefix

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims[userClaim] = user
			claims[groupsClaim] = []string{"admin", "master"}
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			review := makeTokenReviewRequest(apiserverToken, token, testEnv.OIDCServerCA(), true)

			Expect(review.Status.Authenticated).To(BeTrue())
			Expect(review.Status.User.Username).To(Equal(userPrefix + user))
			Expect(review.Status.User.Groups).To(BeEmpty())

			err = idp.Stop(ctx)
			Expect(err).NotTo(HaveOccurred())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not return groups prefixed with `system:` when group prefixing is disabled", func() {
			idp, err := mockidp.NewIdentityServer(serverName, 1)
			Expect(err).NotTo(HaveOccurred())
			err = idp.Start()
			Expect(err).NotTo(HaveOccurred())

			userPrefix := "userpref:"
			userClaim := "custom-sub"
			groupsPrefix := "-"
			groupsClaim := "custom-groups"
			provider := defaultOIDCProvider()
			provider.Spec.IssuerURL = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			provider.Spec.CABundle = idp.CA()
			provider.Spec.UsernameClaim = &userClaim
			provider.Spec.UsernamePrefix = &userPrefix
			provider.Spec.GroupsClaim = &groupsClaim
			provider.Spec.GroupsPrefix = &groupsPrefix

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims[userClaim] = user
			claims[groupsClaim] = []string{"admin", "system:master"}
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			review := makeTokenReviewRequest(apiserverToken, token, testEnv.OIDCServerCA(), true)

			Expect(review.Status.Authenticated).To(BeTrue())
			Expect(review.Status.User.Username).To(Equal(userPrefix + user))
			Expect(review.Status.User.Groups).To(ConsistOf([]string{"admin"}))

			err = idp.Stop(ctx)
			Expect(err).NotTo(HaveOccurred())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not authenticate user if username claim is missing", func() {
			idp, err := mockidp.NewIdentityServer(serverName, 1)
			Expect(err).NotTo(HaveOccurred())
			err = idp.Start()
			Expect(err).NotTo(HaveOccurred())

			userPrefix := "userpref:"
			userClaim := "custom-sub"
			groupsPrefix := "grouppref:"
			groupsClaim := "custom-groups"
			provider := defaultOIDCProvider()
			provider.Spec.IssuerURL = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			provider.Spec.CABundle = idp.CA()
			provider.Spec.UsernameClaim = &userClaim
			provider.Spec.UsernamePrefix = &userPrefix
			provider.Spec.GroupsClaim = &groupsClaim
			provider.Spec.GroupsPrefix = &groupsPrefix

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims[userClaim+"invalid"] = user
			claims[groupsClaim] = []string{"admin"}
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			review := makeTokenReviewRequest(apiserverToken, token, testEnv.OIDCServerCA(), false)

			Expect(review.Status.Authenticated).To(BeFalse())
			Expect(review.Status.User.Username).To(BeEmpty())
			Expect(review.Status.User.Groups).To(BeEmpty())

			err = idp.Stop(ctx)
			Expect(err).NotTo(HaveOccurred())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not authenticate user if audience claim is wrong", func() {
			idp, err := mockidp.NewIdentityServer(serverName, 1)
			Expect(err).NotTo(HaveOccurred())
			err = idp.Start()
			Expect(err).NotTo(HaveOccurred())

			userPrefix := "userpref:"
			userClaim := "custom-sub"
			groupsPrefix := "grouppref:"
			groupsClaim := "custom-groups"
			provider := defaultOIDCProvider()
			provider.Spec.IssuerURL = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			provider.Spec.CABundle = idp.CA()
			provider.Spec.UsernameClaim = &userClaim
			provider.Spec.UsernamePrefix = &userPrefix
			provider.Spec.GroupsClaim = &groupsClaim
			provider.Spec.GroupsPrefix = &groupsPrefix

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims[userClaim] = user
			claims[groupsClaim] = []string{"admin"}
			claims["aud"] = "invalid"
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			review := makeTokenReviewRequest(apiserverToken, token, testEnv.OIDCServerCA(), false)

			Expect(review.Status.Authenticated).To(BeFalse())
			Expect(review.Status.User.Username).To(BeEmpty())
			Expect(review.Status.User.Groups).To(BeEmpty())

			err = idp.Stop(ctx)
			Expect(err).NotTo(HaveOccurred())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should authenticate user against the target audience", func() {
			idp, err := mockidp.NewIdentityServer(serverName, 1)
			Expect(err).NotTo(HaveOccurred())
			err = idp.Start()
			Expect(err).NotTo(HaveOccurred())

			userPrefix1 := "userpref1:"
			userPrefix2 := "userpref2:"
			userClaim := "custom-sub"
			groupsPrefix1 := "grouppref1:"
			groupsPrefix2 := "grouppref2:"
			groupsClaim := "custom-groups"
			provider1 := defaultOIDCProvider()
			provider1.Spec.IssuerURL = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			provider1.Spec.CABundle = idp.CA()
			provider1.Spec.UsernameClaim = &userClaim
			provider1.Spec.UsernamePrefix = &userPrefix1
			provider1.Spec.GroupsClaim = &groupsClaim
			provider1.Spec.GroupsPrefix = &groupsPrefix1
			provider1.Spec.ClientID = "client1"

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider1)

			provider2 := defaultOIDCProvider()
			provider2.Spec.IssuerURL = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			provider2.Spec.CABundle = idp.CA()
			provider2.Spec.UsernameClaim = &userClaim
			provider2.Spec.UsernamePrefix = &userPrefix2
			provider2.Spec.GroupsClaim = &groupsClaim
			provider2.Spec.GroupsPrefix = &groupsPrefix2
			provider2.Spec.ClientID = "client2"

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider2)

			user := "this-is-my-identity"
			claims1 := defaultClaims()
			claims1[userClaim] = user
			claims1[groupsClaim] = []string{"admin"}
			claims1["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			claims1["aud"] = "client1"

			token1, err := idp.Sign(0, claims1)
			Expect(err).NotTo(HaveOccurred())

			claims2 := defaultClaims()
			claims2[userClaim] = user
			claims2[groupsClaim] = []string{"admin"}
			claims2["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			claims2["aud"] = "client2"

			token2, err := idp.Sign(0, claims2)
			Expect(err).NotTo(HaveOccurred())

			review1 := makeTokenReviewRequest(apiserverToken, token1, testEnv.OIDCServerCA(), true)

			Expect(review1.Status.Authenticated).To(BeTrue())
			Expect(review1.Status.User.Username).To(Equal(userPrefix1 + user))
			Expect(review1.Status.User.Groups).To(ConsistOf(groupsPrefix1 + "admin"))

			review2 := makeTokenReviewRequest(apiserverToken, token2, testEnv.OIDCServerCA(), true)

			Expect(review2.Status.Authenticated).To(BeTrue())
			Expect(review2.Status.User.Username).To(Equal(userPrefix2 + user))
			Expect(review2.Status.User.Groups).To(ConsistOf(groupsPrefix2 + "admin"))

			err = idp.Stop(ctx)
			Expect(err).NotTo(HaveOccurred())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider1)
			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider2)
		})
	})
})

func waitForOIDCResourceToBeCreated(ctx context.Context, k8sClient client.Client, oidc *authenticationv1alpha1.OpenIDConnect) {
	err := k8sClient.Create(ctx, oidc)
	Expect(err).NotTo(HaveOccurred())

	openidconnectLookupKey := client.ObjectKeyFromObject(oidc)

	Eventually(func() bool {
		err := k8sClient.Get(ctx, openidconnectLookupKey, oidc)
		return err == nil
	}, timeout, interval).Should(BeTrue())
}

func waitForOIDCResourceToBeDeleted(ctx context.Context, k8sClient client.Client, oidc *authenticationv1alpha1.OpenIDConnect) {
	err := k8sClient.Delete(ctx, oidc)
	Expect(err).NotTo(HaveOccurred())

	openidconnectLookupKey := client.ObjectKeyFromObject(oidc)
	createdOpenIDConnect := &authenticationv1alpha1.OpenIDConnect{}

	Eventually(func() bool {
		err := k8sClient.Get(ctx, openidconnectLookupKey, createdOpenIDConnect)
		return apierrors.IsNotFound(err)
	}, timeout, interval).Should(BeTrue())
}

func defaultOIDCProvider() *authenticationv1alpha1.OpenIDConnect {
	name := rand.String(5)
	return &authenticationv1alpha1.OpenIDConnect{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "authentication.gardener.cloud/v1alpha1",
			Kind:       "OpenIDConnect",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: authenticationv1alpha1.OIDCAuthenticationSpec{
			ClientID: "my-idp-provider",
			JWKS:     authenticationv1alpha1.JWKSSpec{},
		},
	}
}

func defaultClaims() map[string]interface{} {
	return map[string]interface{}{
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute * 15).Unix(),
		"aud": "my-idp-provider",
	}
}
