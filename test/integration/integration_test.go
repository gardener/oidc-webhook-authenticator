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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	authenticationv1 "k8s.io/api/authentication/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/utils/ptr"
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
		stopIDP            = func(ctx context.Context, idp *mockidp.OIDCIdentityServer) {
			err := idp.Stop(ctx)
			Expect(err).NotTo(HaveOccurred())
		}

		createAndStartIDPServer = func(numberOfSigningKeys int) *mockidp.OIDCIdentityServer {
			idp, err := mockidp.NewIdentityServer(rand.String(10), numberOfSigningKeys)
			Expect(err).NotTo(HaveOccurred())
			err = idp.Start()
			Expect(err).NotTo(HaveOccurred())
			return idp
		}
	)

	Context("Creating an openid resource", func() {
		It("A new OpenIDConnect controller resource is successfully created", func() {
			usernameClaim := "subject"
			usernamePrefix := "user-pref:"
			groupsClaim := "groups"
			groupsPrefix := "groups-pref:"
			openidconnect := &authenticationv1alpha1.OpenIDConnect{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-oidc",
					Namespace: "default",
				},
				Spec: authenticationv1alpha1.OIDCAuthenticationSpec{
					IssuerURL:      "https://localhost:1234",
					ClientID:       "some-client-id",
					UsernameClaim:  &usernameClaim,
					UsernamePrefix: &usernamePrefix,
					GroupsClaim:    &groupsClaim,
					GroupsPrefix:   &groupsPrefix,
				},
			}

			Expect(k8sClient.Create(ctx, openidconnect)).To(Succeed())
			createdOIDC := &authenticationv1alpha1.OpenIDConnect{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-oidc",
					Namespace: "default",
				},
			}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, client.ObjectKeyFromObject(createdOIDC), createdOIDC)
				return err == nil
			}, timeout, interval).Should(BeTrue())

			Expect(createdOIDC.Spec.IssuerURL).To(Equal(openidconnect.Spec.IssuerURL))
			Expect(createdOIDC.Spec.ClientID).To(Equal(openidconnect.Spec.ClientID))
			Expect(createdOIDC.Spec.UsernameClaim).To(Equal(openidconnect.Spec.UsernameClaim))
			Expect(createdOIDC.Spec.UsernamePrefix).To(Equal(openidconnect.Spec.UsernamePrefix))
			Expect(createdOIDC.Spec.GroupsClaim).To(Equal(openidconnect.Spec.GroupsClaim))
			Expect(createdOIDC.Spec.GroupsPrefix).To(Equal(openidconnect.Spec.GroupsPrefix))

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, createdOIDC)
		})
	})

	Context("Authenticating user to the kube-apiserver via token from a trusted identity provider", func() {
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

		ensureRoleBindingIsDeleted := func(ctx context.Context, roleBinding *rbacv1.RoleBinding) {
			err := clientset.RbacV1().RoleBindings(roleBinding.Namespace).Delete(ctx, roleBinding.Name, metav1.DeleteOptions{})
			if err != nil {
				Expect(apierrors.IsNotFound(err)).To(BeTrue())
			}
		}

		makeAPIServerRequestAndExpectCode := func(userToken string, expectedStatusCode int) {
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec
				},
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
			idp := createAndStartIDPServer(2)
			defer stopIDP(ctx, idp)

			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
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

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should authenticate but not authorize user with a single registered identity provider and static jwks", func() {
			idp := createAndStartIDPServer(2)
			keys, err := idp.PublicKeySetAsBytes()
			Expect(err).NotTo(HaveOccurred())

			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), nil)
			provider.Name = "static"
			provider.Spec.JWKS.Keys = keys

			// stop the idp server so that we ensure that the keys will not be fetched over the network
			stopIDP(ctx, idp)

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
			idp := createAndStartIDPServer(2)
			defer stopIDP(ctx, idp)

			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			signedTokenWithFirstKey, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			roleBinding := createRoleBindingForUser(ctx, defaultNamespaceName, podReaderRoleName, fmt.Sprintf("%s/%s", provider.Name, user))
			defer ensureRoleBindingIsDeleted(ctx, roleBinding)

			makeAPIServerRequestAndExpectCode(signedTokenWithFirstKey, http.StatusOK)

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should authenticate and authorize user with two registered identity providers", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			idp1 := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp1)

			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
			provider.Spec.UsernameClaim = &emailUserNameClaim

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			provider1 := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp1.ServerSecurePort), idp1.CA())
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
			defer ensureRoleBindingIsDeleted(ctx, roleBinding)

			makeAPIServerRequestAndExpectCode(signedTokenFromSecondIDP, http.StatusOK)

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider1)
		})

		It("Should not authenticate user because of missing required claim", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
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

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should authenticate user with required claim", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
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

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not authenticate user because of wrong issuer", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["iss"] = fmt.Sprintf("https://invalid:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			makeAPIServerRequestAndExpectCode(token, http.StatusUnauthorized)

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not authenticate user because of wrong audience", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			claims["aud"] = "invalid"

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			makeAPIServerRequestAndExpectCode(token, http.StatusUnauthorized)

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not authenticate user because of expired token", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			claims["exp"] = time.Now().Add(time.Minute * -10).Unix()

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			makeAPIServerRequestAndExpectCode(token, http.StatusUnauthorized)

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should authenticate and authorize user with custom prefix", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			prefix := "customprefix:"
			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
			provider.Spec.UsernamePrefix = &prefix

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			roleBinding := createRoleBindingForUser(ctx, defaultNamespaceName, podReaderRoleName, prefix+user)
			defer ensureRoleBindingIsDeleted(ctx, roleBinding)

			makeAPIServerRequestAndExpectCode(token, http.StatusOK)

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		DescribeTable("Should authenticate and authorize user with custom prefix for group",
			func(groups []string, allowedGroup string) {
				idp := createAndStartIDPServer(1)
				defer stopIDP(ctx, idp)

				usernamePrefix := "customprefix:"
				groupNamePrefix := "grprefix:"
				provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
				provider.Spec.UsernamePrefix = &usernamePrefix
				provider.Spec.GroupsPrefix = &groupNamePrefix

				waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

				user := "this-is-my-identity"
				claims := defaultClaims()
				claims["sub"] = user
				claims["groups"] = groups
				claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

				token, err := idp.Sign(0, claims)
				Expect(err).NotTo(HaveOccurred())

				roleBinding := createRoleBindingForGroup(ctx, defaultNamespaceName, podReaderRoleName, groupNamePrefix+allowedGroup)
				defer ensureRoleBindingIsDeleted(ctx, roleBinding)

				makeAPIServerRequestAndExpectCode(token, http.StatusOK)

				waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
			},

			Entry("Authorize the first group", []string{"podreader1", "podreader2"}, "podreader1"),
			Entry("Authorize the second group", []string{"podreader1", "podreader2"}, "podreader2"),
		)

		It("Should not authenticate user with wrong audience", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			prefix := "customprefix:"
			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
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

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should correctly authenticate and authorize user with valid token from idp which is registered multiple times with different client ids", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			prefix := "customprefix:"
			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
			provider.Spec.UsernamePrefix = &prefix
			provider.Spec.ClientID = "123"

			prefix1 := "customprefix1:"
			provider1 := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
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
			defer ensureRoleBindingIsDeleted(ctx, roleBinding)

			makeAPIServerRequestAndExpectCode(token, http.StatusForbidden)

			// matches the second oidc resource - should authenticate and authorize
			claims["aud"] = "456"
			token, err = idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			makeAPIServerRequestAndExpectCode(token, http.StatusOK)

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

	})

	Context("Authenticating user against the webhook authenticator via token from a trusted identity provider", func() {
		var (
			makeTokenReviewRequest = func(userToken string, ca []byte, expectToAuthenticate bool) *authenticationv1.TokenReview {
				caCertPool := x509.NewCertPool()
				caCertPool.AppendCertsFromPEM(ca)

				review := &authenticationv1.TokenReview{
					Spec: authenticationv1.TokenReviewSpec{
						Token: userToken,
					},
				}

				tr := &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs:    caCertPool,
						MinVersion: tls.VersionTLS12,
						Certificates: []tls.Certificate{
							authWebhookClientCert,
						}},
				}
				client := &http.Client{Transport: tr}
				body, err := json.Marshal(review)
				Expect(err).NotTo(HaveOccurred())
				req, err := http.NewRequest("POST", "https://localhost:10443/validate-token", bytes.NewReader(body))
				Expect(err).NotTo(HaveOccurred())

				reviewResponse := &authenticationv1.TokenReview{}
				if expectToAuthenticate {
					Eventually(func() bool {
						res, err := client.Do(req)
						Expect(err).NotTo(HaveOccurred())

						// expect that the webhook returns a 200 response
						Expect(res.StatusCode).To(Equal(http.StatusOK))

						responseBytes, err := io.ReadAll(res.Body)
						Expect(err).NotTo(HaveOccurred())

						err = json.Unmarshal(responseBytes, reviewResponse)
						Expect(err).NotTo(HaveOccurred())

						return reviewResponse.Status.Authenticated
					}, timeout, interval).Should(BeTrue())
				} else {
					// we want to request the endpoint multiple times and always get not authenticated
					// TODO: this can be fixed after https://github.com/gardener/oidc-webhook-authenticator/issues/79 is implemented
					// after the enhancement is implemented the observedGeneration field can be used to sync the reconciliation
					// and the retries will not be needed
					for i := 0; i < 10; i++ {
						res, err := client.Do(req)
						Expect(err).NotTo(HaveOccurred())

						// expect that the webhook returns a 200 response
						Expect(res.StatusCode).To(Equal(http.StatusOK))

						responseBytes, err := io.ReadAll(res.Body)
						Expect(err).NotTo(HaveOccurred())

						err = json.Unmarshal(responseBytes, reviewResponse)
						Expect(err).NotTo(HaveOccurred())

						Expect(reviewResponse.Status.Authenticated).To(BeFalse())
						// wait one second to query again
						time.Sleep(time.Second)
					}
				}

				return reviewResponse
			}
		)

		It("Should not allow anonymous request to /validate-token endpoint of the authenticator", func() {
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(testEnv.OIDCServerCA())

			review := &authenticationv1.TokenReview{
				Spec: authenticationv1.TokenReviewSpec{
					Token: "foo",
				},
			}

			tr := &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    caCertPool,
					MinVersion: tls.VersionTLS12,
				},
			}
			client := &http.Client{Transport: tr}
			body, err := json.Marshal(review)
			Expect(err).NotTo(HaveOccurred())
			req, err := http.NewRequest("POST", "https://localhost:10443/validate-token", bytes.NewReader(body))
			Expect(err).NotTo(HaveOccurred())

			res, err := client.Do(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.StatusCode).To(Equal(http.StatusUnauthorized))
			responseBytes, err := io.ReadAll(res.Body)
			Expect(err).NotTo(HaveOccurred())

			Expect(responseBytes).To(Equal([]byte(`{"code":401,"message":"unauthorized"}`)))
		})

		It("Should allow anonymous request to /healthz endpoint of the authenticator", func() {
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(testEnv.OIDCServerCA())
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    caCertPool,
					MinVersion: tls.VersionTLS12,
				},
			}
			client := &http.Client{Transport: tr}
			req, err := http.NewRequest("GET", "https://localhost:10443/healthz", nil)
			Expect(err).NotTo(HaveOccurred())

			res, err := client.Do(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.StatusCode).To(Equal(http.StatusOK))
			responseBytes, err := io.ReadAll(res.Body)
			Expect(err).NotTo(HaveOccurred())

			Expect(responseBytes).To(Equal([]byte(`{"code":200,"message":"ok"}`)))
		})

		It("Should authenticate token with default prefixes for group and user", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["groups"] = []string{"employee", "admin"}
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), true)

			Expect(review.Status.Authenticated).To(BeTrue())
			Expect(review.Status.User.Username).To(Equal(fmt.Sprintf("%s/%s", provider.Name, user)))
			Expect(review.Status.User.Groups).To(ConsistOf(fmt.Sprintf("%s/%s", provider.Name, "admin"), fmt.Sprintf("%s/%s", provider.Name, "employee")))

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should authenticate tokens signed by different keys from the same identity provider (verified remotely)", func() {
			idp := createAndStartIDPServer(3)
			defer stopIDP(ctx, idp)

			userPrefix := "usr:"
			groupsPrefix := "gr:"
			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
			provider.Spec.UsernamePrefix = &userPrefix
			provider.Spec.GroupsPrefix = &groupsPrefix

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["groups"] = []string{"admin", "employee"}
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			signAndRequest := func(signingKeyIndex int) {
				token, err := idp.Sign(signingKeyIndex, claims)
				Expect(err).NotTo(HaveOccurred())

				review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), true)

				Expect(review.Status.Authenticated).To(BeTrue())
				Expect(review.Status.User.Username).To(Equal(userPrefix + user))
				Expect(review.Status.User.Groups).To(ConsistOf(groupsPrefix+"admin", groupsPrefix+"employee"))
			}

			signAndRequest(0)
			signAndRequest(2)
			signAndRequest(1)

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should authenticate tokens signed by different keys from the same identity provider (verified offline)", func() {
			idp := createAndStartIDPServer(3)
			keys, err := idp.PublicKeySetAsBytes()
			Expect(err).NotTo(HaveOccurred())
			// stop the server to ensure that the tokens will not be verified remotely
			stopIDP(ctx, idp)

			userPrefix := "usr:"
			groupsPrefix := "gr:"
			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
			provider.Spec.UsernamePrefix = &userPrefix
			provider.Spec.GroupsPrefix = &groupsPrefix
			provider.Spec.JWKS.Keys = keys

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["groups"] = []string{"admin", "employee"}
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			signAndRequest := func(signingKeyIndex int) {
				token, err := idp.Sign(signingKeyIndex, claims)
				Expect(err).NotTo(HaveOccurred())

				review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), true)

				Expect(review.Status.Authenticated).To(BeTrue())
				Expect(review.Status.User.Username).To(Equal(userPrefix + user))
				Expect(review.Status.User.Groups).To(ConsistOf(groupsPrefix+"admin", groupsPrefix+"employee"))
			}

			signAndRequest(1)
			signAndRequest(2)
			signAndRequest(0)

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not authenticate tokens signed by untrusted identity provider (verified offline)", func() {
			idp := createAndStartIDPServer(3)
			keys, err := idp.PublicKeySetAsBytes()
			Expect(err).NotTo(HaveOccurred())
			// stop the server to ensure that the tokens will not be verified remotely
			stopIDP(ctx, idp)
			idp1 := createAndStartIDPServer(2)
			defer stopIDP(ctx, idp1)

			userPrefix := "usr:"
			groupsPrefix := "gr:"
			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
			provider.Spec.UsernamePrefix = &userPrefix
			provider.Spec.GroupsPrefix = &groupsPrefix
			provider.Spec.JWKS.Keys = keys

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["groups"] = []string{"admin", "employee"}
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			signByTrustedIDPAndRequest := func(signingKeyIndex int) {
				token, err := idp.Sign(signingKeyIndex, claims)
				Expect(err).NotTo(HaveOccurred())

				review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), true)

				Expect(review.Status.Authenticated).To(BeTrue())
				Expect(review.Status.User.Username).To(Equal(userPrefix + user))
				Expect(review.Status.User.Groups).To(ConsistOf(groupsPrefix+"admin", groupsPrefix+"employee"))
			}

			signByUntrustedIDPAndRequest := func(signingKeyIndex int) {
				// sign the claims by the untrusted identity provider
				// the verification should fail
				token, err := idp1.Sign(signingKeyIndex, claims)
				Expect(err).NotTo(HaveOccurred())

				review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), false)

				Expect(review.Status.Authenticated).To(BeFalse())
				Expect(review.Status.User.Username).To(BeEmpty())
				Expect(review.Status.User.Groups).To(BeEmpty())
			}

			// verification passes so the oidc resources is already reconciled by the oidc-webhook-authenticator
			signByTrustedIDPAndRequest(1)

			signByUntrustedIDPAndRequest(0)
			signByUntrustedIDPAndRequest(1)

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should authenticate token with custom prefixes for group and user", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			userPrefix := "usr:"
			groupsPrefix := "gr:"
			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
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

			review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), true)

			Expect(review.Status.Authenticated).To(BeTrue())
			Expect(review.Status.User.Username).To(Equal(userPrefix + user))
			Expect(review.Status.User.Groups).To(ConsistOf(groupsPrefix+"admin", groupsPrefix+"employee"))

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should authenticate token but not return any groups for user", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			userPrefix := "usr:"
			groupsPrefix := "gr:"
			groupsClaim := "custom-groups"
			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
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

			review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), true)

			Expect(review.Status.Authenticated).To(BeTrue())
			Expect(review.Status.User.Username).To(Equal(userPrefix + user))
			Expect(review.Status.User.Groups).To(BeEmpty())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should authenticate token and return correct user and groups", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			userPrefix := "usr:"
			userClaim := "custom-sub"
			groupsPrefix := "gr:"
			groupsClaim := "custom-groups"
			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
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

			review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), true)

			Expect(review.Status.Authenticated).To(BeTrue())
			Expect(review.Status.User.Username).To(Equal(userPrefix + realUser))

			prefixedGroups := []string{}
			for _, v := range realGroups {
				prefixedGroups = append(prefixedGroups, groupsPrefix+v)
			}
			Expect(review.Status.User.Groups).To(ConsistOf(prefixedGroups))

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not authenticate users prefixed with `system:`", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			userPrefix := "system:"
			userClaim := "custom-sub"
			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
			provider.Spec.UsernameClaim = &userClaim
			provider.Spec.UsernamePrefix = &userPrefix

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims[userClaim] = user
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), false)

			Expect(review.Status.Authenticated).To(BeFalse())
			Expect(review.Status.User.Username).To(BeEmpty())
			Expect(review.Status.User.Groups).To(BeEmpty())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not authenticate users prefixed with `system:` when user prefixing is disabled", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			userPrefix := "-"
			userClaim := "custom-sub"
			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
			provider.Spec.UsernameClaim = &userClaim
			provider.Spec.UsernamePrefix = &userPrefix

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "system:this-is-my-identity"
			claims := defaultClaims()
			claims[userClaim] = user
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), false)

			Expect(review.Status.Authenticated).To(BeFalse())
			Expect(review.Status.User.Username).To(BeEmpty())
			Expect(review.Status.User.Groups).To(BeEmpty())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not return groups prefixed with `system:`", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			userPrefix := "userpref:"
			userClaim := "custom-sub"
			groupsPrefix := "system:"
			groupsClaim := "custom-groups"
			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
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

			review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), true)

			Expect(review.Status.Authenticated).To(BeTrue())
			Expect(review.Status.User.Username).To(Equal(userPrefix + user))
			Expect(review.Status.User.Groups).To(BeEmpty())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not return groups prefixed with `system:` when group prefixing is disabled", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			userPrefix := "userpref:"
			userClaim := "custom-sub"
			groupsPrefix := "-"
			groupsClaim := "custom-groups"
			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
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

			review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), true)

			Expect(review.Status.Authenticated).To(BeTrue())
			Expect(review.Status.User.Username).To(Equal(userPrefix + user))
			Expect(review.Status.User.Groups).To(ConsistOf([]string{"admin"}))

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should return prefixed user when userPrefix is empty string", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			userPrefix := ""
			userClaim := "custom-sub"
			groupsPrefix := "groupspref:"
			groupsClaim := "custom-groups"
			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
			provider.Spec.UsernameClaim = &userClaim
			provider.Spec.UsernamePrefix = &userPrefix
			provider.Spec.GroupsClaim = &groupsClaim
			provider.Spec.GroupsPrefix = &groupsPrefix

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims[userClaim] = user
			claims[groupsClaim] = []string{"admin", "dev"}
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), true)

			Expect(review.Status.Authenticated).To(BeTrue())
			Expect(review.Status.User.Username).To(Equal(fmt.Sprintf("%s/%s", provider.Name, user)))
			Expect(review.Status.User.Groups).To(ConsistOf([]string{groupsPrefix + "admin", groupsPrefix + "dev"}))

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should return prefixed user when userPrefix is empty string (offline)", func() {
			idp := createAndStartIDPServer(1)
			keys, err := idp.PublicKeySetAsBytes()
			Expect(err).NotTo(HaveOccurred())
			stopIDP(ctx, idp)

			userPrefix := ""
			userClaim := "custom-sub"
			groupsPrefix := "groupspref:"
			groupsClaim := "custom-groups"
			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
			provider.Spec.UsernameClaim = &userClaim
			provider.Spec.UsernamePrefix = &userPrefix
			provider.Spec.GroupsClaim = &groupsClaim
			provider.Spec.GroupsPrefix = &groupsPrefix
			provider.Spec.JWKS.Keys = keys

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims[userClaim] = user
			claims[groupsClaim] = []string{"admin", "dev"}
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), true)

			Expect(review.Status.Authenticated).To(BeTrue())
			Expect(review.Status.User.Username).To(Equal(fmt.Sprintf("%s/%s", provider.Name, user)))
			Expect(review.Status.User.Groups).To(ConsistOf([]string{groupsPrefix + "admin", groupsPrefix + "dev"}))

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should return prefixed groups when groupsPrefix is empty string", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			userPrefix := "userpref:"
			userClaim := "custom-sub"
			groupsPrefix := ""
			groupsClaim := "custom-groups"
			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
			provider.Spec.UsernameClaim = &userClaim
			provider.Spec.UsernamePrefix = &userPrefix
			provider.Spec.GroupsClaim = &groupsClaim
			provider.Spec.GroupsPrefix = &groupsPrefix

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims[userClaim] = user
			claims[groupsClaim] = []string{"admin", "dev"}
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), true)

			Expect(review.Status.Authenticated).To(BeTrue())
			Expect(review.Status.User.Username).To(Equal(userPrefix + user))
			Expect(review.Status.User.Groups).To(ConsistOf([]string{fmt.Sprintf("%s/%s", provider.Name, "admin"), fmt.Sprintf("%s/%s", provider.Name, "dev")}))

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should return prefixed groups when groupsPrefix is empty string (offline)", func() {
			idp := createAndStartIDPServer(1)
			keys, err := idp.PublicKeySetAsBytes()
			Expect(err).NotTo(HaveOccurred())
			stopIDP(ctx, idp)

			userPrefix := "userpref:"
			userClaim := "custom-sub"
			groupsPrefix := ""
			groupsClaim := "custom-groups"
			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
			provider.Spec.UsernameClaim = &userClaim
			provider.Spec.UsernamePrefix = &userPrefix
			provider.Spec.GroupsClaim = &groupsClaim
			provider.Spec.GroupsPrefix = &groupsPrefix
			provider.Spec.JWKS.Keys = keys

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims[userClaim] = user
			claims[groupsClaim] = []string{"admin", "dev"}
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), true)

			Expect(review.Status.Authenticated).To(BeTrue())
			Expect(review.Status.User.Username).To(Equal(userPrefix + user))
			Expect(review.Status.User.Groups).To(ConsistOf([]string{fmt.Sprintf("%s/%s", provider.Name, "admin"), fmt.Sprintf("%s/%s", provider.Name, "dev")}))

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not authenticate user if username claim is missing", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			userPrefix := "userpref:"
			userClaim := "custom-sub"
			groupsPrefix := "grouppref:"
			groupsClaim := "custom-groups"
			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
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

			review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), false)

			Expect(review.Status.Authenticated).To(BeFalse())
			Expect(review.Status.User.Username).To(BeEmpty())
			Expect(review.Status.User.Groups).To(BeEmpty())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not authenticate user if audience claim is wrong", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			userPrefix := "userpref:"
			userClaim := "custom-sub"
			groupsPrefix := "grouppref:"
			groupsClaim := "custom-groups"
			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
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

			review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), false)

			Expect(review.Status.Authenticated).To(BeFalse())
			Expect(review.Status.User.Username).To(BeEmpty())
			Expect(review.Status.User.Groups).To(BeEmpty())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not authenticate user if target issuer url is different from the actual issuer url", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v/", idp.ServerSecurePort), idp.CA())

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), false)

			Expect(review.Status.Authenticated).To(BeFalse())
			Expect(review.Status.User.Username).To(BeEmpty())
			Expect(review.Status.User.Groups).To(BeEmpty())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should authenticate user against the target audience", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			userPrefix1 := "userpref1:"
			userPrefix2 := "userpref2:"
			userClaim := "custom-sub"
			groupsPrefix1 := "grouppref1:"
			groupsPrefix2 := "grouppref2:"
			groupsClaim := "custom-groups"
			provider1 := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
			provider1.Spec.UsernameClaim = &userClaim
			provider1.Spec.UsernamePrefix = &userPrefix1
			provider1.Spec.GroupsClaim = &groupsClaim
			provider1.Spec.GroupsPrefix = &groupsPrefix1
			provider1.Spec.ClientID = "client1"

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider1)

			provider2 := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
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

			review1 := makeTokenReviewRequest(token1, testEnv.OIDCServerCA(), true)

			Expect(review1.Status.Authenticated).To(BeTrue())
			Expect(review1.Status.User.Username).To(Equal(userPrefix1 + user))
			Expect(review1.Status.User.Groups).To(ConsistOf(groupsPrefix1 + "admin"))

			review2 := makeTokenReviewRequest(token2, testEnv.OIDCServerCA(), true)

			Expect(review2.Status.Authenticated).To(BeTrue())
			Expect(review2.Status.User.Username).To(Equal(userPrefix2 + user))
			Expect(review2.Status.User.Groups).To(ConsistOf(groupsPrefix2 + "admin"))

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider1)
			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider2)
		})

		It("Should not default groups claim", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			usernameClaim := "sub"
			provider := &authenticationv1alpha1.OpenIDConnect{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "authentication.gardener.cloud/v1alpha1",
					Kind:       "OpenIDConnect",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "not-defaulted-groups-claim",
				},
				Spec: authenticationv1alpha1.OIDCAuthenticationSpec{
					ClientID:      "my-idp-provider",
					UsernameClaim: &usernameClaim,
					IssuerURL:     fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort),
					CABundle:      idp.CA(),
				},
			}

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			Expect(provider.Spec.GroupsClaim).To(BeNil())

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["groups"] = []string{"admin"}
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), true)

			Expect(review.Status.Authenticated).To(BeTrue())
			Expect(review.Status.User.Username).To(Equal(fmt.Sprintf("%s/%s", provider.Name, user)))
			Expect(review.Status.User.Groups).To(BeEmpty())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not default username claim and expect it as required field", func() {
			provider := &authenticationv1alpha1.OpenIDConnect{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "authentication.gardener.cloud/v1alpha1",
					Kind:       "OpenIDConnect",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "not-defaulted-username-claim",
				},
				Spec: authenticationv1alpha1.OIDCAuthenticationSpec{
					ClientID:  "my-idp-provider",
					IssuerURL: "https://some-issuer",
				},
			}

			err := k8sClient.Create(ctx, provider)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal(fmt.Sprintf("OpenIDConnect.authentication.gardener.cloud \"%s\" is invalid: spec.usernameClaim: Required value", provider.Name)))
		})

		It("Should sucessfully remove groups claim from oidc resource", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["groups"] = []string{"admin"}
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), true)

			Expect(review.Status.Authenticated).To(BeTrue())
			Expect(review.Status.User.Username).To(Equal(fmt.Sprintf("%s/%s", provider.Name, user)))
			Expect(review.Status.User.Groups).To(ConsistOf(fmt.Sprintf("%s/%s", provider.Name, "admin")))

			provider.Spec.GroupsClaim = nil
			err = k8sClient.Update(ctx, provider, &client.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() bool {
				review = makeTokenReviewRequest(token, testEnv.OIDCServerCA(), true)
				return len(review.Status.User.Groups) == 0
			}, timeout, interval).Should(BeTrue())

			Expect(review.Status.Authenticated).To(BeTrue())
			Expect(review.Status.User.Username).To(Equal(fmt.Sprintf("%s/%s", provider.Name, user)))
			Expect(review.Status.User.Groups).To(BeEmpty())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not authenticate user because of wrong issuer claim (offline)", func() {
			idp := createAndStartIDPServer(1)
			keys, err := idp.PublicKeySetAsBytes()
			Expect(err).NotTo(HaveOccurred())
			stopIDP(ctx, idp)

			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
			provider.Spec.JWKS.Keys = keys

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), true)
			// user gets authenticated so the oidc resource is reconciled
			Expect(review.Status.Authenticated).To(BeTrue())

			// write an invalid issuer claim
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort+1)
			token, err = idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())
			review = makeTokenReviewRequest(token, testEnv.OIDCServerCA(), false)
			Expect(review.Status.Authenticated).To(BeFalse())
			Expect(review.Status.User.Username).To(BeEmpty())
			Expect(review.Status.User.Groups).To(BeEmpty())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not authenticate user because of expired token", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			claims["exp"] = time.Now().Add(time.Minute * -1).Unix()

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), false)

			Expect(review.Status.Authenticated).To(BeFalse())
			Expect(review.Status.User.Username).To(BeEmpty())
			Expect(review.Status.User.Groups).To(BeEmpty())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not authenticate user because nbf claim represents a time in the future", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"

			claims := defaultClaims()
			claims["sub"] = user
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			claims["nbf"] = time.Now().Add(time.Minute * 2).Unix()

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), false)

			Expect(review.Status.Authenticated).To(BeFalse())
			Expect(review.Status.User.Username).To(BeEmpty())
			Expect(review.Status.User.Groups).To(BeEmpty())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not authenticate user because max token validity is exceeded", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
			provider.Spec.MaxTokenExpirationSeconds = ptr.To[int64](60)
			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), false)
			Expect(review.Status.Authenticated).To(BeFalse())
			Expect(review.Status.User.Username).To(BeEmpty())
			Expect(review.Status.User.Groups).To(BeEmpty())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not authenticate user because max token validity is enforced but iat claim is missing", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
			provider.Spec.MaxTokenExpirationSeconds = ptr.To[int64](60 * 20)
			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			delete(claims, "iat")

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), false)
			Expect(review.Status.Authenticated).To(BeFalse())
			Expect(review.Status.User.Username).To(BeEmpty())
			Expect(review.Status.User.Groups).To(BeEmpty())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should authenticate user because max token validity is not exceeded", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
			provider.Spec.MaxTokenExpirationSeconds = ptr.To[int64](60 * 20)
			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), true)
			Expect(review.Status.Authenticated).To(BeTrue())
			Expect(review.Status.User.Username).To(Equal(fmt.Sprintf("%s/%s", provider.Name, user)))
			Expect(review.Status.User.Groups).To(BeEmpty())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not authenticate user because token was modified after signing", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			split := strings.Split(token, ".")
			decodedBytes, err := base64.RawURLEncoding.DecodeString(split[1])
			Expect(err).NotTo(HaveOccurred())
			newClaims := map[string]interface{}{}
			Expect(json.Unmarshal(decodedBytes, &newClaims)).To(Succeed())

			newClaims["exp"] = time.Now().Add(time.Minute * 30).Unix()
			modifiedPayload, err := json.Marshal(&newClaims)
			Expect(err).NotTo(HaveOccurred())
			modifiedToken := fmt.Sprintf("%s.%s.%s", split[0], base64.RawURLEncoding.EncodeToString(modifiedPayload), split[2])
			Expect(token).NotTo(Equal(modifiedToken))

			review := makeTokenReviewRequest(modifiedToken, testEnv.OIDCServerCA(), false)
			Expect(review.Status.Authenticated).To(BeFalse())
			Expect(review.Status.User.Username).To(BeEmpty())
			Expect(review.Status.User.Groups).To(BeEmpty())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not authenticate user because token was modified after signing (offline)", func() {
			idp := createAndStartIDPServer(1)
			keys, err := idp.PublicKeySetAsBytes()
			Expect(err).NotTo(HaveOccurred())
			stopIDP(ctx, idp)

			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)
			provider.Spec.JWKS.Keys = keys

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			split := strings.Split(token, ".")
			decodedBytes, err := base64.RawURLEncoding.DecodeString(split[1])
			Expect(err).NotTo(HaveOccurred())
			newClaims := map[string]interface{}{}
			Expect(json.Unmarshal(decodedBytes, &newClaims)).To(Succeed())

			newClaims["exp"] = time.Now().Add(time.Minute * 30).Unix()
			modifiedPayload, err := json.Marshal(&newClaims)
			Expect(err).NotTo(HaveOccurred())
			modifiedToken := fmt.Sprintf("%s.%s.%s", split[0], base64.RawURLEncoding.EncodeToString(modifiedPayload), split[2])
			Expect(token).NotTo(Equal(modifiedToken))

			review := makeTokenReviewRequest(modifiedToken, testEnv.OIDCServerCA(), false)
			Expect(review.Status.Authenticated).To(BeFalse())
			Expect(review.Status.User.Username).To(BeEmpty())
			Expect(review.Status.User.Groups).To(BeEmpty())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should not authenticate user because of wrong audience claim (offline)", func() {
			idp := createAndStartIDPServer(1)
			keys, err := idp.PublicKeySetAsBytes()
			Expect(err).NotTo(HaveOccurred())
			stopIDP(ctx, idp)

			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
			provider.Spec.JWKS.Keys = keys

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), true)
			// user gets authenticated so the oidc resource is reconciled
			Expect(review.Status.Authenticated).To(BeTrue())

			// write an invalid issuer claim
			claims["aud"] = "something-invalid"
			token, err = idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())
			review = makeTokenReviewRequest(token, testEnv.OIDCServerCA(), false)
			Expect(review.Status.Authenticated).To(BeFalse())
			Expect(review.Status.User.Username).To(BeEmpty())
			Expect(review.Status.User.Groups).To(BeEmpty())

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
		})

		It("Should authenticate token with extra claims", func() {
			idp := createAndStartIDPServer(1)
			defer stopIDP(ctx, idp)

			userPrefix := "usr:"
			groupsPrefix := "gr:"
			provider := defaultOIDCProvider(fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), idp.CA())
			provider.Spec.UsernamePrefix = &userPrefix
			provider.Spec.GroupsPrefix = &groupsPrefix
			provider.Spec.ExtraClaims = []string{"claim1", "claim2"}

			waitForOIDCResourceToBeCreated(ctx, k8sClient, provider)

			user := "this-is-my-identity"
			claims := defaultClaims()
			claims["sub"] = user
			claims["groups"] = []string{"admin", "employee"}
			claims["iss"] = fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			claims["claim1"] = "test1"
			claims["claim2"] = "test2"

			token, err := idp.Sign(0, claims)
			Expect(err).NotTo(HaveOccurred())

			review := makeTokenReviewRequest(token, testEnv.OIDCServerCA(), true)

			Expect(review.Status.Authenticated).To(BeTrue())
			Expect(review.Status.User.Username).To(Equal(userPrefix + user))
			Expect(review.Status.User.Groups).To(ConsistOf(groupsPrefix+"admin", groupsPrefix+"employee"))

			extraClaims := map[string]authenticationv1.ExtraValue{
				"gardener.cloud/user/claim1": authenticationv1.ExtraValue{"test1"},
				"gardener.cloud/user/claim2": authenticationv1.ExtraValue{"test2"},
			}

			for key, value := range extraClaims {
				Expect(review.Status.User.Extra).To(HaveKeyWithValue(key, value))
			}

			waitForOIDCResourceToBeDeleted(ctx, k8sClient, provider)
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
	err := client.IgnoreNotFound(k8sClient.Delete(ctx, oidc))
	Expect(err).NotTo(HaveOccurred())

	openidconnectLookupKey := client.ObjectKeyFromObject(oidc)
	createdOpenIDConnect := &authenticationv1alpha1.OpenIDConnect{}

	Eventually(func() bool {
		err := k8sClient.Get(ctx, openidconnectLookupKey, createdOpenIDConnect)
		return apierrors.IsNotFound(err)
	}, timeout, interval).Should(BeTrue())
}

func defaultOIDCProvider(issuerURL string, caBundle []byte) *authenticationv1alpha1.OpenIDConnect {
	name := rand.String(5)
	defaultUsernameClaim := "sub"
	defaultGroupsClaim := "groups"
	return &authenticationv1alpha1.OpenIDConnect{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "authentication.gardener.cloud/v1alpha1",
			Kind:       "OpenIDConnect",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: authenticationv1alpha1.OIDCAuthenticationSpec{
			ClientID:      "my-idp-provider",
			JWKS:          authenticationv1alpha1.JWKSSpec{},
			CABundle:      caBundle,
			IssuerURL:     issuerURL,
			UsernameClaim: &defaultUsernameClaim,
			GroupsClaim:   &defaultGroupsClaim,
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
