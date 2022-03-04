// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// +kubebuilder:docs-gen:collapse=Apache License

package authentication

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	mock "github.com/gardener/oidc-webhook-authenticator/test/integration/mock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	ctrl "sigs.k8s.io/controller-runtime"
)

// +kubebuilder:docs-gen:collapse=Imports
type mockAuthRequestHandler struct {
	returnUser      user.Info
	isAuthenticated bool
	issuerURL       string
	err             error
}

func (mock *mockAuthRequestHandler) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	return &authenticator.Response{User: mock.returnUser}, mock.isAuthenticated, mock.err
}

var _ = Describe("OpenIDConnect controller", func() {
	ctx := context.Background()

	Describe("Authentication with Token Authentication handlers", func() {
		var (
			user1               = &user.DefaultInfo{Name: "fresh_ferret", Groups: []string{"first", "second"}, UID: "alpha"}
			user2               = &user.DefaultInfo{Name: "elegant_sheep", Groups: []string{"third", "fourth"}, UID: "beta"}
			user3               = &user.DefaultInfo{Name: "big_elephant", Groups: []string{"fifth", "sixth"}, UID: "gamma"}
			forbiddenUser       = &user.DefaultInfo{Name: "system:admin", Groups: []string{"seventh", "eight"}, UID: "delta"}
			forbiddenGroupsUser = &user.DefaultInfo{Name: "sneaky_gazelle", Groups: []string{"ninth", "system:admin"}, UID: "epsilon"}
			unionHandler        *unionAuthTokenHandler
			authUID             types.UID
			sign                = func(claims map[string]interface{}) (string, error) {
				privateKey := jose.JSONWebKey{}
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					return "", err
				}

				privateKey = jose.JSONWebKey{Key: key, KeyID: "", Algorithm: string(jose.RS256), Use: "sig"}
				thumb, err := privateKey.Thumbprint(crypto.SHA256)
				if err != nil {
					return "", err
				}
				kid := base64.URLEncoding.EncodeToString(thumb)
				privateKey.KeyID = kid

				signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, (&jose.SignerOptions{}).WithType("JWT"))

				if err != nil {
					return "", err
				}

				builder := jwt.Signed(signer)
				token, err := builder.Claims(claims).CompactSerialize()
				if err != nil {
					return "", err
				}
				return token, nil
			}
		)
		BeforeEach(func() {
			unionHandler = &unionAuthTokenHandler{issuerHandlers: sync.Map{}, nameIssuerMapping: sync.Map{}, log: ctrl.Log.WithName("test")}
			authUID = uuid.NewUUID()
		})

		Context("First Token Authenticator Handler Passes", func() {
			It("Authentication should succeed", func() {
				handler1 := &mockAuthRequestHandler{returnUser: user1, isAuthenticated: true, issuerURL: "https://issuer1"}
				handler2 := &mockAuthRequestHandler{returnUser: user2, isAuthenticated: false, issuerURL: "https://issuer2"}

				unionHandler.registerHandler("https://issuer1", "1", &authenticatorInfo{
					Token: handler1,
					name:  "1",
					uid:   authUID,
				})
				unionHandler.registerHandler("https://issuer2", "2", &authenticatorInfo{
					Token: handler2,
					name:  "2",
					uid:   uuid.NewUUID(),
				})

				token, err := sign(map[string]interface{}{
					"iss": "https://issuer1",
				})
				Expect(err).NotTo(HaveOccurred())

				resp, isAuthenticated, err := unionHandler.AuthenticateToken(context.Background(), token)
				Expect(err).NotTo(HaveOccurred())
				Expect(isAuthenticated).To(BeTrue())
				expectedUser := *user1
				expectedUser.Extra = map[string][]string{
					"gardener.cloud/authenticator/name": {"1"},
					"gardener.cloud/authenticator/uid":  {string(authUID)},
				}
				Expect(resp.User).To(Equal(&expectedUser))
			})
		})

		Context("Second Token Authenticator Handler Passes", func() {
			It("Authentication should succeed", func() {
				handler1 := &mockAuthRequestHandler{returnUser: user1, isAuthenticated: false, issuerURL: "https://issuer1"}
				handler2 := &mockAuthRequestHandler{returnUser: user2, isAuthenticated: true, issuerURL: "https://issuer2"}

				unionHandler.registerHandler("https://issuer1", "1", &authenticatorInfo{
					Token: handler1,
					name:  "1",
					uid:   uuid.NewUUID(),
				})
				unionHandler.registerHandler("https://issuer2", "2", &authenticatorInfo{
					Token: handler2,
					name:  "2",
					uid:   authUID,
				})

				token, err := sign(map[string]interface{}{
					"iss": "https://issuer2",
				})
				Expect(err).NotTo(HaveOccurred())

				resp, isAuthenticated, err := unionHandler.AuthenticateToken(context.Background(), token)
				Expect(err).NotTo(HaveOccurred())
				Expect(isAuthenticated).To(BeTrue())
				expectedUser := *user2
				expectedUser.Extra = map[string][]string{
					"gardener.cloud/authenticator/name": {"2"},
					"gardener.cloud/authenticator/uid":  {string(authUID)},
				}
				Expect(resp.User).To(Equal(&expectedUser))
			})
		})

		Context("Third Token Authenticator Handler Passes", func() {
			It("Authentication should succeed", func() {
				handler1 := &mockAuthRequestHandler{returnUser: user1, isAuthenticated: false, issuerURL: "https://issuer1"}
				handler2 := &mockAuthRequestHandler{returnUser: user2, isAuthenticated: false, issuerURL: "https://issuer2"}
				handler3 := &mockAuthRequestHandler{returnUser: user3, isAuthenticated: true, issuerURL: "https://issuer2"}

				unionHandler.registerHandler("https://issuer1", "1", &authenticatorInfo{
					Token: handler1,
					name:  "1",
					uid:   uuid.NewUUID(),
				})
				unionHandler.registerHandler("https://issuer2", "2", &authenticatorInfo{
					Token: handler2,
					name:  "2",
					uid:   uuid.NewUUID(),
				})
				unionHandler.registerHandler("https://issuer2", "3", &authenticatorInfo{
					Token: handler3,
					name:  "3",
					uid:   authUID,
				})

				token, err := sign(map[string]interface{}{
					"iss": "https://issuer2",
				})
				Expect(err).NotTo(HaveOccurred())

				resp, isAuthenticated, err := unionHandler.AuthenticateToken(context.Background(), token)
				Expect(err).NotTo(HaveOccurred())
				Expect(isAuthenticated).To(BeTrue())
				expectedUser := *user3
				expectedUser.Extra = map[string][]string{
					"gardener.cloud/authenticator/name": {"3"},
					"gardener.cloud/authenticator/uid":  {string(authUID)},
				}
				Expect(resp.User).To(Equal(&expectedUser))
			})
		})

		Context("No Token Authenticator Handler passes", func() {
			It("Authentication should fail", func() {
				handler1 := &mockAuthRequestHandler{isAuthenticated: false, issuerURL: "https://issuer1"}
				handler2 := &mockAuthRequestHandler{isAuthenticated: false, issuerURL: "https://issuer2"}
				unionHandler.registerHandler("https://issuer1", "1", &authenticatorInfo{
					Token: handler1,
					name:  "1",
					uid:   uuid.NewUUID(),
				})
				unionHandler.registerHandler("https://issuer2", "2", &authenticatorInfo{
					Token: handler2,
					name:  "2",
					uid:   uuid.NewUUID(),
				})

				token, err := sign(map[string]interface{}{
					"iss": "https://issuer2",
				})
				Expect(err).NotTo(HaveOccurred())

				resp, isAuthenticated, err := unionHandler.AuthenticateToken(context.Background(), token)
				Expect(err).NotTo(HaveOccurred())
				Expect(isAuthenticated).To(BeFalse())
				Expect(resp).To(BeNil())
			})
		})

		Context("No Token Authenticator Handler available", func() {
			It("Authentication should fail", func() {
				token, err := sign(map[string]interface{}{
					"iss": "https://issuer2",
				})
				Expect(err).NotTo(HaveOccurred())

				resp, isAuthenticated, err := unionHandler.AuthenticateToken(context.Background(), token)
				Expect(err).NotTo(HaveOccurred())
				Expect(isAuthenticated).To(BeFalse())
				Expect(resp).To(BeNil())
			})
		})

		Context("Invalid jwt is passed", func() {
			It("Authentication should fail", func() {
				handler1 := &mockAuthRequestHandler{returnUser: user1, isAuthenticated: true, issuerURL: "https://issuer1"}
				unionHandler.registerHandler("https://issuer1", "1", &authenticatorInfo{
					Token: handler1,
					name:  "1",
					uid:   uuid.NewUUID(),
				})

				resp, isAuthenticated, err := unionHandler.AuthenticateToken(context.Background(), "invalid")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal("cannot parse jwt token"))
				Expect(isAuthenticated).To(BeFalse())
				Expect(resp).To(BeNil())
			})
		})

		Context("Issuer is not present in the jwt claims", func() {
			It("Authentication should fail", func() {
				handler1 := &mockAuthRequestHandler{returnUser: user1, isAuthenticated: true, issuerURL: "https://issuer1"}
				unionHandler.registerHandler("https://issuer1", "1", &authenticatorInfo{
					Token: handler1,
					name:  "1",
					uid:   uuid.NewUUID(),
				})

				token, err := sign(map[string]interface{}{
					"iss_invalid": "https://issuer1",
				})
				Expect(err).NotTo(HaveOccurred())

				resp, isAuthenticated, err := unionHandler.AuthenticateToken(context.Background(), token)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal("cannot retrieve issuer URL"))
				Expect(isAuthenticated).To(BeFalse())
				Expect(resp).To(BeNil())
			})
		})

		Context("User is authenticated with system: prefix", func() {
			It("Authentication should fail because system: prefix is present in the username", func() {
				handler1 := &mockAuthRequestHandler{returnUser: forbiddenUser, isAuthenticated: true, issuerURL: "https://issuer1"}
				unionHandler.registerHandler("https://issuer1", "1", &authenticatorInfo{
					Token: handler1,
					name:  "1",
					uid:   uuid.NewUUID(),
				})

				token, err := sign(map[string]interface{}{
					"iss": "https://issuer1",
				})
				Expect(err).NotTo(HaveOccurred())

				resp, isAuthenticated, err := unionHandler.AuthenticateToken(context.Background(), token)
				Expect(err).NotTo(HaveOccurred())
				Expect(isAuthenticated).To(BeFalse())
				Expect(resp).To(BeNil())
			})

			It("Authentication should succeed because but groups starting with system: should be filtered", func() {
				handler1 := &mockAuthRequestHandler{returnUser: forbiddenGroupsUser, isAuthenticated: true, issuerURL: "https://issuer1"}
				unionHandler.registerHandler("https://issuer1", "1", &authenticatorInfo{
					Token: handler1,
					name:  "1",
					uid:   authUID,
				})

				token, err := sign(map[string]interface{}{
					"iss": "https://issuer1",
				})
				Expect(err).NotTo(HaveOccurred())

				resp, isAuthenticated, err := unionHandler.AuthenticateToken(context.Background(), token)
				Expect(err).NotTo(HaveOccurred())
				Expect(isAuthenticated).To(BeTrue())
				expectedUser := *forbiddenGroupsUser
				expectedUser.Groups = []string{"ninth"}
				expectedUser.Extra = map[string][]string{
					"gardener.cloud/authenticator/name": {"1"},
					"gardener.cloud/authenticator/uid":  {string(authUID)},
				}
				Expect(resp.User).To(Equal(&expectedUser))
			})
		})

		Context("Unnecessary Token Authenticator Handler errors suppressed", func() {
			It("Authentication should succeed", func() {
				handler1 := &mockAuthRequestHandler{returnUser: user1, isAuthenticated: true, issuerURL: "https://issuer2", err: errors.New("first")}
				handler2 := &mockAuthRequestHandler{returnUser: user2, isAuthenticated: true, issuerURL: "https://issuer2"}
				unionHandler.registerHandler("https://issuer2", "1", &authenticatorInfo{
					Token: handler1,
					name:  "1",
					uid:   uuid.NewUUID(),
				})
				unionHandler.registerHandler("https://issuer2", "2", &authenticatorInfo{
					Token: handler2,
					name:  "2",
					uid:   authUID,
				})
				token, err := sign(map[string]interface{}{
					"iss": "https://issuer2",
				})
				Expect(err).NotTo(HaveOccurred())

				resp, isAuthenticated, err := unionHandler.AuthenticateToken(context.Background(), token)
				Expect(err).NotTo(HaveOccurred())
				Expect(isAuthenticated).To(BeTrue())
				expectedUser := *user2
				expectedUser.Extra = map[string][]string{
					"gardener.cloud/authenticator/name": {"2"},
					"gardener.cloud/authenticator/uid":  {string(authUID)},
				}
				Expect(resp.User).To(Equal(&expectedUser))
			})
		})

		Context("Token Authenticator Handler additive errors", func() {
			It("All Authentication handlers should fail", func() {
				handler1 := &mockAuthRequestHandler{returnUser: user1, isAuthenticated: true, issuerURL: "https://issuer1", err: errors.New("first")}
				handler2 := &mockAuthRequestHandler{returnUser: user2, isAuthenticated: false, issuerURL: "https://issuer2", err: errors.New("second")}
				handler3 := &mockAuthRequestHandler{returnUser: user3, isAuthenticated: true, issuerURL: "https://issuer2", err: errors.New("third")}
				unionHandler.registerHandler("https://issuer1", "1", &authenticatorInfo{
					Token: handler1,
					name:  "1",
					uid:   uuid.NewUUID(),
				})
				unionHandler.registerHandler("https://issuer2", "2", &authenticatorInfo{
					Token: handler2,
					name:  "2",
					uid:   uuid.NewUUID(),
				})
				unionHandler.registerHandler("https://issuer2", "3", &authenticatorInfo{
					Token: handler3,
					name:  "3",
					uid:   uuid.NewUUID(),
				})

				token, err := sign(map[string]interface{}{
					"iss": "https://issuer2",
				})
				Expect(err).NotTo(HaveOccurred())

				resp, isAuthenticated, err := unionHandler.AuthenticateToken(context.Background(), token)

				Expect(err).NotTo(HaveOccurred())
				Expect(isAuthenticated).To(BeFalse())
				Expect(resp).To(BeNil())
			})
		})
	})

	Describe("Use a mocked identity provider", func() {
		var idp *mock.OIDCIdentityServer
		BeforeEach(func() {
			var err error
			idp, err = mock.NewIdentityServer("test-idp", 1)
			Expect(err).NotTo(HaveOccurred())
			err = idp.Start()
			Expect(err).NotTo(HaveOccurred())
		})
		AfterEach(func() {
			idp.Stop(ctx)
		})

		Describe("Construct a static JWKS key Set", func() {
			Context("VerifySignature of a valid jwt", func() {
				It("verification should succeed", func() {
					jwks, err := idp.PublicKeySetAsBytes()
					Expect(err).NotTo(HaveOccurred())
					staticKeySet, err := newStaticKeySet(jwks)
					Expect(err).NotTo(HaveOccurred())
					Expect(staticKeySet).NotTo(BeNil())

					claims := map[string]interface{}{
						"someclaim": "somevalue",
					}
					token, err := idp.Sign(0, claims)
					Expect(err).NotTo(HaveOccurred())

					payload, err := staticKeySet.VerifySignature(ctx, token)
					Expect(err).NotTo(HaveOccurred())
					Expect(payload).To(Equal([]byte(`{"someclaim":"somevalue"}`)))
				})
			})

			Context("Verify Signature of an invalid jwt", func() {
				It("verification should fail because of not matching kid", func() {
					idp1, err := mock.NewIdentityServer("test-idp", 1)
					Expect(err).NotTo(HaveOccurred())
					err = idp1.Start()
					Expect(err).NotTo(HaveOccurred())
					defer idp1.Stop(ctx)

					jwks, err := idp.PublicKeySetAsBytes()
					Expect(err).NotTo(HaveOccurred())

					staticKeySet, err := newStaticKeySet(jwks)
					Expect(err).NotTo(HaveOccurred())
					Expect(staticKeySet).NotTo(BeNil())

					claims := map[string]interface{}{
						"someclaim": "somevalue",
					}
					token, err := idp1.Sign(0, claims)
					Expect(err).NotTo(HaveOccurred())

					payload, err := staticKeySet.VerifySignature(ctx, token)
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("no keys matches jwk keyid"))
					Expect(payload).To(BeNil())
				})
			})
		})

		Describe("retrieving the JWKS key Set", func() {
			Context("request to IDP server without valid CA certificate", func() {
				It("request should fail", func() {
					keySet, err := remoteKeySet(ctx, fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), nil)
					Expect(err.Error()).To(ContainSubstring("x509: certificate signed by unknown authority"))
					Expect(keySet).To(BeNil())
				})
			})

			Context("request to IDP server with valid CA certificate", func() {
				It("request should succeed", func() {
					serverURL := fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
					keySet, err := remoteKeySet(ctx, serverURL, idp.CA())
					keySetString := fmt.Sprintf("%#v", keySet)
					Expect(keySetString).To(ContainSubstring(serverURL))
					Expect(err).NotTo(HaveOccurred())
				})
				It("request should fail because of not matching issuer URL", func() {
					requestedURL := fmt.Sprintf("https://localhost:%v/", idp.ServerSecurePort)
					serverURL := fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
					keySet, err := remoteKeySet(ctx, requestedURL, idp.CA())
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(BeIdenticalTo(fmt.Sprintf(`oidc: issuer did not match the issuer returned by provider, expected "%s/" got "%s"`, serverURL, serverURL)))
					Expect(keySet).To(BeNil())
				})
			})
		})
	})
})
