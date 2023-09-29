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
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	mock "github.com/gardener/oidc-webhook-authenticator/test/integration/mock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/utils/pointer"
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

func stopIDP(ctx context.Context, idp *mock.OIDCIdentityServer) {
	err := idp.Stop(ctx)
	Expect(err).NotTo(HaveOccurred())
}

var _ = Describe("OpenIDConnect controller", func() {
	ctx := context.Background()

	sign := func(claims map[string]interface{}) (string, error) {
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

	Describe("Authentication with Token Authentication handlers", func() {
		var (
			user1               = &user.DefaultInfo{Name: "fresh_ferret", Groups: []string{"first", "second"}, UID: "alpha"}
			user2               = &user.DefaultInfo{Name: "elegant_sheep", Groups: []string{"third", "fourth"}, UID: "beta"}
			user3               = &user.DefaultInfo{Name: "big_elephant", Groups: []string{"fifth", "sixth"}, UID: "gamma"}
			forbiddenUser       = &user.DefaultInfo{Name: "system:admin", Groups: []string{"seventh", "eight"}, UID: "delta"}
			forbiddenGroupsUser = &user.DefaultInfo{Name: "sneaky_gazelle", Groups: []string{"ninth", "system:admin"}, UID: "epsilon"}
		)

		Context("First Token Authenticator Handler Passes", func() {
			It("Authentication should succeed", func() {
				unionHandler := newUnionAuthTokenHandler()
				authUID := uuid.NewUUID()
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
				unionHandler := newUnionAuthTokenHandler()
				authUID := uuid.NewUUID()
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
				unionHandler := newUnionAuthTokenHandler()
				authUID := uuid.NewUUID()

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
				unionHandler := newUnionAuthTokenHandler()

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
				unionHandler := newUnionAuthTokenHandler()
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
				unionHandler := newUnionAuthTokenHandler()
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
				unionHandler := newUnionAuthTokenHandler()
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
				unionHandler := newUnionAuthTokenHandler()
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
				unionHandler := newUnionAuthTokenHandler()
				authUID := uuid.NewUUID()

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
				unionHandler := newUnionAuthTokenHandler()
				authUID := uuid.NewUUID()

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
				unionHandler := newUnionAuthTokenHandler()

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

		Context("Extra claims handling", func() {
			unionHandler := newUnionAuthTokenHandler()
			issuer1URL := "https://issuer1"
			handler1 := &mockAuthRequestHandler{returnUser: user1, isAuthenticated: true, issuerURL: issuer1URL}
			handler2 := &mockAuthRequestHandler{returnUser: user2, isAuthenticated: false, issuerURL: "https://issuer2"}

			authUID := uuid.NewUUID()
			unionHandler.registerHandler(issuer1URL, "1", &authenticatorInfo{
				Token: handler1,
				name:  "1",
				uid:   authUID,
			})
			unionHandler.registerHandler("https://issuer2", "2", &authenticatorInfo{
				Token: handler2,
				name:  "2",
				uid:   uuid.NewUUID(),
			})

			claims := map[string]interface{}{
				"iss":    issuer1URL,
				"claim1": "value1",
				"claim2": 2,
				"claim3": []interface{}{
					"value3",
					3,
				},
			}

			setIssuer1ExtraClaims := func(extra []string) {
				unionHandler.mutex.Lock()
				defer unionHandler.mutex.Unlock()
				unionHandler.issuerHandlers[issuer1URL]["1"].extraClaims = extra
			}

			It("Authentication should succeed and extra claims be empty", func() {
				setIssuer1ExtraClaims([]string{})

				token, err := sign(claims)
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

			It("Authentication should succeed and all extra claims are available", func() {
				setIssuer1ExtraClaims([]string{"claim1", "claim2", "claim3", "claim5", "CLAim6"})

				token, err := sign(claims)
				Expect(err).NotTo(HaveOccurred())

				resp, isAuthenticated, err := unionHandler.AuthenticateToken(context.Background(), token)
				Expect(err).NotTo(HaveOccurred())
				Expect(isAuthenticated).To(BeTrue())
				expectedUser := *user1
				expectedUser.Extra = map[string][]string{
					"gardener.cloud/authenticator/name":   {"1"},
					"gardener.cloud/authenticator/uid":    {string(authUID)},
					"gardener.cloud/authenticator/claim1": {"value1"},
					"gardener.cloud/authenticator/claim2": {"2"},
					"gardener.cloud/authenticator/claim3": {"[\"value3\",3]"},
				}
				Expect(resp.User).To(Equal(&expectedUser))
			})

			It("Authentication should succeed and subset of extra claims are available", func() {
				setIssuer1ExtraClaims([]string{"claim1", "claim2"})

				token, err := sign(claims)
				Expect(err).NotTo(HaveOccurred())

				resp, isAuthenticated, err := unionHandler.AuthenticateToken(context.Background(), token)
				Expect(err).NotTo(HaveOccurred())
				Expect(isAuthenticated).To(BeTrue())
				expectedUser := *user1
				expectedUser.Extra = map[string][]string{
					"gardener.cloud/authenticator/name":   {"1"},
					"gardener.cloud/authenticator/uid":    {string(authUID)},
					"gardener.cloud/authenticator/claim1": {"value1"},
					"gardener.cloud/authenticator/claim2": {"2"},
				}
				Expect(resp.User).To(Equal(&expectedUser))
			})

			It("Authentication should fail on wrong extra claims", func() {
				setIssuer1ExtraClaims([]string{"claim1", "claim4"})

				token, err := sign(claims)
				Expect(err).NotTo(HaveOccurred())

				resp, isAuthenticated, err := unionHandler.AuthenticateToken(context.Background(), token)
				Expect(isAuthenticated).To(BeFalse())
				Expect(resp).To(BeNil())
				Expect(err).To(BeNil())
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
			Expect(idp.Stop(ctx)).To(Succeed())
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
					defer stopIDP(ctx, idp1)

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
					containsAnyOf := func(s string, anyOf []string) bool {
						for _, v := range anyOf {
							if strings.Contains(s, v) {
								return true
							}
						}
						return false
					}

					Eventually(func() bool {
						keySet, err := remoteKeySet(ctx, fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort), nil)
						if err == nil {
							return false
						}

						// Different errors are returned depending on the OS since go 1.18
						// See a similar issue here https://github.com/golang/go/issues/51991
						expectedAnyOf := []string{"certificate is not trusted", "certificate signed by unknown authority"}
						return containsAnyOf(err.Error(), expectedAnyOf) && keySet == nil
					}, time.Second*10, time.Second).Should(BeTrue())
				})
			})

			Context("request to IDP server with valid CA certificate", func() {
				It("request should succeed", func() {
					serverURL := fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
					Eventually(func() bool {
						keySet, err := remoteKeySet(ctx, serverURL, idp.CA())
						if err != nil {
							return false
						}
						keySetString := fmt.Sprintf("%#v", keySet)
						return strings.Contains(keySetString, serverURL)
					}, time.Second*10, time.Second).Should(BeTrue())
				})
				It("request should succeed and token should be verified without errors", func() {
					serverURL := fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
					Eventually(func() bool {
						keySet, err := remoteKeySet(ctx, serverURL, idp.CA())
						if err != nil {
							return false
						}

						claims := map[string]interface{}{
							"someclaim": "somevalue",
						}
						token, err := idp.Sign(0, claims)
						if err != nil {
							return false
						}
						payload, err := keySet.VerifySignature(ctx, token)
						if err != nil {
							return false
						}

						unmarshaledResp := map[string]string{}
						err = json.Unmarshal(payload, &unmarshaledResp)
						if err != nil {
							return false
						}
						return len(unmarshaledResp) == 1 && unmarshaledResp["someclaim"] == "somevalue"
					}, time.Second*10, time.Second).Should(BeTrue())
				})
				It("request should fail because of not matching issuer URL", func() {
					requestedURL := fmt.Sprintf("https://localhost:%v/", idp.ServerSecurePort)
					serverURL := fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
					Eventually(func() bool {
						keySet, err := remoteKeySet(ctx, requestedURL, idp.CA())
						if err != nil {
							expectedError := fmt.Sprintf(`oidc: issuer did not match the issuer returned by provider, expected "%s/" got "%s"`, serverURL, serverURL)
							return keySet == nil && err.Error() == expectedError
						}
						return false
					}, time.Second*10, time.Second).Should(BeTrue())
				})
			})
		})
	})

	DescribeTable("Check token expiration validity requirements (allowed)",
		func(tokenValidForSeconds int64, maxTokenValiditySeconds *int64) {
			now := time.Now()
			token, err := sign(map[string]interface{}{
				"iss": "https://issuer1",
				"iat": now.Unix(),
				"exp": now.Add(time.Second * time.Duration(tokenValidForSeconds)).Unix(),
			})
			Expect(err).NotTo(HaveOccurred())
			fulfilled, err := areExpirationRequirementsFulfilled(token, maxTokenValiditySeconds)
			Expect(err).NotTo(HaveOccurred())
			Expect(fulfilled).To(BeTrue())
		},

		Entry("token issued for the exact max validity seconds", int64(10), pointer.Int64(10)),
		Entry("token issued for less than the max validity seconds", int64(10), pointer.Int64(50)),
		Entry("no max validity seconds configured", int64(10), nil),
	)

	DescribeTable("Check token expiration validity requirements (denied)",
		func(tokenValidForSeconds int64, maxTokenValiditySeconds *int64, expectedError string) {
			now := time.Now()
			token, err := sign(map[string]interface{}{
				"iss": "https://issuer1",
				"iat": now.Unix(),
				"exp": now.Add(time.Second * time.Duration(tokenValidForSeconds)).Unix(),
			})
			Expect(err).NotTo(HaveOccurred())
			fulfilled, err := areExpirationRequirementsFulfilled(token, maxTokenValiditySeconds)
			Expect(err).To(HaveOccurred())
			Expect(fulfilled).To(BeFalse())
			Expect(err.Error()).To(Equal(expectedError))
		},

		Entry("max validity seconds is negative", int64(10), pointer.Int64(-1), "max validity seconds of a token should not be negative"),
		Entry("token exp is before iat", int64(-1), pointer.Int64(20), "iat is equal or greater than exp claim"),
		Entry("token exp is the exact iat", int64(0), pointer.Int64(20), "iat is equal or greater than exp claim"),
		Entry("token issued for greater validity than the allowed", int64(20), pointer.Int64(10), "token is issued with greater validity than the max allowed"),
	)

	Describe("Check token expiration validity requirements (special cases)", func() {
		It("should fail because of missing iat claim", func() {
			now := time.Now()
			token, err := sign(map[string]interface{}{
				"iss": "https://issuer1",
				"exp": now.Add(time.Second * 10).Unix(),
			})
			Expect(err).NotTo(HaveOccurred())
			fulfilled, err := areExpirationRequirementsFulfilled(token, pointer.Int64(10))
			Expect(err).To(HaveOccurred())
			Expect(fulfilled).To(BeFalse())
			Expect(err.Error()).To(Equal("cannot retrieve iat claim"))
		})

		It("should fail because of missing exp claim", func() {
			now := time.Now()
			token, err := sign(map[string]interface{}{
				"iss": "https://issuer1",
				"iat": now.Unix(),
			})
			Expect(err).NotTo(HaveOccurred())
			fulfilled, err := areExpirationRequirementsFulfilled(token, pointer.Int64(10))
			Expect(err).To(HaveOccurred())
			Expect(fulfilled).To(BeFalse())
			Expect(err.Error()).To(Equal("cannot retrieve exp claim"))
		})

		It("should fail because of negative iat claim", func() {
			now := time.Now()
			token, err := sign(map[string]interface{}{
				"iss": "https://issuer1",
				"exp": now.Unix(),
				"iat": -1,
			})
			Expect(err).NotTo(HaveOccurred())
			fulfilled, err := areExpirationRequirementsFulfilled(token, pointer.Int64(10))
			Expect(err).To(HaveOccurred())
			Expect(fulfilled).To(BeFalse())
			Expect(err.Error()).To(Equal("iat claim value should be positive"))
		})

		It("should fail because of negative exp claim", func() {
			now := time.Now()
			token, err := sign(map[string]interface{}{
				"iss": "https://issuer1",
				"exp": -1,
				"iat": now.Unix(),
			})
			Expect(err).NotTo(HaveOccurred())
			fulfilled, err := areExpirationRequirementsFulfilled(token, pointer.Int64(10))
			Expect(err).To(HaveOccurred())
			Expect(fulfilled).To(BeFalse())
			Expect(err.Error()).To(Equal("exp claim value should be positive"))
		})

		It("should fail because the passed argument is not a jwt", func() {
			fulfilled, err := areExpirationRequirementsFulfilled("notajwt", pointer.Int64(10))
			Expect(err).To(HaveOccurred())
			Expect(fulfilled).To(BeFalse())
			Expect(err.Error()).To(Equal("cannot parse jwt token"))
		})
	})

	Describe("Use a mocked identity provider offering specific TLS version", func() {
		It("request should fail because offered TLS version is < 1.2", func() {
			idp, err := mock.NewIdentityServer("test-idp", 1)
			defer stopIDP(ctx, idp)
			Expect(err).NotTo(HaveOccurred())
			err = idp.StartWithMaxTLSVersion(tls.VersionTLS11)
			Expect(err).NotTo(HaveOccurred())

			serverURL := fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			Eventually(func() bool {
				keySet, err := remoteKeySet(ctx, serverURL, idp.CA())
				if err != nil {
					expectedError := fmt.Sprintf(`Get "%s/.well-known/openid-configuration": remote error: tls: protocol version not supported`, serverURL)
					fmt.Println(err.Error())
					return keySet == nil && err.Error() == expectedError
				}
				return false
			}, time.Second*10, time.Second).Should(BeTrue())
		})

		It("request should succeed because offered TLS version is >= 1.2", func() {
			idp, err := mock.NewIdentityServer("test-idp", 1)
			defer stopIDP(ctx, idp)
			Expect(err).NotTo(HaveOccurred())
			err = idp.StartWithMaxTLSVersion(tls.VersionTLS12)
			Expect(err).NotTo(HaveOccurred())

			serverURL := fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
			Eventually(func() bool {
				keySet, err := remoteKeySet(ctx, serverURL, idp.CA())
				if err != nil {
					return false
				}
				keySetString := fmt.Sprintf("%#v", keySet)
				return strings.Contains(keySetString, serverURL)
			}, time.Second*10, time.Second).Should(BeTrue())
		})
	})
})
