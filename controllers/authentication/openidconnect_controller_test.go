// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// +kubebuilder:docs-gen:collapse=Apache License

package authentication

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
)

// +kubebuilder:docs-gen:collapse=Imports
type mockAuthRequestHandler struct {
	returnUser      user.Info
	isAuthenticated bool
	err             error
}

func (mock *mockAuthRequestHandler) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	return &authenticator.Response{User: mock.returnUser}, mock.isAuthenticated, mock.err
}

var user1 = &user.DefaultInfo{Name: "fresh_ferret", UID: "alfa"}
var user2 = &user.DefaultInfo{Name: "elegant_sheep", UID: "bravo"}

var _ = Describe("OpenIDConnect controller", func() {

	Describe("Authentication with Token Authentication handlers", func() {
		Context("First Token Authenticator Handler Passes", func() {
			It("Authentication should succeed", func() {
				handler1 := &mockAuthRequestHandler{returnUser: user1, isAuthenticated: true}
				handler2 := &mockAuthRequestHandler{returnUser: user2, isAuthenticated: false}
				authRequestHandler := StoreAuthTokenHandler(handler1, handler2)

				resp, isAuthenticated, err := authRequestHandler.AuthenticateToken(context.Background(), "foo")
				Expect(err).NotTo(HaveOccurred())

				Expect(isAuthenticated).Should(BeTrue())

				Expect(user1.GetName()).Should(Equal(resp.User.GetName()))

			})
		})

		Context("Second Token Authenticator Handler Passes", func() {
			It("Authentication should succeed", func() {
				handler1 := &mockAuthRequestHandler{returnUser: user1, isAuthenticated: false}
				handler2 := &mockAuthRequestHandler{returnUser: user2, isAuthenticated: true}
				authRequestHandler := StoreAuthTokenHandler(handler1, handler2)

				resp, isAuthenticated, err := authRequestHandler.AuthenticateToken(context.Background(), "foo")
				Expect(err).NotTo(HaveOccurred())

				Expect(isAuthenticated).Should(BeTrue())

				Expect(user2.GetName()).Should(Equal(resp.User.GetName()))

			})
		})

		Context("No Token Authenticator Handler passes", func() {
			It("Authentication should fail", func() {

				handler1 := &mockAuthRequestHandler{}
				handler2 := &mockAuthRequestHandler{}
				authRequestHandler := StoreAuthTokenHandler(handler1, handler2)

				resp, isAuthenticated, err := authRequestHandler.AuthenticateToken(context.Background(), "foo")
				Expect(err).NotTo(HaveOccurred())

				Expect(isAuthenticated).Should(BeFalse())

				Expect(resp).To(BeNil())
			})
		})

		Context("No Token Authenticator Handler available", func() {
			It("Authentication should fail", func() {

				authRequestHandler := StoreAuthTokenHandler()
				resp, isAuthenticated, err := authRequestHandler.AuthenticateToken(context.Background(), "foo")
				Expect(err).NotTo(HaveOccurred())

				Expect(isAuthenticated).Should(BeFalse())

				Expect(resp).To(BeNil())
			})
		})

		Context("unnecessary Token Authenticator Handler errors suppressed", func() {
			It("Authentication should succeed", func() {

				handler1 := &mockAuthRequestHandler{err: errors.New("first")}
				handler2 := &mockAuthRequestHandler{returnUser: user2, isAuthenticated: true}
				authRequestHandler := StoreAuthTokenHandler(handler1, handler2)

				resp, isAuthenticated, err := authRequestHandler.AuthenticateToken(context.Background(), "foo")
				Expect(err).NotTo(HaveOccurred())

				Expect(isAuthenticated).Should(BeTrue())

				Expect(resp).NotTo(BeNil())
			})
		})

		Context("Token Authenticator Handler additive errors", func() {
			It("All Authentication handlers should fail", func() {

				handler1 := &mockAuthRequestHandler{err: errors.New("first")}
				handler2 := &mockAuthRequestHandler{err: errors.New("second")}
				authRequestHandler := StoreAuthTokenHandler(handler1, handler2)

				resp, isAuthenticated, err := authRequestHandler.AuthenticateToken(context.Background(), "foo")
				Expect(err).NotTo(HaveOccurred())

				Expect(isAuthenticated).Should(BeFalse())

				Expect(resp).To(BeNil())
			})
		})
	})
	Describe("retrieving the JWKS key Set", func() {
		Context("request to IDP server without valid CA certificate", func() {
			It("request should fail", func() {

				issuerURL := testIDPServer()
				ctx := context.Background()
				keySet, err := remoteKeySet(ctx, issuerURL, nil)
				Expect(strings.Contains(err.Error(), "x509: certificate signed by unknown authority")).To(BeTrue())
				Expect(keySet).To(BeNil())
			})
		})
		Context("request to IDP server with valid CA certificate", func() {
			It("request should succeed", func() {

				issuerURL := testIDPServer()
				caCert, err := ioutil.ReadFile("../../cfssl/ca.crt")
				Expect(err).NotTo(HaveOccurred())
				ctx := context.Background()
				keySet, err := remoteKeySet(ctx, issuerURL, caCert)
				keySetString := fmt.Sprintf("%#v", keySet)
				Expect(strings.Contains(keySetString, issuerURL)).To(BeTrue())
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})
})

func StoreAuthTokenHandler(authTokenHandlers ...authenticator.Token) unionAuthTokenHandler {
	union := unionAuthTokenHandler{}
	for _, auth := range authTokenHandlers {
		uuid := uuid.NewUUID()
		union.handlers.Store(uuid, &authenticatorInfo{
			Token: auth,
			name:  string(uuid),
			uid:   uuid,
		})
	}

	return union
}

func testIDPServer() string {
	newMux := http.NewServeMux()
	server := httptest.NewUnstartedServer(newMux)
	cert, err := tls.LoadX509KeyPair("../../cfssl/tls.crt", "../../cfssl/tls.key")
	Expect(err).NotTo(HaveOccurred())
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.StartTLS()
	userInfo := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicHJvZmlsZSI6IkpvZSBEb2UiLCJlbWFpbCI6ImpvZUBkb2UuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImlzX2FkbWluIjp0cnVlfQ.ejzc2IOLtvYp-2n5w3w4SW3rHNG9pOahnwpQCwuIaj7DvO4SxDIzeJmFPMKTJUc-1zi5T42mS4Gs2r18KWhSkk8kqYermRX0VcGEEsH0r2BG5boeza_EjCoJ5-jBPX5ODWGhu2sZIkZl29IbaVSC8jk8qKnqacchiHNmuv_xXjRsAgUsqYftrEQOxqhpfL5KN2qtgeVTczg3ABqs2-SFeEzcgA1TnA9H3AynCPCVUMFgh7xyS8jxx7DN-1vRHBySz5gNbf8z8MNx_XBLfRxxxMF24rDIE8Z2gf1DEAPr4tT38hD8ugKSE84gC3xHJWFWsRLg-Ll6OQqshs82axS00Q"

	// generated using mkjwk.org
	jwks := `{
		"keys": [
			{
				"kty": "RSA",
				"e": "AQAB",
				"use": "sig",
				"kid": "test",
				"alg": "RS256",
				"n": "ilhCmTGFjjIPVN7Lfdn_fvpXOlzxa3eWnQGZ_eRa2ibFB1mnqoWxZJ8fkWIVFOQpsn66bIfWjBo_OI3sE6LhhRF8xhsMxlSeRKhpsWg0klYnMBeTWYET69YEAX_rGxy0MCZlFZ5tpr56EVZ-3QLfNiR4hcviqj9F2qE6jopfywsnlulJgyMi3N3kugit_JCNBJ0yz4ndZrMozVOtGqt35HhggUgYROzX6SWHUJdPXSmbAZU-SVLlesQhPfHS8LLq0sACb9OmdcwrpEFdbGCSTUPlHGkN5h6Zy8CS4s_bCdXKkjD20jv37M3GjRQkjE8vyMxFlo_qT8F8VZlSgXYTFw"
			}
		]
	}`

	wellKnown := fmt.Sprintf(`{
		"issuer": "%[1]s",
		"authorization_endpoint": "%[1]s/auth",
		"token_endpoint": "%[1]s/token",
		"jwks_uri": "%[1]s/keys",
		"userinfo_endpoint": "%[1]s/userinfo",
		"id_token_signing_alg_values_supported": ["RS256"]
	}`, server.URL)

	newMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, req *http.Request) {
		_, err := io.WriteString(w, wellKnown)
		if err != nil {
			w.WriteHeader(500)
		}
	})
	newMux.HandleFunc("/keys", func(w http.ResponseWriter, req *http.Request) {
		_, err := io.WriteString(w, jwks)
		if err != nil {
			w.WriteHeader(500)
		}
	})
	newMux.HandleFunc("/userinfo", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Add("Content-Type", "application/jwt")
		_, err := io.WriteString(w, userInfo)
		if err != nil {
			w.WriteHeader(500)
		}
	})
	return server.URL
}
