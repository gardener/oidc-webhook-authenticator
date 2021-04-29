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
var server *httptest.Server
var jwksdata = `{
  "keys": [
    {
      "use": "sig",
      "kty": "RSA",
      "kid": "5b0a93c3bff25a39db9246d4dfe60d496fd41fa3",
      "alg": "RS256",
      "n": "vzquxAk7mmhbX9ZctbFkhFGYGrPBAzoXBNc8CKlGx8KhrEvqJAqDEn1LbKBsWku6kYj_Mtfn9dOkjizJtyWw14649xIbGSsUOSWUwrXwyiql-sQukV3mTPfZTxMjPKLmCH42cUIKm-4H8ANN8bOqRwceR3kg5WRkQaBAUcKmCHij42TTtD2GZuXfO569P40OXHl9b20e3fPcR92J9zXri4N0Y8c62h-sXb8FtH4GCICEMgE6swdRGkzFngoUouIEHCfYc5DgtbTTOgznZ7gFs3YWvgGu2nzm1Lf7JH00i44mNiuMEnIvD_ZNycrYmPHc0-ux_LOgvFtyfnCbiCPM3Q",
      "e": "AQAB"
    },
    {
      "use": "sig",
      "kty": "RSA",
      "kid": "75335fd1ecaacab9afd094e22b8d5d177fdb208d",
      "alg": "RS256",
      "n": "0bURUQITUeSDLr-NKMThwvnekDS6A1aF_2M8Ns0dm27q4tf7ykZw0A5sZxyDh-GC793jWQeHbldyfgO258WS32BxJmr5HyfmKvxEJe1rO88IBQqyjJeQ-LFjXIwSceTY-QAytB4zYgzQQCD3LTL7Fuig3kcfRLCtbGqSqHreESuOGUhZwmqZeuktLqWM0oPCN9f3zrbjFfz5y1gA5sLcNcwp1TPWrUSSjdm8hUVTX68_IAmyD_1IPKa-cdeLVM2qT8yhVjfq5T4Zd4qH-e4M_JMcXuGWJaFPRanVZMiN9E6mXqRrMePbUdi1aoCqUwVprVzrTyrNqlWG4UcMIG39xQ",
      "e": "AQAB"
    },
    {
      "use": "sig",
      "kty": "RSA",
      "kid": "f742aa0df758dea9120aa36542f623dc54646189",
      "alg": "RS256",
      "n": "1NDLhqr9N3Zof0-N5zbqdGw4YmPsWihElv5MmVJvIfTu-4CDRhIQqd8koafAlwptDLY-xd897sLzahPm28ffdDZKeOHgy0YKCJh7INJX_vxXkjaUBaLddVJcykJIP_nmWPKs_5hoBrP2NImeUcLEfqG2P7OYCm19aEPtjs_WvmubVBu5mlY_8zhlnoRkNL32IGrAyrKezK5gVb-pGhfC5vvIkcaRlWi76YUhPUazUjevLGU-CA2fv_y9kTwd-ryzYSiFEND40R7PncJ1GJm36d-sysuOo9L1osp5ATfJYRZay1ZHwfd7x8SIVOZKIh4AwtyseM5ug4AQk54UHoYUJQ",
      "e": "AQAB"
    },
    {
      "use": "sig",
      "kty": "RSA",
      "kid": "1bd7edb283a8b16adb8cb70723f7e46e650c4d67",
      "alg": "RS256",
      "n": "t3Udy4XgsluOYPBNWfyQ6cg7Ta1hD07EpYJAJZFTsiufJiVSw_7xk1sYWaD8aguliKraeSj_fSu1dOwMrduDiIAz6HLq3jqAhQSkmk67FQwkVyrdouCbEEt4p9gUAy4jMgKPE3rh1z9NhlgJpYan-f8AeR8NL_Jk5pqzkKBzsFR-PnfZZKtl65SoxK1C0iEbIMV9gHZl4cysgsSc70ZQm83eiSzNWuKVVEgVG2EDrh_4AJhjLokVGFF6lp1M92EtP-OZ7nBmgRSWaxdML-G0eaoZpe1myo3oxz-m5bpLWigb9GA19GP7LwPyJ_tqMnit02riA7Li_fr_2xbfH0neKw",
      "e": "AQAB"
    },
    {
      "use": "sig",
      "kty": "RSA",
      "kid": "7cb7d3941fe4293b61d7245f072d516be8ddd64e",
      "alg": "RS256",
      "n": "q6vCJ6fabtEYvELsX7Zha_LKRO3eWgA2T7pl71EkD7CHSKwpueLxW9SqPllEMgPXKwSXL7i087FUbyYqFsHcj4LZokUyFBKNZvylR3_aHIxsE50QBc5kMRxIK0ILUABxx2qzX-KD4JeIztQ_CqyOMhYJyAutWfTJjSZdMzOd6i8gknnOrbTWa8dG0AXVyN9w3vTMI02RTC3VRetVKFnJ1HMaTAB1KNl9ANOIMCwrN1oImcggf-mdTEar9oisP1hJO5Th0k0_zMUWgXilLOYJGKchSkWGSn3UQacWmLlZk3vuISf189nYRrwaYBhlR2qIHCnuoFRl1F3SrkraOIHtFw",
      "e": "AQAB"
    }
  ]
}`

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
	Describe("Construct a static JWKS key Set", func() {
		Context("request to IDP server with valid CA certificate", func() {
			It("request should succeed", func() {
				staticKeySet, err := newStaticKeySet([]byte(jwksdata))
				Expect(err).NotTo(HaveOccurred())
				Expect(staticKeySet).NotTo(BeNil())
				ctx := context.Background()
				jwt := "eyJhbGciOiJSUzI1NiIsImtpZCI6IjViMGE5M2MzYmZmMjVhMzlkYjkyNDZkNGRmZTYwZDQ5NmZkNDFmYTMifQ.eyJpc3MiOiJodHRwczovL2NvbnRyb2wtcGxhbmUubWluaWt1YmUuaW50ZXJuYWw6MzExMzMiLCJzdWIiOiJDaVF3T0dFNE5qZzBZaTFrWWpnNExUUmlOek10T1RCaE9TMHpZMlF4TmpZeFpqVTBOallTQld4dlkyRnMiLCJhdWQiOiJvaWRjLXdlYmhvb2siLCJleHAiOjE2MTk4Nzg2OTMsImlhdCI6MTYxOTc5MjI5Mywibm9uY2UiOiJXZWdhYkJJeTJWV0NKUWpHU3BRbmZrTFlHYzBTdm9oV2dpUkhYMFNxcTlZIiwiYXRfaGFzaCI6Im1hUUlrbzZ3UDNfbk5uRTFfSTZlelEiLCJlbWFpbCI6ImFkbWluQGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJhZG1pbiJ9.YZUkJGnkz_6qONfDNdMzQWYUToB57IuqXpVOBIYuF0AbJ1ZJs6R9fvJRARn2ls6ObEgV6lhsT9ds2D53fAwFN_Q5TW1Ra2qwJGWrpch3p2UQlGk05ksRv9qVm-fJpAYMaBF0mBC0M7fT6ZHC9pfFXG9DxLMSIrwsG_QOOLjPIYO7YweJz5XppcrEwGIQBuI70xlWfWb8SBUHIleEMJHotxpaSuFYeQGKnES-IWsdcnrTN2EOR86wixLhO4UWE998Qj-BvtkP8-k84XVApU0Z6hsErc3IqIMBtw3ljT41JlZEDRI3zbaT46ABNv81D5tZ5rIXV53kb2OXpPzt9581zQ"
				_, err = staticKeySet.VerifySignature(ctx, jwt)

				Expect(err).NotTo(HaveOccurred())
			})
		})
	})
	BeforeEach(func() {
		server = testIDPServer()
	})

	AfterEach(func() {
		server.Close()
	})

	Describe("retrieving the JWKS key Set", func() {
		Context("request to IDP server without valid CA certificate", func() {
			It("request should fail", func() {
				ctx := context.Background()
				keySet, err := remoteKeySet(ctx, server.URL, nil)
				Expect(strings.Contains(err.Error(), "x509: certificate signed by unknown authority")).To(BeTrue())
				Expect(keySet).To(BeNil())
			})
		})
		Context("request to IDP server with valid CA certificate", func() {
			It("request should succeed", func() {
				caCert, err := ioutil.ReadFile("../../cfssl/ca.crt")
				Expect(err).NotTo(HaveOccurred())
				ctx := context.Background()
				keySet, err := remoteKeySet(ctx, server.URL, caCert)
				keySetString := fmt.Sprintf("%#v", keySet)
				Expect(strings.Contains(keySetString, server.URL)).To(BeTrue())
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

func testIDPServer() *httptest.Server {
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
	return server
}
