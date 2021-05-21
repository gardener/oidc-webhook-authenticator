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
	issuerURL       string
}

func (mock *mockAuthRequestHandler) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	return &authenticator.Response{User: mock.returnUser}, mock.isAuthenticated, mock.err
}

var user1 = &user.DefaultInfo{Name: "fresh_ferret", UID: "alfa"}
var user2 = &user.DefaultInfo{Name: "elegant_sheep", UID: "bravo"}
var server *httptest.Server
var payloadString = `{"iss":"https://control-plane.minikube.internal:31133","sub":"CiQwOGE4Njg0Yi1kYjg4LTRiNzMtOTBhOS0zY2QxNjYxZjU0NjYSBWxvY2Fs","aud":"oidc-webhook","exp":1620082901,"iat":1619996501,"nonce":"5tBc_OEvRo0rQd1Of5blBw5iamNQSP08_YfS3Nn64qw","at_hash":"KNgnpzE_KIS60exlG8aRhA","email":"admin@example.com","email_verified":true,"name":"admin"}`
var jwtValid = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImQ5ZTBjMDc5MjVkNTRkY2M1MWJiYzViYWIwZDU3MWYyM2IwYmUyZWMifQ.eyJpc3MiOiJodHRwczovL2NvbnRyb2wtcGxhbmUubWluaWt1YmUuaW50ZXJuYWw6MzExMzMiLCJzdWIiOiJDaVF3T0dFNE5qZzBZaTFrWWpnNExUUmlOek10T1RCaE9TMHpZMlF4TmpZeFpqVTBOallTQld4dlkyRnMiLCJhdWQiOiJvaWRjLXdlYmhvb2siLCJleHAiOjE2MjAwODI5MDEsImlhdCI6MTYxOTk5NjUwMSwibm9uY2UiOiI1dEJjX09FdlJvMHJRZDFPZjVibEJ3NWlhbU5RU1AwOF9ZZlMzTm42NHF3IiwiYXRfaGFzaCI6IktOZ25wekVfS0lTNjBleGxHOGFSaEEiLCJlbWFpbCI6ImFkbWluQGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJhZG1pbiJ9.NkAeXMioHPeaqDcq-0364m4squnfkLx-jFXsdDBnfQwykSFOIKltisoQ-Eb4VsTQQ-fS0crkBWuKoEj_TAK3MHOZ9tqkm8NLNpDwxIiz3B81Se8tBoRqM33n_jjl3tE_Ho8-eJj2u4i3JIJ3_25RmcR-jjCIX-JWqs_yM3mh7vh3kNeTsIpoSAjzIcgbvTHZOqTrjJbmMUp72fDGdariEfiumoLtQ4LyHIpIcFpKAIDuoTbAyWwaIlXZHmPGmgkFEgZNiWlF5V8XX9e_RsTdXLI6d16jxczViPVH7FumTn7U9Lx9YiEZwDMN5X7Ym8ZnuTTDFrBXQwhDlV_yIIN0yg"
var jwtInvalid = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImQ5ZTBjMDc5MjVkNTRkY2M1MWJiYzViYWIwZDU3MWYyM2IwZmQzMiJ9.eyJpc3MiOiJodHRwczovL2NvbnRyb2wtcGxhbmUubWluaWt1YmUuaW50ZXJuYWw6MzExMzMiLCJzdWIiOiJDaVF3T0dFNE5qZzBZaTFrWWpnNExUUmlOek10T1RCaE9TMHpZMlF4TmpZeFpqVTBOallTQld4dlkyRnMiLCJhdWQiOiJvaWRjLXdlYmhvb2siLCJleHAiOjE2MjAwODI5MDEsImlhdCI6MTYxOTk5NjUwMSwibm9uY2UiOiI1dEJjX09FdlJvMHJRZDFPZjVibEJ3NWlhbU5RU1AwOF9ZZlMzTm42NHF3IiwiYXRfaGFzaCI6IktOZ25wekVfS0lTNjBleGxHOGFSaEEiLCJlbWFpbCI6ImFkbWluQGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJhZG1pbiJ9.JYPysQVYHkE_ArZ9JHQCRfCJ4pPb4WYl5GZAi7PjNmJ7SfqS-MMLuBxDOnDiypWVYHYijTRsHYVBPx2HKijiNomAPwLswZFZcjjcSqGksnhS1XbLQYHM-rl3M6n31d2ILTDwi5gPXOpzYl1b_OcxngVLDs1u_6Gg1hhD6dSfAJyL4NTzKkC0VVTO1VIFNWVVziGexyVG_rPNQngyOxLj3liATJ6l3fEDl4giDwv3IIUkIyhIiymYYIKCoxf28wtUBvjkfavOuHYtqZ2Z6BL5qhxjbNtjXXLUppMY4MJBG47t9mp6OyxyGcGWZySoJcH5BaYyvALWQWxeIaClOyh2LdWiG57qUkoYSZOD8OYp_gyGgG7Rk7zsjwRkZkujx5uc88blpE3bGtQ7zGmERt6ETyR69KHGYiWEZDxWwP6YlBXJ0K4NKV-7gfcobvZRg-GdKToLTA0pvGA0mbdZUvAvjZ5aU10ydsd4cUFGMzlMI0wyyJYf9VzM85VSCQvgQJ0PH0zfPFH_A5DsU6Y7Aozismq17xdFugqIKmsKlrhtU90voUjRLYOUQWTGpiI8E7EIYgHYTLB-x4ob6YgXEjZEBuzpZSmuLw6tfnSN3BM6JUixdt1auRVtAHrWFrji0EGO_CSgr0yYH9qoZ1aSz_P0UEBSAQY2NkR6CM25a4_nIJ8"
var jwksdata = `{
  "keys": [
    {
      "use": "sig",
      "kty": "RSA",
      "kid": "d9e0c07925d54dcc51bbc5bab0d571f23b0be2ec",
      "alg": "RS256",
      "n": "sx8JV3TjVZ1AaRUSaJEvikz-ZV_p5KB4dX7DHW7qdtNVTnwMtzW0vFHS43PBow_kfGJhiqi5ccnu9MecSS8dRTZ4lAkZomlPDZKQxocC1lPRHZD3bKj0kbLaKOBPJ2VHSnrZsrN3GfR8qhluX1aPe2hfTIiqxjV9y7ZLFFMBoMKDDaI2IncNAJXVPz18pymWiLcQbr_M9FZ8OimvzbslZ3A3JD2-vgmmSmeEz3avHruJmmH3nKqM5CSWKOEH8S4I0z9wHn87JWA803_wq49h7O_y2ybiNzDp0gtlP2UuGV_rneUp3v_Xh0J13jcKPZBKm_Q6C8tGdvWCUyCC8r7LpQ",
      "e": "AQAB"
    },
    {
      "use": "sig",
      "kty": "RSA",
      "kid": "ab9087a5d0554b63a8382e876056fc5c55498952",
      "alg": "RS256",
      "n": "yPEgUfxQTcIS48IMSqO7VB9QnsNqUhNQI-OBkRnN3raDxvsWTRVjVa7UJIg4OVwRYIoANpCau_iAfrbRCZMrRHGboUVqMXc1vP1hj_ccezkE5DWjAmfza9jLnCbgUV76p7d_DdKgyUTzCDgLN07VLbZyxyAVsXJ8x1_pv8CT0v4hsAQ93ER3NBJ1-_narfygEJKCmI91AuTF3YzbOai2Cd-ZXlkOShMhJKaKP96uawpfE2mreUMQ2Ff9wh73mLMOZ5LSfD29qonduP3thU0Xp7V23ErrMa1Z_2FJhKuH1EQ0RpBRIUekk5cQqPz5zYGlsaKJv9t6UaEQigdvShjK7w",
      "e": "AQAB"
    },
    {
      "use": "sig",
      "kty": "RSA",
      "kid": "c509400bcc0256750753bbea8d46ee5f27016957",
      "alg": "RS256",
      "n": "2e61tRW9IfGpAmqrqyZS15EDFm1bjlwRq6J5RTYGnBcflQGpgnPhc7RjaA7PgpULFAZjq8UWzn33jTUVOGLEiF72Vc7cWiDhn_MrEcHUTP1XGTtCNKP18c92PhqWuRzTHeJZYvBZBynwrW-4Wfnti_uomVc85-JT_POB0EZfA6thTi9c_5G2wLv56k3WDkVsm8vbPzXFtTI5SDdXKe19GDbeXFhV96z3wtthSTST7M7MwVW-Dy18ll6gvxQgaUf5OGhx-HjiThTvfkfGIgYqHmDb8d9DDbUs4R6RijU3Docj7AWYgF0_A5deiW4lt0s5ZRBCtK3IMM9SoMkPyfm4_w",
      "e": "AQAB"
    },
    {
      "use": "sig",
      "kty": "RSA",
      "kid": "9c94d9f1899ca25d03473357814b6c3107e28ac3",
      "alg": "RS256",
      "n": "1wXiR7uaZ0svadMYZZulKOWmadFTUt1ul9UrEm5hpCc2TbOnEqaQDStsdYMC9k8hEPTwtEPZFUSxTdYYNnEN8HcF_TWDODx_GO__3NMtuaru65It6v33_rLp9P_Ij9f-UlFg13JImsWqNDT0NALe7eiUjUtPrjWIdWY9SA6Sc5LCVy-1YatvMWUzb_wvo-nOD5XiSzbGu_z_TrvSSm7IRQVv0it-Vu38U3tFKUv6v5vXiBKuLnP49sUToFK480kyd_OwYPclpHCUhznAjF0psQ8as51NiVQpGDsHwAsO6Wd3kfP7tpPpk1ZkJysRC8_aMjRL3seaREE3DiNnQ0RegQ",
      "e": "AQAB"
    }
  ]
}`

var _ = Describe("OpenIDConnect controller", func() {

	Describe("Authentication with Token Authentication handlers", func() {
		Context("First Token Authenticator Handler Passes", func() {
			It("Authentication should succeed", func() {

				handler1 := &mockAuthRequestHandler{returnUser: user1, isAuthenticated: true}
				handler2 := &mockAuthRequestHandler{returnUser: user2, isAuthenticated: false, issuerURL: "https://invalid"}
				authRequestHandler := StoreAuthTokenHandler(handler1, handler2)

				resp, isAuthenticated, err := authRequestHandler.AuthenticateToken(context.Background(), jwtValid)
				Expect(err).NotTo(HaveOccurred())

				Expect(isAuthenticated).Should(BeTrue())

				Expect(user1.GetName()).Should(Equal(resp.User.GetName()))

			})
		})

		Context("Second Token Authenticator Handler Passes", func() {
			It("Authentication should succeed", func() {
				handler1 := &mockAuthRequestHandler{returnUser: user1, isAuthenticated: false, issuerURL: "https://invalid"}
				handler2 := &mockAuthRequestHandler{returnUser: user2, isAuthenticated: true}
				authRequestHandler := StoreAuthTokenHandler(handler1, handler2)

				resp, isAuthenticated, err := authRequestHandler.AuthenticateToken(context.Background(), jwtValid)
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

				resp, isAuthenticated, err := authRequestHandler.AuthenticateToken(context.Background(), jwtValid)
				Expect(err).NotTo(HaveOccurred())

				Expect(isAuthenticated).Should(BeFalse())

				Expect(resp).To(BeNil())
			})
		})

		Context("No Token Authenticator Handler available", func() {
			It("Authentication should fail", func() {

				authRequestHandler := StoreAuthTokenHandler()
				resp, isAuthenticated, err := authRequestHandler.AuthenticateToken(context.Background(), jwtValid)
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

				resp, isAuthenticated, err := authRequestHandler.AuthenticateToken(context.Background(), jwtValid)
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

				resp, isAuthenticated, err := authRequestHandler.AuthenticateToken(context.Background(), jwtValid)
				Expect(err).NotTo(HaveOccurred())

				Expect(isAuthenticated).Should(BeFalse())

				Expect(resp).To(BeNil())
			})
		})
	})

	Describe("Construct a static JWKS key Set", func() {
		Context("VerifySignature of a valid jwt", func() {
			It("verification should succeed", func() {
				staticKeySet, err := newStaticKeySet([]byte(jwksdata))
				Expect(err).NotTo(HaveOccurred())
				Expect(staticKeySet).NotTo(BeNil())
				ctx := context.Background()
				payload, err := staticKeySet.VerifySignature(ctx, jwtValid)
				Expect(err).NotTo(HaveOccurred())
				Expect(payload).Should(Equal([]byte(payloadString)))
			})
		})
		Context("Verify Signature of an invalid jwt", func() {
			It("verification should fail", func() {
				staticKeySet, err := newStaticKeySet([]byte(jwksdata))
				Expect(err).NotTo(HaveOccurred())
				Expect(staticKeySet).NotTo(BeNil())
				ctx := context.Background()
				_, err = staticKeySet.VerifySignature(ctx, jwtInvalid)
				Expect(err).To(HaveOccurred())
				Expect(strings.Contains(err.Error(), "no keys matches jwk keyid")).To(BeTrue())
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

func StoreAuthTokenHandler(authTokenHandlers ...*mockAuthRequestHandler) unionAuthTokenHandler {
	union := unionAuthTokenHandler{}
	var defaultIssuerURL string = "https://control-plane.minikube.internal:31133"

	for _, auth := range authTokenHandlers {
		uuid := uuid.NewUUID()
		if len(auth.issuerURL) == 0 {
			auth.issuerURL = defaultIssuerURL
		}

		union.handlers.Store(string(uuid), &authenticatorInfo{
			Token: auth,
			name:  string(uuid),
			uid:   uuid,
		})
		union.issuerURL.Store(auth.issuerURL, string(uuid))
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
