// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package mock

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	utils "github.com/gardener/oidc-webhook-authenticator/test/integration/cert-utils"
)

const (
	wellKnownResponseTemplate = `{
	"issuer": "%[1]s",
	"authorization_endpoint": "%[1]s/auth",
	"token_endpoint": "%[1]s/token",
	"jwks_uri": "%[1]s/keys",
	"userinfo_endpoint": "%[1]s/userinfo",
	"id_token_signing_alg_values_supported": ["RS256"]
}`
)

type OIDCIdentityServer struct {
	Name             string
	certificate      *utils.Certificate
	privateKeys      []jose.JSONWebKey
	publicWebKeySet  *jose.JSONWebKeySet
	certDir          string
	server           *http.Server
	ServerSecurePort int
}

func NewIdentityServer(name string, numberOfPrivateKeys int) (*OIDCIdentityServer, error) {
	caCertificateConfig := &utils.CertConfig{
		Name:       name,
		CommonName: name,
		CertType:   utils.CACert,
	}
	caCertificate, err := caCertificateConfig.GenerateCertificate()
	if err != nil {
		return nil, err
	}

	certificateConfig := &utils.CertConfig{
		Name:       "oidc-webhook-authenticator",
		CommonName: "oidc-webhook-authenticator",
		DNSNames: []string{
			"localhost",
			"127.0.0.1",
		},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		CertType:    utils.ServerCert,
		SigningCA:   caCertificate,
	}
	certificate, err := certificateConfig.GenerateCertificate()
	if err != nil {
		return nil, err
	}

	keySet := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{},
	}

	privateKeys := []jose.JSONWebKey{}
	for i := 0; i < numberOfPrivateKeys; i++ {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}

		privateKey := jose.JSONWebKey{Key: key, KeyID: "", Algorithm: string(jose.RS256), Use: "sig"}
		thumb, err := privateKey.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, err
		}
		kid := base64.URLEncoding.EncodeToString(thumb)
		privateKey.KeyID = kid

		privateKeys = append(privateKeys, privateKey)
		publicKey := jose.JSONWebKey{Key: key.Public(), KeyID: privateKey.KeyID, Algorithm: string(jose.RS256), Use: "sig"}
		keySet.Keys = append(keySet.Keys, publicKey)
	}

	return &OIDCIdentityServer{
		Name:            name,
		certificate:     certificate,
		privateKeys:     privateKeys,
		publicWebKeySet: keySet,
	}, nil
}

func (idp *OIDCIdentityServer) Start() error {
	certDir, err := os.MkdirTemp("", "mock-identity-provider-")
	if err != nil {
		return err
	}

	idp.certDir = certDir

	certFile := filepath.Join(certDir, "tls.crt")
	err = os.WriteFile(certFile, idp.certificate.CertificatePEM, 0640)
	if err != nil {
		return err
	}

	keyFile := filepath.Join(certDir, "tls.key")
	err = os.WriteFile(keyFile, idp.certificate.PrivateKeyPEM, 0640)
	if err != nil {
		return err
	}

	port, err := suggestLocalPort()
	if err != nil {
		return err
	}
	idp.ServerSecurePort = port
	idp.server = &http.Server{Addr: fmt.Sprintf("localhost:%v", port), Handler: idp.buildHandler()}

	go func() {
		if err := idp.server.ListenAndServeTLS(certFile, keyFile); err != http.ErrServerClosed {
			fmt.Printf("Could not start mock identity provider server: %v \n", err)
		}
	}()
	return nil
}

func (idp *OIDCIdentityServer) Stop(ctx context.Context) error {
	err := idp.server.Shutdown(ctx)
	if err != nil {
		return err
	}

	if idp.certDir != "" {
		if err := os.RemoveAll(idp.certDir); err != nil {
			return err
		}
	}

	return nil
}

func (idp *OIDCIdentityServer) buildHandler() http.Handler {
	handler := http.NewServeMux()
	handler.HandleFunc("/.well-known/openid-configuration", idp.buildWellKnownHandler())
	handler.HandleFunc("/keys", idp.buildJWKSHandler())

	return handler
}

func (idp *OIDCIdentityServer) buildWellKnownHandler() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		host := fmt.Sprintf("https://localhost:%v", idp.ServerSecurePort)
		wellKnown := fmt.Sprintf(wellKnownResponseTemplate, host)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Write([]byte(wellKnown))
	}
}

func (idp *OIDCIdentityServer) buildJWKSHandler() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		jwks, err := json.Marshal(idp.publicWebKeySet)
		if err != nil {
			w.WriteHeader(500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Write(jwks)
	}
}

func suggestLocalPort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort("localhost", "0"))
	if err != nil {
		return -1, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return -1, err
	}

	port := l.Addr().(*net.TCPAddr).Port
	err = l.Close()
	if err != nil {
		return -1, err
	}

	return port, nil
}

func (idp *OIDCIdentityServer) Sign(idx int, claims interface{}) (string, error) {
	if idx < 0 || idx >= len(idp.privateKeys) {
		return "", fmt.Errorf("index out of boundaries")
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: idp.privateKeys[idx]}, (&jose.SignerOptions{}).WithType("JWT"))

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

func (idp *OIDCIdentityServer) CA() []byte {
	return idp.certificate.CA.CertificatePEM
}

func (idp *OIDCIdentityServer) PublicKeySetAsBytes() ([]byte, error) {
	jwks, err := json.Marshal(idp.publicWebKeySet)
	if err != nil {
		return nil, err
	}
	return jwks, nil
}
