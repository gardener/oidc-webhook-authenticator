// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	oidc "github.com/coreos/go-oidc"
	"k8s.io/apimachinery/pkg/util/net"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/klog/v2"
)

type OptionsForked struct {
	Options

	// PEM encoded root certificate of the provider.
	CA []byte
}

func NewForkedAuthenticator(opts OptionsForked) (*Authenticator, error) {
	url, err := url.Parse(opts.IssuerURL)
	if err != nil {
		return nil, err
	}

	if url.Scheme != "https" {
		return nil, fmt.Errorf("'oidc-issuer-url' (%q) has invalid scheme (%q), require 'https'", opts.IssuerURL, url.Scheme)
	}

	if opts.UsernameClaim == "" {
		return nil, errors.New("no username claim provided")
	}

	supportedSigningAlgs := opts.SupportedSigningAlgs
	if len(supportedSigningAlgs) == 0 {
		// RS256 is the default recommended by OpenID Connect and an 'alg' value
		// providers are required to implement.
		supportedSigningAlgs = []string{oidc.RS256}
	}
	for _, alg := range supportedSigningAlgs {
		if !allowedSigningAlgs[alg] {
			return nil, fmt.Errorf("oidc: unsupported signing alg: %q", alg)
		}
	}

	var roots *x509.CertPool
	if len(opts.CA) > 0 {
		roots, err = certutil.NewPoolFromBytes(opts.CA)
		if err != nil {
			return nil, fmt.Errorf("Failed to read the CA file: %v", err)
		}
	} else {
		klog.Info("OIDC: No x509 certificates provided, will use host's root CA set")
	}

	// Copied from http.DefaultTransport.
	tr := net.SetTransportDefaults(&http.Transport{
		// According to golang's doc, if RootCAs is nil,
		// TLS uses the host's root CA set.
		TLSClientConfig: &tls.Config{RootCAs: roots},
	})

	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}

	ctx, cancel := context.WithCancel(context.Background())
	ctx = oidc.ClientContext(ctx, client)

	now := opts.now
	if now == nil {
		now = time.Now
	}

	verifierConfig := &oidc.Config{
		ClientID:             opts.ClientID,
		SupportedSigningAlgs: supportedSigningAlgs,
		Now:                  now,
	}

	var resolver *claimResolver
	if opts.GroupsClaim != "" {
		resolver = newClaimResolver(opts.GroupsClaim, client, verifierConfig)
	}

	authenticator := &Authenticator{
		issuerURL:      opts.IssuerURL,
		usernameClaim:  opts.UsernameClaim,
		usernamePrefix: opts.UsernamePrefix,
		groupsClaim:    opts.GroupsClaim,
		groupsPrefix:   opts.GroupsPrefix,
		requiredClaims: opts.RequiredClaims,
		cancel:         cancel,
		resolver:       resolver,
	}

	provider, err := oidc.NewProvider(ctx, authenticator.issuerURL)
	if err != nil {
		klog.Errorf("oidc authenticator: initializing plugin: %v", err)
		return nil, err
	}

	verifier := provider.Verifier(verifierConfig)
	authenticator.setVerifier(verifier)

	return authenticator, nil
}
