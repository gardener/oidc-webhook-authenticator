// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package env

import (
	"fmt"
	"os"
	"path/filepath"

	"sigs.k8s.io/controller-runtime/pkg/envtest"

	utils "github.com/gardener/oidc-webhook-authenticator/test/integration/cert-utils"
)

// AggregatorConfig is able to configure the kube-aggregator (kube-apiserver aggregation layer)
// by provisioning the front-proxy certs and setting the corresponding flags on the kube-apiserver.
type AggregatorConfig struct {
	certDir string
}

// ConfigureAPIServerArgs generates the needed certs, writes them to the given directory and configures args
// to point to the generated certs.
func (a AggregatorConfig) ConfigureAPIServerArgs(certDir string, args *envtest.Arguments) error {
	a.certDir = certDir

	if err := a.generateCerts(); err != nil {
		return err
	}

	args.
		Set("requestheader-extra-headers-prefix", "X-Remote-Extra-").
		Set("requestheader-group-headers", "X-Remote-Group").
		Set("requestheader-username-headers", "X-Remote-User").
		Set("requestheader-client-ca-file", a.caCrtPath()).
		Set("proxy-client-cert-file", a.clientCrtPath()).
		Set("proxy-client-key-file", a.clientKeyPath())

	return nil
}

func (a AggregatorConfig) caCrtPath() string {
	return filepath.Join(a.certDir, "proxy-ca.crt")
}

func (a AggregatorConfig) clientCrtPath() string {
	return filepath.Join(a.certDir, "proxy-client.crt")
}

func (a AggregatorConfig) clientKeyPath() string {
	return filepath.Join(a.certDir, "proxy-client.key")
}

func (a AggregatorConfig) generateCerts() error {
	caConfig := &utils.CertConfig{
		Name:       "front-proxy",
		CommonName: "front-proxy",
		CertType:   utils.CACert,
	}

	ca, err := caConfig.GenerateCertificate()
	if err != nil {
		return err
	}
	if err := os.WriteFile(a.caCrtPath(), ca.CertificatePEM, 0640); err != nil {
		return fmt.Errorf("unable to save the proxy client CA certificate to %s: %w", a.caCrtPath(), err)
	}

	clientConfig := &utils.CertConfig{
		Name:       "front-proxy",
		CommonName: "front-proxy",
		CertType:   utils.ClientCert,
		SigningCA:  ca,
	}

	clientCert, err := clientConfig.GenerateCertificate()
	if err != nil {
		return err
	}
	if err := os.WriteFile(a.clientCrtPath(), clientCert.CertificatePEM, 0640); err != nil {
		return fmt.Errorf("unable to save the proxy client certificate to %s: %w", a.clientCrtPath(), err)
	}
	if err := os.WriteFile(a.clientKeyPath(), clientCert.PrivateKeyPEM, 0640); err != nil {
		return fmt.Errorf("unable to save the proxy client key to %s: %w", a.clientKeyPath(), err)
	}

	return nil
}
