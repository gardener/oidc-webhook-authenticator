// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package env

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/onsi/gomega/gexec"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	utils "github.com/gardener/oidc-webhook-authenticator/test/integration/cert-utils"
)

const (
	envOIDCWebhookAuthenticatorBin = "TEST_ASSET_OIDC_WEBHOOK_AUTHENTICATOR"
)

type oidcWebhookServer struct {
	// Path is the path to the oidc-webhook-authenticator binary, must be set via TEST_ASSET_OIDC_WEBHOOK_AUTHENTICATOR env variable.
	Path string
	// CertDir is the directory where the oidc-webhook-authenticator certificates are stored.
	CertDir       string
	KubeconfigDir string
	CaCert        *utils.Certificate
	ClientCert    *utils.Certificate
	Args          []string
	Out           io.Writer
	Err           io.Writer
	// terminateFunc holds a func that will terminate this OIDC Webhook Server.
	terminateFunc func()
	// exited is a channel that will be closed, when this OIDC Webhook Server exits.
	exited chan struct{}
}

func (s *oidcWebhookServer) configureDefaults(rootDir string) error {
	if s.KubeconfigDir == "" {
		kubeconfigDir, err := os.MkdirTemp(rootDir, "oidc-target-cluster-kubeconfig-")
		if err != nil {
			return err
		}
		s.KubeconfigDir = kubeconfigDir
	}

	if s.CertDir == "" {
		tempDir, err := os.MkdirTemp(rootDir, "oidc-server-certificates-")
		if err != nil {
			return err
		}
		caCertificateConfig := &utils.CertConfig{
			Name:       "oidc-webhook-authenticator",
			CommonName: "oidc-webhook-authenticator",
			CertType:   utils.CACert,
		}
		caCertificate, err := caCertificateConfig.GenerateCertificate()
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(tempDir, "ca.crt"), caCertificate.CertificatePEM, 0644); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(tempDir, "ca.key"), caCertificate.PrivateKeyPEM, 0644); err != nil {
			return err
		}

		certificateConfig := &utils.CertConfig{
			Name:       "oidc-webhook-authenticator",
			CommonName: "oidc-webhook-authenticator",
			DNSNames: []string{
				"localhost",
				"127.0.0.1",
				"oidc-webhook-authenticator",
				"oidc-webhook-authenticator.default",
				"oidc-webhook-authenticator.default.svc",
			},
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
			CertType:    utils.ServerCert,
			SigningCA:   caCertificate,
		}
		certificate, err := certificateConfig.GenerateCertificate()
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(tempDir, "tls.crt"), certificate.CertificatePEM, 0644); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(tempDir, "tls.key"), certificate.PrivateKeyPEM, 0644); err != nil {
			return err
		}

		clientCertConfig := &utils.CertConfig{
			Name:       "oidc-client",
			CommonName: "oidc-client",
			CertType:   utils.ClientCert,
			SigningCA:  caCertificate,
		}
		clientCertificate, err := clientCertConfig.GenerateCertificate()
		if err != nil {
			return err
		}

		s.CaCert = caCertificate
		s.CertDir = tempDir
		s.ClientCert = clientCertificate
	}

	if binPath := os.Getenv(envOIDCWebhookAuthenticatorBin); len(binPath) > 0 {
		s.Path = binPath
	}

	_, err := os.Stat(s.Path)
	if err != nil {
		return fmt.Errorf("failed checking for oidc-webhook-authenticator binary under %q: %w", s.Path, err)
	}

	kubeconfigFile := filepath.Join(s.KubeconfigDir, "kubeconfig.yaml")
	s.Args = append(
		s.Args,
		"--v=2",
		"--tls-cert-file="+filepath.Join(s.CertDir, "tls.crt"),
		"--tls-private-key-file="+filepath.Join(s.CertDir, "tls.key"),
		"--kubeconfig="+kubeconfigFile,
		"--client-ca-file="+filepath.Join(s.CertDir, "ca.crt"),
		"--authentication-skip-paths=/healthz,/readyz",
	)

	return nil
}

func (s *oidcWebhookServer) start() error {
	s.exited = make(chan struct{})
	command := exec.Command(s.Path, s.Args...)
	session, err := gexec.Start(command, s.Out, s.Err)
	if err != nil {
		return err
	}

	s.terminateFunc = func() {
		session.Terminate()
	}

	go func() {
		<-session.Exited
		close(s.exited)
	}()

	return nil
}

func (s *oidcWebhookServer) stop() error {
	var errList []error

	// trigger stop procedure
	if s.terminateFunc != nil {
		s.terminateFunc()

		select {
		case <-s.exited:
			break
		case <-time.After(time.Second * 20):
			errList = append(errList, fmt.Errorf("timeout waiting for oidc-webhook-authenticator to stop"))
		}
	}

	// cleanup temp dirs
	if s.CertDir != "" {
		if err := os.RemoveAll(s.CertDir); err != nil {
			errList = append(errList, err)
		}
	}

	if s.KubeconfigDir != "" {
		if err := os.RemoveAll(s.KubeconfigDir); err != nil {
			errList = append(errList, err)
		}
	}

	return utilerrors.NewAggregate(errList)
}
