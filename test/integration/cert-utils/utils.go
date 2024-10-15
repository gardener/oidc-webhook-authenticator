// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package certutils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"
)

const (
	// PKCS1 certificate format
	PKCS1 = iota
	// PKCS8 certificate format
	PKCS8
)

const (
	// CACert indicates that the certificate should be a certificate authority.
	CACert string = "ca"
	// ServerCert indicates that the certificate should have the ExtKeyUsageServerAuth usage.
	ServerCert string = "server"
	// ClientCert indicates that the certificate should have the ExtKeyUsageClientAuth usage.
	ClientCert string = "client"
	// ServerClientCert indicates that the certificate should have both the ExtKeyUsageServerAuth and ExtKeyUsageClientAuth usage.
	ServerClientCert string = "both"
)

// CertConfig contains configurations depending on which a certificate can be generated.
type CertConfig struct {
	Name string

	CommonName   string
	Organization []string
	DNSNames     []string
	IPAddresses  []net.IP

	CertType  string
	Validity  *time.Duration
	SigningCA *Certificate
	PKCS      int
}

// Certificate contains a [x509.Certificate].
type Certificate struct {
	Name string

	CA *Certificate

	PrivateKey    *rsa.PrivateKey
	PrivateKeyPEM []byte

	Certificate    *x509.Certificate
	CertificatePEM []byte
}

// GenerateCertificate generates a certificate depending on the provided certificate configuration.
func (s *CertConfig) GenerateCertificate() (*Certificate, error) {
	certificateObj := &Certificate{
		Name: s.Name,
		CA:   s.SigningCA,
	}

	// If no cert type is given then we only return a certificate object that contains the CA.
	if s.CertType != "" {
		privateKey, err := generateRSAPrivateKey(2048)
		if err != nil {
			return nil, err
		}

		var (
			certificate       = s.generateCertificateTemplate()
			certificateSigner = certificate
			privateKeySigner  = privateKey
		)

		if s.SigningCA != nil {
			certificateSigner = s.SigningCA.Certificate
			privateKeySigner = s.SigningCA.PrivateKey
		}

		certificatePEM, err := signCertificate(certificate, privateKey, certificateSigner, privateKeySigner)
		if err != nil {
			return nil, err
		}

		var pk []byte
		if s.PKCS == PKCS1 {
			pk = pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
			})
		} else if s.PKCS == PKCS8 {
			bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
			if err != nil {
				return nil, err
			}
			pk = pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: bytes,
			})
		}

		certificateObj.PrivateKey = privateKey
		certificateObj.PrivateKeyPEM = pk
		certificateObj.Certificate = certificate
		certificateObj.CertificatePEM = certificatePEM
	}

	return certificateObj, nil
}

// generateRSAPrivateKey generates a RSA private for the given number of <bits>.
func generateRSAPrivateKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

func (s *CertConfig) generateCertificateTemplate() *x509.Certificate {
	var (
		serialNumber, _ = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		isCA            = s.CertType == CACert

		template = &x509.Certificate{
			BasicConstraintsValid: true,
			IsCA:                  isCA,
			SerialNumber:          serialNumber,
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(0, 0, 2),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			Subject: pkix.Name{
				CommonName:   s.CommonName,
				Organization: s.Organization,
			},
			DNSNames:    s.DNSNames,
			IPAddresses: s.IPAddresses,
		}
	)

	switch s.CertType {
	case CACert:
		template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	case ServerCert:
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case ClientCert:
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case ServerClientCert:
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	return template
}

func signCertificate(certificateTemplate *x509.Certificate, privateKey *rsa.PrivateKey, certificateTemplateSigner *x509.Certificate, privateKeySigner *rsa.PrivateKey) ([]byte, error) {
	certificate, err := x509.CreateCertificate(rand.Reader, certificateTemplate, certificateTemplateSigner, &privateKey.PublicKey, privateKeySigner)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate,
	}), nil
}
