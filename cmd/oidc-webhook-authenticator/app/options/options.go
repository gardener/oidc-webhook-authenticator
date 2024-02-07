// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
)

// Options contain the server options.
type Options struct {
	ResyncPeriod   resyncPeriod
	ServingOptions ServingOptions
}

// ServingOptions are options applied to the authentication webhook server.
type ServingOptions struct {
	TLSCertFile                    string
	TLSKeyFile                     string
	ClientCAFile                   string
	AuthenticationAlwaysAllowPaths []string

	Address string
	Port    uint
}

// AddFlags adds server options to flagset
func (s *ServingOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&s.TLSCertFile, "tls-cert-file", s.TLSCertFile, "File containing the x509 Certificate for HTTPS.")
	fs.StringVar(&s.TLSKeyFile, "tls-private-key-file", s.TLSKeyFile, "File containing the x509 private key matching --tls-cert-file.")
	fs.StringVar(&s.ClientCAFile, "client-ca-file", s.ClientCAFile, "If set, any request should present a client certificate signed by one of the authorities in the client-ca-file.")
	fs.StringSliceVar(&s.AuthenticationAlwaysAllowPaths, "authentication-always-allow-paths", s.AuthenticationAlwaysAllowPaths, "A list of HTTP paths that do not require authentication. If authentication is not configured all paths are allowed.")

	fs.StringVar(&s.Address, "address", "", "The IP address that the server will listen on. If unspecified all interfaces will be used.")
	fs.UintVar(&s.Port, "port", 10443, "The port that the server will listen on.")
}

func (s *ServingOptions) Validate() []error {
	errs := []error{}
	if strings.TrimSpace(s.TLSCertFile) == "" {
		errs = append(errs, errors.New("--tls-cert-file is required"))
	}

	if strings.TrimSpace(s.TLSKeyFile) == "" {
		errs = append(errs, errors.New("--tls-private-key-file is required"))
	}

	return errs
}

func (s *ServingOptions) ApplyTo(c *AuthServerConfig) error {
	c.Address = fmt.Sprintf("%s:%s", s.Address, strconv.Itoa(int(s.Port)))
	serverCert, err := tls.LoadX509KeyPair(s.TLSCertFile, s.TLSKeyFile)
	if err != nil {
		return fmt.Errorf("failed to parse authentication server certificates: %w", err)
	}

	c.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}

	if len(s.ClientCAFile) > 0 {
		provider, err := dynamiccertificates.NewDynamicCAContentFromFile("client-ca-bundle", s.ClientCAFile)
		if err != nil {
			return fmt.Errorf("failed to parse authentication server client ca bindle: %w", err)
		}
		c.TLSConfig.ClientAuth = tls.RequestClientCert
		c.ClientCAProvider = provider
	}

	c.AuthenticationAlwaysAllowPaths = map[string]struct{}{}
	for _, p := range s.AuthenticationAlwaysAllowPaths {
		c.AuthenticationAlwaysAllowPaths[p] = struct{}{}
	}

	return nil
}

type resyncPeriod struct {
	Duration time.Duration
}

// NewOptions return options with default values.
func NewOptions() *Options {
	opts := &Options{
		ResyncPeriod: resyncPeriod{},
	}
	return opts
}

// AddFlags adds server options to flagset
func (o *Options) AddFlags(fs *pflag.FlagSet) {
	o.ServingOptions.AddFlags(fs)
	o.ResyncPeriod.AddFlags(fs)
}

func (s *resyncPeriod) AddFlags(fs *pflag.FlagSet) {
	if s == nil {
		return
	}

	fs.DurationVar(&s.Duration, "resync-period", time.Minute*10, "resync period")
}

func (s *resyncPeriod) ApplyTo(c *resyncPeriod) error {
	if s == nil {
		return nil
	}
	c.Duration = s.Duration

	return nil
}

// ApplyTo adds RecommendedOptions to the server configuration.
// pluginInitializers can be empty, it is only need for additional initializers.
func (o *Options) ApplyTo(server *Config) error {
	if err := o.ResyncPeriod.ApplyTo(&server.ResyncPeriod); err != nil {
		return err
	}

	if err := o.ServingOptions.ApplyTo(&server.AuthServerConfig); err != nil {
		return err
	}

	return nil
}

// Validate checks if options are valid
func (o *Options) Validate() []error {
	return o.ServingOptions.Validate()
}

// Config has all the context to run an OIDC Webhook Authenticator
type Config struct {
	ResyncPeriod     resyncPeriod
	AuthServerConfig AuthServerConfig
}

type AuthServerConfig struct {
	TLSConfig                      *tls.Config
	Address                        string
	ClientCAProvider               dynamiccertificates.CAContentProvider
	AuthenticationAlwaysAllowPaths map[string]struct{}
}
