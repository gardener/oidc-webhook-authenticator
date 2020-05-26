// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime"
	apiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"
)

// Options contain the server options.
type Options struct {
	SecureServing  *genericoptions.SecureServingOptionsWithLoopback
	Authentication *genericoptions.DelegatingAuthenticationOptions
	Authorization  *genericoptions.DelegatingAuthorizationOptions
}

// NewOptions return options with default values.
func NewOptions() *Options {
	// reuse the K8S defaults
	recommended := genericoptions.NewRecommendedOptions("", runtime.NoopDecoder{})

	opts := &Options{
		SecureServing:  recommended.SecureServing,
		Authentication: recommended.Authentication,
		Authorization:  recommended.Authorization,
	}

	opts.Authentication.RemoteKubeConfigFileOptional = true
	opts.Authorization.RemoteKubeConfigFileOptional = true

	opts.SecureServing.ServerCert.CertDirectory = ""
	opts.SecureServing.ServerCert.PairName = "oidc-webhoohook-authenticator"
	opts.SecureServing.BindPort = 10443
	opts.SecureServing.MinTLSVersion = "VersionTLS12"

	return opts
}

// AddFlags adds server options to flagset
func (o *Options) AddFlags(fs *pflag.FlagSet) {
	o.SecureServing.AddFlags(fs)
	o.Authentication.AddFlags(fs)
	o.Authorization.AddFlags(fs)
}

// ApplyTo adds RecommendedOptions to the server configuration.
// pluginInitializers can be empty, it is only need for additional initializers.
func (o *Options) ApplyTo(server *Config) error {
	if err := o.SecureServing.ApplyTo(&server.SecureServing, nil); err != nil {
		return err
	}
	if err := o.Authentication.ApplyTo(&server.Authentication, server.SecureServing, nil); err != nil {
		return err
	}
	if err := o.Authorization.ApplyTo(&server.Authorization); err != nil {
		return err
	}
	return nil
}

// Validate checks if options are valid
func (o *Options) Validate() []error {
	errors := []error{}
	errors = append(errors, o.SecureServing.Validate()...)
	errors = append(errors, o.Authentication.Validate()...)
	errors = append(errors, o.Authorization.Validate()...)

	return errors
}

// Config has all the context to run an OIDC Webhook Authenticator
type Config struct {
	Authentication apiserver.AuthenticationInfo
	Authorization  apiserver.AuthorizationInfo
	SecureServing  *apiserver.SecureServingInfo
}
