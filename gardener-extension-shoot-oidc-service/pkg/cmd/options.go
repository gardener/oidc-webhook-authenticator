// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"io/ioutil"

	"github.com/gardener/gardener/extensions/pkg/controller/cmd"
	extensionshealthcheckcontroller "github.com/gardener/gardener/extensions/pkg/controller/healthcheck"
	healthcheckconfig "github.com/gardener/gardener/extensions/pkg/controller/healthcheck/config"
	webhookcmd "github.com/gardener/gardener/extensions/pkg/webhook/cmd"
	apisconfig "github.com/gardener/oidc-webhook-authenticator/gardener-extension-shoot-oidc-service/pkg/apis/config"
	"github.com/gardener/oidc-webhook-authenticator/gardener-extension-shoot-oidc-service/pkg/apis/config/v1alpha1"
	controllerconfig "github.com/gardener/oidc-webhook-authenticator/gardener-extension-shoot-oidc-service/pkg/controller/config"
	healthcheckcontroller "github.com/gardener/oidc-webhook-authenticator/gardener-extension-shoot-oidc-service/pkg/controller/healthcheck"
	"github.com/gardener/oidc-webhook-authenticator/gardener-extension-shoot-oidc-service/pkg/controller/lifecycle"
	webhook "github.com/gardener/oidc-webhook-authenticator/gardener-extension-shoot-oidc-service/pkg/webhook/kapiserver"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

const (
	webhookName = "oidc"
)

// WebhookSwitchOptions are the webhookcmd.SwitchOptions for the oidc webhooks.
func WebhookSwitchOptions() *webhookcmd.SwitchOptions {
	return webhookcmd.NewSwitchOptions(
		webhookcmd.Switch(webhookName, webhook.New),
	)
}

var (
	scheme  *runtime.Scheme
	decoder runtime.Decoder
)

func init() {
	scheme = runtime.NewScheme()
	utilruntime.Must(apisconfig.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))

	decoder = serializer.NewCodecFactory(scheme).UniversalDecoder()
}

// OIDCServiceOptions holds options related to the OIDC service.
type OIDCServiceOptions struct {
	ConfigLocation string
	config         *OIDCServiceConfig
}

// AddFlags implements Flagger.AddFlags.
func (o *OIDCServiceOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.ConfigLocation, "config", "", "Path to oidc service configuration")
}

// Complete implements Completer.Complete.
func (o *OIDCServiceOptions) Complete() error {
	if o.ConfigLocation == "" {
		return errors.New("config location is not set")
	}
	data, err := ioutil.ReadFile(o.ConfigLocation)
	if err != nil {
		return err
	}

	config := apisconfig.Configuration{}
	_, _, err = decoder.Decode(data, nil, &config)
	if err != nil {
		return err
	}

	// TODO Validate configuration

	o.config = &OIDCServiceConfig{
		config: config,
	}

	return nil
}

// Completed returns the decoded OIDCServiceConfiguration instance. Only call this if `Complete` was successful.
func (o *OIDCServiceOptions) Completed() *OIDCServiceConfig {
	return o.config
}

// OIDCServiceConfig contains configuration information about the OIDC service.
type OIDCServiceConfig struct {
	config apisconfig.Configuration
}

// Apply applies the OIDCServiceOptions to the passed ControllerOptions instance.
func (c *OIDCServiceConfig) Apply(config *controllerconfig.Config) {
	config.Configuration = c.config
}

func (c *OIDCServiceConfig) ApplyHealthCheckConfig(config *healthcheckconfig.HealthCheckConfig) {
	if c.config.HealthCheckConfig != nil {
		*config = *c.config.HealthCheckConfig
	}
}

// ControllerSwitches are the cmd.ControllerSwitches for the provider controllers.
func ControllerSwitches() *cmd.SwitchOptions {
	return cmd.NewSwitchOptions(
		cmd.Switch(lifecycle.Name, lifecycle.AddToManager),
		cmd.Switch(extensionshealthcheckcontroller.ControllerName, healthcheckcontroller.AddToManager),
	)
}
