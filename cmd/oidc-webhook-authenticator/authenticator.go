// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	"github.com/gardener/oidc-webhook-authenticator/cmd/oidc-webhook-authenticator/app"
	"github.com/spf13/pflag"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/logs"
	_ "k8s.io/component-base/metrics/prometheus/clientgo"
	_ "k8s.io/component-base/metrics/prometheus/version" // for version metric registration
	ctrl "sigs.k8s.io/controller-runtime"
)

func main() {
	cmd := app.NewOIDCWebhookAuthenticatorCommand(ctrl.SetupSignalHandler())

	pflag.CommandLine.SetNormalizeFunc(cliflag.WordSepNormalizeFunc)
	// utilflag.InitFlags()
	logs.InitLogs()
	defer logs.FlushLogs()

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
