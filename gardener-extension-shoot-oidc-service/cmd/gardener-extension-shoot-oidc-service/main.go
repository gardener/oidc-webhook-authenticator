// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"

	"github.com/gardener/oidc-webhook-authenticator/gardener-extension-shoot-oidc-service/cmd/gardener-extension-shoot-oidc-service/app"

	controllercmd "github.com/gardener/gardener/extensions/pkg/controller/cmd"
	"github.com/gardener/gardener/extensions/pkg/log"
	runtimelog "sigs.k8s.io/controller-runtime/pkg/log"
)

func main() {
	runtimelog.SetLogger(log.ZapLogger(false))

	ctx := signals.SetupSignalHandler()
	if err := app.NewServiceControllerCommand().ExecuteContext(ctx); err != nil {
		controllercmd.LogErrAndExit(err, "error executing the main controller command")
	}
}
