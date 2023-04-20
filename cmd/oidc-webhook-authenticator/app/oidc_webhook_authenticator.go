// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	goflag "flag"
	"net/http"
	"os"

	authenticationv1alpha1 "github.com/gardener/oidc-webhook-authenticator/apis/authentication/v1alpha1"
	"github.com/gardener/oidc-webhook-authenticator/cmd/oidc-webhook-authenticator/app/options"
	authcontroller "github.com/gardener/oidc-webhook-authenticator/controllers/authentication"
	"github.com/gardener/oidc-webhook-authenticator/webhook/authentication"
	"github.com/gardener/oidc-webhook-authenticator/webhook/metrics"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	genericapifilters "k8s.io/apiserver/pkg/endpoints/filters"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	genericfilters "k8s.io/apiserver/pkg/server/filters"
	"k8s.io/apiserver/pkg/server/healthz"
	"k8s.io/apiserver/pkg/server/mux"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/cli/globalflag"
	"k8s.io/component-base/version/verflag"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// NewOIDCWebhookAuthenticatorCommand is the root command for OIDC webhook authenticator.
func NewOIDCWebhookAuthenticatorCommand(ctx context.Context) *cobra.Command {
	opt := options.NewOptions()
	conf := &options.Config{}
	settupLogger := ctrl.Log.WithName("setup")
	zapOpts := zap.Options{}

	cmd := &cobra.Command{
		Use: "oidc-webhook-authenticator",
		Run: func(cmd *cobra.Command, args []string) {
			verflag.PrintAndExitIfRequested()
			cliflag.PrintFlags(cmd.Flags())

			ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zapOpts)))

			err := opt.ApplyTo(conf)
			if err != nil {
				settupLogger.Error(err, "cannot apply options")

				os.Exit(1)
			}

			err = run(ctx, conf, settupLogger)
			if err != nil {
				settupLogger.Error(err, "cannot run")

				os.Exit(1)
			}
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			var err error

			errors := opt.Validate()
			if len(errors) > 0 {
				err = utilerrors.NewAggregate(errors)
			}

			return err
		},
	}

	fs := cmd.Flags()
	verflag.AddFlags(fs)
	fs.StringSliceVar((*[]string)(&conf.Authentication.APIAudiences), "api-audiences", []string{}, "Identifiers of the API. Tokens used against the API should be bound to at least one of these audiences.")

	opt.AddFlags(fs)
	globalflag.AddGlobalFlags(fs, "global")

	zapOpts.BindFlags(goflag.CommandLine)
	fs.AddGoFlagSet(goflag.CommandLine)

	return cmd
}

func run(ctx context.Context, opts *options.Config, setupLog logr.Logger) error {
	scheme := runtime.NewScheme()

	err := clientgoscheme.AddToScheme(scheme)
	if err != nil {
		return err
	}

	err = authenticationv1alpha1.AddToScheme(scheme)
	if err != nil {
		return err
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: "0",
		Port:               0,
		LeaderElection:     false,
		CertDir:            "",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		return err
	}

	authReconciler := &authcontroller.OpenIDConnectReconciler{
		Client:       mgr.GetClient(),
		Log:          ctrl.Log.WithName("controllers").WithName("OpenIDConnect"),
		Scheme:       mgr.GetScheme(),
		ResyncPeriod: opts.ResyncPeriod.Duration,
	}

	if err = (authReconciler).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenIDConnect")
		return err
	}

	authWH := &authentication.Webhook{
		Authenticator: authReconciler,
		Log:           ctrl.Log.WithName("webhooks").WithName("TokenReview"),
	}

	handler, err := newHandler(opts, authWH, mgr.GetScheme())
	if err != nil {
		setupLog.Error(err, "problem initializing handler")
		return err
	}

	if _, _, err := opts.SecureServing.Serve(handler, 0, ctx.Done()); err != nil {
		setupLog.Error(err, "problem starting secure server")
		return err
	}

	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		return err
	}

	return nil
}

func newHandler(opts *options.Config, authWH *authentication.Webhook, scheme *runtime.Scheme) (http.Handler, error) {
	const (
		authPath       = "/validate-token"
		defaultingPath = "/webhooks/mutating"
		validatingPath = "/webhooks/validating"
		metricsPath    = "/metrics"
	)
	pathRecorder := mux.NewPathRecorderMux("oidc-webhook-authenticator")

	healthz.InstallHandler(pathRecorder, healthz.LogHealthz, healthz.PingHealthz)
	healthz.InstallReadyzHandler(pathRecorder, healthz.LogHealthz, healthz.PingHealthz)
	healthz.InstallLivezHandler(pathRecorder, healthz.LogHealthz, healthz.PingHealthz)

	metricsHandler := promhttp.Handler()
	metricsHandler = withAuthz(metricsHandler, opts)
	pathRecorder.Handle(metricsPath, metricsHandler)

	authHandler := authWH.Build()
	authHandler = withAuthz(authHandler, opts)
	authHandler = metrics.InstrumentedHandler(authPath, authHandler)
	pathRecorder.Handle(authPath, authHandler)

	oidc := &authenticationv1alpha1.OpenIDConnect{}

	defaultingWebhook := admission.DefaultingWebhookFor(oidc)
	if err := defaultingWebhook.InjectLogger(ctrl.Log.WithName("webhooks").WithName("Mutating")); err != nil {
		return nil, err
	}
	if err := defaultingWebhook.InjectScheme(scheme); err != nil {
		return nil, err
	}

	defaultingHandler := withAuthz(defaultingWebhook, opts)
	defaultingHandler = metrics.InstrumentedHandler(defaultingPath, defaultingHandler)
	pathRecorder.Handle(defaultingPath, defaultingHandler)

	validatingWebhook := admission.ValidatingWebhookFor(oidc)
	if err := validatingWebhook.InjectLogger(ctrl.Log.WithName("webhooks").WithName("Validating")); err != nil {
		return nil, err
	}
	if err := validatingWebhook.InjectScheme(scheme); err != nil {
		return nil, err
	}

	validatingHandler := withAuthz(validatingWebhook, opts)
	validatingHandler = metrics.InstrumentedHandler(validatingPath, validatingHandler)
	pathRecorder.Handle(validatingPath, validatingHandler)

	return pathRecorder, nil
}

func withAuthz(handler http.Handler, opts *options.Config) http.Handler {
	var (
		failedHandler       = genericapifilters.Unauthorized(clientgoscheme.Codecs)
		requestInfoResolver = &apirequest.RequestInfoFactory{}
	)

	handler = genericapifilters.WithAuthorization(handler, opts.Authorization.Authorizer, clientgoscheme.Codecs)
	handler = genericapifilters.WithAuthentication(handler, opts.Authentication.Authenticator, failedHandler, opts.Authentication.APIAudiences)
	handler = genericapifilters.WithRequestInfo(handler, requestInfoResolver)
	handler = genericapifilters.WithCacheControl(handler)
	handler = genericfilters.WithPanicRecovery(handler, requestInfoResolver)

	return handler
}
