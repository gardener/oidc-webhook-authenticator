// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	goflag "flag"
	"net/http"
	"os"

	"github.com/gardener/oidc-webhook-authenticator/cmd/oidc-webhook-authenticator/app/options"
	"github.com/gardener/oidc-webhook-authenticator/webhook/authentication"
	"github.com/gardener/oidc-webhook-authenticator/webhook/metrics"
	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	genericapifilters "k8s.io/apiserver/pkg/endpoints/filters"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	genericfilters "k8s.io/apiserver/pkg/server/filters"
	"k8s.io/apiserver/pkg/server/healthz"
	"k8s.io/apiserver/pkg/server/mux"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/cli/globalflag"
	"k8s.io/component-base/version/verflag"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	authenticationv1alpha1 "github.com/gardener/oidc-webhook-authenticator/apis/authentication/v1alpha1"
	authcontroller "github.com/gardener/oidc-webhook-authenticator/controllers/authentication"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// NewOIDCWebhookAuthenticatorCommand is the root command for OIDC webhook authenticator.
func NewOIDCWebhookAuthenticatorCommand(ctx context.Context) *cobra.Command {
	opt := options.NewOptions()
	conf := &options.Config{}
	settupLogger := ctrl.Log.WithName("setup")

	cmd := &cobra.Command{
		Use: "oidc-webhook-authenticator",
		Run: func(cmd *cobra.Command, args []string) {
			verflag.PrintAndExitIfRequested()
			cliflag.PrintFlags(cmd.Flags())

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

	opts := zap.Options{}
	opts.BindFlags(goflag.CommandLine)
	fs.AddGoFlagSet(goflag.CommandLine)
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

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

	ctx, cancel := context.WithCancel(ctx)

	diagnosticMux := http.NewServeMux()
	healthz.InstallHandler(diagnosticMux, healthz.LogHealthz, healthz.PingHealthz)
	healthz.InstallReadyzHandler(diagnosticMux, healthz.LogHealthz, healthz.PingHealthz)
	healthz.InstallLivezHandler(diagnosticMux, healthz.LogHealthz, healthz.PingHealthz)
	diagnosticMux.Handle("/metrics", promhttp.Handler())
	go func() {
		setupLog.Info("Starting diagnostic server", "address", opts.DiagnosticAddr.Addr)
		err := http.ListenAndServe(opts.DiagnosticAddr.Addr, diagnosticMux)
		if err != nil {
			cancel() // Canceling the context closes the associated channel, when the channel is closed, the secure server below also shuts down.
			setupLog.Error(err, "diagnostic server exited with error")
		}
	}()

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
	var (
		authPath     = "/validate-token"
		authHandler  = authWH.Build()
		pathRecorder = mux.NewPathRecorderMux("oidc-webhook-authenticator")
	)
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

	var (
		defaultingPath    = "/webhooks/mutating"
		defaultingHandler = metrics.InstrumentedHandler(defaultingPath, defaultingWebhook)
	)
	pathRecorder.Handle(defaultingPath, defaultingHandler)

	validatingWebhook := admission.ValidatingWebhookFor(oidc)
	if err := validatingWebhook.InjectLogger(ctrl.Log.WithName("webhooks").WithName("Validating")); err != nil {
		return nil, err
	}
	if err := validatingWebhook.InjectScheme(scheme); err != nil {
		return nil, err
	}

	var (
		validatingPath    = "/webhooks/validating"
		validatingHandler = metrics.InstrumentedHandler(validatingPath, validatingWebhook)
	)
	pathRecorder.Handle(validatingPath, validatingHandler)

	requestInfoResolver := &apirequest.RequestInfoFactory{}
	failedHandler := genericapifilters.Unauthorized(clientgoscheme.Codecs)

	handler := genericapifilters.WithAuthorization(pathRecorder, opts.Authorization.Authorizer, clientgoscheme.Codecs)
	handler = genericapifilters.WithAuthentication(handler, opts.Authentication.Authenticator, failedHandler, opts.Authentication.APIAudiences)
	handler = genericapifilters.WithRequestInfo(handler, requestInfoResolver)
	handler = genericapifilters.WithCacheControl(handler)
	handler = genericfilters.WithPanicRecovery(handler, requestInfoResolver)

	// Instrument the outermost handler to detect issues inside the handler chain.
	handler = metrics.InstrumentedHandler("GLOBAL", handler)

	return handler, nil
}
