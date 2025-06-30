// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	goflag "flag"
	"fmt"
	"maps"
	"net/http"
	"os"
	"time"

	authenticationv1alpha1 "github.com/gardener/oidc-webhook-authenticator/apis/authentication/v1alpha1"
	"github.com/gardener/oidc-webhook-authenticator/cmd/oidc-webhook-authenticator/app/options"
	authcontroller "github.com/gardener/oidc-webhook-authenticator/controllers/authentication"
	"github.com/gardener/oidc-webhook-authenticator/internal/defaultervalidator"
	"github.com/gardener/oidc-webhook-authenticator/internal/filters"
	generichandlers "github.com/gardener/oidc-webhook-authenticator/internal/handlers"
	"github.com/gardener/oidc-webhook-authenticator/webhook/authentication"
	"github.com/gardener/oidc-webhook-authenticator/webhook/metrics"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/request/x509"
	genericapifilters "k8s.io/apiserver/pkg/endpoints/filters"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/cli/globalflag"
	"k8s.io/component-base/version/verflag"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// NewOIDCWebhookAuthenticatorCommand is the root command for OIDC webhook authenticator.
func NewOIDCWebhookAuthenticatorCommand(ctx context.Context) *cobra.Command {
	opt := options.NewOptions()
	conf := &options.Config{}
	setupLogger := ctrl.Log.WithName("setup")
	zapOpts := zap.Options{}

	cmd := &cobra.Command{
		Use: "oidc-webhook-authenticator",
		Run: func(cmd *cobra.Command, _ []string) {
			verflag.PrintAndExitIfRequested()
			cliflag.PrintFlags(cmd.Flags())

			ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zapOpts)))

			err := opt.ApplyTo(conf)
			if err != nil {
				setupLogger.Error(err, "cannot apply options")

				os.Exit(1)
			}

			err = run(ctx, conf, setupLogger)
			if err != nil {
				setupLogger.Error(err, "cannot run")

				os.Exit(1)
			}
		},
		PreRunE: func(_ *cobra.Command, _ []string) error {
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
		Scheme: scheme,
		Metrics: server.Options{
			BindAddress: "0",
		},
		WebhookServer: webhook.NewServer(webhook.Options{
			Port:    0,
			CertDir: "",
		}),
		LeaderElection: false,
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

	srv := &http.Server{
		Addr:         opts.AuthServerConfig.Address,
		Handler:      handler,
		TLSConfig:    opts.AuthServerConfig.TLSConfig,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	srvCh := make(chan error)
	serverCtx, cancelSrv := context.WithCancel(ctx)

	mgrCh := make(chan error)
	mgrCtx, cancelMgr := context.WithCancel(ctx)

	go func(ch chan<- error) {
		defer cancelSrv()
		ch <- mgr.Start(mgrCtx)
	}(mgrCh)

	go func(ch chan<- error) {
		defer cancelMgr()
		ch <- runServer(serverCtx, srv)
	}(srvCh)

	select {
	case err := <-mgrCh:
		return errors.Join(err, <-srvCh)
	case err := <-srvCh:
		return errors.Join(err, <-mgrCh)
	}
}

func newHandler(opts *options.Config, authWH *authentication.Webhook, scheme *runtime.Scheme) (http.Handler, error) {
	const (
		authPath       = "/validate-token"
		defaultingPath = "/webhooks/mutating"
		validatingPath = "/webhooks/validating"
		metricsPath    = "/metrics"
		livezPath      = "/livez"
		readyzPath     = "/readyz"
		healthzPath    = "/healthz"
	)

	var (
		oidc               = &authenticationv1alpha1.OpenIDConnect{}
		defaulterValidator = &defaultervalidator.DefaulterValidator{}
	)

	mutatingLogger := ctrl.Log.WithName("webhooks").WithName("Mutating")
	defaultingWebhook := admission.WithCustomDefaulter(scheme, oidc, defaulterValidator)
	defaultingWebhook.LogConstructor = func(_ logr.Logger, _ *admission.Request) logr.Logger {
		return mutatingLogger
	}

	validatingLogger := ctrl.Log.WithName("webhooks").WithName("Validating")
	validatingWebhook := admission.WithCustomValidator(scheme, oidc, defaulterValidator)
	validatingWebhook.LogConstructor = func(_ logr.Logger, _ *admission.Request) logr.Logger {
		return validatingLogger
	}

	handlers := map[string]http.Handler{
		authPath:       filters.WithAllowedMethod(http.MethodPost, genericapifilters.WithCacheControl(authWH.Build())),
		defaultingPath: filters.WithAllowedMethod(http.MethodPost, genericapifilters.WithCacheControl(defaultingWebhook)),
		validatingPath: filters.WithAllowedMethod(http.MethodPost, genericapifilters.WithCacheControl(validatingWebhook)),
		metricsPath:    filters.WithAllowedMethod(http.MethodGet, genericapifilters.WithCacheControl(promhttp.Handler())),
		livezPath:      filters.WithAllowedMethod(http.MethodGet, generichandlers.Ping()),
		readyzPath:     filters.WithAllowedMethod(http.MethodGet, generichandlers.Ping()),
		healthzPath:    filters.WithAllowedMethod(http.MethodGet, generichandlers.Ping()),
	}

	var auth authenticator.Request = &noOpAuthenticator{}
	if opts.AuthServerConfig.ClientCAProvider != nil {
		auth = x509.NewDynamic(opts.AuthServerConfig.ClientCAProvider.VerifyOptions, x509.CommonNameUserConversion)
	}

	// ensure that we have an actual map and not nil
	alwaysAllowPaths := map[string]struct{}{}
	if opts.AuthServerConfig.AuthenticationAlwaysAllowPaths != nil {
		alwaysAllowPaths = maps.Clone(opts.AuthServerConfig.AuthenticationAlwaysAllowPaths)
	}

	// add the authentication filter to not skipped paths
	for path, handler := range handlers {
		if _, ok := alwaysAllowPaths[path]; !ok {
			handlers[path] = filters.WithAuthentication(auth, handler)
		}
	}

	// instrument some of the handlers with additional metrics
	handlers[authPath] = metrics.InstrumentedHandler(authPath, handlers[authPath])
	handlers[validatingPath] = metrics.InstrumentedHandler(validatingPath, handlers[validatingPath])
	handlers[defaultingPath] = metrics.InstrumentedHandler(defaultingPath, handlers[defaultingPath])

	recorder := http.NewServeMux()
	for path, handler := range handlers {
		recorder.Handle(path, handler)
	}
	// "/" matches all paths that are not matched by other registered paths
	// see https://pkg.go.dev/net/http#ServeMux
	recorder.Handle("/", filters.WithAuthentication(auth, generichandlers.NotFound()))
	return recorder, nil
}

// noOpAuthenticator implements [authenticator.Request]
type noOpAuthenticator struct{}

var _ authenticator.Request = (*noOpAuthenticator)(nil)

func (a *noOpAuthenticator) AuthenticateRequest(_ *http.Request) (*authenticator.Response, bool, error) {
	return nil, true, nil
}

// runServer starts the webhook server. It returns if context is canceled or the server cannot start initially.
func runServer(ctx context.Context, srv *http.Server) error {
	errCh := make(chan error)
	l := ctrl.Log.WithName("authentication-server")
	go func(errCh chan<- error) {
		l.Info("starts listening", "address", srv.Addr)
		defer close(errCh)
		if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("authentication server failed serving content: %w", err)
		} else {
			l.Info("server stopped listening")
		}
	}(errCh)

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		l.Info("shutting down")
		cancelCtx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()
		err := srv.Shutdown(cancelCtx)
		if err != nil {
			return fmt.Errorf("authentication server failed graceful shutdown: %w", err)
		}
		l.Info("shutdown successful")
		return nil
	}
}
