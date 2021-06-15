// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// +kubebuilder:docs-gen:collapse=Apache License

package integration_test

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	authenticationv1alpha1 "github.com/gardener/oidc-webhook-authenticator/apis/authentication/v1alpha1"
	"github.com/gardener/oidc-webhook-authenticator/controllers/authentication"
	webhook "github.com/gardener/oidc-webhook-authenticator/webhook/authentication"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var (
	apiServerSecurePort int
	k8sClient           client.Client
	testEnv             *envtest.Environment
	userNameClaim1      = "email"
	userNameClaim2      = "customclaim"
)

const (
	idpServerPort1            = 50002
	idpServerPort2            = 50003
	idpServerPort3            = 50004
	timeout                   = time.Second * 10
	interval                  = time.Millisecond * 250
	defaultNamespaceName      = "default"
	differentNamespaceName    = "different"
	oidcName1                 = "test1"
	oidcName2                 = "test2"
	oidcName3                 = "test3"
	oidcName4                 = "test4"
	wellKnownResponseTemplate = `{
		"issuer": "%[1]s",
		"authorization_endpoint": "%[1]s/auth",
		"token_endpoint": "%[1]s/token",
		"jwks_uri": "%[1]s/keys",
		"userinfo_endpoint": "%[1]s/userinfo",
		"id_token_signing_alg_values_supported": ["RS256"]
	}`
	jwksResponse = `{
		"keys": [
			{
				"kty": "RSA",
				"e": "AQAB",
				"use": "sig",
				"kid": "oailugIRQPOcchy27dKroagZ-CcqI4WtwQhUlpgxOp0",
				"alg": "RS256",
				"n": "ve3iKlP5TA4Ld0so_8SZE9MYmILQluC6x9iJkCCqYNvo4xs6JlmcvBVO6z4Jdl5snydHV0d47DWMmJgn4oGKZEad5VtwoTMIVjmWU-IXJI72BR-ZUYOYgSUH9FN_ApuKRTmjhnh1lxMZk2VTElFc_zlY9rbgsxqYvSjYZEHrVq-rFImSe2BpZOGXOQXQv0foFKRptqFBSwT4BPrd9mUlgSZ0J4j6rGp5bgyJEQv2FyiYF8q_ROdpzZYaSn3eSfRqlkftViIWjnKe21GASao5BVjEpHWoiptjsVfReKHaWOcRIaV2GU97IaSXahAlCNhuUbvXsHgqiK4vVhww_9bE6w"
			},
			{
				"kty": "RSA",
				"e": "AQAB",
				"use": "sig",
				"kid": "TWrNCL7oSJwX8eqhQ_OwD6nIfj8K7c2Sgvk2Xd4j4oI",
				"alg": "RS256",
				"n": "4A9FFN4cxZ3aewzh7gdh1Thdn2ouxJ51jAIGKPRwtfuZzI0kOLfk6V_iNsqXZYxHh6FcklYUazh_AdT1MronHb68tBDXJKjy30V0F_qzO4Z4sQti02dl7sXnZHKzEUPbnQasHC4TvhprR54rrOmRRA3jpno-P-1Jklfer3_deueh7rdpn3SnpXBIlr1gX5MQbIIpQsfksJqjdVbv8BwOvoAvK4coPDokx8-9ACq8xDo2WCHdJ9Ge_7QIYgIEE-XaO2dIPMjFXvcmNjZQB0hczoCPMijOFMIL08X7RlX7rA8PsLyTpON0GggpAwk5jyA11KuRT24h49zulb6RI68-nQ"
			}
		]
	}`
)

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Integration Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.UseDevMode(true), zap.WriteTo(GinkgoWriter)))

	By("bootstrapping test environment")
	wd, err := os.Getwd()
	Expect(err).NotTo(HaveOccurred())
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	apiServer := testEnv.ControlPlane.GetAPIServer()
	apiServer.Configure().Set("bind-address", "127.0.0.1")
	apiServer.Configure().Set("authentication-token-webhook-config-file", filepath.Join(wd, "config", "webhook-kubeconfig.yaml"))
	cfg, err := testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())
	apiServerSecurePort, err = strconv.Atoi(apiServer.SecureServing.Port)
	Expect(err).NotTo(HaveOccurred())
	err = authenticationv1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:             scheme.Scheme,
		MetricsBindAddress: "0",
		Port:               0,
		LeaderElection:     false,
		CertDir:            "",
	})
	Expect(err).NotTo(HaveOccurred())

	authReconciler := &authentication.OpenIDConnectReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("OpenIDConnect"),
		Scheme: mgr.GetScheme(),
	}
	err = (authReconciler).SetupWithManager(mgr)
	Expect(err).ToNot(HaveOccurred())

	authWH := &webhook.Webhook{
		Authenticator: authReconciler,
		Log:           ctrl.Log.WithName("webhooks").WithName("TokeReview"),
	}

	By("running webhook server")

	wh := mgr.GetWebhookServer()
	wh.Host = "127.0.0.1"
	wh.Port = 50001
	wh.KeyName = "apiserver.key"
	wh.CertName = "apiserver.crt"
	wh.CertDir = apiServer.CertDir
	wh.Register("/validate-token", authWH.Build())

	go func() {
		mgr.Start(ctrl.SetupSignalHandler())
		Expect(err).NotTo(HaveOccurred())
	}()

	k8sClient = mgr.GetClient()
	Expect(k8sClient).ToNot(BeNil())

	handler1 := http.NewServeMux()
	handler1.HandleFunc("/.well-known/openid-configuration", handleWellKnownFirstIDP)
	handler1.HandleFunc("/keys", handleKeys)
	startIDPServer(idpServerPort1, handler1)

	handler2 := http.NewServeMux()
	handler2.HandleFunc("/.well-known/openid-configuration", handleWellKnownSecondIDP)
	handler2.HandleFunc("/keys", handleKeys)
	startIDPServer(idpServerPort2, handler2)

	setupCustomRecources()
}, 60)

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).ToNot(HaveOccurred())
})

func startIDPServer(port int, handler *http.ServeMux) {
	go func() {
		if err := http.ListenAndServeTLS(fmt.Sprintf(":%v", port), "./id-certs/tls.crt", "./id-certs/tls.key", handler); err != nil {
			fmt.Println(err)
		}
	}()
}

func setupCustomRecources() {
	ctx := context.Background()
	ca, err := ioutil.ReadFile("./ca/ca.crt")
	Expect(err).NotTo(HaveOccurred())
	openidconnect1 := &authenticationv1alpha1.OpenIDConnect{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "authentication.gardener.cloud/v1alpha1",
			Kind:       "OpenIDConnect",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      oidcName1,
			Namespace: defaultNamespaceName,
		},
		Spec: authenticationv1alpha1.OIDCAuthenticationSpec{
			IssuerURL:     fmt.Sprintf("https://localhost:%v", idpServerPort1),
			ClientID:      "1234567890",
			UsernameClaim: &userNameClaim1,
			CABundle:      ca,
		},
	}
	openidconnect2 := &authenticationv1alpha1.OpenIDConnect{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "authentication.gardener.cloud/v1alpha1",
			Kind:       "OpenIDConnect",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      oidcName2,
			Namespace: defaultNamespaceName,
		},
		Spec: authenticationv1alpha1.OIDCAuthenticationSpec{
			IssuerURL:     fmt.Sprintf("https://localhost:%v", idpServerPort2),
			ClientID:      "some-client-id",
			UsernameClaim: &userNameClaim2,
			CABundle:      ca,
		},
	}

	openidconnect3 := &authenticationv1alpha1.OpenIDConnect{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "authentication.gardener.cloud/v1alpha1",
			Kind:       "OpenIDConnect",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      oidcName3,
			Namespace: defaultNamespaceName,
		},
		Spec: authenticationv1alpha1.OIDCAuthenticationSpec{
			IssuerURL:     fmt.Sprintf("https://localhost:%v", idpServerPort3),
			ClientID:      "static",
			UsernameClaim: &userNameClaim1,
			CABundle:      ca,
			JWKS: authenticationv1alpha1.JWKSSpec{
				Keys: []byte(jwksResponse),
			},
		},
	}

	// This is a configuration similar to openidconnect1 but with different client id
	openidconnect4 := &authenticationv1alpha1.OpenIDConnect{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "authentication.gardener.cloud/v1alpha1",
			Kind:       "OpenIDConnect",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      oidcName4,
			Namespace: defaultNamespaceName,
		},
		Spec: authenticationv1alpha1.OIDCAuthenticationSpec{
			IssuerURL:     fmt.Sprintf("https://localhost:%v", idpServerPort1),
			ClientID:      "different-client-id",
			UsernameClaim: &userNameClaim1,
			CABundle:      ca,
		},
	}

	Expect(k8sClient.Create(ctx, openidconnect4)).Should(Succeed())
	waitForOIDCResourceToBecomeAvailable(oidcName4, defaultNamespaceName)

	Expect(k8sClient.Create(ctx, openidconnect1)).Should(Succeed())
	waitForOIDCResourceToBecomeAvailable(oidcName1, defaultNamespaceName)

	Expect(k8sClient.Create(ctx, openidconnect2)).Should(Succeed())
	waitForOIDCResourceToBecomeAvailable(oidcName2, defaultNamespaceName)

	Expect(k8sClient.Create(ctx, openidconnect3)).Should(Succeed())
	waitForOIDCResourceToBecomeAvailable(oidcName3, defaultNamespaceName)
}

func waitForOIDCResourceToBecomeAvailable(name string, namespace string) {
	ctx := context.Background()
	openidconnectLookupKey := types.NamespacedName{Name: name, Namespace: namespace}
	createdOpenIDConnect := &authenticationv1alpha1.OpenIDConnect{}

	Eventually(func() bool {
		err := k8sClient.Get(ctx, openidconnectLookupKey, createdOpenIDConnect)
		return err == nil
	}, timeout, interval).Should(BeTrue())
}

func handleWellKnownFirstIDP(w http.ResponseWriter, r *http.Request) {
	host := fmt.Sprintf("https://localhost:%v", idpServerPort1)
	wellKnown := fmt.Sprintf(wellKnownResponseTemplate, host)
	_, err := io.WriteString(w, wellKnown)
	if err != nil {
		w.WriteHeader(500)
	}
}

func handleWellKnownSecondIDP(w http.ResponseWriter, r *http.Request) {
	host := fmt.Sprintf("https://localhost:%v", idpServerPort2)
	wellKnown := fmt.Sprintf(wellKnownResponseTemplate, host)
	_, err := io.WriteString(w, wellKnown)
	if err != nil {
		w.WriteHeader(500)
	}
}

func handleKeys(w http.ResponseWriter, req *http.Request) {
	_, err := io.WriteString(w, jwksResponse)
	if err != nil {
		w.WriteHeader(500)
	}
}
