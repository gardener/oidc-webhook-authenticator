package authentication

import (
	"context"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	authenticationv1alpha1 "github.com/gardener/oidc-webhook-authenticator/apis/authentication/v1alpha1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/envtest/printer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	// +kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var cfg *rest.Config
var k8sClient client.Client
var testEnv *envtest.Environment
var testCtx, testCancel = context.WithCancel(context.Background())
var (
	mutatingWebhookPath   = "/webhooks/mutating"
	validatingWebhookPath = "/webhooks/validating"
)

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecsWithDefaultAndCustomReporters(t,
		"Controller Suite",
		[]Reporter{printer.NewlineReporter{}})
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.UseDevMode(true), zap.WriteTo(GinkgoWriter)))
	//	Expect(os.Setenv("KUBEBUILDER_ASSETS", "/usr/local/kubebuilder/bin")).To(Succeed())

	By("bootstrapping test environment")

	//	failPolicy := admissionregistrationv1.Fail
	//	sideEffects := admissionregistrationv1.SideEffectClassNone
	/*	webhookInstallOptions := envtest.WebhookInstallOptions{
		_ := envtest.WebhookInstallOptions{
			MutatingWebhooks: []client.Object{
				&admissionregistrationv1.MutatingWebhookConfiguration{
					ObjectMeta: metav1.ObjectMeta{
						Name: "mutating-webhook-configuration",
					},
					TypeMeta: metav1.TypeMeta{
						Kind:       "MutatingWebhookConfiguration",
						APIVersion: "admissionregistration.k8s.io/v1",
					},
					Webhooks: []admissionregistrationv1.MutatingWebhook{
						{
							Name:                    "mutating-webhook-configuration",
							AdmissionReviewVersions: []string{"v1", "v1beta1"},
							FailurePolicy:           &failPolicy,
							ClientConfig: admissionregistrationv1.WebhookClientConfig{
								Service: &admissionregistrationv1.ServiceReference{
									Name:      "webhook-service",
									Namespace: "system",
									Path:      &mutatingWebhookPath,
								},
							},
							Rules: []admissionregistrationv1.RuleWithOperations{
								{
									Operations: []admissionregistrationv1.OperationType{
										admissionregistrationv1.Create,
										admissionregistrationv1.Update,
									},
									Rule: admissionregistrationv1.Rule{
										APIGroups:   []string{"authentication.gardener.cloud"},
										APIVersions: []string{"v1alpha1"},
										Resources:   []string{"openidconnects"},
									},
								},
							},
							SideEffects: &sideEffects,
						},
						{
							Name:                    "validating-webhook-configuration",
							AdmissionReviewVersions: []string{"v1", "v1beta1"},
							FailurePolicy:           &failPolicy,
							ClientConfig: admissionregistrationv1.WebhookClientConfig{
								Service: &admissionregistrationv1.ServiceReference{
									Name:      "webhook-service",
									Namespace: "system",
									Path:      &validatingWebhookPath,
								},
							},
							Rules: []admissionregistrationv1.RuleWithOperations{
								{
									Operations: []admissionregistrationv1.OperationType{
										admissionregistrationv1.Create,
										admissionregistrationv1.Update,
									},
									Rule: admissionregistrationv1.Rule{
										APIGroups:   []string{"authentication.gardener.cloud"},
										APIVersions: []string{"v1alpha1"},
										Resources:   []string{"openidconnects"},
									},
								},
							},
							SideEffects: &sideEffects,
						},
					},
				},
			},
		}
	*/
	//	customApiServerFlags := []string{
	//		"--authentication-token-webhook-config-file=/etc/kubernetes/webhook/minikube-webhook-kubeconfig.yaml",
	//	}
	apiServerFlags := append([]string(nil), envtest.DefaultKubeAPIServerFlags...)
	//	apiServerFlags = append(apiServerFlags, customApiServerFlags...)

	testEnv = &envtest.Environment{
		CRDDirectoryPaths:  []string{filepath.Join("..", "config", "crd", "bases")},
		KubeAPIServerFlags: apiServerFlags,
		//		WebhookInstallOptions: webhookInstallOptions,
	}

	cfg, err := testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	err = authenticationv1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	// +kubebuilder:scaffold:scheme
	//	cmd := NewOIDCWebhookAuthenticatorCommand(ctrl.SetupSignalHandler())

	//	pflag.CommandLine.SetNormalizeFunc(cliflag.WordSepNormalizeFunc)
	// utilflag.InitFlags()
	//	logs.InitLogs()
	//	defer logs.FlushLogs()
	//	err = cmd.Execute()
	//	Expect(err).NotTo(HaveOccurred())

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:             scheme.Scheme,
		MetricsBindAddress: "0",
		Port:               0,
		LeaderElection:     false,
		CertDir:            "",
	})

	Expect(err).NotTo(HaveOccurred())

	authReconciler := &OpenIDConnectReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("OpenIDConnect"),
		Scheme: mgr.GetScheme(),
	}

	err = (authReconciler).SetupWithManager(mgr)
	Expect(err).ToNot(HaveOccurred())

	go func() {
		mgr.Start(ctrl.SetupSignalHandler())
		Expect(err).NotTo(HaveOccurred())
	}()

	k8sClient = mgr.GetClient()
	Expect(k8sClient).ToNot(BeNil())

}, 60)

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).ToNot(HaveOccurred())
})
