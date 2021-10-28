// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// +kubebuilder:docs-gen:collapse=Apache License

package integration_test

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	authenticationv1 "k8s.io/api/authentication/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	authenticationv1alpha1 "github.com/gardener/oidc-webhook-authenticator/apis/authentication/v1alpha1"
	oidctestenv "github.com/gardener/oidc-webhook-authenticator/test/integration/env"
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var (
	apiServerSecurePort                          int
	apiserverToken                               string
	testEnv                                      *oidctestenv.OIDCWebhookTestEnvironment
	oidcOut, oidcErr, apiserverOut, apiserverErr bytes.Buffer
	k8sClient                                    client.Client
	clientset                                    *kubernetes.Clientset
)

const (
	dumpLogs = false
	timeout  = time.Second * 10
	interval = time.Millisecond * 250
)

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Integration Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.UseDevMode(true), zap.WriteTo(GinkgoWriter)))

	By("bootstrapping test environment")
	testEnv = &oidctestenv.OIDCWebhookTestEnvironment{
		APIServerOut: &apiserverOut,
		Environment: &envtest.Environment{
			CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
			ErrorIfCRDPathMissing: true,
		},
	}

	if dumpLogs {
		testEnv.OIDCOut = &oidcOut
		testEnv.OIDCErr = &oidcErr
		testEnv.APIServerOut = &apiserverOut
		testEnv.APIServerErr = &apiserverErr
	}

	cfg, err := testEnv.Start()
	Expect(err).ToNot(HaveOccurred())
	Expect(cfg).ToNot(BeNil())

	apiServerSecurePort, err = strconv.Atoi(testEnv.Environment.ControlPlane.GetAPIServer().SecureServing.Port)
	Expect(err).ToNot(HaveOccurred())
	err = authenticationv1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).ToNot(HaveOccurred())

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:             scheme.Scheme,
		MetricsBindAddress: "0",
		Port:               0,
		LeaderElection:     false,
		CertDir:            "",
	})
	Expect(err).ToNot(HaveOccurred())

	go func() {
		err = mgr.Start(ctrl.SetupSignalHandler())
		Expect(err).ToNot(HaveOccurred())
	}()

	k8sClient = mgr.GetClient()

	clientset, err = kubernetes.NewForConfig(cfg)
	Expect(err).NotTo(HaveOccurred())

	// create pod-reader role so we can use it in some test scenarios
	ctx := context.Background()
	_, err = clientset.RbacV1().Roles("default").Create(ctx, &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-reader",
			Namespace: "default",
		},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list", "watch"},
		}},
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())

	ttl := int64((30 * time.Minute).Seconds())
	resp, err := clientset.CoreV1().ServiceAccounts("default").CreateToken(ctx, "kube-apiserver", &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			ExpirationSeconds: &ttl,
		},
	}, metav1.CreateOptions{})

	Expect(err).NotTo(HaveOccurred())

	apiserverToken = resp.Status.Token
}, 60)

var _ = AfterSuite(func() {
	if dumpLogs {
		fmt.Println("apiserver out: " + apiserverOut.String())
		fmt.Println("apiserver err: " + apiserverErr.String())
		fmt.Println("oidc out: " + oidcOut.String())
		fmt.Println("oidc err: " + oidcErr.String())
	}
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).ToNot(HaveOccurred())
})
