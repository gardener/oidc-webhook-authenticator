// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

/**
	Overview
		- Tests the licefycle controller for the shoot-oidc-service extension.
	Prerequisites
		- A Shoot exists and the oidc extension is enabled in the seed cluster.
	Test-case:
		1) Extension
			1.1) Secrets
				-  deploy the Extension 'shoot-oidc-service' then delete it and verify that the secrets associated with it are deleted.
			1.2) Deployment
				-  deploy the Extension 'shoot-oidc-service' then hibernate the shoot cluster. Verify that the oidc-webhook-authenticator is scaled to 0 replicas in the shoot cluster's namespace in the seed.
 **/

package lifecycle

import (
	"context"
	"fmt"
	"time"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/utils/retry"
	"github.com/gardener/gardener/test/framework"
	"github.com/gardener/oidc-webhook-authenticator/gardener-extension-shoot-oidc-service/pkg/controller/lifecycle"
	"github.com/gardener/oidc-webhook-authenticator/gardener-extension-shoot-oidc-service/pkg/service"
	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	k8sretry "k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	fastTimeout = 3 * time.Minute
	timeout     = 15 * time.Minute
)

var _ = ginkgo.Describe("Extension-shoot-oidc-service integration test: lifecycle", func() {
	f := framework.NewShootFramework(nil)

	ginkgo.Context("Extension", func() {

		ginkgo.Context("Secrets", func() {
			f.Serial().Release().CIt("Secrets should be created when extension resource is deployed and deleted when extension resource is removed.", func(ctx context.Context) {
				deployExtension(ctx, f)
				namespacedTLSSecret := types.NamespacedName{
					Namespace: f.ShootSeedNamespace(),
					Name:      lifecycle.WebhookTLSecretName,
				}
				namespacedShootSecret := types.NamespacedName{
					Namespace: f.ShootSeedNamespace(),
					Name:      lifecycle.ShootResourcesName,
				}
				_, err := getSecret(ctx, f.SeedClient.Client(), namespacedTLSSecret)
				framework.ExpectNoError(err)
				_, err = getSecret(ctx, f.SeedClient.Client(), namespacedShootSecret)
				framework.ExpectNoError(err)

				deleteExtension(ctx, f)

				err = waitSecretToBeDeleted(ctx, f.SeedClient.Client(), namespacedShootSecret)

				gomega.Expect(err).To(gomega.HaveOccurred())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring(fmt.Sprintf("secrets \"%s\" not found", namespacedShootSecret.Name)))

				err = waitSecretToBeDeleted(ctx, f.SeedClient.Client(), namespacedTLSSecret)
				gomega.Expect(err).To(gomega.HaveOccurred())
				gomega.Expect(err.Error()).To(gomega.ContainSubstring(fmt.Sprintf("secrets \"%s\" not found", namespacedTLSSecret.Name)))
			}, fastTimeout)
		})

		ginkgo.Context("Deployment", func() {
			f.Serial().Release().CIt("OIDC authenticator should be deployed with 2 replicas and scaled back to 0 replicas when the shoot is hibernated.", func(ctx context.Context) {
				deployExtension(ctx, f)
				namespacedDeployment := types.NamespacedName{
					Namespace: f.ShootSeedNamespace(),
					Name:      lifecycle.SeedResourcesName,
				}

				depl, err := getDeployment(ctx, f.SeedClient.Client(), namespacedDeployment)
				framework.ExpectNoError(err)

				gomega.Expect(int(*depl.Spec.Replicas)).To(gomega.Equal(2))

				err = f.HibernateShoot(ctx)
				framework.ExpectNoError(err)

				reconcileExtension(ctx, f)

				depl, err = getDeployment(ctx, f.SeedClient.Client(), namespacedDeployment)
				framework.ExpectNoError(err)

				gomega.Expect(int(*depl.Spec.Replicas)).To(gomega.Equal(0))
			}, timeout, framework.WithCAfterTest(func(ctx context.Context) {
				ginkgo.By("waking up shoot")
				err := f.WakeUpShoot(ctx)
				framework.ExpectNoError(err)
				ginkgo.By("cleanup extension resource")
				deleteExtension(ctx, f)
			}, timeout))
		})

	})
})

func deployExtension(ctx context.Context, f *framework.ShootFramework) {
	extension := &extensionsv1alpha1.Extension{
		ObjectMeta: metav1.ObjectMeta{
			Name:      service.ServiceName,
			Namespace: f.ShootSeedNamespace(),
		},
		Spec: extensionsv1alpha1.ExtensionSpec{
			DefaultSpec: extensionsv1alpha1.DefaultSpec{
				Type: service.ExtensionType,
			},
		},
	}
	err := f.SeedClient.Client().Create(ctx, extension)
	framework.ExpectNoError(err)
}

func getDeployment(ctx context.Context, seedClient client.Client, namespacedName types.NamespacedName) (*appsv1.Deployment, error) {
	depl := &appsv1.Deployment{}
	err := retry.Until(ctx, 2*time.Second, func(ctx context.Context) (done bool, err error) {
		if err = seedClient.Get(ctx, namespacedName, depl); err != nil {
			return retry.MinorError(fmt.Errorf("unable to retrieve deployment from seed (ns: %s, name: %s)", namespacedName.Namespace, namespacedName.Name))
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return depl, nil
}

func getSecret(ctx context.Context, seedClient client.Client, namespacedName types.NamespacedName) (*corev1.Secret, error) {
	secret := &corev1.Secret{}
	err := retry.Until(ctx, 2*time.Second, func(ctx context.Context) (done bool, err error) {
		if err = seedClient.Get(ctx, namespacedName, secret); err != nil {
			return retry.MinorError(fmt.Errorf("unable to retrieve secret from seed (ns: %s, name: %s)", namespacedName.Namespace, namespacedName.Name))
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return secret, nil
}

func waitSecretToBeDeleted(ctx context.Context, seedClient client.Client, namespacedName types.NamespacedName) error {
	err := retry.Until(ctx, 2*time.Second, func(ctx context.Context) (done bool, err error) {
		if err = seedClient.Get(ctx, namespacedName, &corev1.Secret{}); err == nil {
			return retry.MinorError(fmt.Errorf("able to retrieve secret from seed (ns: %s, name: %s). Waiting for secret to be deleted", namespacedName.Namespace, namespacedName.Name))
		}
		return true, err
	})
	return err
}

func reconcileExtension(ctx context.Context, f *framework.ShootFramework) {
	namespace := f.ShootSeedNamespace()

	namespacedExtension := types.NamespacedName{
		Namespace: namespace,
		Name:      service.ServiceName,
	}
	extension := &extensionsv1alpha1.Extension{}
	err := f.SeedClient.Client().Get(ctx, namespacedExtension, extension)
	framework.ExpectNoError(err)

	err = extensionscontroller.TryPatch(ctx, k8sretry.DefaultBackoff, f.SeedClient.Client(), extension, func() error {
		if extension.ObjectMeta.Annotations == nil {
			extension.ObjectMeta.Annotations = make(map[string]string)
		}
		extension.ObjectMeta.Annotations[v1beta1constants.GardenerOperation] = v1beta1constants.GardenerOperationReconcile
		return nil
	})
	framework.ExpectNoError(err)

	err = retry.Until(ctx, 2*time.Second, func(ctx context.Context) (done bool, err error) {
		getExtension := &extensionsv1alpha1.Extension{}
		if err = f.SeedClient.Client().Get(ctx, namespacedExtension, getExtension); err != nil {
			return retry.MinorError(fmt.Errorf("unable to retrieve extension from seed (ns: %s, name: %s)", namespacedExtension.Namespace, namespacedExtension.Name))
		}

		if v, ok := getExtension.ObjectMeta.Annotations[v1beta1constants.GardenerOperation]; ok && v == v1beta1constants.GardenerOperationReconcile {
			return retry.MinorError(fmt.Errorf("extension is still not reconciled (ns: %s, name: %s)", namespacedExtension.Namespace, namespacedExtension.Name))
		}
		return true, nil
	})

	framework.ExpectNoError(err)
}

func deleteExtension(ctx context.Context, f *framework.ShootFramework) {
	namespace := f.ShootSeedNamespace()

	namespacedExtension := types.NamespacedName{
		Namespace: namespace,
		Name:      service.ServiceName,
	}
	extension := &extensionsv1alpha1.Extension{}
	err := f.SeedClient.Client().Get(ctx, namespacedExtension, extension)
	framework.ExpectNoError(err)

	err = extensionscontroller.TryPatch(ctx, k8sretry.DefaultBackoff, f.SeedClient.Client(), extension, func() error {
		if extension.ObjectMeta.Annotations == nil {
			extension.ObjectMeta.Annotations = make(map[string]string)
		}
		extension.ObjectMeta.Annotations["confirmation.gardener.cloud/deletion"] = "true"
		return nil
	})
	framework.ExpectNoError(err)
	err = f.SeedClient.Client().Delete(ctx, extension)
	framework.ExpectNoError(err)
}
