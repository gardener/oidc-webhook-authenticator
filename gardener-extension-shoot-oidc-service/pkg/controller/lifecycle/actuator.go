// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/extension"
	"github.com/gardener/gardener/extensions/pkg/util"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/utils"
	managedresources "github.com/gardener/gardener/pkg/utils/managedresources"
	"github.com/gardener/gardener/pkg/utils/secrets"
	"github.com/gardener/oidc-webhook-authenticator/gardener-extension-shoot-oidc-service/pkg/apis/config"
	"github.com/gardener/oidc-webhook-authenticator/gardener-extension-shoot-oidc-service/pkg/imagevector"
	"github.com/gardener/oidc-webhook-authenticator/gardener-extension-shoot-oidc-service/pkg/service"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/rest"
	configlatest "k8s.io/client-go/tools/clientcmd/api/latest"
	configv1 "k8s.io/client-go/tools/clientcmd/api/v1"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// ActuatorName is the name of the OIDC Service actuator.
	ActuatorName = service.ServiceName + "-actuator"
	// SeedResourcesName is the name for resource describing the resources applied to the seed cluster.
	SeedResourcesName = "oidc-webhook-authenticator"
	// ShootResourcesName is the name for resource describing the resources applied to the shoot cluster.
	ShootResourcesName = SeedResourcesName + "-shoot"
	// WebhookTLSecretName is the name of the TLS secret resource used by the OIDC webhook in the seed cluster.
	WebhookTLSecretName = SeedResourcesName + "-tls"
	// ShootRBACName is the name of the RBAC resources created in the shoot cluster.
	ShootRBACName = "extensions.gardener.cloud:extension-shoot-oidc-service:shoot"
	// WebhookTLSCertDir is the directory used for mounting the webhook certificates.
	WebhookTLSCertDir = "/var/run/oidc-webhook-authenticator/tls"
	// WebhookShootConfigDir is the directory used for mounting the shoot kubeconfig.
	WebhookShootConfigDir = "/var/run/oidc-webhook-authenticator/shoot"
)

//go:embed authentication.gardener.cloud_openidconnects.yaml
var crdContent string

// NewActuator returns an actuator responsible for Extension resources.
func NewActuator(config config.Configuration) extension.Actuator {
	return &actuator{
		logger:        log.Log.WithName(ActuatorName),
		serviceConfig: config,
	}
}

type actuator struct {
	client        client.Client
	config        *rest.Config
	decoder       runtime.Decoder
	serviceConfig config.Configuration
	logger        logr.Logger
}

// Reconcile the Extension resource.
func (a *actuator) Reconcile(ctx context.Context, ex *extensionsv1alpha1.Extension) error {
	namespace := ex.GetNamespace()

	cluster, err := controller.GetCluster(ctx, a.client, namespace)
	if err != nil {
		return err
	}

	// validate

	var oidcReplicas int32 = 2
	if controller.IsHibernated(cluster) {
		oidcReplicas = 0
	}

	seedResources, err := getSeedResources(oidcReplicas, namespace)

	if err != nil {
		return err
	}

	_, err = a.getOrCreateTLSSecret(ctx, secrets.CertificateSecretConfig{
		Name:       WebhookTLSecretName,
		CommonName: SeedResourcesName,
		DNSNames: []string{
			SeedResourcesName,
			fmt.Sprintf("%s.%s", SeedResourcesName, namespace),
			fmt.Sprintf("%s.%s.svc", SeedResourcesName, namespace),
			fmt.Sprintf("%s.%s.svc.cluster.local", SeedResourcesName, namespace),
		},
	}, namespace)

	if err != nil {
		return err
	}

	_, err = util.GetOrCreateShootKubeconfig(ctx, a.client, secrets.CertificateSecretConfig{
		Name:       ShootResourcesName,
		CommonName: SeedResourcesName,
	}, namespace)

	if err != nil {
		return err
	}

	if err := managedresources.CreateForSeed(ctx, a.client, namespace, service.ManagedResourceNamesSeed, false, seedResources); err != nil {
		return err
	}

	shootResources, err := getShootResources()
	if err != nil {
		return err
	}

	if err := managedresources.CreateForShoot(ctx, a.client, namespace, service.ManagedResourceNamesShoot, false, shootResources); err != nil {
		return err
	}

	// patch deployment for kube-apiserver in order to trigger webhook
	depl := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      v1beta1constants.DeploymentNameKubeAPIServer,
		},
	}

	key := client.ObjectKeyFromObject(depl)
	if err := a.client.Get(ctx, key, depl); err != nil {
		return err
	}

	err = a.client.Patch(ctx, depl, client.MergeFrom(depl.DeepCopyObject().(client.Object)))
	if err != nil {
		return err
	}
	return nil
}

// Delete the Extension resource.
func (a *actuator) Delete(ctx context.Context, ex *extensionsv1alpha1.Extension) error {
	namespace := ex.GetNamespace()

	if err := managedresources.DeleteForSeed(ctx, a.client, namespace, service.ManagedResourceNamesSeed); err != nil {
		return err
	}
	if err := managedresources.DeleteForShoot(ctx, a.client, namespace, service.ManagedResourceNamesShoot); err != nil {
		return err
	}

	if err := a.client.Delete(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ShootResourcesName,
			Namespace: namespace,
		},
	}); err != nil {
		return err
	}

	if err := a.client.Delete(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      WebhookTLSecretName,
			Namespace: namespace,
		},
	}); err != nil {
		return err
	}

	return nil
}

// Restore the Extension resource.
func (a *actuator) Restore(ctx context.Context, ex *extensionsv1alpha1.Extension) error {
	return a.Reconcile(ctx, ex)
}

// Migrate the Extension resource.
func (a *actuator) Migrate(ctx context.Context, ex *extensionsv1alpha1.Extension) error {
	// Keep objects for shoot managed resources so that they are not deleted from the shoot during the migration

	return a.Delete(ctx, ex)
}

// InjectConfig injects the rest config to this actuator.
func (a *actuator) InjectConfig(config *rest.Config) error {
	a.config = config
	return nil
}

// InjectClient injects the controller runtime client into the reconciler.
func (a *actuator) InjectClient(client client.Client) error {
	a.client = client
	return nil
}

// InjectScheme injects the given scheme into the reconciler.
func (a *actuator) InjectScheme(scheme *runtime.Scheme) error {
	a.decoder = serializer.NewCodecFactory(scheme, serializer.EnableStrict).UniversalDecoder()
	return nil
}

func (a *actuator) getOrCreateTLSSecret(ctx context.Context, certificateConfig secrets.CertificateSecretConfig, namespace string) (*corev1.Secret, error) {
	caSecret, ca, err := secrets.LoadCAFromSecret(ctx, a.client, namespace, v1beta1constants.SecretNameCACluster)
	if err != nil {
		return nil, fmt.Errorf("error fetching CA secret %s/%s: %v", namespace, v1beta1constants.SecretNameCACluster, err)
	}

	var (
		secret = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: make(map[string]string),
				Name:        certificateConfig.Name,
				Namespace:   namespace,
			},
		}
		key = types.NamespacedName{
			Name:      certificateConfig.Name,
			Namespace: namespace,
		}
	)
	if err := a.client.Get(ctx, key, &secret); client.IgnoreNotFound(err) != nil {
		return nil, fmt.Errorf("error preparing kubeconfig: %v", err)
	}

	var (
		computedChecksum   = utils.ComputeChecksum(caSecret.Data)
		storedChecksum, ok = secret.Annotations[util.CAChecksumAnnotation]
	)
	if ok && computedChecksum == storedChecksum {
		return &secret, nil
	}

	certificateConfig.SigningCA = ca
	certificateConfig.CertType = secrets.ServerCert

	config := secrets.ControlPlaneSecretConfig{
		CertificateSecretConfig: &certificateConfig,
	}

	controlPlane, err := config.GenerateControlPlane()
	if err != nil {
		return nil, fmt.Errorf("error creating kubeconfig: %v", err)
	}

	_, err = controllerutil.CreateOrUpdate(ctx, a.client, &secret, func() error {
		secret.Data = controlPlane.SecretData()
		if secret.Annotations == nil {
			secret.Annotations = make(map[string]string)
		}
		secret.Annotations[util.CAChecksumAnnotation] = computedChecksum
		return nil
	})

	return &secret, err
}

func getLabels() map[string]string {
	return map[string]string{
		"app": SeedResourcesName,
	}
}

func getSeedResources(oidcReplicas int32, namespace string) (map[string][]byte, error) {
	var (
		tcpProto  = corev1.ProtocolTCP
		port10443 = intstr.FromInt(10443)
		registry  = managedresources.NewRegistry(kubernetes.SeedScheme, kubernetes.SeedCodec, kubernetes.SeedSerializer)
	)

	kubeConfig := &configv1.Config{
		Clusters: []configv1.NamedCluster{{
			Name: SeedResourcesName,
			Cluster: configv1.Cluster{
				Server:               fmt.Sprintf("https://%s/%s", SeedResourcesName, "validate-token"),
				CertificateAuthority: "/srv/kubernetes/ca/ca.crt",
			},
		}},
		Contexts: []configv1.NamedContext{{
			Name: SeedResourcesName,
			Context: configv1.Context{
				Cluster:  SeedResourcesName,
				AuthInfo: SeedResourcesName,
			},
		}},
		CurrentContext: SeedResourcesName,
		AuthInfos: []configv1.NamedAuthInfo{{
			Name: SeedResourcesName,
			AuthInfo: configv1.AuthInfo{
				TokenFile: "/var/run/secrets/kubernetes.io/serviceaccount/token",
			},
		}},
	}

	kubeAPIServerKubeConfig, err := runtime.Encode(configlatest.Codec, kubeConfig)
	if err != nil {
		return nil, err
	}

	image, err := imagevector.ImageVector().FindImage(service.ImageName)
	if err != nil {
		return nil, fmt.Errorf("failed to find image version for %s: %v", service.ImageName, err)
	}

	resources, err := registry.AddAllAndSerialize(
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      SeedResourcesName,
				Namespace: namespace,
				Labels:    getLabels(),
			},
		},
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      SeedResourcesName,
				Namespace: namespace,
				Labels:    getLabels(),
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     "system:auth-delegator",
			},
			Subjects: []rbacv1.Subject{
				{
					APIGroup:  "",
					Kind:      "ServiceAccount",
					Name:      SeedResourcesName,
					Namespace: namespace,
				},
			},
		},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      SeedResourcesName,
				Namespace: namespace,
				Labels:    getLabels(),
			},
			Spec: appsv1.DeploymentSpec{
				Replicas:             pointer.Int32Ptr(oidcReplicas),
				RevisionHistoryLimit: pointer.Int32Ptr(1),
				Selector:             &metav1.LabelSelector{MatchLabels: getLabels()},
				Strategy: appsv1.DeploymentStrategy{
					Type: appsv1.RollingUpdateDeploymentStrategyType,
					RollingUpdate: &appsv1.RollingUpdateDeployment{
						MaxUnavailable: &intstr.IntOrString{Type: intstr.Int, IntVal: 1},
						MaxSurge:       &intstr.IntOrString{Type: intstr.Int, IntVal: 1},
					},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: utils.MergeStringMaps(getLabels(), map[string]string{
							v1beta1constants.LabelNetworkPolicyToDNS:              v1beta1constants.LabelNetworkPolicyAllowed,
							v1beta1constants.LabelNetworkPolicyFromShootAPIServer: v1beta1constants.LabelNetworkPolicyAllowed,
							v1beta1constants.LabelNetworkPolicyToShootAPIServer:   v1beta1constants.LabelNetworkPolicyAllowed,
							v1beta1constants.LabelNetworkPolicyToSeedAPIServer:    v1beta1constants.LabelNetworkPolicyAllowed,
							v1beta1constants.LabelNetworkPolicyToPublicNetworks:   v1beta1constants.LabelNetworkPolicyAllowed,
							v1beta1constants.LabelNetworkPolicyToPrivateNetworks:  v1beta1constants.LabelNetworkPolicyAllowed,
						}),
					},
					Spec: corev1.PodSpec{
						Affinity: &corev1.Affinity{
							PodAntiAffinity: &corev1.PodAntiAffinity{
								PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{{
									Weight: 100,
									PodAffinityTerm: corev1.PodAffinityTerm{
										TopologyKey:   corev1.LabelHostname,
										LabelSelector: &metav1.LabelSelector{MatchLabels: getLabels()},
									},
								}},
							},
						},
						ServiceAccountName: SeedResourcesName,
						Containers: []corev1.Container{{
							Name:            SeedResourcesName,
							Image:           image.String(),
							ImagePullPolicy: corev1.PullAlways,
							Args: []string{
								fmt.Sprintf("--kubeconfig=%s/kubeconfig", WebhookShootConfigDir),
								fmt.Sprintf("--tls-cert-file=%s/%s.crt", WebhookTLSCertDir, WebhookTLSecretName),
								fmt.Sprintf("--tls-private-key-file=%s/%s.key", WebhookTLSCertDir, WebhookTLSecretName),
								"--authentication-skip-lookup=true",
								"--authorization-always-allow-paths=/validate-token",
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "tls",
									ReadOnly:  true,
									MountPath: WebhookTLSCertDir,
								}, {
									Name:      "shoot-kubeconfig",
									ReadOnly:  true,
									MountPath: WebhookShootConfigDir,
								},
							},
						}},
						Volumes: []corev1.Volume{
							{
								Name: "tls",
								VolumeSource: corev1.VolumeSource{
									Secret: &corev1.SecretVolumeSource{
										SecretName: WebhookTLSecretName,
									},
								},
							},
							{
								Name: "shoot-kubeconfig",
								VolumeSource: corev1.VolumeSource{
									Secret: &corev1.SecretVolumeSource{
										SecretName: ShootResourcesName,
									},
								},
							},
						},
					},
				},
			},
		}, &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      SeedResourcesName,
				Namespace: namespace,
				Labels:    getLabels(),
			},
			Spec: corev1.ServiceSpec{
				Type:     corev1.ServiceTypeClusterIP,
				Selector: getLabels(),
				Ports: []corev1.ServicePort{
					{
						Name:       "tls",
						Protocol:   corev1.ProtocolTCP,
						Port:       443,
						TargetPort: port10443,
					},
				},
			},
		},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      SeedResourcesName + "-allow-kube-apiserver",
				Namespace: namespace,
				Labels:    getLabels(),
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      v1beta1constants.LabelRole,
							Operator: metav1.LabelSelectorOpIn,
							Values:   []string{v1beta1constants.LabelAPIServer},
						},
					},
				},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
				Egress: []networkingv1.NetworkPolicyEgressRule{
					{
						Ports: []networkingv1.NetworkPolicyPort{{
							Protocol: &tcpProto,
							Port:     &port10443,
						}},
						To: []networkingv1.NetworkPolicyPeer{{
							PodSelector: &metav1.LabelSelector{MatchLabels: getLabels()},
						}},
					},
				},
			},
		},
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      SeedResourcesName,
				Namespace: namespace,
				Labels:    getLabels(),
			},
			Data: map[string]string{
				"kubeconfig": string(kubeAPIServerKubeConfig),
			},
		},
	)

	if err != nil {
		return nil, err
	}

	return resources, nil
}

func getShootResources() (map[string][]byte, error) {
	shootRegistry := managedresources.NewRegistry(kubernetes.ShootScheme, kubernetes.ShootCodec, kubernetes.ShootSerializer)
	shootResources, err := shootRegistry.AddAllAndSerialize(
		&rbacv1.ClusterRole{
			// TODO add labels to resources
			// app.kubernetes.io/instance: {{ .Release.Name }}
			// app.kubernetes.io/managed-by: {{ .Release.Service }}
			ObjectMeta: metav1.ObjectMeta{
				Name:   ShootRBACName,
				Labels: getLabels(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"authentication.gardener.cloud"},
					Verbs:     []string{"get", "list", "watch"},
					Resources: []string{"openidconnects"},
				},
			},
		},
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:   ShootRBACName,
				Labels: getLabels(),
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     ShootRBACName,
			},
			Subjects: []rbacv1.Subject{
				{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "User",
					Name:     SeedResourcesName,
				},
			},
		},
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ShootRBACName,
				Namespace: "kube-system",
				Labels:    getLabels(),
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     "extension-apiserver-authentication-reader",
			},
			Subjects: []rbacv1.Subject{
				{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "User",
					Name:     SeedResourcesName,
				},
			},
		},
	)

	if err != nil {
		return nil, err
	}

	shootResources["crd.yaml"] = []byte(crdContent)
	return shootResources, nil
}
