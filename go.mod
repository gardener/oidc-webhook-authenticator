module github.com/gardener/oidc-webhook-authenticator

go 1.15

require (
	github.com/coreos/go-oidc v2.1.0+incompatible
	github.com/go-logr/logr v0.4.0
	github.com/onsi/ginkgo v1.14.1
	github.com/onsi/gomega v1.10.2
	github.com/spf13/cobra v1.1.1
	github.com/spf13/pflag v1.0.5
	golang.org/x/time v0.0.0-20200630173020-3af7569d3a1e
	k8s.io/api v0.20.2
	k8s.io/apimachinery v0.20.2
	k8s.io/apiserver v0.20.2
	k8s.io/client-go v0.20.2
	k8s.io/component-base v0.20.2
	k8s.io/klog/v2 v2.5.0
	sigs.k8s.io/controller-runtime v0.8.1
)

// keep this in sync with k8s.io/apiserver version
replace github.com/googleapis/gnostic => github.com/googleapis/gnostic v0.4.1 // 0.4.1 is for k8s.io/apiserver@v0.20.2
