module github.com/gardener/oidc-webhook-authenticator

go 1.16

require (
	github.com/coreos/go-oidc/v3 v3.1.0
	github.com/go-logr/logr v0.4.0
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/gomega v1.13.0
	github.com/spf13/cobra v1.1.3
	github.com/spf13/pflag v1.0.5
	golang.org/x/time v0.0.0-20210723032227-1f47c861a9ac
	gopkg.in/square/go-jose.v2 v2.6.0
	k8s.io/api v0.22.2
	k8s.io/apimachinery v0.22.2
	k8s.io/apiserver v0.22.2
	k8s.io/client-go v0.22.2
	k8s.io/component-base v0.22.2
	k8s.io/utils v0.0.0-20210819203725-bdf08cb9a70a
	sigs.k8s.io/controller-runtime v0.9.0
)

// keep this in sync with k8s.io/apiserver version
replace github.com/googleapis/gnostic => github.com/googleapis/gnostic v0.5.5 // v0.5.5 is for k8s.io/apiserver@v0.22.2
