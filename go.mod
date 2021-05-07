module github.com/gardener/oidc-webhook-authenticator

go 1.15

require (
	github.com/coreos/go-oidc v2.1.0+incompatible
	github.com/go-logr/logr v0.4.0
	github.com/onsi/ginkgo v1.15.0
	github.com/onsi/gomega v1.10.5
	github.com/spf13/cobra v1.1.1
	github.com/spf13/pflag v1.0.5
	golang.org/x/time v0.0.0-20210220033141-f8bda1e9f3ba
	gopkg.in/square/go-jose.v2 v2.5.1
	k8s.io/api v0.21.0
	k8s.io/apimachinery v0.21.0
	k8s.io/apiserver v0.21.0
	k8s.io/client-go v0.21.0
	k8s.io/component-base v0.21.0
	sigs.k8s.io/controller-runtime v0.9.0-alpha.1.0.20210412152200-442d3cad1e99
)

// keep this in sync with k8s.io/apiserver version
replace github.com/googleapis/gnostic => github.com/googleapis/gnostic v0.4.1 // 0.4.1 is for k8s.io/apiserver@v0.20.2

replace k8s.io/apiserver => k8s.io/apiserver v0.0.0-20210412033426-c5d971fadc40
