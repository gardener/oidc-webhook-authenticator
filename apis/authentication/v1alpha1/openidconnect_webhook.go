// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"gopkg.in/square/go-jose.v2"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	certutil "k8s.io/client-go/util/cert"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var (
	// log is for logging in this package.
	openidconnectlog = logf.Log.WithName("openidconnect-resource")

	allowedSigningAlgs = map[SigningAlgorithm]bool{
		RS256: true,
		RS384: true,
		RS512: true,
		ES256: true,
		ES384: true,
		ES512: true,
		PS256: true,
		PS384: true,
		PS512: true,
	}
)

// +kubebuilder:webhook:path=/webhooks/mutating,mutating=true,failurePolicy=fail,sideEffects=None,groups=authentication.gardener.cloud,resources=openidconnects,verbs=create;update,versions=v1alpha1,name=oidc.authentication.gardener.cloud,admissionReviewVersions={v1,v1beta1}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *OpenIDConnect) Default() {
	openidconnectlog.Info("default", "name", r.Name)

	var (
		defaultUsernameClaim = "sub"
		defaultGroupsClaim   = "groups"
	)

	if r.Spec.UsernameClaim == nil {
		r.Spec.UsernameClaim = &defaultUsernameClaim
	}

	if r.Spec.GroupsClaim == nil {
		r.Spec.GroupsClaim = &defaultGroupsClaim
	}

	if len(r.Spec.SupportedSigningAlgs) == 0 {
		r.Spec.SupportedSigningAlgs = []SigningAlgorithm{RS256}
	}
}

// +kubebuilder:webhook:verbs=create;update,path=/webhooks/validating,mutating=false,failurePolicy=fail,sideEffects=None,groups=authentication.gardener.cloud,resources=openidconnects,versions=v1alpha1,name=oidc.authentication.gardener.cloud,admissionReviewVersions={v1,v1beta1}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *OpenIDConnect) ValidateCreate() (admission.Warnings, error) {
	openidconnectlog.Info("validate create", "name", r.Name)

	return nil, r.validate().ToAggregate()
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *OpenIDConnect) ValidateUpdate(old runtime.Object) (admission.Warnings, error) {
	openidconnectlog.Info("validate update", "name", r.Name)

	return nil, r.validate().ToAggregate()
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *OpenIDConnect) ValidateDelete() (admission.Warnings, error) {
	openidconnectlog.Info("validate delete", "name", r.Name)

	return nil, nil
}

func (r *OpenIDConnect) validate() field.ErrorList {
	allErrs := field.ErrorList{}

	url, err := url.Parse(r.Spec.IssuerURL)
	if err != nil {
		allErrs = append(allErrs, field.Invalid(field.NewPath("issuerURL"), r.Spec.IssuerURL, "must be a valid URL"))
	}

	if url.Scheme != "https" {
		allErrs = append(allErrs, field.Invalid(field.NewPath("issuerURL"), r.Spec.IssuerURL, "must start with https"))
	}

	for i, alg := range r.Spec.SupportedSigningAlgs {
		if !allowedSigningAlgs[alg] {
			allErrs = append(allErrs, field.Invalid(field.NewPath("supportedSigningAlgs").Index(i), alg, "unsupported signing alg"))
		}
	}

	if len(r.Spec.CABundle) > 0 {
		if _, err := certutil.NewPoolFromBytes(r.Spec.CABundle); err != nil {
			allErrs = append(allErrs, field.Invalid(field.NewPath("caBundle"), string(r.Spec.CABundle), "must be a valid base64 encoded certificate bundle"))
		}
	}

	if len(r.Spec.JWKS.Keys) > 0 {
		if err := validateJWKS(r.Spec.JWKS.Keys); err != nil {
			allErrs = append(allErrs, field.Invalid(field.NewPath("keys"), string(r.Spec.JWKS.Keys), "must be a valid base64 encoded JWKS"))
		}
	}

	if len(r.Spec.ClientID) == 0 {
		allErrs = append(allErrs, field.Invalid(field.NewPath("clientID"), r.Spec.ClientID, "must not be empty"))
	}

	if isPrefixingMalicious(r.Spec.UsernamePrefix) {
		allErrs = append(allErrs, field.Invalid(field.NewPath("usernamePrefix"), r.Spec.UsernamePrefix, fmt.Sprintf("must not start with %s", SystemPrefix)))
	}

	if isPrefixingMalicious(r.Spec.GroupsPrefix) {
		allErrs = append(allErrs, field.Invalid(field.NewPath("groupsPrefix"), r.Spec.GroupsPrefix, fmt.Sprintf("must not start with %s", SystemPrefix)))
	}

	if r.Spec.MaxTokenExpirationSeconds != nil && *r.Spec.MaxTokenExpirationSeconds <= 0 {
		allErrs = append(allErrs, field.Invalid(field.NewPath("maxTokenExpirationSeconds"), *r.Spec.MaxTokenExpirationSeconds, "should be positive"))
	}

	if len(r.Spec.ExtraClaims) > 0 {
		claims := map[string]struct{}{}
		for _, claim := range r.Spec.ExtraClaims {
			lowered := strings.ToLower(claim)
			if _, ok := claims[lowered]; ok {
				allErrs = append(allErrs, field.Invalid(field.NewPath("extraClaims"), r.Spec.ExtraClaims, "duplicated claims found"))
				break
			}
			claims[lowered] = struct{}{}
		}
	}

	return allErrs
}

func validateJWKS(jwks []byte) error {
	return json.Unmarshal(jwks, &jose.JSONWebKeySet{})
}

func isPrefixingMalicious(s *string) bool {
	return s != nil && len(*s) > 0 && *s != ClaimPrefixingDisabled && strings.HasPrefix(*s, SystemPrefix)
}
