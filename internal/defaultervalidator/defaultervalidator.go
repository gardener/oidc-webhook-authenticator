// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package defaultervalidator

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	certutil "k8s.io/client-go/util/cert"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	authenticationv1alpha1 "github.com/gardener/oidc-webhook-authenticator/apis/authentication/v1alpha1"
)

var (
	// log is for logging in this package.
	log = logf.Log.WithName("defaulter-validator")

	allowedSigningAlgs = map[authenticationv1alpha1.SigningAlgorithm]bool{
		authenticationv1alpha1.RS256: true,
		authenticationv1alpha1.RS384: true,
		authenticationv1alpha1.RS512: true,
		authenticationv1alpha1.ES256: true,
		authenticationv1alpha1.ES384: true,
		authenticationv1alpha1.ES512: true,
		authenticationv1alpha1.PS256: true,
		authenticationv1alpha1.PS384: true,
		authenticationv1alpha1.PS512: true,
	}
)

// +kubebuilder:webhook:path=/webhooks/mutating,mutating=true,failurePolicy=fail,sideEffects=None,groups=authentication.gardener.cloud,resources=openidconnects,verbs=create;update,versions=v1alpha1,name=oidc.authentication.gardener.cloud,admissionReviewVersions={v1,v1beta1}
// +kubebuilder:webhook:verbs=create;update,path=/webhooks/validating,mutating=false,failurePolicy=fail,sideEffects=None,groups=authentication.gardener.cloud,resources=openidconnects,versions=v1alpha1,name=oidc.authentication.gardener.cloud,admissionReviewVersions={v1,v1beta1}

// DefaulterValidator implements defaulting and validation for the OpenIDConnect resource.
type DefaulterValidator struct{}

// ensure webhookHandler implements CustomDefaulter and CustomValidator interfaces
var _ webhook.CustomDefaulter = (*DefaulterValidator)(nil)
var _ webhook.CustomValidator = (*DefaulterValidator)(nil)

// Default implements [webhook.CustomDefaulter] so a webhook can be registered for the type.
func (*DefaulterValidator) Default(_ context.Context, obj runtime.Object) error {
	oidc, ok := obj.(*authenticationv1alpha1.OpenIDConnect)
	if !ok {
		return fmt.Errorf("expected *authenticationv1alpha1.OpenIDConnect but got %T", obj)
	}

	log.Info("Defaulting OpenIDConnect resource", "name", oidc.Name)

	var (
		defaultUsernameClaim = "sub"
		defaultGroupsClaim   = "groups"
	)

	if oidc.Spec.UsernameClaim == nil {
		oidc.Spec.UsernameClaim = &defaultUsernameClaim
	}

	if oidc.Spec.GroupsClaim == nil {
		oidc.Spec.GroupsClaim = &defaultGroupsClaim
	}

	if len(oidc.Spec.SupportedSigningAlgs) == 0 {
		oidc.Spec.SupportedSigningAlgs = []authenticationv1alpha1.SigningAlgorithm{authenticationv1alpha1.RS256}
	}

	return nil
}

// ValidateCreate validates the object on creation.
// Return an error if the object is invalid.
// ValidateCreate implements [webhook.CustomValidator] so a webhook can be registered for the type.
func (*DefaulterValidator) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	oidc, ok := obj.(*authenticationv1alpha1.OpenIDConnect)
	if !ok {
		return nil, fmt.Errorf("expected *authenticationv1alpha1.OpenIDConnect but got %T", obj)
	}

	log.Info("Validating OpenIDConnect", "operation", "create", "name", oidc.Name)

	return nil, validate(oidc).ToAggregate()
}

// ValidateUpdate validates the object on update.
// Return an error if the object is invalid.
// ValidateUpdate implements [webhook.CustomValidator] so a webhook can be registered for the type.
func (*DefaulterValidator) ValidateUpdate(_ context.Context, _, obj runtime.Object) (admission.Warnings, error) {
	oidc, ok := obj.(*authenticationv1alpha1.OpenIDConnect)
	if !ok {
		return nil, fmt.Errorf("expected *authenticationv1alpha1.OpenIDConnect but got %T", obj)
	}

	log.Info("Validating OpenIDConnect", "operation", "update", "name", oidc.Name)

	return nil, validate(oidc).ToAggregate()
}

// ValidateDelete validates the object on deletion.
// Return an error if the object is invalid.
// ValidateDelete implements [webhook.CustomValidator] so a webhook can be registered for the type.
func (*DefaulterValidator) ValidateDelete(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	oidc, ok := obj.(*authenticationv1alpha1.OpenIDConnect)
	if !ok {
		return nil, fmt.Errorf("expected *authenticationv1alpha1.OpenIDConnect but got %T", obj)
	}

	log.Info("Validating OpenIDConnect", "operation", "delete", "name", oidc.Name)

	return nil, nil
}

func validate(oidc *authenticationv1alpha1.OpenIDConnect) field.ErrorList {
	allErrs := field.ErrorList{}

	url, err := url.Parse(oidc.Spec.IssuerURL)
	if err != nil {
		allErrs = append(allErrs, field.Invalid(field.NewPath("issuerURL"), oidc.Spec.IssuerURL, "must be a valid URL"))
	}

	if url.Scheme != "https" {
		allErrs = append(allErrs, field.Invalid(field.NewPath("issuerURL"), oidc.Spec.IssuerURL, "must start with https"))
	}

	for i, alg := range oidc.Spec.SupportedSigningAlgs {
		if !allowedSigningAlgs[alg] {
			allErrs = append(allErrs, field.Invalid(field.NewPath("supportedSigningAlgs").Index(i), alg, "unsupported signing alg"))
		}
	}

	if len(oidc.Spec.CABundle) > 0 {
		if _, err := certutil.NewPoolFromBytes(oidc.Spec.CABundle); err != nil {
			allErrs = append(allErrs, field.Invalid(field.NewPath("caBundle"), string(oidc.Spec.CABundle), "must be a valid base64 encoded certificate bundle"))
		}
	}

	if len(oidc.Spec.JWKS.Keys) > 0 {
		if err := validateJWKS(oidc.Spec.JWKS.Keys); err != nil {
			allErrs = append(allErrs, field.Invalid(field.NewPath("keys"), string(oidc.Spec.JWKS.Keys), "must be a valid base64 encoded JWKS"))
		}
	}

	if len(oidc.Spec.ClientID) == 0 {
		allErrs = append(allErrs, field.Invalid(field.NewPath("clientID"), oidc.Spec.ClientID, "must not be empty"))
	}

	if isPrefixingMalicious(oidc.Spec.UsernamePrefix) {
		allErrs = append(allErrs, field.Invalid(field.NewPath("usernamePrefix"), oidc.Spec.UsernamePrefix, fmt.Sprintf("must not start with %s", authenticationv1alpha1.SystemPrefix)))
	}

	if isPrefixingMalicious(oidc.Spec.GroupsPrefix) {
		allErrs = append(allErrs, field.Invalid(field.NewPath("groupsPrefix"), oidc.Spec.GroupsPrefix, fmt.Sprintf("must not start with %s", authenticationv1alpha1.SystemPrefix)))
	}

	if oidc.Spec.MaxTokenExpirationSeconds != nil && *oidc.Spec.MaxTokenExpirationSeconds <= 0 {
		allErrs = append(allErrs, field.Invalid(field.NewPath("maxTokenExpirationSeconds"), *oidc.Spec.MaxTokenExpirationSeconds, "should be positive"))
	}

	if len(oidc.Spec.ExtraClaims) > 0 {
		claims := map[string]struct{}{}
		for _, claim := range oidc.Spec.ExtraClaims {
			lowered := strings.ToLower(claim)
			if _, ok := claims[lowered]; ok {
				allErrs = append(allErrs, field.Invalid(field.NewPath("extraClaims"), oidc.Spec.ExtraClaims, "duplicated claims found"))
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
	return s != nil && len(*s) > 0 && *s != authenticationv1alpha1.ClaimPrefixingDisabled && strings.HasPrefix(*s, authenticationv1alpha1.SystemPrefix)
}
