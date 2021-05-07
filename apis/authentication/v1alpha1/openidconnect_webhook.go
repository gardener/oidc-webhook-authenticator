// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"

	"gopkg.in/square/go-jose.v2"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	certutil "k8s.io/client-go/util/cert"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
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
func (r *OpenIDConnect) ValidateCreate() error {
	openidconnectlog.Info("validate create", "name", r.Name)

	return r.validate().ToAggregate()
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *OpenIDConnect) ValidateUpdate(old runtime.Object) error {
	openidconnectlog.Info("validate update", "name", r.Name)

	oldOAC, ok := old.(*OpenIDConnect)
	if !ok {
		openidconnectlog.Info("cannot convert to OpenIDConnect", "old obj", old)

		return fmt.Errorf("cannot convert old Object to OpenIDConnect")
	}

	return oldOAC.validate().ToAggregate()
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *OpenIDConnect) ValidateDelete() error {
	openidconnectlog.Info("validate delete", "name", r.Name)

	return nil
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
	return allErrs
}

func validateJWKS(jwks []byte) error {
	data, err := base64.StdEncoding.DecodeString(string(jwks))
	if err != nil {
		return err
	}

	err = json.Unmarshal([]byte(data), &jose.JSONWebKeySet{})
	if err != nil {
		return err
	}

	return nil
}
