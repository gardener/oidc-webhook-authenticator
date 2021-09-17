// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=openidconnects,scope=Cluster,shortName=oidc;oidcs
// +kubebuilder:printcolumn:name="Issuer",type=string,JSONPath=`.spec.issuerURL`,description="Issuer is the URL the provider signs ID Tokens as"
// +kubebuilder:printcolumn:name="Client ID",type=string,JSONPath=`.spec.clientID`,description="ClientID is the audience for which this ID Token is issued for"
// +kubebuilder:printcolumn:name="Username Claim",type=string,JSONPath=`.spec.usernameClaim`,description="Username claim is the JWT field to use as the user's username"
// +kubebuilder:printcolumn:name="Groups Claim",type=string,JSONPath=`.spec.groupsClaim`,description="Groups claim is the JWT field to use as the user's groups"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=`.metadata.creationTimestamp`,description="CreationTimestamp is a timestamp representing the server time when this object was created"

// OpenIDConnect allows to dynamically register OpenID Connect providers used
// to authenticate against the kube-apiserver.
type OpenIDConnect struct {
	metav1.TypeMeta `json:",inline"`

	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OIDCAuthenticationSpec   `json:"spec"`
	Status OIDCAuthenticationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenIDConnectList contains a list of OpenIDConnect
type OpenIDConnectList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenIDConnect `json:"items"`
}

// OIDCAuthenticationSpec defines the desired state of OpenIDConnect
type OIDCAuthenticationSpec struct {

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^https:\/\/`

	// IssuerURL is the URL the provider signs ID Tokens as. This will be the "iss"
	// field of all tokens produced by the provider and is used for configuration
	// discovery.
	//
	// The URL is usually the provider's URL without a path, for example
	// "https://foo.com" or "https://example.com".
	//
	// The provider must implement configuration discovery.
	// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
	IssuerURL string `json:"issuerURL"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1

	// ClientID is the audience for which the JWT must be issued for, the "aud" field.
	//
	// The plugin supports the "authorized party" OpenID Connect claim, which allows
	// specialized providers to issue tokens to a client for a different client.
	// See: https://openid.net/specs/openid-connect-core-1_0.html#IDToken
	ClientID string `json:"clientID"`

	// +optional
	// +kubebuilder:default=sub

	// UsernameClaim is the JWT field to use as the user's username.
	UsernameClaim *string `json:"usernameClaim,omitempty"`

	// +optional

	// UsernamePrefix, if specified, causes claims mapping to username to be prefix with
	// the provided value. A value "oidc:" would result in usernames like "oidc:john".
	//
	// If not provided, the prefix defaults to "( .metadata.name )/".
	// The value "-"" can be used to disable all prefixing.
	UsernamePrefix *string `json:"usernamePrefix,omitempty"`

	// +optional
	// +kubebuilder:default=groups

	// GroupsClaim, if specified, causes the OIDCAuthenticator to try to populate the user's
	// groups with an ID Token field. If the GroupsClaim field is present in an ID Token the value
	// must be a string or list of strings.
	GroupsClaim *string `json:"groupsClaim,omitempty"`

	// +optional

	// GroupsPrefix, if specified, causes claims mapping to group names to be prefixed with the
	// value. A value "oidc:" would result in groups like "oidc:engineering" and "oidc:marketing".
	//
	// If not provided, the prefix defaults to "( .metadata.name )/".
	// The value "-"" can be used to disable all prefixing.
	GroupsPrefix *string `json:"groupsPrefix,omitempty"`

	// +kubebuilder:default={RS256}

	// SupportedSigningAlgs sets the accepted set of JOSE signing algorithms that
	// can be used by the provider to sign tokens.
	//
	// https://tools.ietf.org/html/rfc7518#section-3.1
	//
	// This value defaults to RS256, the value recommended by the OpenID Connect
	// spec:
	//
	// https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
	SupportedSigningAlgs []SigningAlgorithm `json:"supportedSigningAlgs,omitempty"`

	// +optional

	// RequiredClaims, if specified, causes the OIDCAuthenticator to verify that all the
	// required claims key value pairs are present in the ID Token.
	RequiredClaims map[string]string `json:"requiredClaims,omitempty"`

	// +optional

	// CABundle is a PEM encoded CA bundle which will be used to validate the OpenID server's certificate.
	// If unspecified, system trust roots on the apiserver are used.
	CABundle []byte `json:"caBundle,omitempty"`

	// +optional

	// JWKS if specified, provides an option to specify JWKS keys offline.
	JWKS JWKSSpec `json:"jwks,omitempty"`
}

// +kubebuilder:validation:Enum=RS256;RS384;RS512;ES256;ES384;ES512;PS256;PS384;PS512

// SigningAlgorithm is JOSE asymmetric signing algorithm value as defined by RFC 7518
type SigningAlgorithm string

// JWKSSpec defines the configuration for specifying JWKS keys offline.
type JWKSSpec struct {
	// `keys` is a base64 encoded JSON webkey Set. If specified, the OIDCAuthenticator skips the request to the issuer's jwks_uri endpoint to retrieve the keys.
	Keys []byte `json:"keys,omitempty"`

	// +kubebuilder:default=true
	// `distributedClaims` enables the OIDCAuthenticator to return references to claims that are asserted by external Claims providers.
	DistributedClaims *bool `json:"distributedClaims,omitempty"`
}

const (
	// RS256 is RSASSA-PKCS-v1.5 using SHA-256
	// This is the default value.
	RS256 SigningAlgorithm = "RS256"
	// RS384 is RSASSA-PKCS-v1.5 using SHA-384
	RS384 SigningAlgorithm = "RS384"
	// RS512 is RSASSA-PKCS-v1.5 using SHA-512
	RS512 SigningAlgorithm = "RS512"
	// ES256 is ECDSA using P-256 and SHA-256
	ES256 SigningAlgorithm = "ES256"
	// ES384 is ECDSA using P-384 and SHA-384
	ES384 SigningAlgorithm = "ES384"
	// ES512 is ECDSA using P-521 and SHA-512
	ES512 SigningAlgorithm = "ES512"
	// PS256 is RSASSA-PSS using SHA256 and MGF1-SHA256
	PS256 SigningAlgorithm = "PS256"
	// PS384 is RSASSA-PSS using SHA384 and MGF1-SHA384
	PS384 SigningAlgorithm = "PS384"
	// PS512 is RSASSA-PSS using SHA512 and MGF1-SHA512
	PS512 SigningAlgorithm = "PS512"
)

// ClaimPrefixingDisabled indicates that username or groups claim should not be
// prefixed automatically.
const ClaimPrefixingDisabled = "-"

type OIDCAuthenticationStatus struct{}

func init() {
	SchemeBuilder.Register(&OpenIDConnect{}, &OpenIDConnectList{})
}
