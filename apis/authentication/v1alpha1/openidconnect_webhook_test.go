// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1_test

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"k8s.io/utils/ptr"

	. "github.com/gardener/oidc-webhook-authenticator/apis/authentication/v1alpha1"
)

var _ = Describe("OpenidconnectWebhook", func() {
	var (
		oidc         OpenIDConnect
		systemPrefix = SystemPrefix
	)

	BeforeEach(func() {
		oidc = OpenIDConnect{}
	})

	Context("defaulting", func() {
		It("should default username claim", func() {
			oidc.Default()
			Expect(*oidc.Spec.UsernameClaim).To(Equal("sub"))
		})

		It("should not default username claim if explicitly set", func() {
			oidc.Spec.UsernameClaim = ptr.To("someuserclaim")
			oidc.Default()
			Expect(*oidc.Spec.UsernameClaim).To(Equal("someuserclaim"))
		})

		It("should default groups claim", func() {
			oidc.Default()
			Expect(*oidc.Spec.GroupsClaim).To(Equal("groups"))
		})

		It("should not default groups claim if explicitly set", func() {
			oidc.Spec.GroupsClaim = ptr.To("somegroupsclaim")
			oidc.Default()
			Expect(*oidc.Spec.GroupsClaim).To(Equal("somegroupsclaim"))
		})

		It("should default supported signing algs", func() {
			oidc.Default()
			Expect(len(oidc.Spec.SupportedSigningAlgs)).To(Equal(1))
			Expect(oidc.Spec.SupportedSigningAlgs[0]).To(Equal(RS256))
		})

		It("should not default supported signing algs if explicitly set", func() {
			oidc.Spec.SupportedSigningAlgs = []SigningAlgorithm{RS256, RS512}
			oidc.Default()
			Expect(len(oidc.Spec.SupportedSigningAlgs)).To(Equal(2))
			Expect(oidc.Spec.SupportedSigningAlgs).To(ConsistOf(RS256, RS512))
		})
	})

	Context("create validation", func() {
		BeforeEach(func() {
			oidc.Spec.IssuerURL = "https://secure.com"
			oidc.Spec.ClientID = "some-client-id"
		})

		It("should return error if issuer url is not starting with https", func() {
			oidc.Spec.IssuerURL = "http://notsecure.com"
			warnings, err := oidc.ValidateCreate()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("issuerURL: Invalid value: \"http://notsecure.com\": must start with https"))
			Expect(warnings).To(BeNil())
		})

		It("should return error for supported signing algorithms that are not allowed", func() {
			oidc.Spec.SupportedSigningAlgs = []SigningAlgorithm{
				RS256,
				"deprecated1",
				"deprecated2",
			}
			warnings, err := oidc.ValidateCreate()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("[supportedSigningAlgs[1]: Invalid value: \"deprecated1\": unsupported signing alg, supportedSigningAlgs[2]: Invalid value: \"deprecated2\": unsupported signing alg]"))
			Expect(warnings).To(BeNil())
		})

		It("should return error for invalid ca bundle", func() {
			oidc.Spec.CABundle = []byte("dGVzdA==")
			warnings, err := oidc.ValidateCreate()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("caBundle: Invalid value: \"dGVzdA==\": must be a valid base64 encoded certificate bundle"))
			Expect(warnings).To(BeNil())
		})

		It("should return error for invalid jwks", func() {
			oidc.Spec.JWKS.Keys = []byte("dGVzdA==")
			warnings, err := oidc.ValidateCreate()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("keys: Invalid value: \"dGVzdA==\": must be a valid base64 encoded JWKS"))
			Expect(warnings).To(BeNil())
		})

		It("should return error for empty clientID", func() {
			oidc.Spec.ClientID = ""
			warnings, err := oidc.ValidateCreate()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("clientID: Invalid value: \"\": must not be empty"))
			Expect(warnings).To(BeNil())
		})

		DescribeTable("should not allow username prefix to start with 'system:'",
			func(maliciousPrefix string) {
				errMessageTemplate := "usernamePrefix: Invalid value: \"%s\": must not start with system:"
				oidc.Spec.UsernamePrefix = &maliciousPrefix
				warnings, err := oidc.ValidateCreate()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal(fmt.Sprintf(errMessageTemplate, maliciousPrefix)))
				Expect(warnings).To(BeNil())
			},

			Entry("exact match", systemPrefix),
			Entry("match with suffix", systemPrefix+"some-more-text"),
		)

		DescribeTable("should allow username prefix if it does not start with 'system:'",
			func(validPrefix string) {
				oidc.Spec.UsernamePrefix = &validPrefix
				warnings, err := oidc.ValidateCreate()
				Expect(err).NotTo(HaveOccurred())
				Expect(warnings).To(BeNil())
			},

			Entry("valid prefix ending with system:", "pref-"+systemPrefix),
			Entry("valid prefix containing system:", "pref-"+systemPrefix+"-suff"),
			Entry("valid prefix not containing system:", "pref-"),
			Entry("disabled prefixing", "-"),
			Entry("empty prefix", ""),
		)

		DescribeTable("should not allow groups prefix to start with 'system:'",
			func(maliciousPrefix string) {
				errMessageTemplate := "groupsPrefix: Invalid value: \"%s\": must not start with system:"
				oidc.Spec.GroupsPrefix = &maliciousPrefix
				warnings, err := oidc.ValidateCreate()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal(fmt.Sprintf(errMessageTemplate, maliciousPrefix)))
				Expect(warnings).To(BeNil())
			},

			Entry("exact match", systemPrefix),
			Entry("match with suffix", systemPrefix+"some-more-text"),
		)

		DescribeTable("should allow groups prefix if it does not start with 'system:'",
			func(validPrefix string) {
				oidc.Spec.GroupsPrefix = &validPrefix
				warnings, err := oidc.ValidateCreate()
				Expect(err).NotTo(HaveOccurred())
				Expect(warnings).To(BeNil())
			},

			Entry("valid prefix ending with system:", "pref-"+systemPrefix),
			Entry("valid prefix containing system:", "pref-"+systemPrefix+"-suff"),
			Entry("valid prefix not containing system:", "pref-"),
			Entry("disabled prefixing", "-"),
			Entry("empty prefix", ""),
		)
	})

	Context("update validation", func() {
		BeforeEach(func() {
			oidc.Spec.IssuerURL = "https://secure.com"
			oidc.Spec.ClientID = "some-client-id"
		})

		It("should not return error if new oidc object is valid", func() {
			newObj := OpenIDConnect{
				Spec: OIDCAuthenticationSpec{
					IssuerURL: "https://secure2.com",
					ClientID:  "some-id",
				},
			}
			warnings, err := newObj.ValidateUpdate(&oidc)
			Expect(err).NotTo(HaveOccurred())
			Expect(warnings).To(BeNil())
		})

		It("should return error if new oidc object is not valid", func() {
			newObj := OpenIDConnect{
				Spec: OIDCAuthenticationSpec{
					IssuerURL: "http://notsecure.com",
					ClientID:  "some-id",
				},
			}
			warnings, err := newObj.ValidateUpdate(&oidc)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("issuerURL: Invalid value: \"http://notsecure.com\": must start with https"))
			Expect(warnings).To(BeNil())
		})

		DescribeTable("should not allow username prefix to start with 'system:'",
			func(maliciousPrefix string) {
				errMessageTemplate := "usernamePrefix: Invalid value: \"%s\": must not start with system:"
				newObj := OpenIDConnect{
					Spec: OIDCAuthenticationSpec{
						IssuerURL:      "https://secure2.com",
						ClientID:       "some-id",
						UsernamePrefix: &maliciousPrefix,
					},
				}
				warnings, err := newObj.ValidateUpdate(&oidc)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal(fmt.Sprintf(errMessageTemplate, maliciousPrefix)))
				Expect(warnings).To(BeNil())
			},

			Entry("exact match", systemPrefix),
			Entry("match with suffix", systemPrefix+"some-more-text"),
		)

		DescribeTable("should allow username prefix if it does not start with 'system:'",
			func(validPrefix string) {
				newObj := OpenIDConnect{
					Spec: OIDCAuthenticationSpec{
						IssuerURL:      "https://secure2.com",
						ClientID:       "some-id",
						UsernamePrefix: &validPrefix,
					},
				}
				warnings, err := newObj.ValidateUpdate(&oidc)
				Expect(err).NotTo(HaveOccurred())
				Expect(warnings).To(BeNil())
			},

			Entry("valid prefix ending with system:", "pref-"+systemPrefix),
			Entry("valid prefix containing system:", "pref-"+systemPrefix+"-suff"),
			Entry("valid prefix not containing system:", "pref-"),
			Entry("disabled prefixing", "-"),
			Entry("empty prefix", ""),
		)

		DescribeTable("should not allow groups prefix to start with 'system:'",
			func(maliciousPrefix string) {
				errMessageTemplate := "groupsPrefix: Invalid value: \"%s\": must not start with system:"
				newObj := OpenIDConnect{
					Spec: OIDCAuthenticationSpec{
						IssuerURL:    "https://secure2.com",
						ClientID:     "some-id",
						GroupsPrefix: &maliciousPrefix,
					},
				}
				warnings, err := newObj.ValidateUpdate(&oidc)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal(fmt.Sprintf(errMessageTemplate, maliciousPrefix)))
				Expect(warnings).To(BeNil())
			},

			Entry("exact match", systemPrefix),
			Entry("match with suffix", systemPrefix+"some-more-text"),
		)

		DescribeTable("should allow groups prefix if it does not start with 'system:'",
			func(validPrefix string) {
				newObj := OpenIDConnect{
					Spec: OIDCAuthenticationSpec{
						IssuerURL:    "https://secure2.com",
						ClientID:     "some-id",
						GroupsPrefix: &validPrefix,
					},
				}
				warnings, err := newObj.ValidateUpdate(&oidc)
				Expect(err).NotTo(HaveOccurred())
				Expect(warnings).To(BeNil())
			},

			Entry("valid prefix ending with system:", "pref-"+systemPrefix),
			Entry("valid prefix containing system:", "pref-"+systemPrefix+"-suff"),
			Entry("valid prefix not containing system:", "pref-"),
			Entry("disabled prefixing", "-"),
			Entry("empty prefix", ""),
		)

		It("should return error for negative maxTokenExpirationSeconds", func() {
			oidc.Spec.MaxTokenExpirationSeconds = ptr.To[int64](-1)
			warnings, err := oidc.ValidateCreate()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("maxTokenExpirationSeconds: Invalid value: -1: should be positive"))
			Expect(warnings).To(BeNil())
		})

		It("should return error for zero maxTokenExpirationSeconds", func() {
			oidc.Spec.MaxTokenExpirationSeconds = ptr.To[int64](0)
			warnings, err := oidc.ValidateCreate()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("maxTokenExpirationSeconds: Invalid value: 0: should be positive"))
			Expect(warnings).To(BeNil())
		})

		It("should return error for duplicate claims in ExtraClaims", func() {
			oidc.Spec.ExtraClaims = []string{"claim1", "claim2", "ClaIm1"}
			warnings, err := oidc.ValidateCreate()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("extraClaims: Invalid value: []string{\"claim1\", \"claim2\", \"ClaIm1\"}: duplicated claims found"))
			Expect(warnings).To(BeNil())
		})
	})
})
