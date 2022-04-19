// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package authentication

import (
	"sync"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("OpenidconnectWebhook", func() {

	const (
		issuer1     = "https://issuer1"
		issuer2     = "https://issuer2"
		handlerKey1 = "my-unique-name-1"
		handlerKey2 = "my-unique-name-2"
		handlerKey3 = "my-unique-name-3"
	)
	var (
		unionHandler *unionAuthTokenHandler
	)

	BeforeEach(func() {
		unionHandler = &unionAuthTokenHandler{}
	})

	verifyHandler := func(u *unionAuthTokenHandler, issuer string, handlerKey string, auth *authenticatorInfo) {
		val, ok := u.issuerHandlers.Load(issuer)
		Expect(ok).To(BeTrue())

		asMap, ok := val.(*sync.Map)
		Expect(ok).To(BeTrue())

		val, ok = asMap.Load(handlerKey)
		Expect(ok).To(BeTrue())

		handler, ok := val.(*authenticatorInfo)
		Expect(ok).To(BeTrue())
		Expect(handler).To(Equal(auth))

		val, ok = u.nameIssuerMapping.Load(handlerKey)
		Expect(ok).To(BeTrue())

		url, ok := val.(string)
		Expect(ok).To(BeTrue())
		Expect(url).To(Equal(issuer))
	}

	verifyHandlerDoesNotExist := func(u *unionAuthTokenHandler, issuer string, handlerKey string) {
		val, ok := u.issuerHandlers.Load(issuer)
		Expect(ok).To(BeTrue())

		asMap, ok := val.(*sync.Map)
		Expect(ok).To(BeTrue())

		_, ok = asMap.Load(handlerKey)
		Expect(ok).To(BeFalse())
	}

	Context("Registering handlers", func() {
		It("should successfully register a single handler", func() {
			unionHandler.registerHandler(issuer1, handlerKey1, &authenticatorInfo{
				Token: nil,
				name:  "test",
				uid:   "someid",
			})

			verifyHandler(unionHandler, issuer1, handlerKey1, &authenticatorInfo{
				Token: nil,
				name:  "test",
				uid:   "someid",
			})
		})

		It("should successfully register a single handler then change issuer", func() {
			unionHandler.registerHandler(issuer1, handlerKey1, &authenticatorInfo{
				Token: nil,
				name:  "test",
				uid:   "someid",
			})

			unionHandler.registerHandler(issuer2, handlerKey1, &authenticatorInfo{
				Token: nil,
				name:  "test",
				uid:   "someid",
			})

			verifyHandlerDoesNotExist(unionHandler, issuer1, handlerKey1)
			verifyHandler(unionHandler, issuer2, handlerKey1, &authenticatorInfo{
				Token: nil,
				name:  "test",
				uid:   "someid",
			})
		})

		It("should successfully register a single handler then delete it", func() {
			unionHandler.registerHandler(issuer1, handlerKey1, &authenticatorInfo{
				Token: nil,
				name:  "test",
				uid:   "someid",
			})

			unionHandler.deleteHandler(handlerKey1)

			verifyHandlerDoesNotExist(unionHandler, issuer1, handlerKey1)
		})

		It("should successfully register a single handler change its issuer then delete it", func() {
			unionHandler.registerHandler(issuer1, handlerKey1, &authenticatorInfo{
				Token: nil,
				name:  "test",
				uid:   "someid",
			})

			unionHandler.registerHandler(issuer2, handlerKey1, &authenticatorInfo{
				Token: nil,
				name:  "test",
				uid:   "someid",
			})

			verifyHandlerDoesNotExist(unionHandler, issuer1, handlerKey1)
			verifyHandler(unionHandler, issuer2, handlerKey1, &authenticatorInfo{
				Token: nil,
				name:  "test",
				uid:   "someid",
			})

			unionHandler.deleteHandler(handlerKey1)
			verifyHandlerDoesNotExist(unionHandler, issuer2, handlerKey1)
		})

		It("should successfully register multiple handlers", func() {
			unionHandler.registerHandler(issuer1, handlerKey1, &authenticatorInfo{
				Token: nil,
				name:  "test",
				uid:   "someid",
			})

			unionHandler.registerHandler(issuer1, handlerKey2, &authenticatorInfo{
				Token: nil,
				name:  "test1",
				uid:   "someid1",
			})

			unionHandler.registerHandler(issuer2, handlerKey3, &authenticatorInfo{
				Token: nil,
				name:  "test2",
				uid:   "someid2",
			})

			verifyHandler(unionHandler, issuer1, handlerKey1, &authenticatorInfo{
				Token: nil,
				name:  "test",
				uid:   "someid",
			})

			verifyHandler(unionHandler, issuer1, handlerKey2, &authenticatorInfo{
				Token: nil,
				name:  "test1",
				uid:   "someid1",
			})

			verifyHandler(unionHandler, issuer2, handlerKey3, &authenticatorInfo{
				Token: nil,
				name:  "test2",
				uid:   "someid2",
			})
		})

		It("should successfully register multiple handlers then change issuer of one of them", func() {
			unionHandler.registerHandler(issuer1, handlerKey1, &authenticatorInfo{
				Token: nil,
				name:  "test",
				uid:   "someid",
			})

			unionHandler.registerHandler(issuer1, handlerKey2, &authenticatorInfo{
				Token: nil,
				name:  "test1",
				uid:   "someid1",
			})

			unionHandler.registerHandler(issuer2, handlerKey3, &authenticatorInfo{
				Token: nil,
				name:  "test2",
				uid:   "someid2",
			})

			verifyHandler(unionHandler, issuer1, handlerKey1, &authenticatorInfo{
				Token: nil,
				name:  "test",
				uid:   "someid",
			})

			verifyHandler(unionHandler, issuer1, handlerKey2, &authenticatorInfo{
				Token: nil,
				name:  "test1",
				uid:   "someid1",
			})

			verifyHandler(unionHandler, issuer2, handlerKey3, &authenticatorInfo{
				Token: nil,
				name:  "test2",
				uid:   "someid2",
			})

			unionHandler.registerHandler(issuer2, handlerKey2, &authenticatorInfo{
				Token: nil,
				name:  "test1-new",
				uid:   "someid1-new",
			})

			verifyHandlerDoesNotExist(unionHandler, issuer1, handlerKey2)

			verifyHandler(unionHandler, issuer2, handlerKey2, &authenticatorInfo{
				Token: nil,
				name:  "test1-new",
				uid:   "someid1-new",
			})
		})

		It("should successfully register multiple handlers then delete one of them", func() {
			unionHandler.registerHandler(issuer1, handlerKey1, &authenticatorInfo{
				Token: nil,
				name:  "test",
				uid:   "someid",
			})

			unionHandler.registerHandler(issuer1, handlerKey2, &authenticatorInfo{
				Token: nil,
				name:  "test1",
				uid:   "someid1",
			})

			unionHandler.registerHandler(issuer2, handlerKey3, &authenticatorInfo{
				Token: nil,
				name:  "test2",
				uid:   "someid2",
			})

			unionHandler.deleteHandler(handlerKey2)

			verifyHandler(unionHandler, issuer1, handlerKey1, &authenticatorInfo{
				Token: nil,
				name:  "test",
				uid:   "someid",
			})

			verifyHandlerDoesNotExist(unionHandler, issuer1, handlerKey2)

			verifyHandler(unionHandler, issuer2, handlerKey3, &authenticatorInfo{
				Token: nil,
				name:  "test2",
				uid:   "someid2",
			})
		})
	})
})
