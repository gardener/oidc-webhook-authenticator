// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// +kubebuilder:docs-gen:collapse=Apache License

package authentication

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
)

// +kubebuilder:docs-gen:collapse=Imports
type mockAuthRequestHandler struct {
	returnUser      user.Info
	isAuthenticated bool
	err             error
}

func (mock *mockAuthRequestHandler) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	return &authenticator.Response{User: mock.returnUser}, mock.isAuthenticated, mock.err
}

var user1 = &user.DefaultInfo{Name: "fresh_ferret", UID: "alfa"}
var user2 = &user.DefaultInfo{Name: "elegant_sheep", UID: "bravo"}

var _ = Describe("OpenIDConnect controller", func() {

	Context("First Token Authenticator Handler Passes", func() {
		It("Authentication should succeed", func() {
			handler1 := &mockAuthRequestHandler{returnUser: user1, isAuthenticated: true}
			handler2 := &mockAuthRequestHandler{returnUser: user2, isAuthenticated: false}
			authRequestHandler := StoreAuthTokenHandler(handler1, handler2)

			resp, isAuthenticated, err := authRequestHandler.AuthenticateToken(context.Background(), "foo")
			Expect(err).NotTo(HaveOccurred())

			Expect(isAuthenticated).Should(BeTrue())

			Expect(user1.GetName()).Should(Equal(resp.User.GetName()))

		})
	})

	Context("Second Token Authenticator Handler Passes", func() {
		It("Authentication should succeed", func() {
			handler1 := &mockAuthRequestHandler{returnUser: user1, isAuthenticated: false}
			handler2 := &mockAuthRequestHandler{returnUser: user2, isAuthenticated: true}
			authRequestHandler := StoreAuthTokenHandler(handler1, handler2)

			resp, isAuthenticated, err := authRequestHandler.AuthenticateToken(context.Background(), "foo")
			Expect(err).NotTo(HaveOccurred())

			Expect(isAuthenticated).Should(BeTrue())

			Expect(user2.GetName()).Should(Equal(resp.User.GetName()))

		})
	})

	Context("No Token Authenticator Handler passes", func() {
		It("Authentication should fail", func() {

			handler1 := &mockAuthRequestHandler{}
			handler2 := &mockAuthRequestHandler{}
			authRequestHandler := StoreAuthTokenHandler(handler1, handler2)

			resp, isAuthenticated, err := authRequestHandler.AuthenticateToken(context.Background(), "foo")
			Expect(err).NotTo(HaveOccurred())

			Expect(isAuthenticated).Should(BeFalse())

			Expect(resp).To(BeNil())
		})
	})

	Context("No Token Authenticator Handler available", func() {
		It("Authentication should fail", func() {

			authRequestHandler := StoreAuthTokenHandler()
			resp, isAuthenticated, err := authRequestHandler.AuthenticateToken(context.Background(), "foo")
			Expect(err).NotTo(HaveOccurred())

			Expect(isAuthenticated).Should(BeFalse())

			Expect(resp).To(BeNil())
		})
	})

	Context("unnecessary Token Authenticator Handler errors suppressed", func() {
		It("Authentication should succeed", func() {

			handler1 := &mockAuthRequestHandler{err: errors.New("first")}
			handler2 := &mockAuthRequestHandler{returnUser: user2, isAuthenticated: true}
			authRequestHandler := StoreAuthTokenHandler(handler1, handler2)

			resp, isAuthenticated, err := authRequestHandler.AuthenticateToken(context.Background(), "foo")
			Expect(err).NotTo(HaveOccurred())

			Expect(isAuthenticated).Should(BeTrue())

			Expect(resp).NotTo(BeNil())
		})
	})

	Context("Token Authenticator Handler additive errors", func() {
		It("All Authentication handlers should fail", func() {

			handler1 := &mockAuthRequestHandler{err: errors.New("first")}
			handler2 := &mockAuthRequestHandler{err: errors.New("second")}
			authRequestHandler := StoreAuthTokenHandler(handler1, handler2)

			resp, isAuthenticated, err := authRequestHandler.AuthenticateToken(context.Background(), "foo")
			Expect(err).NotTo(HaveOccurred())

			Expect(isAuthenticated).Should(BeFalse())

			Expect(resp).To(BeNil())
		})
	})
})

func StoreAuthTokenHandler(authTokenHandlers ...authenticator.Token) unionAuthTokenHandler {
	union := unionAuthTokenHandler{}
	for _, auth := range authTokenHandlers {
		uuid := uuid.NewUUID()
		union.handlers.Store(uuid, &authenticatorInfo{
			Token: auth,
			name:  string(uuid),
			uid:   uuid,
		})
	}

	return union
}
