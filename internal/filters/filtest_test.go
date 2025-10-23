// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package filters_test

import (
	"errors"
	"net/http"
	"net/http/httptest"

	"github.com/gardener/oidc-webhook-authenticator/internal/filters"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apiserver/pkg/authentication/authenticator"
)

type mockAuth struct {
	err           error
	authenticated bool
}

func (a *mockAuth) AuthenticateRequest(_ *http.Request) (*authenticator.Response, bool, error) {
	return nil, a.authenticated, a.err
}

var _ = Describe("Filters", func() {
	testHandler := func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("ok"))
		Expect(err).ToNot(HaveOccurred())
	}

	Context("Authentication filter", func() {
		It("should return 200", func() {
			auth := &mockAuth{authenticated: true}
			h := filters.WithAuthentication(auth, http.HandlerFunc(testHandler))
			req := httptest.NewRequest("GET", "https://test", nil)
			recorder := httptest.NewRecorder()
			h.ServeHTTP(recorder, req)

			Expect(recorder.Code).To(Equal(http.StatusOK))
			Expect(recorder.Body.Bytes()).To(Equal([]byte("ok")))
		})

		It("should return 401 because of error", func() {
			auth := &mockAuth{authenticated: true, err: errors.New("err")}
			h := filters.WithAuthentication(auth, http.HandlerFunc(testHandler))
			req := httptest.NewRequest("GET", "https://test", nil)
			recorder := httptest.NewRecorder()
			h.ServeHTTP(recorder, req)

			Expect(recorder.Code).To(Equal(http.StatusUnauthorized))
			Expect(recorder.Body.Bytes()).To(Equal([]byte(`{"code":401,"message":"unauthorized"}`)))
			Expect(recorder.Result().Header["Content-Type"]).To(Equal([]string{"application/json"}))
		})

		It("should return 401 because of not authenticated response", func() {
			auth := &mockAuth{authenticated: false}
			h := filters.WithAuthentication(auth, http.HandlerFunc(testHandler))
			req := httptest.NewRequest("GET", "https://test", nil)
			recorder := httptest.NewRecorder()
			h.ServeHTTP(recorder, req)

			Expect(recorder.Code).To(Equal(http.StatusUnauthorized))
			Expect(recorder.Body.Bytes()).To(Equal([]byte(`{"code":401,"message":"unauthorized"}`)))
			Expect(recorder.Result().Header["Content-Type"]).To(Equal([]string{"application/json"}))
		})

		It("should write close connection header when request is not authenticated and protocol is http 2", func() {
			auth := &mockAuth{authenticated: false}
			h := filters.WithAuthentication(auth, http.HandlerFunc(testHandler))
			req := httptest.NewRequest("GET", "https://test", nil)
			req.ProtoMajor = 2
			recorder := httptest.NewRecorder()
			h.ServeHTTP(recorder, req)

			Expect(recorder.Code).To(Equal(http.StatusUnauthorized))
			Expect(recorder.Result().Header["Connection"]).To(Equal([]string{"close"}))
		})
	})

	Context("Allowed method filter", func() {
		It("should return 200", func() {
			h := filters.WithAllowedMethod("GET", http.HandlerFunc(testHandler))
			req := httptest.NewRequest("GET", "https://test", nil)
			recorder := httptest.NewRecorder()
			h.ServeHTTP(recorder, req)

			Expect(recorder.Code).To(Equal(http.StatusOK))
			Expect(recorder.Body.Bytes()).To(Equal([]byte("ok")))
		})

		It("should return 405 (method not allowed)", func() {
			h := filters.WithAllowedMethod("POST", http.HandlerFunc(testHandler))
			req := httptest.NewRequest("GET", "https://test", nil)
			recorder := httptest.NewRecorder()
			h.ServeHTTP(recorder, req)

			Expect(recorder.Code).To(Equal(http.StatusMethodNotAllowed))
			Expect(recorder.Body.Bytes()).To(Equal([]byte(`{"code":405,"message":"method not allowed"}`)))
			Expect(recorder.Result().Header["Content-Type"]).To(Equal([]string{"application/json"}))
		})
	})
})
