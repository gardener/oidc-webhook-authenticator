// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package authentication_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/gardener/oidc-webhook-authenticator/webhook/authentication"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	ctrl "sigs.k8s.io/controller-runtime"
)

type mockAuthenticator struct {
	response        authenticator.Response
	isAuthenticated bool
	err             error
}

func (mock *mockAuthenticator) AuthenticateToken(_ context.Context, _ string) (*authenticator.Response, bool, error) {
	return &mock.response, mock.isAuthenticated, mock.err
}

func (mock *mockAuthenticator) defaultWebhook() *authentication.Webhook {
	return &authentication.Webhook{
		Authenticator: mock,
		Log:           ctrl.Log.WithName("webhooks").WithName("TokenReview"),
	}
}

var _ = Describe("Authentication", func() {
	const (
		actualTokenReviewJSON = `{
			"apiVersion": "authentication.k8s.io/v1",
			"kind": "TokenReview",
			"metadata": {
				"name": "test-token-review",
				"namespace": "default"
			},
			"spec": {
				"token": "testtokenhere",
				"audiences": [
					"one",
					"two"
				]
			},
			"status": {
				"user": {
					"username": "johndoe",
					"uid": "first"
				}
			}
		}`
	)
	var (
		response1 = authenticator.Response{
			User: &user.DefaultInfo{
				Name:   "johndoe",
				UID:    "first",
				Groups: []string{"dev", "admin"},
				Extra: map[string][]string{
					"extra1": {"value1", "value2"},
					"extra2": {"value3"},
				},
			},
			Audiences: authenticator.Audiences{},
		}
		mockAuth            *mockAuthenticator
		recorder            *httptest.ResponseRecorder
		expectedTokenReview *authenticationv1.TokenReview
	)

	BeforeEach(func() {
		mockAuth = &mockAuthenticator{
			response:        response1,
			isAuthenticated: true,
		}
		recorder = httptest.NewRecorder()
		expectedTokenReview = &authenticationv1.TokenReview{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "authentication.k8s.io/v1",
				Kind:       "TokenReview",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-token-review",
				Namespace: "default",
			},
			Status: authenticationv1.TokenReviewStatus{
				Authenticated: false,
			},
			Spec: authenticationv1.TokenReviewSpec{
				Token:     "testtokenhere",
				Audiences: []string{"one", "two"},
			},
		}
	})

	Context("user is not authenticated", func() {
		It("should return empty user info", func() {
			mockAuth.isAuthenticated = false
			webhook := mockAuth.defaultWebhook()

			req, err := http.NewRequest(http.MethodPost, "/some-valid-path", bytes.NewBufferString(actualTokenReviewJSON))
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Content-Type", "application/json")
			handler := webhook.Build()
			handler.ServeHTTP(recorder, req)
			Expect(recorder.Code).To(Equal(http.StatusOK))

			actualTokenReview := &authenticationv1.TokenReview{}
			err = json.NewDecoder(recorder.Body).Decode(actualTokenReview)
			Expect(err).NotTo(HaveOccurred())
			Expect(actualTokenReview).To(Equal(expectedTokenReview))
		})
	})

	Context("authenticator returns error", func() {
		It("should return empty user info", func() {
			mockAuth.isAuthenticated = true
			mockAuth.err = errors.New("Error occured during the authentication process")
			webhook := mockAuth.defaultWebhook()

			req, err := http.NewRequest(http.MethodPost, "/some-valid-path", bytes.NewBufferString(actualTokenReviewJSON))
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Content-Type", "application/json")
			handler := webhook.Build()
			handler.ServeHTTP(recorder, req)
			Expect(recorder.Code).To(Equal(http.StatusOK))

			actualTokenReview := &authenticationv1.TokenReview{}
			err = json.NewDecoder(recorder.Body).Decode(actualTokenReview)
			Expect(err).NotTo(HaveOccurred())
			Expect(actualTokenReview).To(Equal(expectedTokenReview))
		})
	})

	Context("user is authenticated", func() {
		It("should return user info", func() {
			webhook := mockAuth.defaultWebhook()

			req, err := http.NewRequest(http.MethodPost, "/some-valid-path", bytes.NewBufferString(actualTokenReviewJSON))
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Content-Type", "application/json")
			handler := webhook.Build()
			handler.ServeHTTP(recorder, req)
			Expect(recorder.Code).To(Equal(http.StatusOK))

			actualTokenReview := &authenticationv1.TokenReview{}
			err = json.NewDecoder(recorder.Body).Decode(actualTokenReview)
			Expect(err).NotTo(HaveOccurred())
			expectedTokenReview.Status = authenticationv1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1.UserInfo{
					Username: "johndoe",
					UID:      "first",
					Groups:   []string{"dev", "admin"},
					Extra: map[string]authenticationv1.ExtraValue{
						"extra1": {"value1", "value2"},
						"extra2": {"value3"},
					},
				},
			}
			Expect(actualTokenReview).To(Equal(expectedTokenReview))
		})

		It("should return user info with additional keys if user is passed in the context of the request", func() {
			webhook := mockAuth.defaultWebhook()
			req, err := http.NewRequest(http.MethodPost, "/some-valid-path", bytes.NewBufferString(actualTokenReviewJSON))
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Content-Type", "application/json")
			handler := webhook.Build()
			handler.ServeHTTP(recorder, req)
			Expect(recorder.Code).To(Equal(http.StatusOK))

			actualTokenReview := &authenticationv1.TokenReview{}
			err = json.NewDecoder(recorder.Body).Decode(actualTokenReview)
			Expect(err).NotTo(HaveOccurred())
			expectedTokenReview.Status = authenticationv1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1.UserInfo{
					Username: "johndoe",
					UID:      "first",
					Groups:   []string{"dev", "admin"},
					Extra: map[string]authenticationv1.ExtraValue{
						"extra1": {"value1", "value2"},
						"extra2": {"value3"},
					},
				},
			}
			Expect(actualTokenReview).To(Equal(expectedTokenReview))
		})
	})
})
