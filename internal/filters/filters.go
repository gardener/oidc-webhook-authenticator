// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package filters

import (
	"net/http"

	"k8s.io/apiserver/pkg/authentication/authenticator"
)

// WithAuthentication tries to authenticate the request against the passed authenticator
// before invoking the next handler. If the request is not authenticated then a 401 response is returned.
func WithAuthentication(auth authenticator.Request, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok, err := auth.AuthenticateRequest(r)

		if err != nil || !ok {
			if r.ProtoMajor == 2 {
				// close the TCP connection if user is not authenticated
				// see https://github.com/kubernetes/kubernetes/commit/800a8eaba7f25bd223fefe6e7613e39a5d7f1eeb for more details
				w.Header().Set("Connection", "close")
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			w.Write([]byte(`{"code":401,"message":"unauthorized"}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// WithAllowedMethod verifies the request method before invoking the next handler.
func WithAllowedMethod(method string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(405)
			w.Write([]byte(`{"code":405,"message":"method not allowed"}`))
		}
		next.ServeHTTP(w, r)
	})
}
