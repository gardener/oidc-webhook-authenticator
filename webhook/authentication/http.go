// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package authentication

import (
	"encoding/json"
	"net/http"

	"github.com/gardener/oidc-webhook-authenticator/webhook/metrics"
	"github.com/go-logr/logr"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	genericapifilters "k8s.io/apiserver/pkg/endpoints/filters"
	"k8s.io/client-go/kubernetes/scheme"
)

// handler implements http.Handler
type handler struct {
	authenticator.Token
	log         logr.Logger
	failHandler http.Handler
}

var _ http.Handler = (*handler)(nil)

// ServeHTTP handles http requests.
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := r.Body.Close(); err != nil {
			h.log.Error(err, "failed closing body")
		}
	}()
	timer := metrics.NewTimerForTokenValidationRequest()
	defer timer.ObserveDuration()

	tr := &authenticationv1.TokenReview{}

	err := json.NewDecoder(r.Body).Decode(tr)
	if err != nil {
		h.log.Error(err, "failed to read conversion request")
		h.failHandler.ServeHTTP(w, r)
		metrics.IncTotalRequestValidationErrors()
		return
	}

	authResp, ok, err := h.AuthenticateToken(r.Context(), tr.Spec.Token)
	authenticated := false
	if err != nil || !ok {
		tr.Status = authenticationv1.TokenReviewStatus{
			Authenticated: false,
		}
	} else {
		authenticated = true
		tr.Status = authenticationv1.TokenReviewStatus{
			Authenticated: true,
			User: authenticationv1.UserInfo{
				UID:      authResp.User.GetUID(),
				Extra:    make(map[string]authenticationv1.ExtraValue),
				Groups:   authResp.User.GetGroups(),
				Username: authResp.User.GetName(),
			},
			// The OIDC authenticator doesn't return any audiences
			// https://github.com/kubernetes/kubernetes/pull/87612
			// Audiences: authResp.Audiences,
		}

		// Convert the extra information in the user object
		for key, val := range authResp.User.GetExtra() {
			tr.Status.User.Extra[key] = authenticationv1.ExtraValue(val)
		}
	}

	err = json.NewEncoder(w).Encode(tr)
	if err != nil {
		h.log.Error(err, "failed to write response")
		metrics.IncTotalRequestValidationErrors()
		return
	}
	metrics.IncTotalRequestValidations(authenticated)
}

// Webhook represents each individual webhook.
type Webhook struct {
	Authenticator authenticator.Token
	Log           logr.Logger
}

// Build returns an [http.Handler] that can authenticate requests.
func (wh *Webhook) Build() http.Handler {
	return &handler{
		Token:       wh.Authenticator,
		log:         wh.Log,
		failHandler: genericapifilters.Unauthorized(scheme.Codecs),
	}
}
