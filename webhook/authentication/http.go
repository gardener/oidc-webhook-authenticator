// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package authentication

import (
	"encoding/json"
	"net/http"

	"github.com/go-logr/logr"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	genericapifilters "k8s.io/apiserver/pkg/endpoints/filters"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"

	"k8s.io/client-go/kubernetes/scheme"
)

type handler struct {
	authenticator.Token
	log         logr.Logger
	failHandler http.Handler
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	tr := &authenticationv1.TokenReview{}

	err := json.NewDecoder(r.Body).Decode(tr)
	if err != nil {
		h.log.Error(err, "failed to read conversion request")
		h.failHandler.ServeHTTP(w, r)

		return
	}

	authResp, ok, err := h.AuthenticateToken(r.Context(), tr.Spec.Token)
	if err != nil || !ok {
		tr.Status = authenticationv1.TokenReviewStatus{
			Authenticated: false,
		}
	} else {
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

		usr, ok := apirequest.UserFrom(r.Context())

		if ok && usr != nil {
			if uid := usr.GetUID(); uid != "" {
				tr.Status.User.Extra["gardener.cloud/apiserver/uid"] = []string{uid}
			}
			if userName := usr.GetName(); userName != "" {
				tr.Status.User.Extra["gardener.cloud/apiserver/username"] = []string{userName}
			}
			if groups := usr.GetGroups(); len(groups) > 0 {
				tr.Status.User.Extra["gardener.cloud/apiserver/groups"] = authenticationv1.ExtraValue(groups)
			}
		}

	}

	err = json.NewEncoder(w).Encode(tr)
	if err != nil {
		h.log.Error(err, "failed to write response")
		return
	}
}

// Webhook represents each individual webhook.
type Webhook struct {
	Authenticator authenticator.Token
	Log           logr.Logger
}

func (wh *Webhook) Build() http.Handler {
	return &handler{
		Token:       wh.Authenticator,
		log:         wh.Log,
		failHandler: genericapifilters.Unauthorized(scheme.Codecs),
	}
}
