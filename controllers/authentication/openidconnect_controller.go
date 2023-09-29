// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package authentication

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	authenticationv1alpha1 "github.com/gardener/oidc-webhook-authenticator/apis/authentication/v1alpha1"
	"github.com/go-logr/logr"
	"golang.org/x/time/rate"
	jose "gopkg.in/square/go-jose.v2"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// OpenIDConnectReconciler reconciles an OpenIDConnect object
type OpenIDConnectReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
	*unionAuthTokenHandler
	ResyncPeriod time.Duration
}

// +kubebuilder:rbac:groups=authentication.gardener.cloud,resources=openidconnects,verbs=get;list;watch

func (r *OpenIDConnectReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("openidconnect", req.Name)

	log.Info("Reconciling")
	defer log.Info("Reconcile finished")

	config := &authenticationv1alpha1.OpenIDConnect{}

	err := r.Get(ctx, req.NamespacedName, config)
	if err != nil {
		if apierrors.IsNotFound(err) {

			r.deleteHandler(req.Name)

			return reconcile.Result{}, nil
		}
	}

	if config.DeletionTimestamp != nil {
		log.Info("Deletion timestamp present - removing OIDC authenticator")

		r.deleteHandler(req.Name)

		return reconcile.Result{}, nil
	}

	algs := make([]string, 0, len(config.Spec.SupportedSigningAlgs))

	for _, alg := range config.Spec.SupportedSigningAlgs {
		algs = append(algs, string(alg))
	}

	var caBundle dynamiccertificates.CAContentProvider
	if config.Spec.CABundle != nil {
		caBundle, err = dynamiccertificates.NewStaticCAContent("CABundle", config.Spec.CABundle)
		if err != nil {
			log.Error(err, "Invalid CABundle")

			r.deleteHandler(req.Name)

			return reconcile.Result{}, nil
		}
	}

	var keySet gooidc.KeySet

	if len(config.Spec.JWKS.Keys) != 0 {
		keySet, err = newStaticKeySet(config.Spec.JWKS.Keys)
		if err != nil {
			log.Error(err, "Invalid static JWKS KeySet")

			r.deleteHandler(req.Name)

			// can't do anything until spec is changed
			return reconcile.Result{}, nil
		}

	} else {
		// retrieve the JWKS keySet from the jwksURL endpoint
		keySet, err = remoteKeySet(ctx, config.Spec.IssuerURL, config.Spec.CABundle)
		if err != nil {
			log.Error(err, "Invalid remote JWKS KeySet")

			r.deleteHandler(req.Name)

			return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
		}
	}

	opts := oidc.Options{
		CAContentProvider:    caBundle,
		ClientID:             config.Spec.ClientID,
		KeySet:               keySet,
		IssuerURL:            config.Spec.IssuerURL,
		RequiredClaims:       config.Spec.RequiredClaims,
		SupportedSigningAlgs: algs,
	}

	if config.Spec.GroupsClaim != nil {
		opts.GroupsClaim = *config.Spec.GroupsClaim
	}

	if config.Spec.GroupsPrefix != nil && len(*config.Spec.GroupsPrefix) > 0 {
		if *config.Spec.GroupsPrefix != authenticationv1alpha1.ClaimPrefixingDisabled {
			opts.GroupsPrefix = *config.Spec.GroupsPrefix
		}
	} else {
		opts.GroupsPrefix = config.Name + "/"
	}

	if config.Spec.UsernameClaim != nil {
		opts.UsernameClaim = *config.Spec.UsernameClaim
	}

	if config.Spec.UsernamePrefix != nil && len(*config.Spec.UsernamePrefix) > 0 {
		if *config.Spec.UsernamePrefix != authenticationv1alpha1.ClaimPrefixingDisabled {
			opts.UsernamePrefix = *config.Spec.UsernamePrefix
		}
	} else {
		opts.UsernamePrefix = config.Name + "/"
	}

	auth, err := oidc.New(opts)

	if err != nil {
		log.Error(err, "Invalid OIDC authenticator, removing it from store")

		r.deleteHandler(req.Name)

		return reconcile.Result{}, err
	}

	r.registerHandler(config.Spec.IssuerURL, req.Name, &authenticatorInfo{
		Token:                   auth,
		name:                    req.Name,
		uid:                     config.UID,
		maxTokenValiditySeconds: config.Spec.MaxTokenExpirationSeconds,
		extraClaims:             config.Spec.ExtraClaims,
	})

	return ctrl.Result{RequeueAfter: r.ResyncPeriod}, nil
}

// SetupWithManager specifies how the controller is built to watch custom resources of kind OpenIDConnect
func (r *OpenIDConnectReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.unionAuthTokenHandler == nil {
		r.unionAuthTokenHandler = newUnionAuthTokenHandler()
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&authenticationv1alpha1.OpenIDConnect{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 50,
			RateLimiter: workqueue.NewMaxOfRateLimiter(
				workqueue.NewItemExponentialFailureRateLimiter(5*time.Second, 10*time.Second),
				&workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(10), 100)},
			),
		}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}

// unionAuthTokenHandler authenticates tokens using a chain of authenticator.Token objects
type unionAuthTokenHandler struct {
	mutex             sync.RWMutex
	issuerHandlers    map[string]map[string]*authenticatorInfo
	nameIssuerMapping map[string]string
	log               logr.Logger
}

func newUnionAuthTokenHandler() *unionAuthTokenHandler {
	return &unionAuthTokenHandler{
		mutex:             sync.RWMutex{},
		issuerHandlers:    map[string]map[string]*authenticatorInfo{},
		nameIssuerMapping: map[string]string{},
		log:               ctrl.Log.WithName("unionAuthTokenHandler"),
	}
}

// AuthenticateToken authenticates the token using a chain of authenticator.Token objects.
func (u *unionAuthTokenHandler) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	iss, err := getIssuerURL(token)
	if err != nil {
		u.log.V(10).Info("Failed retrieving issuer URL from token", "error", err)
		return nil, false, err
	}

	u.mutex.RLock()
	defer u.mutex.RUnlock()

	handlers, ok := u.issuerHandlers[iss]
	if !ok {
		u.log.V(10).Info(fmt.Sprintf("No available handlers for issuer %s", iss))
		return nil, false, nil
	}

	for _, h := range handlers {
		fulfilled, err := areExpirationRequirementsFulfilled(token, h.maxTokenValiditySeconds)
		if err != nil {
			// keep iterating over the handlers
			// since the requirements can be met for a different handler
			u.log.V(10).Info("Token expiration requirements are not fulfilled", "error", err)
			continue
		}
		if !fulfilled {
			// keep iterating over the handlers
			// since the requirements can be met for a different handler
			u.log.V(10).Info("Token expiration requirements are not fulfilled")
			continue
		}

		resp, authenticated, err := h.AuthenticateToken(ctx, token)

		if !authenticated && err != nil {
			u.log.V(10).Info("Authentication error", "error", err)
		}

		if err == nil && authenticated {
			userName := resp.User.GetName()
			// Mark token as invalid when userName has "system:" prefix.
			if strings.HasPrefix(userName, authenticationv1alpha1.SystemPrefix) {
				// TODO add logging

				return nil, false, nil
			}

			filteredGroups := []string{}
			for _, group := range resp.User.GetGroups() {
				// ignore groups with "system:" prefix
				if !strings.HasPrefix(group, authenticationv1alpha1.SystemPrefix) {
					filteredGroups = append(filteredGroups, group)
				}
			}

			extra := map[string][]string{
				"gardener.cloud/authenticator/name": {h.name},
				"gardener.cloud/authenticator/uid":  {string(h.uid)},
			}

			extraClaims, err := extractClaims(token, h.extraClaims)
			if err != nil {
				u.log.V(10).Info("Loading extra claims failed", "error", err)
				continue
			}

			for key, val := range extraClaims {
				extra["gardener.cloud/user/"+strings.ToLower(key)] = val
			}

			info := &authenticator.Response{
				User: &user.DefaultInfo{
					Name:   userName,
					Extra:  extra,
					Groups: filteredGroups,
					UID:    resp.User.GetUID(),
				},
			}

			return info, true, nil
		}
	}

	return nil, false, nil
}

func (u *unionAuthTokenHandler) registerHandler(issuerURL string, handlerKey string, authInfo *authenticatorInfo) {
	u.mutex.Lock()
	defer u.mutex.Unlock()
	// remove previous location of the handler if issuer url differs
	if url, ok := u.nameIssuerMapping[handlerKey]; ok {
		if url != issuerURL {
			if m, ok := u.issuerHandlers[url]; ok {
				delete(m, handlerKey)
			}
		}
	}

	if m, ok := u.issuerHandlers[issuerURL]; ok {
		// conversions should be safe
		m[handlerKey] = authInfo
		u.nameIssuerMapping[handlerKey] = issuerURL
	} else {
		issuerHandlers := map[string]*authenticatorInfo{}
		issuerHandlers[handlerKey] = authInfo
		u.issuerHandlers[issuerURL] = issuerHandlers
		u.nameIssuerMapping[handlerKey] = issuerURL
	}
}

func (u *unionAuthTokenHandler) deleteHandler(handlerKey string) {
	u.mutex.Lock()
	defer u.mutex.Unlock()
	if url, ok := u.nameIssuerMapping[handlerKey]; ok {
		if m, ok := u.issuerHandlers[url]; ok {
			delete(m, handlerKey)
		}

		delete(u.nameIssuerMapping, handlerKey)
	}
}

type authenticatorInfo struct {
	authenticator.Token
	name                    string
	uid                     types.UID
	maxTokenValiditySeconds *int64
	extraClaims             []string
}

type providerJSON struct {
	Issuer      string   `json:"issuer"`
	AuthURL     string   `json:"authorization_endpoint"`
	TokenURL    string   `json:"token_endpoint"`
	JWKSURL     string   `json:"jwks_uri"`
	UserInfoURL string   `json:"userinfo_endpoint"`
	Algorithms  []string `json:"id_token_signing_alg_values_supported"`
}

// staticKeySet implements gooidc.KeySet.
type staticKeySet struct {
	keys []jose.JSONWebKey
}

// VerifySignature validates the signature of the JWT using static JWKs and returns the payload.
func (s staticKeySet) VerifySignature(ctx context.Context, jwt string) (payload []byte, err error) {
	jws, err := jose.ParseSigned(jwt)
	if err != nil {
		return nil, err
	}
	if len(jws.Signatures) == 0 {
		return nil, fmt.Errorf("jwt contained no signatures")
	}
	kid := jws.Signatures[0].Header.KeyID

	for _, key := range s.keys {
		if key.KeyID == kid {
			return jws.Verify(key)
		}
	}

	return nil, fmt.Errorf("no keys matches jwk keyid")
}

// remoteKeySet uses HTTP GET to discover the JWKs URL of the issuer
// and returns a KeySet that can validate JSON web tokens by fetching
// JSON web token sets hosted at that remote URL.
func remoteKeySet(ctx context.Context, issuer string, cabundle []byte) (gooidc.KeySet, error) {
	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"

	var caCertPool *x509.CertPool
	if cabundle != nil {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(cabundle)
		caCertPool = pool
	} else {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		caCertPool = pool
	}

	tr := net.SetTransportDefaults(&http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    caCertPool,
			MinVersion: tls.VersionTLS12,
		},
	})

	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}

	var p providerJSON
	err = unmarshalResp(resp, body, &p)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to decode provider discovery object: %v", err)
	}

	if p.Issuer != issuer {
		return nil, fmt.Errorf("oidc: issuer did not match the issuer returned by provider, expected %q got %q", issuer, p.Issuer)
	}

	neverCanceledContext := gooidc.ClientContext(ctx, client)
	return gooidc.NewRemoteKeySet(neverCanceledContext, p.JWKSURL), nil
}

// newStaticKeySet returns a KeySet that can validate JSON web tokens.
func newStaticKeySet(jwks []byte) (gooidc.KeySet, error) {
	pubKeys, err := loadKey(jwks)
	if err != nil {
		return nil, err
	}

	return &staticKeySet{keys: pubKeys}, nil
}

func unmarshalResp(r *http.Response, body []byte, v interface{}) error {
	err := json.Unmarshal(body, &v)
	if err == nil {
		return nil
	}
	ct := r.Header.Get("Content-Type")
	mediaType, _, parseErr := mime.ParseMediaType(ct)
	if parseErr == nil && mediaType == "application/json" {
		return fmt.Errorf("got Content-Type = application/json, but could not unmarshal as JSON: %v", err)
	}
	return fmt.Errorf("expected Content-Type = application/json, got %q: %v", ct, err)
}

// loadKey parses the jwks key Set, and returns the available keys.
func loadKey(jwks []byte) ([]jose.JSONWebKey, error) {
	keySet := jose.JSONWebKeySet{}

	err := json.Unmarshal(jwks, &keySet)
	if err != nil {
		return nil, err
	}

	return keySet.Keys, nil
}
