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
	"io/ioutil"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc"
	authenticationv1alpha1 "github.com/gardener/oidc-webhook-authenticator/apis/authentication/v1alpha1"
	"github.com/go-logr/logr"
	"github.com/lestrrat-go/jwx/jwk"
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

// OpenIDConnectReconciler reconciles a OpenIDConnect object
type OpenIDConnectReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
	*unionAuthTokenHandler
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
			r.handlers.Delete(req.Name)

			return reconcile.Result{}, nil
		}
	}

	if config.DeletionTimestamp != nil {
		log.Info("Deletion timestamp present - removing OIDC authenticator")
		r.handlers.Delete(req.Name)

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

			r.handlers.Delete(req.Name)

			return reconcile.Result{}, nil
		}
	}

	var keySet gooidc.KeySet

	if len(config.Spec.JWKS.Keys) != 0 {
		keySet, err = newStaticKeySet(config.Spec.JWKS.Keys)
		if err != nil {
			log.Error(err, "Invalid static JWKS KeySet")

			r.handlers.Delete(req.Name)
		}

	} else {
		// retrieve the JWKS keySet from the jwksURL endpoint
		keySet, err = remoteKeySet(ctx, config.Spec.IssuerURL, config.Spec.CABundle)
		if err != nil {
			log.Error(err, "Invalid remote JWKS KeySet")

			r.handlers.Delete(req.Name)
		}

		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
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

	if config.Spec.GroupsPrefix != nil {
		if *config.Spec.GroupsPrefix != authenticationv1alpha1.ClaimPrefixingDisabled {
			opts.GroupsPrefix = *config.Spec.GroupsPrefix
		}
	} else {
		opts.GroupsPrefix = config.Name + "/"
	}

	if config.Spec.UsernameClaim != nil {
		opts.UsernameClaim = *config.Spec.UsernameClaim
	}

	if config.Spec.UsernamePrefix != nil {
		if *config.Spec.UsernamePrefix != authenticationv1alpha1.ClaimPrefixingDisabled {
			opts.UsernamePrefix = *config.Spec.UsernamePrefix
		}
	} else {
		opts.UsernamePrefix = config.Name + "/"
	}

	auth, err := oidc.New(opts)

	if err != nil {
		log.Error(err, "Invalid OIDC authenticator, removing it from store")

		r.handlers.Delete(req.Name)

		return reconcile.Result{}, err
	}

	r.handlers.Store(req.Name, &authenticatorInfo{
		Token: auth,
		name:  req.Name,
		uid:   config.UID,
	})

	return ctrl.Result{}, nil
}

func (r *OpenIDConnectReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.unionAuthTokenHandler == nil {
		r.unionAuthTokenHandler = &unionAuthTokenHandler{handlers: sync.Map{}, log: r.Log}
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
	handlers sync.Map
	log      logr.Logger
}

// AuthenticateToken authenticates the token using a chain of authenticator.Token objects.
func (u *unionAuthTokenHandler) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	var (
		info    *authenticator.Response
		success bool
	)

	u.handlers.Range(func(key interface{}, value interface{}) bool {
		currAuthRequestHandler, ok := value.(*authenticatorInfo)
		if !ok {
			u.log.Info("cannot convert to authenticatorInfo", "key", key, "value", value)

			return false
		}

		resp, authenticated, err := currAuthRequestHandler.AuthenticateToken(ctx, token)

		done := err == nil && authenticated
		if done {
			userName := resp.User.GetName()
			// Mark token as invalid when userName has "system:" prefix.
			if strings.HasPrefix(userName, "system:") {
				// TODO add logging

				return false
			}

			filteredGroups := []string{}
			for _, group := range resp.User.GetGroups() {
				// ignore groups with "system:" prefix
				if !strings.HasPrefix(group, "system:") {
					filteredGroups = append(filteredGroups, group)
				}
			}

			info = &authenticator.Response{
				User: &user.DefaultInfo{
					Name: userName,
					Extra: map[string][]string{
						"gardener.cloud/authenticator/name": {currAuthRequestHandler.name},
						"gardener.cloud/authenticator/uid":  {string(currAuthRequestHandler.uid)},
					},
					Groups: filteredGroups,
					UID:    resp.User.GetUID(),
				},
			}

			success = true
		}

		return !done
	})

	return info, success, nil
}

type authenticatorInfo struct {
	authenticator.Token
	name string
	uid  types.UID
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

func remoteKeySet(ctx context.Context, issuer string, cabundle []byte) (gooidc.KeySet, error) {

	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"

	caCertPool := x509.NewCertPool()
	if cabundle != nil {
		caCertPool.AppendCertsFromPEM(cabundle)
	}

	tr := net.SetTransportDefaults(&http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: caCertPool},
	})

	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}

	ctx = gooidc.ClientContext(ctx, client)

	req, err := http.NewRequest("GET", wellKnown, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
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
		return nil, fmt.Errorf("oidc: issuer did not match the issuer returned by provider,   expected %q got %q", issuer, p.Issuer)
	}
	return gooidc.NewRemoteKeySet(ctx, p.JWKSURL), nil

}

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
		return fmt.Errorf("got Content-Type = application/json, but could   not unmarshal as JSON: %v", err)
	}
	return fmt.Errorf("expected Content-Type = application/json, got %q: %v", ct, err)
}

// loadKey parses the jwks key Set, extracts public rsa keys found and converts them into a JOSE JWK format.
func loadKey(jwks []byte) ([]jose.JSONWebKey, error) {
	var keyList []jose.JSONWebKey

	pubKeyJwk, err := jwk.ParseString(string(jwks))
	if err != nil {
		return nil, err
	}

	for _, j := range pubKeyJwk.Keys {
		pubKey, err := j.Materialize()
		if err != nil {
			return nil, err
		}

		keyList = append(keyList, jose.JSONWebKey{Key: pubKey, KeyID: j.KeyID(), Use: "sig", Algorithm: j.Algorithm()})
	}
	return keyList, nil
}
