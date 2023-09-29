// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package authentication

import (
	"encoding/json"
	"errors"
	"fmt"

	jwt "gopkg.in/square/go-jose.v2/jwt"
)

func extractClaims(tokenStr string, extraClaims []string) (map[string][]string, error) {
	if len(extraClaims) == 0 {
		return nil, nil
	}

	token, err := jwt.ParseSigned(tokenStr)
	if err != nil {
		return nil, errors.New("cannot parse jwt token")
	}

	var claims map[string]interface{}
	err = token.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		return nil, errors.New("cannot parse claims")
	}

	extra := make(map[string][]string)
	for _, claim := range extraClaims {
		value, ok := claims[claim]
		if !ok {
			return nil, fmt.Errorf("%s claim not found", claim)
		}

		if valueStr, ok := value.(string); ok {
			extra[claim] = []string{valueStr}
		} else {
			data, err := json.Marshal(value)
			if err != nil {
				return nil, err
			}
			extra[claim] = []string{string(data)}
		}
	}

	return extra, nil
}

func getIssuerURL(token string) (string, error) {
	var claims map[string]interface{}
	tok, err := jwt.ParseSigned(token)
	if err != nil {
		return "", errors.New("cannot parse jwt token")
	}

	err = tok.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		return "", errors.New("cannot parse claims")
	}

	iss, ok := claims["iss"].(string)
	if !ok {
		return "", errors.New("cannot retrieve issuer URL")
	}
	return iss, nil
}

func areExpirationRequirementsFulfilled(token string, maxValiditySeconds *int64) (bool, error) {
	// if maximum validity is not set we do not check further
	if maxValiditySeconds == nil {
		return true, nil
	}

	if *maxValiditySeconds < 0 {
		return false, errors.New("max validity seconds of a token should not be negative")
	}

	var claims map[string]interface{}
	tok, err := jwt.ParseSigned(token)
	if err != nil {
		return false, errors.New("cannot parse jwt token")
	}

	err = tok.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		return false, errors.New("cannot parse claims")
	}

	iat, ok := claims["iat"].(float64)
	if !ok {
		return false, errors.New("cannot retrieve iat claim")
	}

	if iat <= 0 {
		return false, errors.New("iat claim value should be positive")
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return false, errors.New("cannot retrieve exp claim")
	}

	if exp <= 0 {
		return false, errors.New("exp claim value should be positive")
	}

	if iat >= exp {
		return false, errors.New("iat is equal or greater than exp claim")
	}

	tokenIssuedFor := exp - iat
	if int64(tokenIssuedFor) > *maxValiditySeconds {
		return false, errors.New("token is issued with greater validity than the max allowed")
	}

	return true, nil
}
