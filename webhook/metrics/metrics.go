// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	subsystemName = "oidc_webhook_authenticator"
)

var (
	totalTokenValidations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "token_validation_total",
		Subsystem: subsystemName,
		Help:      "Number of token validation requests.",
	}, []string{"result"})

	durationTokenValidation = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:      "token_validation_time_seconds",
		Subsystem: subsystemName,
		Help:      "Duration of HTTP token validation requests.",
	}, []string{})
)

func init() {
	prometheus.Register(totalTokenValidations)
	prometheus.Register(durationTokenValidation)
}

// IncTotalRequestValidationErrors increments the total number of errors occured during token validation requests
func IncTotalRequestValidationErrors() {
	totalTokenValidations.WithLabelValues("error").Inc()
}

// IncTotalRequestValidations increments the total number of token validation requests which do execute without the occurrence of an error
func IncTotalRequestValidations(authenticated bool) {
	if authenticated {
		totalTokenValidations.WithLabelValues("authenticated").Inc()
	} else {
		totalTokenValidations.WithLabelValues("unauthenticated").Inc()
	}
}

// NewTimerForTokenValidationRequest creates a new timer for measuring the time needed for a token validation request to execute
func NewTimerForTokenValidationRequest() *prometheus.Timer {
	return prometheus.NewTimer(durationTokenValidation.WithLabelValues())
}
