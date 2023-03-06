// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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

	durationTokenValidation = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:      "token_validation_time_seconds",
		Subsystem: subsystemName,
		Help:      "Duration of HTTP token validation requests.",
	}, []string{})

	requestLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:      "path_latency_seconds",
		Subsystem: subsystemName,
		Help:      "Histogram of the latency of processing HTTP requests",
	},
		[]string{"path"},
	)

	requestTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "path_requests_total",
		Subsystem: subsystemName,
		Help:      "Total number of HTTP requests by path and code.",
	},
		[]string{"path", "code"},
	)

	requestInFlight = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "path_requests_in_flight",
		Subsystem: subsystemName,
		Help:      "Number of currently server HTTP requests.",
	},
		[]string{"path"},
	)
)

func init() {
	prometheus.MustRegister(totalTokenValidations, durationTokenValidation, requestLatency, requestTotal, requestInFlight)
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

// InstrumentedHandler instrument http handler with request generic metrics.
func InstrumentedHandler(path string, hookRaw http.Handler) http.Handler {
	var (
		label    = prometheus.Labels{"path": path}
		latency  = requestLatency.MustCurryWith(label)
		total    = requestTotal.MustCurryWith(label)
		inFlight = requestInFlight.With(label)
	)

	return promhttp.InstrumentHandlerDuration(latency,
		promhttp.InstrumentHandlerCounter(total,
			promhttp.InstrumentHandlerInFlight(inFlight, hookRaw),
		))
}
