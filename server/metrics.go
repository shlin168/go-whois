package server

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	ipLookupFound    = "found"
	ipLookupNotFound = "not_found"
	ipLookupError    = "error"
)

var (
	httpRequestsTotal         *prometheus.CounterVec
	httpRequestsInFlightGauge prometheus.Gauge
	httpRequestsDuration      *prometheus.HistogramVec

	whoisAPIRespTotal *prometheus.CounterVec
	iplookupTotal     *prometheus.CounterVec

	// unit: seconds
	defaultDurationBucket = []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}
	defaultBodySizeBucket = prometheus.ExponentialBuckets(128, 2, 11)
)

// MetricRegister register metrics when server starts
func MetricRegister(registerer prometheus.Registerer) {
	if registerer == nil {
		registerer = prometheus.DefaultRegisterer
	}
	MetricRegisterOn(registerer)
}

// MetricRegisterOn register needed promutheus metrics on given registerer
func MetricRegisterOn(registerer prometheus.Registerer) {
	/* http request */
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "whois_http_request_total",
			Help: "The amount of requests per HTTP status code",
		},
		[]string{"code"})
	httpRequestsInFlightGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "whois_http_request_in_flight",
			Help: "A gauge of requests currently being served by the wrapped handler"})
	httpRequestsDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "whois_http_request_duration_seconds",
			Help:    "A histogram of latencies for requests",
			Buckets: defaultDurationBucket},
		[]string{})

	/* Whois Counters */
	whoisAPIRespTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "whois_response_total",
			Help: "The amount of response from per input_type, per components and per result type for queries",
		},
		[]string{"type", "resp_by", "resp_type"},
	)
	iplookupTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "whois_nslookup_total",
			Help: "The amount of return status when doing ip lookup for domains",
		},
		[]string{"status"},
	)

	registerer.MustRegister(
		httpRequestsTotal,
		httpRequestsInFlightGauge,
		httpRequestsDuration,
		whoisAPIRespTotal,
		iplookupTotal,
	)
}

// MetricUnRegister unregister metrics when server shutdown
func MetricUnRegister(registerer prometheus.Registerer) {
	if registerer == nil {
		registerer = prometheus.DefaultRegisterer
	}
	MetricUnRegisterFrom(registerer)
}

// MetricUnRegisterFrom unregister metrics from registerer
func MetricUnRegisterFrom(registerer prometheus.Registerer) {
	registerer.Unregister(httpRequestsTotal)
	registerer.Unregister(httpRequestsInFlightGauge)
	registerer.Unregister(httpRequestsDuration)
	registerer.Unregister(whoisAPIRespTotal)
	registerer.Unregister(iplookupTotal)
}

// MetricMiddleware is middlerware to record prometheus metrics for http request
func MetricMiddleware(h http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chain := promhttp.InstrumentHandlerInFlight(httpRequestsInFlightGauge,
			promhttp.InstrumentHandlerDuration(httpRequestsDuration,
				promhttp.InstrumentHandlerCounter(httpRequestsTotal, h)))
		chain.ServeHTTP(w, r) // call ServeHTTP on the original handler
	})
}

func IncrRespMetrics(inputType, respBy, respType string) {
	whoisAPIRespTotal.With(prometheus.Labels{
		"type":      inputType,
		"resp_by":   respBy,
		"resp_type": respType,
	}).Add(1)
}

func IncrIPLookupMetrics(status string) {
	iplookupTotal.With(prometheus.Labels{"status": status}).Add(1)
}
