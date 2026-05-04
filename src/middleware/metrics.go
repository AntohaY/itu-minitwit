package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
)

var HttpResponsesTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "minitwit_http_responses_total",
		Help: "Total number of HTTP responses sent to users",
	},
	[]string{"method", "path", "status"},
)

var HttpDuration = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name: "minitwit_http_request_duration_seconds",
		Help: "Duration of HTTP requests in seconds",
		// These buckets represent 10ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s, 5s, 10s
		Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	},
	[]string{"method", "path", "status"},
)

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ignore Prometheus scraping itself
		if r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}

		// Start the timer right before we process the request
		start := time.Now()

		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Process the request
		next.ServeHTTP(lrw, r)

		// Calculate how long it took in seconds
		duration := time.Since(start).Seconds()

		// Get the Mux route safely
		path := r.URL.Path
		route := mux.CurrentRoute(r)
		if route != nil {
			if tmpl, err := route.GetPathTemplate(); err == nil && tmpl != "" {
				path = tmpl
			}
		}

		statusStr := strconv.Itoa(lrw.statusCode)

		HttpResponsesTotal.WithLabelValues(r.Method, path, statusStr).Inc()
		HttpDuration.WithLabelValues(r.Method, path, statusStr).Observe(duration)
	})
}
