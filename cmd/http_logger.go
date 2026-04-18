package main

import (
	"log/slog"
	"net/http"

	"github.com/falmar/pihole-external-dns-webhooks/internal/hooksserver"
)

// TODO: remove later.

// requestLogger is an HTTP handler that logs requests before passing them to the hooks server.
type requestLogger struct {
	logger      *slog.Logger
	hooksServer hooksserver.HooksServer
	handler     http.Handler
}

// ServeHTTP logs every http request path and query parameters.
func (rl *requestLogger) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	rl.logger.Info("request received",
		"method", req.Method,
		"path", req.URL.Path,
		"query", req.URL.Query().Encode(),
	)

	rl.handler.ServeHTTP(wr, req)
}
