package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	mux := http.NewServeMux()

	whServer := &webhookServer{
		logger:  logger,
		handler: mux,
	}

	svr := &http.Server{
		Addr:    ":" + port,
		Handler: whServer,
	}

	setupRoutes(mux, whServer)

	errChan := make(chan error, 1)

	go func() {
		defer close(errChan)

		logger.Info("http server started", "addr", svr.Addr)
		errChan <- svr.ListenAndServe()
	}()
	go func() {
		<-ctx.Done()
		_ = svr.Close()
	}()

	select {
	case <-errChan:
		logger.Info("http server stopped")
	}
}

func setupRoutes(mux *http.ServeMux, wh *webhookServer) {
	mux.HandleFunc("GET /", wh.handleNegotiation)
	mux.HandleFunc("GET /records", wh.handleGetRecords)
	mux.HandleFunc("POST /records", wh.handlePostRecords)
	mux.HandleFunc("POST /adjustendpoints", wh.handleAdjustments)
}

type Record struct {
	DnsName    string   `json:"dnsName"`
	RecordTTL  int64    `json:"recordTTL"`
	RecordType string   `json:"recordType"`
	Targets    []string `json:"targets"`
}

type webhookServer struct {
	logger  *slog.Logger
	handler http.Handler
}

func (svr *webhookServer) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	svr.logger.Info("request received",
		"method", req.Method,
		"path", req.URL.Path,
		"query", req.URL.Query().Encode(),
	)

	svr.handler.ServeHTTP(wr, req)
}

func (svr *webhookServer) handleNegotiation(wr http.ResponseWriter, req *http.Request) {
	wr.Header().Set("content-type", "application/external.dns.webhook+json;version=1")
	wr.WriteHeader(200)

	json.NewEncoder(wr).Encode(map[string]interface{}{
		"filters": []string{
			"kind.local",
		},
	})
}

func (svr *webhookServer) handleGetRecords(wr http.ResponseWriter, req *http.Request) {
	wr.Header().Set("content-type", "application/external.dns.webhook+json;version=1")
	wr.WriteHeader(200)

	json.NewEncoder(wr).Encode([]Record{})
}

func (svr *webhookServer) handlePostRecords(wr http.ResponseWriter, req *http.Request) {
	wr.Header().Set("content-type", "application/external.dns.webhook+json;version=1")
	wr.WriteHeader(200)

	b, err := io.ReadAll(req.Body)
	if err != nil {
		wr.WriteHeader(500)
		svr.logger.Error("error reading body", "err", err)
		return
	}

	svr.logger.Debug("request body", "content", string(b))
}

func (svr *webhookServer) handleAdjustments(wr http.ResponseWriter, req *http.Request) {
	wr.Header().Set("content-type", "application/external.dns.webhook+json;version=1")
	var records []Record

	b, err := io.ReadAll(req.Body)
	if err != nil {
		wr.WriteHeader(500)
		svr.logger.Error("error reading body", "err", err)
		return
	}

	svr.logger.Debug("request body", "content", string(b))

	err = json.Unmarshal(b, &records)
	if err != nil {
		wr.WriteHeader(500)
		svr.logger.Error("error decoding body", "err", err)
		return
	}

	wr.WriteHeader(200)
	err = json.NewEncoder(wr).Encode(records)
	if err != nil {
		svr.logger.Error("error encoding body", "err", err)
	}
}
