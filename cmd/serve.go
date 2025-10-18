package main

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/falmar/pihole-external-dns-webhooks/internal/piholeapi"
	"github.com/falmar/pihole-external-dns-webhooks/internal/slogger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var serveCmd = &cobra.Command{
	Use: "serve",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		logger := slogger.FromContext(ctx)

		port := viper.GetString("port")

		mux := http.NewServeMux()
		whServer := &webhookServer{
			logger:  logger,
			handler: mux,
			piAPI: piholeapi.NewPiholeAPI(&piholeapi.Config{
				Logger:   logger,
				Endpoint: viper.GetString("pihole.endpoint"),
				Password: viper.GetString("pihole.password"),
			}),
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

	serverLoop:
		for {
			select {
			case <-ctx.Done():
				err := svr.Close()
				if err != nil {
					return err
				}
			case err := <-errChan:
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					logger.Error("http server stopped with error", "err", err)
					return err
				}

				logger.Info("http server stopped")
				break serverLoop
			}
		}

		return nil
	},
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
	piAPI   piholeapi.PiholeAPI
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
	ctx := req.Context()

	piRecords, err := svr.piAPI.GetDomains(ctx, piholeapi.LocalDNSTypeA)
	if err != nil {
		svr.logger.Error("unable to get domains", "error", err)
		wr.WriteHeader(http.StatusInternalServerError)
		return
	}

	wr.Header().Set("content-type", "application/external.dns.webhook+json;version=1")
	wr.WriteHeader(http.StatusOK)

	var records = make([]Record, 0, len(piRecords))

	for _, r := range piRecords {
		records = append(records, Record{
			RecordTTL:  0,
			DnsName:    r.Name,
			Targets:    []string{r.Value},
			RecordType: piholeapi.LocalDNSTypeA,
		})
	}

	_ = json.NewEncoder(wr).Encode(records)
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
