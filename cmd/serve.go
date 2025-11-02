package main

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/falmar/pihole-external-dns-webhooks/internal/dnssyncer"
	"github.com/falmar/pihole-external-dns-webhooks/internal/hooksserver"
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

		// Initialize Pi-hole API client
		piAPI := piholeapi.NewPiholeAPI(&piholeapi.Config{
			Logger:   logger,
			Endpoint: viper.GetString("pihole.endpoint"),
			Password: viper.GetString("pihole.password"),
		})

		// Initialize DNSSyncer (placeholder for future multi-instance support)
		syncer := dnssyncer.NewSyncer(logger)

		// Get filters from config (can be nil or empty)
		filters := viper.GetStringSlice("filters")

		// Initialize hooks server
		hooksServer := hooksserver.New(&hooksserver.Config{
			Logger:  logger,
			PiAPI:   piAPI,
			Syncer:  syncer,
			Filters: filters,
		})

		// Create HTTP router with logging middleware
		mux := http.NewServeMux()
		handler := &requestLogger{
			logger:      logger,
			hooksServer: hooksServer,
			handler:     mux,
		}

		setupRoutes(mux, hooksServer)

		svr := &http.Server{
			Addr:    ":" + port,
			Handler: handler,
		}

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

func setupRoutes(mux *http.ServeMux, hooksServer hooksserver.HooksServer) {
	mux.HandleFunc("GET /", hooksServer.HandleNegotiation)
	mux.HandleFunc("GET /records", hooksServer.HandleGetRecords)
	mux.HandleFunc("POST /records", hooksServer.HandlePostRecords)
	mux.HandleFunc("POST /adjustendpoints", hooksServer.HandleAdjustments)
}

// requestLogger is an HTTP handler that logs requests before passing them to the hooks server
type requestLogger struct {
	logger      *slog.Logger
	hooksServer hooksserver.HooksServer
	handler     http.Handler
}

// ServeHTTP TODO: remove later
func (rl *requestLogger) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	rl.logger.Info("request received",
		"method", req.Method,
		"path", req.URL.Path,
		"query", req.URL.Query().Encode(),
	)

	rl.handler.ServeHTTP(wr, req)
}
