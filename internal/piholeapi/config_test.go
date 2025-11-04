package piholeapi

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
)

func TestGetConfigHosts(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name    string
		element string
		sid     string
		setup   func() *piholeAPI
		wantErr bool
		errMsg  string
		verify  func(*testing.T, *configResponse)
	}{
		{
			name:    "successful config retrieval",
			element: "dns/hosts",
			sid:     "test-session",
			setup: func() *piholeAPI {
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						return createMockResponse(http.StatusOK, createConfigResponse([]string{"192.168.1.1 test.local"}, 0.123)), nil
					},
				}
				return &piholeAPI{
					endpoint: "http://test.example.com",
					logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
					mu:       &sync.RWMutex{},
					client:   mockClient,
				}
			},
			wantErr: false,
			verify: func(t *testing.T, cfg *configResponse) {
				if cfg == nil {
					t.Fatal("config response is nil")
				}
				if cfg.Config.DNS == nil {
					t.Fatal("DNS config is nil")
				}
				if len(cfg.Config.DNS.Hosts) != 1 {
					t.Errorf("expected 1 host, got %d", len(cfg.Config.DNS.Hosts))
				}
				if cfg.Took != 0.123 {
					t.Errorf("expected took=0.123, got %f", cfg.Took)
				}
			},
		},
		{
			name:    "config with empty hosts",
			element: "dns/hosts",
			sid:     "test-session",
			setup: func() *piholeAPI {
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						return createMockResponse(http.StatusOK, createConfigResponse([]string{}, 0.0)), nil
					},
				}
				return &piholeAPI{
					endpoint: "http://test.example.com",
					logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
					mu:       &sync.RWMutex{},
					client:   mockClient,
				}
			},
			wantErr: false,
			verify: func(t *testing.T, cfg *configResponse) {
				if cfg == nil {
					t.Fatal("config response is nil")
				}
				if cfg.Config.DNS == nil {
					t.Fatal("DNS config is nil")
				}
				if len(cfg.Config.DNS.Hosts) != 0 {
					t.Errorf("expected 0 hosts, got %d", len(cfg.Config.DNS.Hosts))
				}
			},
		},
		{
			name:    "config with null DNS object",
			element: "dns/hosts",
			sid:     "test-session",
			setup: func() *piholeAPI {
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						return createMockResponse(http.StatusOK, `{"config":{"dns":null},"took":0.1}`), nil
					},
				}
				return &piholeAPI{
					endpoint: "http://test.example.com",
					logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
					mu:       &sync.RWMutex{},
					client:   mockClient,
				}
			},
			wantErr: false,
			verify: func(t *testing.T, cfg *configResponse) {
				if cfg == nil {
					t.Fatal("config response is nil")
				}
				if cfg.Config.DNS != nil {
					t.Error("expected DNS to be nil")
				}
			},
		},
		{
			name:    "config with network error",
			element: "dns/hosts",
			sid:     "test-session",
			setup: func() *piholeAPI {
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						return nil, fmt.Errorf("network error")
					},
				}
				return &piholeAPI{
					endpoint: "http://test.example.com",
					logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
					mu:       &sync.RWMutex{},
					client:   mockClient,
				}
			},
			wantErr: true,
			errMsg:  "unable to execute request",
		},
		{
			name:    "config with non-200 status code",
			element: "dns/hosts",
			sid:     "test-session",
			setup: func() *piholeAPI {
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						return createMockResponse(http.StatusInternalServerError, ""), nil
					},
				}
				return &piholeAPI{
					endpoint: "http://test.example.com",
					logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
					mu:       &sync.RWMutex{},
					client:   mockClient,
				}
			},
			wantErr: true,
			errMsg:  "unexpected status code: 500",
		},
		{
			name:    "config with 401 unauthorized",
			element: "dns/hosts",
			sid:     "invalid-session",
			setup: func() *piholeAPI {
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						return createMockResponse(http.StatusUnauthorized, ""), nil
					},
				}
				return &piholeAPI{
					endpoint: "http://test.example.com",
					logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
					mu:       &sync.RWMutex{},
					client:   mockClient,
				}
			},
			wantErr: true,
			errMsg:  "unexpected status code: 401",
		},
		{
			name:    "config with 404 not found",
			element: "invalid/endpoint",
			sid:     "test-session",
			setup: func() *piholeAPI {
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						return createMockResponse(http.StatusNotFound, ""), nil
					},
				}
				return &piholeAPI{
					endpoint: "http://test.example.com",
					logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
					mu:       &sync.RWMutex{},
					client:   mockClient,
				}
			},
			wantErr: true,
			errMsg:  "unexpected status code: 404",
		},
		{
			name:    "config with malformed JSON",
			element: "dns/hosts",
			sid:     "test-session",
			setup: func() *piholeAPI {
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						return createMockResponse(http.StatusOK, "not valid json"), nil
					},
				}
				return &piholeAPI{
					endpoint: "http://test.example.com",
					logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
					mu:       &sync.RWMutex{},
					client:   mockClient,
				}
			},
			wantErr: true,
			errMsg:  "unable to decode config response",
		},
		{
			name:    "config with empty response body",
			element: "dns/hosts",
			sid:     "test-session",
			setup: func() *piholeAPI {
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						return createMockResponse(http.StatusOK, ""), nil
					},
				}
				return &piholeAPI{
					endpoint: "http://test.example.com",
					logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
					mu:       &sync.RWMutex{},
					client:   mockClient,
				}
			},
			wantErr: true,
			errMsg:  "unable to decode config response",
		},
		{
			name:    "verifies correct URL path construction",
			element: "dns/hosts",
			sid:     "test-session",
			setup: func() *piholeAPI {
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						expectedPath := "/api/config/dns/hosts"
						if req.URL.Path != expectedPath {
							return nil, fmt.Errorf("unexpected path: %s, want %s", req.URL.Path, expectedPath)
						}
						if req.Method != "GET" {
							return nil, fmt.Errorf("unexpected method: %s, want GET", req.Method)
						}
						if req.Header.Get("accept") != "application/json" {
							return nil, fmt.Errorf("missing accept header")
						}
						if req.Header.Get("sid") != "test-session" {
							return nil, fmt.Errorf("unexpected sid header: %s", req.Header.Get("sid"))
						}
						return createMockResponse(http.StatusOK, createConfigResponse([]string{}, 0.0)), nil
					},
				}
				return &piholeAPI{
					endpoint: "http://test.example.com",
					logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
					mu:       &sync.RWMutex{},
					client:   mockClient,
				}
			},
			wantErr: false,
		},
		{
			name:    "config with malformed endpoint URL",
			element: "dns/hosts",
			sid:     "test-session",
			setup: func() *piholeAPI {
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						t.Error("HTTP call should not be made when endpoint URL is malformed")
						return nil, fmt.Errorf("should not be called")
					},
				}
				return &piholeAPI{
					endpoint: "://invalid-url",
					logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
					mu:       &sync.RWMutex{},
					client:   mockClient,
				}
			},
			wantErr: true,
			errMsg:  "invalid endpoint URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := tt.setup()

			cfg, err := api.getConfig(ctx, tt.element, tt.sid)

			if (err != nil) != tt.wantErr {
				t.Errorf("getConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if tt.errMsg != "" && (err == nil || !strings.Contains(err.Error(), tt.errMsg)) {
					t.Errorf("getConfig() error = %v, want error containing %v", err, tt.errMsg)
				}
				return
			}

			if tt.verify != nil {
				tt.verify(t, cfg)
			}
		})
	}
}

func TestGetConfigContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	mockClient := &mockHTTPDoer{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return nil, context.Canceled
		},
	}

	api := &piholeAPI{
		endpoint: "http://test.example.com",
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		mu:       &sync.RWMutex{},
		client:   mockClient,
	}

	cancel() // Cancel context before getConfig

	_, err := api.getConfig(ctx, "dns/hosts", "test-session")
	if err == nil {
		t.Error("expected error with cancelled context, got nil")
	}
}
