package piholeapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockHTTPDoer is a mock implementation of HTTPDoer for testing.
type mockHTTPDoer struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockHTTPDoer) Do(req *http.Request) (*http.Response, error) {
	if m.DoFunc != nil {
		return m.DoFunc(req)
	}
	return nil, fmt.Errorf("not implemented")
}

// createMockResponse creates a mock HTTP response with the given status code and body.
func createMockResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

// createAuthResponse creates a JSON auth response string.
func createAuthResponse(valid bool, sid string, message string) string {
	resp := map[string]interface{}{
		"session": map[string]interface{}{
			"valid":   valid,
			"sid":     sid,
			"message": message,
		},
	}
	b, _ := json.Marshal(resp)
	return string(b)
}

// createConfigResponse creates a JSON config response string.
func createConfigResponse(hosts []string, took float64) string {
	resp := map[string]interface{}{
		"config": map[string]interface{}{
			"dns": map[string]interface{}{
				"hosts": hosts,
			},
		},
		"took": took,
	}
	b, _ := json.Marshal(resp)
	return string(b)
}

// equalLocalDNSRecords compares two slices of LocalDNSRecord for equality.
func equalLocalDNSRecords(a, b []*LocalDNSRecord) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].Type != b[i].Type || a[i].Value != b[i].Value {
			return false
		}
	}
	return true
}

func TestNewPiholeAPI(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		verify  func(*testing.T, PiholeAPI)
	}{
		{
			name: "create new API instance",
			config: &Config{
				Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
				Password: "test-password",
				Endpoint: "http://test.example.com",
			},
			wantErr: false,
			verify: func(t *testing.T, api PiholeAPI) {
				if api == nil {
					t.Error("NewPiholeAPI() returned nil")
				}
				if papi, ok := api.(*piholeAPI); ok {
					if papi.endpoint != "http://test.example.com" {
						t.Errorf("endpoint = %v, want http://test.example.com", papi.endpoint)
					}
					if papi.pass != "test-password" {
						t.Errorf("pass = %v, want test-password", papi.pass)
					}
				} else {
					t.Error("NewPiholeAPI() did not return *piholeAPI")
				}
			},
		},
		{
			name: "create with default HTTP client",
			config: &Config{
				Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
				Password: "test-password",
				Endpoint: "http://test.example.com",
				Client:   nil,
			},
			wantErr: false,
			verify: func(t *testing.T, api PiholeAPI) {
				if api == nil {
					t.Error("NewPiholeAPI() returned nil")
				}
				if papi, ok := api.(*piholeAPI); ok {
					if papi.client == nil {
						t.Error("client should not be nil (should default to http.Client)")
					}
					if _, ok := papi.client.(*http.Client); !ok {
						t.Error("client should be *http.Client when not provided")
					}
				}
			},
		},
		{
			name: "create with custom HTTP client",
			config: &Config{
				Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
				Password: "test-password",
				Endpoint: "http://test.example.com",
				Client:   &mockHTTPDoer{},
			},
			wantErr: false,
			verify: func(t *testing.T, api PiholeAPI) {
				if api == nil {
					t.Error("NewPiholeAPI() returned nil")
				}
				if papi, ok := api.(*piholeAPI); ok {
					if papi.client == nil {
						t.Error("client should not be nil")
					}
					if _, ok := papi.client.(*mockHTTPDoer); !ok {
						t.Error("client should be the provided mockHTTPDoer")
					}
				}
			},
		},
		{
			name: "create with nil logger (defaults to discard logger)",
			config: &Config{
				Logger:   nil,
				Password: "test-password",
				Endpoint: "http://test.example.com",
			},
			wantErr: false,
			verify: func(t *testing.T, api PiholeAPI) {
				if api == nil {
					t.Error("NewPiholeAPI() returned nil")
				}
				if papi, ok := api.(*piholeAPI); ok {
					if papi.logger == nil {
						t.Error("logger should default to discard logger when not provided")
					}
				}
			},
		},
		{
			name: "create with empty endpoint",
			config: &Config{
				Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
				Password: "test-password",
				Endpoint: "",
			},
			wantErr: false,
			verify: func(t *testing.T, api PiholeAPI) {
				if api == nil {
					t.Error("NewPiholeAPI() returned nil")
				}
				if papi, ok := api.(*piholeAPI); ok {
					if papi.endpoint != "" {
						t.Errorf("endpoint = %v, want empty string", papi.endpoint)
					}
				}
			},
		},
		{
			name: "create with empty password",
			config: &Config{
				Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
				Password: "",
				Endpoint: "http://test.example.com",
			},
			wantErr: false,
			verify: func(t *testing.T, api PiholeAPI) {
				if api == nil {
					t.Error("NewPiholeAPI() returned nil")
				}
				if papi, ok := api.(*piholeAPI); ok {
					if papi.pass != "" {
						t.Errorf("pass = %v, want empty string", papi.pass)
					}
				}
			},
		},
		{
			name: "create with custom auth timeout",
			config: &Config{
				Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
				Password:    "test-password",
				Endpoint:    "http://test.example.com",
				AuthTimeout: time.Minute * 30,
			},
			wantErr: false,
			verify: func(t *testing.T, api PiholeAPI) {
				if api == nil {
					t.Error("NewPiholeAPI() returned nil")
				}
				if papi, ok := api.(*piholeAPI); ok {
					if papi.authTimeout != time.Minute*30 {
						t.Errorf("authTimeout = %v, want %v", papi.authTimeout, time.Minute*30)
					}
				}
			},
		},
		{
			name: "create with default auth timeout when not specified",
			config: &Config{
				Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
				Password: "test-password",
				Endpoint: "http://test.example.com",
			},
			wantErr: false,
			verify: func(t *testing.T, api PiholeAPI) {
				if api == nil {
					t.Error("NewPiholeAPI() returned nil")
				}
				if papi, ok := api.(*piholeAPI); ok {
					if papi.authTimeout != time.Minute*55 {
						t.Errorf("authTimeout = %v, want %v", papi.authTimeout, time.Minute*55)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := NewPiholeAPI(tt.config)

			if (api == nil) == !tt.wantErr {
				t.Errorf("NewPiholeAPI() returned nil, wantErr %v", tt.wantErr)
				return
			}

			if tt.verify != nil {
				tt.verify(t, api)
			}
		})
	}
}

func TestGetRequest(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		endpoint  string
		sessID    string
		wantErr   bool
		errMsg    string
		verifyReq func(*testing.T, *http.Request)
	}{
		{
			name:     "creates request with valid endpoint",
			endpoint: "http://test.example.com",
			sessID:   "",
			wantErr:  false,
			verifyReq: func(t *testing.T, req *http.Request) {
				if req.URL.Host != "test.example.com" {
					t.Errorf("expected host test.example.com, got %s", req.URL.Host)
				}
				if req.Header.Get("accept") != "application/json" {
					t.Error("expected accept header application/json")
				}
			},
		},
		{
			name:     "sets sid header when provided",
			endpoint: "http://test.example.com",
			sessID:   "test-session",
			wantErr:  false,
			verifyReq: func(t *testing.T, req *http.Request) {
				if req.Header.Get("sid") != "test-session" {
					t.Errorf("expected sid header test-session, got %s", req.Header.Get("sid"))
				}
			},
		},
		{
			name:     "does not set sid header when empty",
			endpoint: "http://test.example.com",
			sessID:   "",
			wantErr:  false,
			verifyReq: func(t *testing.T, req *http.Request) {
				if req.Header.Get("sid") != "" {
					t.Errorf("expected empty sid header, got %s", req.Header.Get("sid"))
				}
			},
		},
		{
			name:     "handles malformed endpoint URL",
			endpoint: "://invalid-url",
			sessID:   "",
			wantErr:  true,
			errMsg:   "invalid endpoint URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := &piholeAPI{
				endpoint: tt.endpoint,
				mu:       &sync.RWMutex{},
			}

			req, err := api.getRequest(ctx, tt.sessID)

			if (err != nil) != tt.wantErr {
				t.Errorf("getRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if tt.errMsg != "" && (err == nil || !strings.Contains(err.Error(), tt.errMsg)) {
					t.Errorf("getRequest() error = %v, want error containing %v", err, tt.errMsg)
				}
				return
			}

			if req == nil {
				t.Fatal("getRequest() returned nil request")
			}

			if tt.verifyReq != nil {
				tt.verifyReq(t, req)
			}
		})
	}
}
