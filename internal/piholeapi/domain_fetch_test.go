package piholeapi

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestGetDomains(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name    string
		dnsType LocalDNSType
		setup   func() (PiholeAPI, *mockHTTPDoer)
		want    []*LocalDNSRecord
		wantErr bool
		errMsg  string
	}{
		{
			name:    "get A records successfully",
			dnsType: LocalDNSTypeA,
			setup: func() (PiholeAPI, *mockHTTPDoer) {
				callCount := 0
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						callCount++
						if callCount == 1 {
							return createMockResponse(http.StatusOK, createAuthResponse(true, "abc123xyz", "")), nil
						}
						return createMockResponse(http.StatusOK, createConfigResponse([]string{"192.168.1.1 test.local"}, 0.123)), nil
					},
				}
				api := NewPiholeAPI(&Config{
					Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
					Password: "test-password",
					Endpoint: "http://test.example.com",
					Client:   mockClient,
				})
				return api, mockClient
			},
			want: []*LocalDNSRecord{
				{
					Type:  LocalDNSTypeA,
					Value: "192.168.1.1",
					Name:  "test.local",
				},
			},
			wantErr: false,
		},
		{
			name:    "get A records with empty result",
			dnsType: LocalDNSTypeA,
			setup: func() (PiholeAPI, *mockHTTPDoer) {
				callCount := 0
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						callCount++
						if callCount == 1 {
							return createMockResponse(http.StatusOK, createAuthResponse(true, "abc123xyz", "")), nil
						}
						return createMockResponse(http.StatusOK, createConfigResponse([]string{}, 0.123)), nil
					},
				}
				api := NewPiholeAPI(&Config{
					Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
					Password: "test-password",
					Endpoint: "http://test.example.com",
					Client:   mockClient,
				})
				return api, mockClient
			},
			want:    []*LocalDNSRecord{},
			wantErr: false,
		},
		{
			name:    "unsupported DNS type CNAME",
			dnsType: LocalDNSTypeCNAME,
			setup: func() (PiholeAPI, *mockHTTPDoer) {
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						t.Error("HTTP call should not be made for unsupported DNS type")
						return nil, nil
					},
				}
				api := NewPiholeAPI(&Config{
					Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
					Password: "test-password",
					Endpoint: "http://test.example.com",
					Client:   mockClient,
				})
				return api, mockClient
			},
			want:    nil,
			wantErr: true,
			errMsg:  "not implemented for dns type: CNAME",
		},
		{
			name:    "unknown DNS type",
			dnsType: LocalDNSType("UNKNOWN"),
			setup: func() (PiholeAPI, *mockHTTPDoer) {
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						t.Error("HTTP call should not be made for unknown DNS type")
						return nil, nil
					},
				}
				api := NewPiholeAPI(&Config{
					Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
					Password: "test-password",
					Endpoint: "http://test.example.com",
					Client:   mockClient,
				})
				return api, mockClient
			},
			want:    nil,
			wantErr: true,
			errMsg:  "not implemented for dns type: UNKNOWN",
		},
		{
			name:    "empty string DNS type",
			dnsType: LocalDNSType(""),
			setup: func() (PiholeAPI, *mockHTTPDoer) {
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						t.Error("HTTP call should not be made for empty DNS type")
						return nil, nil
					},
				}
				api := NewPiholeAPI(&Config{
					Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
					Password: "test-password",
					Endpoint: "http://test.example.com",
					Client:   mockClient,
				})
				return api, mockClient
			},
			want:    nil,
			wantErr: true,
			errMsg:  "not implemented for dns type: ",
		},
		{
			name:    "fetchARecords error",
			dnsType: LocalDNSTypeA,
			setup: func() (PiholeAPI, *mockHTTPDoer) {
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						return nil, fmt.Errorf("network error")
					},
				}
				api := NewPiholeAPI(&Config{
					Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
					Password: "test-password",
					Endpoint: "http://test.example.com",
					Client:   mockClient,
				})
				return api, mockClient
			},
			want:    nil,
			wantErr: true,
			// Error will come from fetchARecords, not wrapped
		},
		{
			name:    "session timeout triggers re-authentication",
			dnsType: LocalDNSTypeA,
			setup: func() (PiholeAPI, *mockHTTPDoer) {
				callCount := 0
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						callCount++
						// First call: re-authenticate (session expired, so authenticate() makes auth request)
						if callCount == 1 {
							return createMockResponse(http.StatusOK, createAuthResponse(true, "session2", "")), nil
						}
						// Second call: config fetch with new session
						return createMockResponse(http.StatusOK, createConfigResponse([]string{"192.168.1.1 test.local"}, 0.123)), nil
					},
				}
				api := NewPiholeAPI(&Config{
					Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
					Password:    "test-password",
					Endpoint:    "http://test.example.com",
					Client:      mockClient,
					AuthTimeout: time.Second * 1, // Very short timeout for testing
				})
				// Set up expired session by manually setting lastAuth
				if papi, ok := api.(*piholeAPI); ok {
					papi.mu.Lock()
					papi.sessionID = "expired-session"
					papi.lastAuth = time.Now().Add(-2 * time.Second) // Expired
					papi.mu.Unlock()
				}
				return api, mockClient
			},
			want: []*LocalDNSRecord{
				{
					Type:  LocalDNSTypeA,
					Value: "192.168.1.1",
					Name:  "test.local",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api, _ := tt.setup()
			got, err := api.GetDomains(ctx, tt.dnsType)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetDomains() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if tt.errMsg != "" && (err == nil || !strings.Contains(err.Error(), tt.errMsg)) {
					t.Errorf("GetDomains() error = %v, want error containing %v", err, tt.errMsg)
				}
				return
			}

			if tt.want == nil {
				if got != nil {
					t.Errorf("GetDomains() = %v, want nil", got)
				}
				return
			}

			if len(tt.want) == 0 {
				if got == nil || len(got) != 0 {
					t.Errorf("GetDomains() = %v, want empty slice", got)
				}
				return
			}

			if !equalLocalDNSRecords(got, tt.want) {
				t.Errorf("GetDomains() = %v, want %v", got, tt.want)
			}
		})
	}
}
