package piholeapi

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDeleteDomain(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		record    *LocalDNSRecord
		setup     func() (PiholeAPI, *mockHTTPDoer)
		wantErr   bool
		errMsg    string
		verifyReq func(*testing.T, *http.Request)
	}{
		{
			name: "successful domain delete with 200 OK",
			record: &LocalDNSRecord{
				Name:  "test.local",
				Type:  LocalDNSTypeA,
				Value: "192.168.1.1",
			},
			setup: func() (PiholeAPI, *mockHTTPDoer) {
				callCount := 0
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						callCount++
						if callCount == 1 {
							return createMockResponse(http.StatusOK, createAuthResponse(true, "abc123xyz", "")), nil
						}
						return createMockResponse(http.StatusOK, "{}"), nil
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
			wantErr: false,
			verifyReq: func(t *testing.T, req *http.Request) {
				if req.Method != "DELETE" {
					t.Errorf("expected method DELETE, got %s", req.Method)
				}
				if req.URL.Path != "/api/config/dns/hosts/192.168.1.1 test.local" {
					t.Errorf("expected path /api/config/dns/hosts/192.168.1.1 test.local, got %s", req.URL.Path)
				}
				if req.Header.Get("accept") != "application/json" {
					t.Errorf("expected accept header application/json, got %s", req.Header.Get("accept"))
				}
				if req.Header.Get("sid") != "abc123xyz" {
					t.Errorf("expected sid header abc123xyz, got %s", req.Header.Get("sid"))
				}
			},
		},
		{
			name: "successful domain delete with 204 No Content",
			record: &LocalDNSRecord{
				Name:  "test.local",
				Type:  LocalDNSTypeA,
				Value: "192.168.1.1",
			},
			setup: func() (PiholeAPI, *mockHTTPDoer) {
				callCount := 0
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						callCount++
						if callCount == 1 {
							return createMockResponse(http.StatusOK, createAuthResponse(true, "abc123xyz", "")), nil
						}
						return createMockResponse(http.StatusNoContent, ""), nil
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
			wantErr: false,
			verifyReq: func(t *testing.T, req *http.Request) {
				if req.Method != "DELETE" {
					t.Errorf("expected method DELETE, got %s", req.Method)
				}
			},
		},
		{
			name: "domain delete with different IP",
			record: &LocalDNSRecord{
				Name:  "test.local",
				Type:  LocalDNSTypeA,
				Value: "10.0.0.1",
			},
			setup: func() (PiholeAPI, *mockHTTPDoer) {
				callCount := 0
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						callCount++
						if callCount == 1 {
							return createMockResponse(http.StatusOK, createAuthResponse(true, "abc123xyz", "")), nil
						}
						return createMockResponse(http.StatusOK, "{}"), nil
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
			wantErr: false,
			verifyReq: func(t *testing.T, req *http.Request) {
				if req.URL.Path != "/api/config/dns/hosts/10.0.0.1 test.local" {
					t.Errorf("expected path /api/config/dns/hosts/10.0.0.1 test.local, got %s", req.URL.Path)
				}
			},
		},
		{
			name: "domain delete with different domain name",
			record: &LocalDNSRecord{
				Name:  "example.com",
				Type:  LocalDNSTypeA,
				Value: "192.168.1.1",
			},
			setup: func() (PiholeAPI, *mockHTTPDoer) {
				callCount := 0
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						callCount++
						if callCount == 1 {
							return createMockResponse(http.StatusOK, createAuthResponse(true, "abc123xyz", "")), nil
						}
						return createMockResponse(http.StatusOK, "{}"), nil
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
			wantErr: false,
			verifyReq: func(t *testing.T, req *http.Request) {
				if req.URL.Path != "/api/config/dns/hosts/192.168.1.1 example.com" {
					t.Errorf("expected path /api/config/dns/hosts/192.168.1.1 example.com, got %s", req.URL.Path)
				}
			},
		},
		{
			name: "reuses existing valid session",
			record: &LocalDNSRecord{
				Name:  "test.local",
				Type:  LocalDNSTypeA,
				Value: "192.168.1.1",
			},
			setup: func() (PiholeAPI, *mockHTTPDoer) {
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						// Only domain delete should be called, not authentication
						if req.URL.Path == "/api/auth" {
							return nil, fmt.Errorf("authentication should not be called when session is valid")
						}
						return createMockResponse(http.StatusOK, "{}"), nil
					},
				}
				api := NewPiholeAPI(&Config{
					Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
					Password:    "test-password",
					Endpoint:    "http://test.example.com",
					Client:      mockClient,
					AuthTimeout: time.Hour, // Long timeout for valid session test
				})
				// Set up valid session by manually setting sessionID and lastAuth
				if papi, ok := api.(*piholeAPI); ok {
					papi.mu.Lock()
					papi.sessionID = "existing-sid"
					papi.lastAuth = time.Now().Add(-30 * time.Minute) // Still valid (within 1 hour)
					papi.mu.Unlock()
				}
				return api, mockClient
			},
			wantErr: false,
			verifyReq: func(t *testing.T, req *http.Request) {
				if req.Header.Get("sid") != "existing-sid" {
					t.Errorf("expected sid header existing-sid, got %s", req.Header.Get("sid"))
				}
			},
		},
		{
			name: "invalid record type (not A)",
			record: &LocalDNSRecord{
				Name:  "test.local",
				Type:  LocalDNSTypeCNAME,
				Value: "example.com",
			},
			setup: func() (PiholeAPI, *mockHTTPDoer) {
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						t.Error("HTTP call should not be made for validation error")
						return nil, fmt.Errorf("should not be called")
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
			wantErr: true,
			errMsg:  "DeleteDomain not implemented for type CNAME",
		},
		{
			name: "missing domain name",
			record: &LocalDNSRecord{
				Name:  "",
				Type:  LocalDNSTypeA,
				Value: "192.168.1.1",
			},
			setup: func() (PiholeAPI, *mockHTTPDoer) {
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						t.Error("HTTP call should not be made for validation error")
						return nil, fmt.Errorf("should not be called")
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
			wantErr: true,
			errMsg:  "domain name and IP address are required",
		},
		{
			name: "missing IP address",
			record: &LocalDNSRecord{
				Name:  "test.local",
				Type:  LocalDNSTypeA,
				Value: "",
			},
			setup: func() (PiholeAPI, *mockHTTPDoer) {
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						t.Error("HTTP call should not be made for validation error")
						return nil, fmt.Errorf("should not be called")
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
			wantErr: true,
			errMsg:  "domain name and IP address are required",
		},
		{
			name: "both name and value empty",
			record: &LocalDNSRecord{
				Name:  "",
				Type:  LocalDNSTypeA,
				Value: "",
			},
			setup: func() (PiholeAPI, *mockHTTPDoer) {
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						t.Error("HTTP call should not be made for validation error")
						return nil, fmt.Errorf("should not be called")
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
			wantErr: true,
			errMsg:  "domain name and IP address are required",
		},
		{
			name: "authentication failure",
			record: &LocalDNSRecord{
				Name:  "test.local",
				Type:  LocalDNSTypeA,
				Value: "192.168.1.1",
			},
			setup: func() (PiholeAPI, *mockHTTPDoer) {
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						return createMockResponse(http.StatusOK, createAuthResponse(false, "", "Invalid password")), nil
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
			wantErr: true,
			errMsg:  "unable to authenticate",
		},
		{
			name: "network error",
			record: &LocalDNSRecord{
				Name:  "test.local",
				Type:  LocalDNSTypeA,
				Value: "192.168.1.1",
			},
			setup: func() (PiholeAPI, *mockHTTPDoer) {
				callCount := 0
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						callCount++
						if callCount == 1 {
							return createMockResponse(http.StatusOK, createAuthResponse(true, "abc123xyz", "")), nil
						}
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
			wantErr: true,
			errMsg:  "unable to delete domain",
		},
		{
			name: "unexpected status code (not 200 or 204)",
			record: &LocalDNSRecord{
				Name:  "test.local",
				Type:  LocalDNSTypeA,
				Value: "192.168.1.1",
			},
			setup: func() (PiholeAPI, *mockHTTPDoer) {
				callCount := 0
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						callCount++
						if callCount == 1 {
							return createMockResponse(http.StatusOK, createAuthResponse(true, "abc123xyz", "")), nil
						}
						return createMockResponse(http.StatusNotFound, `{"error": "Domain not found"}`), nil
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
			wantErr: true,
			errMsg:  "unexpected status code: 404",
		},
		{
			name: "unexpected status code (500)",
			record: &LocalDNSRecord{
				Name:  "test.local",
				Type:  LocalDNSTypeA,
				Value: "192.168.1.1",
			},
			setup: func() (PiholeAPI, *mockHTTPDoer) {
				callCount := 0
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						callCount++
						if callCount == 1 {
							return createMockResponse(http.StatusOK, createAuthResponse(true, "abc123xyz", "")), nil
						}
						return createMockResponse(http.StatusInternalServerError, `{"error": "Internal server error"}`), nil
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
			wantErr: true,
			errMsg:  "unexpected status code: 500",
		},
		{
			name: "domain name with spaces",
			record: &LocalDNSRecord{
				Name:  "test local",
				Type:  LocalDNSTypeA,
				Value: "192.168.1.1",
			},
			setup: func() (PiholeAPI, *mockHTTPDoer) {
				callCount := 0
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						callCount++
						if callCount == 1 {
							return createMockResponse(http.StatusOK, createAuthResponse(true, "abc123xyz", "")), nil
						}
						return createMockResponse(http.StatusOK, "{}"), nil
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
			wantErr: false,
			verifyReq: func(t *testing.T, req *http.Request) {
				// URL path should include space in domain name
				if req.URL.Path != "/api/config/dns/hosts/192.168.1.1 test local" {
					t.Errorf("expected path /api/config/dns/hosts/192.168.1.1 test local, got %s", req.URL.Path)
				}
			},
		},
		{
			name: "IP address with spaces (invalid but test behavior)",
			record: &LocalDNSRecord{
				Name:  "test.local",
				Type:  LocalDNSTypeA,
				Value: "192.168.1.1 ",
			},
			setup: func() (PiholeAPI, *mockHTTPDoer) {
				callCount := 0
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						callCount++
						if callCount == 1 {
							return createMockResponse(http.StatusOK, createAuthResponse(true, "abc123xyz", "")), nil
						}
						return createMockResponse(http.StatusOK, "{}"), nil
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
			wantErr: false,
			verifyReq: func(t *testing.T, req *http.Request) {
				// URL path should include space after IP
				if req.URL.Path != "/api/config/dns/hosts/192.168.1.1  test.local" {
					t.Errorf("expected path /api/config/dns/hosts/192.168.1.1  test.local, got %s", req.URL.Path)
				}
			},
		},
		{
			name: "empty response body",
			record: &LocalDNSRecord{
				Name:  "test.local",
				Type:  LocalDNSTypeA,
				Value: "192.168.1.1",
			},
			setup: func() (PiholeAPI, *mockHTTPDoer) {
				callCount := 0
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						callCount++
						if callCount == 1 {
							return createMockResponse(http.StatusOK, createAuthResponse(true, "abc123xyz", "")), nil
						}
						return createMockResponse(http.StatusOK, ""), nil
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
			wantErr: false,
		},
		{
			name: "session timeout triggers re-authentication",
			record: &LocalDNSRecord{
				Name:  "test.local",
				Type:  LocalDNSTypeA,
				Value: "192.168.1.1",
			},
			setup: func() (PiholeAPI, *mockHTTPDoer) {
				callCount := 0
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						callCount++
						// First call: re-authenticate (session expired)
						if callCount == 1 {
							return createMockResponse(http.StatusOK, createAuthResponse(true, "session2", "")), nil
						}
						// Second call: domain delete with new session
						return createMockResponse(http.StatusOK, "{}"), nil
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
			wantErr: false,
			verifyReq: func(t *testing.T, req *http.Request) {
				if req.Header.Get("sid") != "session2" {
					t.Errorf("expected sid header session2, got %s", req.Header.Get("sid"))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api, mockClient := tt.setup()

			// Capture request for verification
			var capturedReq *http.Request
			if tt.verifyReq != nil && mockClient.DoFunc != nil {
				originalDoFunc := mockClient.DoFunc
				mockClient.DoFunc = func(req *http.Request) (*http.Response, error) {
					// Only capture DELETE requests (not auth requests)
					if req.Method == "DELETE" {
						// Read body before capturing if it exists
						if req.Body != nil {
							bodyBytes, _ := io.ReadAll(req.Body)
							req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
						}
						capturedReq = req
					}
					return originalDoFunc(req)
				}
			}

			err := api.DeleteDomain(ctx, tt.record)

			if (err != nil) != tt.wantErr {
				t.Errorf("deleteDomain() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errMsg != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("deleteDomain() error = %v, want error containing %v", err, tt.errMsg)
				}
				return
			}

			// Verify request if needed
			if tt.verifyReq != nil && capturedReq != nil {
				tt.verifyReq(t, capturedReq)
			}
		})
	}
}
