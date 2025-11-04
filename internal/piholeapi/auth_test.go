package piholeapi

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuthenticate(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		setup     func() *piholeAPI
		wantErr   bool
		errMsg    string
		verifyReq func(*testing.T, *http.Request)
	}{
		{
			name: "successful authentication",
			setup: func() *piholeAPI {
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						return createMockResponse(http.StatusOK, createAuthResponse(true, "test-session-id", "")), nil
					},
				}
				return &piholeAPI{
					endpoint:    "http://test.example.com",
					pass:        "test-password",
					logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
					authTimeout: time.Hour,
					mu:          &sync.RWMutex{},
					client:      mockClient,
				}
			},
			wantErr: false,
			verifyReq: func(t *testing.T, req *http.Request) {
				if req.Method != "POST" {
					t.Errorf("expected POST method, got %s", req.Method)
				}
				if req.URL.Path != "/api/auth" {
					t.Errorf("expected path /api/auth, got %s", req.URL.Path)
				}
			},
		},
		{
			name: "authentication failure - invalid password",
			setup: func() *piholeAPI {
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						return createMockResponse(http.StatusOK, createAuthResponse(false, "", "Invalid password")), nil
					},
				}
				return &piholeAPI{
					endpoint:    "http://test.example.com",
					pass:        "wrong-password",
					logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
					authTimeout: time.Hour,
					mu:          &sync.RWMutex{},
					client:      mockClient,
				}
			},
			wantErr: true,
			errMsg:  "unable to authenticate: Invalid password",
		},
		{
			name: "authentication with non-200 status code",
			setup: func() *piholeAPI {
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						return createMockResponse(http.StatusInternalServerError, ""), nil
					},
				}
				return &piholeAPI{
					endpoint:    "http://test.example.com",
					pass:        "test-password",
					logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
					authTimeout: time.Hour,
					mu:          &sync.RWMutex{},
					client:      mockClient,
				}
			},
			wantErr: true,
			errMsg:  "unexpected status code: 500",
		},
		{
			name: "authentication with network error",
			setup: func() *piholeAPI {
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						return nil, fmt.Errorf("network error")
					},
				}
				return &piholeAPI{
					endpoint:    "http://test.example.com",
					pass:        "test-password",
					logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
					authTimeout: time.Hour,
					mu:          &sync.RWMutex{},
					client:      mockClient,
				}
			},
			wantErr: true,
			errMsg:  "unable to authenticate",
		},
		{
			name: "authentication with malformed JSON response",
			setup: func() *piholeAPI {
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						return createMockResponse(http.StatusOK, "not valid json"), nil
					},
				}
				return &piholeAPI{
					endpoint:    "http://test.example.com",
					pass:        "test-password",
					logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
					authTimeout: time.Hour,
					mu:          &sync.RWMutex{},
					client:      mockClient,
				}
			},
			wantErr: true,
			errMsg:  "unable to decode response body",
		},
		{
			name: "reuses valid session",
			setup: func() *piholeAPI {
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						t.Error("authenticate() should not make HTTP call when session is valid")
						return nil, fmt.Errorf("should not be called")
					},
				}
				api := &piholeAPI{
					endpoint:    "http://test.example.com",
					pass:        "test-password",
					logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
					authTimeout: time.Hour,
					mu:          &sync.RWMutex{},
					client:      mockClient,
					sessionID:   "existing-session",
					lastAuth:    time.Now(),
				}
				return api
			},
			wantErr: false,
		},
		{
			name: "re-authenticates when session expired",
			setup: func() *piholeAPI {
				mockClient := &mockHTTPDoer{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						return createMockResponse(http.StatusOK, createAuthResponse(true, "new-session", "")), nil
					},
				}
				api := &piholeAPI{
					endpoint:    "http://test.example.com",
					pass:        "test-password",
					logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
					authTimeout: time.Second,
					mu:          &sync.RWMutex{},
					client:      mockClient,
					sessionID:   "expired-session",
					lastAuth:    time.Now().Add(-2 * time.Second),
				}
				return api
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := tt.setup()

			sid, err := api.authenticate(ctx)

			if (err != nil) != tt.wantErr {
				t.Errorf("authenticate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if tt.errMsg != "" && (err == nil || !strings.Contains(err.Error(), tt.errMsg)) {
					t.Errorf("authenticate() error = %v, want error containing %v", err, tt.errMsg)
				}
				return
			}

			if sid == "" {
				t.Error("authenticate() returned empty session ID")
			}

			// Verify session was stored
			if api.sessionID == "" {
				t.Error("sessionID was not stored after authentication")
			}
			if api.lastAuth.IsZero() {
				t.Error("lastAuth was not set after authentication")
			}
		})
	}
}

func TestAuthenticateConcurrent(t *testing.T) {
	ctx := context.Background()
	callCount := int32(0)

	mockClient := &mockHTTPDoer{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			atomic.AddInt32(&callCount, 1)
			time.Sleep(10 * time.Millisecond) // Simulate network delay
			return createMockResponse(http.StatusOK, createAuthResponse(true, "concurrent-session", "")), nil
		},
	}

	api := &piholeAPI{
		endpoint:    "http://test.example.com",
		pass:        "test-password",
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		authTimeout: time.Hour,
		mu:          &sync.RWMutex{},
		client:      mockClient,
	}

	// Launch multiple goroutines authenticating concurrently
	const numGoroutines = 10
	var wg sync.WaitGroup
	sessions := make([]string, numGoroutines)
	errors := make([]error, numGoroutines)

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			sid, err := api.authenticate(ctx)
			sessions[idx] = sid
			errors[idx] = err
		}(i)
	}

	wg.Wait()

	// Verify only one authentication HTTP call was made
	finalCallCount := atomic.LoadInt32(&callCount)
	if finalCallCount != 1 {
		t.Errorf("expected 1 authentication call, got %d", finalCallCount)
	}

	// Verify all goroutines got the same session ID
	for i, sid := range sessions {
		if sid == "" {
			t.Errorf("goroutine %d got empty session ID", i)
		}
		if sid != sessions[0] {
			t.Errorf("goroutine %d got different session ID: %s vs %s", i, sid, sessions[0])
		}
		if errors[i] != nil {
			t.Errorf("goroutine %d got error: %v", i, errors[i])
		}
	}
}

func TestIsAuthenticated(t *testing.T) {
	tests := []struct {
		name        string
		setup       func() *piholeAPI
		expectEmpty bool
	}{
		{
			name: "returns session ID when valid",
			setup: func() *piholeAPI {
				return &piholeAPI{
					sessionID:   "valid-session",
					lastAuth:    time.Now(),
					authTimeout: time.Hour,
					mu:          &sync.RWMutex{},
				}
			},
			expectEmpty: false,
		},
		{
			name: "returns empty when session expired",
			setup: func() *piholeAPI {
				return &piholeAPI{
					sessionID:   "expired-session",
					lastAuth:    time.Now().Add(-2 * time.Hour),
					authTimeout: time.Hour,
					mu:          &sync.RWMutex{},
				}
			},
			expectEmpty: true,
		},
		{
			name: "returns empty when never authenticated",
			setup: func() *piholeAPI {
				return &piholeAPI{
					sessionID:   "",
					lastAuth:    time.Time{},
					authTimeout: time.Hour,
					mu:          &sync.RWMutex{},
				}
			},
			expectEmpty: true,
		},
		{
			name: "returns empty when session ID is empty",
			setup: func() *piholeAPI {
				return &piholeAPI{
					sessionID:   "",
					lastAuth:    time.Now(),
					authTimeout: time.Hour,
					mu:          &sync.RWMutex{},
				}
			},
			expectEmpty: true,
		},
		{
			name: "handles exactly at timeout boundary",
			setup: func() *piholeAPI {
				timeout := time.Second
				return &piholeAPI{
					sessionID:   "boundary-session",
					lastAuth:    time.Now().Add(-timeout),
					authTimeout: timeout,
					mu:          &sync.RWMutex{},
				}
			},
			expectEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := tt.setup()
			sid := api.isAuthenticated()

			if tt.expectEmpty {
				if sid != "" {
					t.Errorf("isAuthenticated() = %q, want empty string", sid)
				}
			} else {
				if sid == "" {
					t.Error("isAuthenticated() returned empty, want non-empty session ID")
				}
			}
		})
	}
}

func TestAuthenticateContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	mockClient := &mockHTTPDoer{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return nil, context.Canceled
		},
	}

	api := &piholeAPI{
		endpoint:    "http://test.example.com",
		pass:        "test-password",
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		authTimeout: time.Hour,
		mu:          &sync.RWMutex{},
		client:      mockClient,
	}

	cancel() // Cancel context before authenticate

	_, err := api.authenticate(ctx)
	if err == nil {
		t.Error("expected error with cancelled context, got nil")
	}
}
