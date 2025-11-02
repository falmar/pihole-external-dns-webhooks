package hooksserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/falmar/pihole-external-dns-webhooks/internal/kit"
)

// makeMockEndpoint creates a mock endpoint for testing
func makeMockEndpoint(callFunc func(ctx context.Context, request interface{}) (interface{}, error)) kit.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		return callFunc(ctx, request)
	}
}

func TestNewHTTPTransport(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockEndpoint := makeMockEndpoint(func(ctx context.Context, request interface{}) (interface{}, error) {
		return nil, nil
	})

	transport := NewHTTPTransport(
		mockEndpoint,
		mockEndpoint,
		mockEndpoint,
		mockEndpoint,
		logger,
	)

	if transport == nil {
		t.Fatal("NewHTTPTransport() returned nil")
	}
	if transport.negotiationEndpoint == nil {
		t.Error("NewHTTPTransport() negotiationEndpoint is nil")
	}
	if transport.getRecordsEndpoint == nil {
		t.Error("NewHTTPTransport() getRecordsEndpoint is nil")
	}
	if transport.postRecordsEndpoint == nil {
		t.Error("NewHTTPTransport() postRecordsEndpoint is nil")
	}
	if transport.adjustEndpointsEndpoint == nil {
		t.Error("NewHTTPTransport() adjustEndpointsEndpoint is nil")
	}
	if transport.logger == nil {
		t.Error("NewHTTPTransport() logger is nil")
	}
}

func TestHTTPTransport_HandleNegotiation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name           string
		mockEndpoint   kit.Endpoint
		expectedStatus int
		expectedBody   string
		checkHeaders   bool
	}{
		{
			name: "valid request",
			mockEndpoint: makeMockEndpoint(func(ctx context.Context, request interface{}) (interface{}, error) {
				return negotiationResponse{Filters: []string{"kind.local"}}, nil
			}),
			expectedStatus: http.StatusOK,
			expectedBody:   `{"filters":["kind.local"]}` + "\n",
			checkHeaders:   true,
		},
		{
			name: "empty filters",
			mockEndpoint: makeMockEndpoint(func(ctx context.Context, request interface{}) (interface{}, error) {
				return negotiationResponse{Filters: []string{}}, nil
			}),
			expectedStatus: http.StatusOK,
			expectedBody:   `{"filters":[]}` + "\n",
			checkHeaders:   true,
		},
		{
			name: "multiple filters",
			mockEndpoint: makeMockEndpoint(func(ctx context.Context, request interface{}) (interface{}, error) {
				return negotiationResponse{Filters: []string{"kind.local", "cluster.local"}}, nil
			}),
			expectedStatus: http.StatusOK,
			expectedBody:   `{"filters":["kind.local","cluster.local"]}` + "\n",
			checkHeaders:   true,
		},
		{
			name: "endpoint error",
			mockEndpoint: makeMockEndpoint(func(ctx context.Context, request interface{}) (interface{}, error) {
				return nil, fmt.Errorf("endpoint error")
			}),
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "internal server error\n",
			checkHeaders:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := NewHTTPTransport(
				tt.mockEndpoint,
				nil,
				nil,
				nil,
				logger,
			)

			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()

			transport.HandleNegotiation(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("HandleNegotiation() status = %v, want %v", w.Code, tt.expectedStatus)
			}

			body := strings.TrimSpace(w.Body.String())
			expectedBody := strings.TrimSpace(tt.expectedBody)
			if body != expectedBody {
				t.Errorf("HandleNegotiation() body = %v, want %v", body, expectedBody)
			}

			if tt.checkHeaders {
				contentType := w.Header().Get("content-type")
				if contentType != ContentType {
					t.Errorf("HandleNegotiation() content-type = %v, want %v", contentType, ContentType)
				}
			}
		})
	}
}

func TestHTTPTransport_HandleGetRecords(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name           string
		mockEndpoint   kit.Endpoint
		expectedStatus int
		validateBody   func(t *testing.T, body string) bool
		checkHeaders   bool
	}{
		{
			name: "valid request with records",
			mockEndpoint: makeMockEndpoint(func(ctx context.Context, request interface{}) (interface{}, error) {
				return getRecordsResponse{
					Records: []*Record{
						{DNSName: "test.local", RecordType: "A", Targets: []string{"192.168.1.1"}},
					},
				}, nil
			}),
			expectedStatus: http.StatusOK,
			validateBody: func(t *testing.T, body string) bool {
				var records []*Record
				if err := json.Unmarshal([]byte(body), &records); err != nil {
					t.Errorf("Failed to parse response: %v", err)
					return false
				}
				if len(records) != 1 {
					t.Errorf("Expected 1 record, got %d", len(records))
					return false
				}
				if records[0].DNSName != "test.local" {
					t.Errorf("Expected DNSName 'test.local', got %s", records[0].DNSName)
					return false
				}
				return true
			},
			checkHeaders: true,
		},
		{
			name: "empty records",
			mockEndpoint: makeMockEndpoint(func(ctx context.Context, request interface{}) (interface{}, error) {
				return getRecordsResponse{Records: []*Record{}}, nil
			}),
			expectedStatus: http.StatusOK,
			validateBody: func(t *testing.T, body string) bool {
				if strings.TrimSpace(body) != "[]" {
					t.Errorf("Expected empty array, got %s", body)
					return false
				}
				return true
			},
			checkHeaders: true,
		},
		{
			name: "multiple records",
			mockEndpoint: makeMockEndpoint(func(ctx context.Context, request interface{}) (interface{}, error) {
				return getRecordsResponse{
					Records: []*Record{
						{DNSName: "test1.local", RecordType: "A", Targets: []string{"192.168.1.1"}},
						{DNSName: "test2.local", RecordType: "A", Targets: []string{"192.168.1.2"}},
					},
				}, nil
			}),
			expectedStatus: http.StatusOK,
			validateBody: func(t *testing.T, body string) bool {
				var records []*Record
				if err := json.Unmarshal([]byte(body), &records); err != nil {
					t.Errorf("Failed to parse response: %v", err)
					return false
				}
				if len(records) != 2 {
					t.Errorf("Expected 2 records, got %d", len(records))
					return false
				}
				return true
			},
			checkHeaders: true,
		},
		{
			name: "endpoint error",
			mockEndpoint: makeMockEndpoint(func(ctx context.Context, request interface{}) (interface{}, error) {
				return nil, fmt.Errorf("endpoint error")
			}),
			expectedStatus: http.StatusInternalServerError,
			validateBody: func(t *testing.T, body string) bool {
				// On error, no body should be set
				return true
			},
			checkHeaders: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := NewHTTPTransport(
				nil,
				tt.mockEndpoint,
				nil,
				nil,
				logger,
			)

			req := httptest.NewRequest("GET", "/records", nil)
			w := httptest.NewRecorder()

			transport.HandleGetRecords(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("HandleGetRecords() status = %v, want %v", w.Code, tt.expectedStatus)
			}

			if tt.validateBody != nil {
				tt.validateBody(t, w.Body.String())
			}

			if tt.checkHeaders {
				contentType := w.Header().Get("content-type")
				if contentType != ContentType {
					t.Errorf("HandleGetRecords() content-type = %v, want %v", contentType, ContentType)
				}
			}
		})
	}
}

func TestHTTPTransport_HandlePostRecords(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name           string
		contentType    string
		body           string
		mockEndpoint   kit.Endpoint
		expectedStatus int
		checkHeaders   bool
	}{
		{
			name:        "valid request with correct Content-Type",
			contentType: ContentType,
			body:        `{"create":[{"dnsName":"test.local","recordType":"A","targets":["192.168.1.1"]}]}`,
			mockEndpoint: makeMockEndpoint(func(ctx context.Context, request interface{}) (interface{}, error) {
				return postRecordsResponse{ChangeSetResult: &ChangeSetResult{Created: 1}}, nil
			}),
			expectedStatus: http.StatusOK,
			checkHeaders:   true,
		},
		{
			name:        "empty change set",
			contentType: ContentType,
			body:        `{"create":[],"update":[],"delete":[]}`,
			mockEndpoint: makeMockEndpoint(func(ctx context.Context, request interface{}) (interface{}, error) {
				return postRecordsResponse{ChangeSetResult: &ChangeSetResult{}}, nil
			}),
			expectedStatus: http.StatusOK,
			checkHeaders:   true,
		},
		{
			name:           "invalid Content-Type",
			contentType:    "application/json",
			body:           `{"create":[]}`,
			mockEndpoint:   nil,
			expectedStatus: http.StatusBadRequest,
			checkHeaders:   false,
		},
		{
			name:           "missing Content-Type",
			contentType:    "",
			body:           `{"create":[]}`,
			mockEndpoint:   nil,
			expectedStatus: http.StatusBadRequest,
			checkHeaders:   false,
		},
		{
			name:           "invalid JSON body",
			contentType:    ContentType,
			body:           `{invalid json`,
			mockEndpoint:   nil,
			expectedStatus: http.StatusBadRequest,
			checkHeaders:   false,
		},
		{
			name:        "empty body",
			contentType: ContentType,
			body:        `{}`,
			mockEndpoint: makeMockEndpoint(func(ctx context.Context, request interface{}) (interface{}, error) {
				return postRecordsResponse{ChangeSetResult: &ChangeSetResult{}}, nil
			}),
			expectedStatus: http.StatusOK,
			checkHeaders:   true,
		},
		{
			name:        "endpoint error",
			contentType: ContentType,
			body:        `{"create":[{"dnsName":"test.local","recordType":"A","targets":["192.168.1.1"]}]}`,
			mockEndpoint: makeMockEndpoint(func(ctx context.Context, request interface{}) (interface{}, error) {
				return nil, fmt.Errorf("endpoint error")
			}),
			expectedStatus: http.StatusInternalServerError,
			checkHeaders:   false,
		},
		{
			name:        "endpoint error with partial result",
			contentType: ContentType,
			body:        `{"create":[{"dnsName":"test.local","recordType":"A","targets":["192.168.1.1"]}]}`,
			mockEndpoint: makeMockEndpoint(func(ctx context.Context, request interface{}) (interface{}, error) {
				return postRecordsResponse{
					ChangeSetResult: &ChangeSetResult{
						Created: 1,
						Errors:  []error{fmt.Errorf("partial error")},
					},
				}, fmt.Errorf("change set applied with 1 errors")
			}),
			expectedStatus: http.StatusInternalServerError,
			checkHeaders:   true, // Partial failure still sets content-type
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mockEndpoint kit.Endpoint
			if tt.mockEndpoint != nil {
				mockEndpoint = tt.mockEndpoint
			} else {
				mockEndpoint = makeMockEndpoint(func(ctx context.Context, request interface{}) (interface{}, error) {
					return nil, nil
				})
			}

			transport := NewHTTPTransport(
				nil,
				nil,
				mockEndpoint,
				nil,
				logger,
			)

			req := httptest.NewRequest("POST", "/records", bytes.NewReader([]byte(tt.body)))
			if tt.contentType != "" {
				req.Header.Set("content-type", tt.contentType)
			}
			w := httptest.NewRecorder()

			transport.HandlePostRecords(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("HandlePostRecords() status = %v, want %v", w.Code, tt.expectedStatus)
			}

			if tt.checkHeaders {
				contentType := w.Header().Get("content-type")
				if contentType != ContentType {
					t.Errorf("HandlePostRecords() content-type = %v, want %v", contentType, ContentType)
				}
			}
		})
	}
}

func TestHTTPTransport_HandleAdjustments(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name           string
		body           string
		mockEndpoint   kit.Endpoint
		expectedStatus int
		validateBody   func(t *testing.T, body string) bool
		checkHeaders   bool
	}{
		{
			name: "valid POST request",
			body: `[{"dnsName":"test.local","recordType":"A","targets":["192.168.1.1"],"recordTTL":300}]`,
			mockEndpoint: makeMockEndpoint(func(ctx context.Context, request interface{}) (interface{}, error) {
				return adjustEndpointsResponse{
					Records: []*Record{
						{DNSName: "test.local", RecordType: "A", Targets: []string{"192.168.1.1"}, RecordTTL: 0},
					},
				}, nil
			}),
			expectedStatus: http.StatusOK,
			validateBody: func(t *testing.T, body string) bool {
				var records []*Record
				if err := json.Unmarshal([]byte(body), &records); err != nil {
					t.Errorf("Failed to parse response: %v", err)
					return false
				}
				if len(records) != 1 {
					t.Errorf("Expected 1 record, got %d", len(records))
					return false
				}
				if records[0].RecordTTL != 0 {
					t.Errorf("Expected normalized record with TTL 0, got %d", records[0].RecordTTL)
					return false
				}
				return true
			},
			checkHeaders: true,
		},
		{
			name: "empty records",
			body: `[]`,
			mockEndpoint: makeMockEndpoint(func(ctx context.Context, request interface{}) (interface{}, error) {
				return adjustEndpointsResponse{Records: []*Record{}}, nil
			}),
			expectedStatus: http.StatusOK,
			validateBody: func(t *testing.T, body string) bool {
				if strings.TrimSpace(body) != "[]" {
					t.Errorf("Expected empty array, got %s", body)
					return false
				}
				return true
			},
			checkHeaders: true,
		},
		{
			name: "multiple records",
			body: `[{"dnsName":"test1.local","recordType":"A","targets":["192.168.1.1"]},{"dnsName":"test2.local","recordType":"A","targets":["192.168.1.2"]}]`,
			mockEndpoint: makeMockEndpoint(func(ctx context.Context, request interface{}) (interface{}, error) {
				return adjustEndpointsResponse{
					Records: []*Record{
						{DNSName: "test1.local", RecordType: "A", Targets: []string{"192.168.1.1"}, RecordTTL: 0},
						{DNSName: "test2.local", RecordType: "A", Targets: []string{"192.168.1.2"}, RecordTTL: 0},
					},
				}, nil
			}),
			expectedStatus: http.StatusOK,
			validateBody: func(t *testing.T, body string) bool {
				var records []*Record
				if err := json.Unmarshal([]byte(body), &records); err != nil {
					t.Errorf("Failed to parse response: %v", err)
					return false
				}
				if len(records) != 2 {
					t.Errorf("Expected 2 records, got %d", len(records))
					return false
				}
				return true
			},
			checkHeaders: true,
		},
		{
			name:           "invalid JSON body",
			body:           `{invalid json`,
			mockEndpoint:   nil,
			expectedStatus: http.StatusBadRequest,
			validateBody:   nil,
			checkHeaders:   false,
		},
		{
			name: "endpoint error",
			body: `[{"dnsName":"test.local","recordType":"A","targets":["192.168.1.1"]}]`,
			mockEndpoint: makeMockEndpoint(func(ctx context.Context, request interface{}) (interface{}, error) {
				return nil, fmt.Errorf("endpoint error")
			}),
			expectedStatus: http.StatusInternalServerError,
			validateBody:   nil,
			checkHeaders:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mockEndpoint kit.Endpoint
			if tt.mockEndpoint != nil {
				mockEndpoint = tt.mockEndpoint
			} else {
				mockEndpoint = makeMockEndpoint(func(ctx context.Context, request interface{}) (interface{}, error) {
					return nil, nil
				})
			}

			transport := NewHTTPTransport(
				nil,
				nil,
				nil,
				mockEndpoint,
				logger,
			)

			req := httptest.NewRequest("POST", "/adjustendpoints", bytes.NewReader([]byte(tt.body)))
			w := httptest.NewRecorder()

			transport.HandleAdjustments(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("HandleAdjustments() status = %v, want %v", w.Code, tt.expectedStatus)
			}

			if tt.validateBody != nil {
				tt.validateBody(t, w.Body.String())
			}

			if tt.checkHeaders {
				contentType := w.Header().Get("content-type")
				if contentType != ContentType {
					t.Errorf("HandleAdjustments() content-type = %v, want %v", contentType, ContentType)
				}
			}
		})
	}
}
