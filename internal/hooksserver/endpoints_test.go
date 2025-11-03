package hooksserver

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"
)

// mockService is a mock implementation of the Service interface.
type mockService struct {
	GetFiltersFunc      func() []string
	GetRecordsFunc      func(ctx context.Context) ([]*Record, error)
	ApplyChangesFunc    func(ctx context.Context, req *ChangeSetRequest) (*ChangeSetResult, error)
	AdjustEndpointsFunc func(ctx context.Context, records []*Record) ([]*Record, error)
}

func (m *mockService) GetFilters() []string {
	if m.GetFiltersFunc != nil {
		return m.GetFiltersFunc()
	}
	return []string{}
}

func (m *mockService) GetRecords(ctx context.Context) ([]*Record, error) {
	if m.GetRecordsFunc != nil {
		return m.GetRecordsFunc(ctx)
	}
	return nil, nil
}

func (m *mockService) ApplyChanges(ctx context.Context, req *ChangeSetRequest) (*ChangeSetResult, error) {
	if m.ApplyChangesFunc != nil {
		return m.ApplyChangesFunc(ctx, req)
	}
	return &ChangeSetResult{}, nil
}

func (m *mockService) AdjustEndpoints(ctx context.Context, records []*Record) ([]*Record, error) {
	if m.AdjustEndpointsFunc != nil {
		return m.AdjustEndpointsFunc(ctx, records)
	}
	return nil, nil
}

func TestMakeNegotiationEndpoint(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name        string
		mockService *mockService
		request     interface{}
		want        negotiationResponse
		wantErr     bool
		errMsg      string
	}{
		{
			name: "returns filters from service",
			mockService: &mockService{
				GetFiltersFunc: func() []string {
					return []string{"kind.local", "cluster.local"}
				},
			},
			request: negotiationRequest{},
			want: negotiationResponse{
				Filters: []string{"kind.local", "cluster.local"},
			},
			wantErr: false,
		},
		{
			name: "returns empty filters",
			mockService: &mockService{
				GetFiltersFunc: func() []string {
					return []string{}
				},
			},
			request: negotiationRequest{},
			want: negotiationResponse{
				Filters: []string{},
			},
			wantErr: false,
		},
		{
			name:        "invalid request type",
			mockService: &mockService{},
			request:     "invalid request type",
			want:        negotiationResponse{},
			wantErr:     true,
			errMsg:      "invalid request type: expected negotiationRequest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint := makeNegotiationEndpoint(tt.mockService, logger)
			got, err := endpoint(ctx, tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("makeNegotiationEndpoint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if tt.errMsg != "" && (err == nil || !strings.Contains(err.Error(), tt.errMsg)) {
					t.Errorf("makeNegotiationEndpoint() error = %v, want error containing %v", err, tt.errMsg)
				}
				return
			}
			if !tt.wantErr {
				resp := got.(negotiationResponse)
				if !reflect.DeepEqual(resp, tt.want) {
					t.Errorf("makeNegotiationEndpoint() = %v, want %v", resp, tt.want)
				}
			}
		})
	}
}

func TestMakeGetRecordsEndpoint(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name        string
		mockService *mockService
		request     interface{}
		want        getRecordsResponse
		wantErr     bool
		errMsg      string
	}{
		{
			name: "successfully returns records",
			mockService: &mockService{
				GetRecordsFunc: func(ctx context.Context) ([]*Record, error) {
					return []*Record{
						{DNSName: "test.local", RecordType: "A", Targets: []string{"192.168.1.1"}},
					}, nil
				},
			},
			request: getRecordsRequest{},
			want: getRecordsResponse{
				Records: []*Record{
					{DNSName: "test.local", RecordType: "A", Targets: []string{"192.168.1.1"}},
				},
			},
			wantErr: false,
		},
		{
			name: "empty records",
			mockService: &mockService{
				GetRecordsFunc: func(ctx context.Context) ([]*Record, error) {
					return []*Record{}, nil
				},
			},
			request: getRecordsRequest{},
			want: getRecordsResponse{
				Records: []*Record{},
			},
			wantErr: false,
		},
		{
			name: "service error",
			mockService: &mockService{
				GetRecordsFunc: func(ctx context.Context) ([]*Record, error) {
					return nil, fmt.Errorf("service error")
				},
			},
			request: getRecordsRequest{},
			want:    getRecordsResponse{},
			wantErr: true,
			errMsg:  "unable to get records",
		},
		{
			name:        "invalid request type",
			mockService: &mockService{},
			request:     "invalid request type",
			want:        getRecordsResponse{},
			wantErr:     true,
			errMsg:      "invalid request type: expected getRecordsRequest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint := makeGetRecordsEndpoint(tt.mockService, logger)
			got, err := endpoint(ctx, tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("makeGetRecordsEndpoint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("makeGetRecordsEndpoint() error = %v, want error containing %v", err, tt.errMsg)
				}
				return
			}
			if !tt.wantErr {
				resp := got.(getRecordsResponse)
				if !reflect.DeepEqual(resp, tt.want) {
					t.Errorf("makeGetRecordsEndpoint() = %v, want %v", resp, tt.want)
				}
			}
		})
	}
}

func TestMakePostRecordsEndpoint(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name        string
		mockService *mockService
		request     interface{}
		want        postRecordsResponse
		wantErr     bool
		errMsg      string
	}{
		{
			name: "valid request with creates only",
			mockService: &mockService{
				ApplyChangesFunc: func(ctx context.Context, req *ChangeSetRequest) (*ChangeSetResult, error) {
					return &ChangeSetResult{Created: 1, Updated: 0, Deleted: 0, Errors: nil}, nil
				},
			},
			request: postRecordsRequest{
				ChangeSetRequest: &ChangeSetRequest{
					Create: []*Record{
						{DNSName: "test.local", RecordType: "A", Targets: []string{"192.168.1.1"}},
					},
				},
			},
			want: postRecordsResponse{
				ChangeSetResult: &ChangeSetResult{Created: 1, Updated: 0, Deleted: 0, Errors: nil},
			},
			wantErr: false,
		},
		{
			name: "valid request with updates only",
			mockService: &mockService{
				ApplyChangesFunc: func(ctx context.Context, req *ChangeSetRequest) (*ChangeSetResult, error) {
					return &ChangeSetResult{Created: 0, Updated: 1, Deleted: 0, Errors: nil}, nil
				},
			},
			request: postRecordsRequest{
				ChangeSetRequest: &ChangeSetRequest{
					Update: []*Record{
						{DNSName: "test.local", RecordType: "A", Targets: []string{"192.168.1.2"}},
					},
				},
			},
			want: postRecordsResponse{
				ChangeSetResult: &ChangeSetResult{Created: 0, Updated: 1, Deleted: 0, Errors: nil},
			},
			wantErr: false,
		},
		{
			name: "valid request with deletes only",
			mockService: &mockService{
				ApplyChangesFunc: func(ctx context.Context, req *ChangeSetRequest) (*ChangeSetResult, error) {
					return &ChangeSetResult{Created: 0, Updated: 0, Deleted: 1, Errors: nil}, nil
				},
			},
			request: postRecordsRequest{
				ChangeSetRequest: &ChangeSetRequest{
					Delete: []*Record{
						{DNSName: "test.local", RecordType: "A", Targets: []string{"192.168.1.1"}},
					},
				},
			},
			want: postRecordsResponse{
				ChangeSetResult: &ChangeSetResult{Created: 0, Updated: 0, Deleted: 1, Errors: nil},
			},
			wantErr: false,
		},
		{
			name: "valid request with mixed operations",
			mockService: &mockService{
				ApplyChangesFunc: func(ctx context.Context, req *ChangeSetRequest) (*ChangeSetResult, error) {
					return &ChangeSetResult{Created: 1, Updated: 1, Deleted: 1, Errors: nil}, nil
				},
			},
			request: postRecordsRequest{
				ChangeSetRequest: &ChangeSetRequest{
					Create: []*Record{
						{DNSName: "new.local", RecordType: "A", Targets: []string{"192.168.1.1"}},
					},
					Update: []*Record{
						{DNSName: "update.local", RecordType: "A", Targets: []string{"192.168.1.2"}},
					},
					Delete: []*Record{
						{DNSName: "delete.local", RecordType: "A", Targets: []string{"192.168.1.3"}},
					},
				},
			},
			want: postRecordsResponse{
				ChangeSetResult: &ChangeSetResult{Created: 1, Updated: 1, Deleted: 1, Errors: nil},
			},
			wantErr: false,
		},
		{
			name: "empty change set",
			mockService: &mockService{
				ApplyChangesFunc: func(ctx context.Context, req *ChangeSetRequest) (*ChangeSetResult, error) {
					return &ChangeSetResult{}, nil
				},
			},
			request: postRecordsRequest{
				ChangeSetRequest: &ChangeSetRequest{},
			},
			want: postRecordsResponse{
				ChangeSetResult: &ChangeSetResult{},
			},
			wantErr: false,
		},
		{
			name:        "nil ChangeSetRequest",
			mockService: &mockService{},
			request: postRecordsRequest{
				ChangeSetRequest: nil,
			},
			want:    postRecordsResponse{},
			wantErr: true,
			errMsg:  "change set request is required",
		},
		{
			name:        "missing dnsName in create record",
			mockService: &mockService{},
			request: postRecordsRequest{
				ChangeSetRequest: &ChangeSetRequest{
					Create: []*Record{
						{DNSName: "", RecordType: "A", Targets: []string{"192.168.1.1"}},
					},
				},
			},
			want:    postRecordsResponse{},
			wantErr: true,
			errMsg:  "invalid record at index 0: missing dnsName",
		},
		{
			name:        "missing dnsName in update record",
			mockService: &mockService{},
			request: postRecordsRequest{
				ChangeSetRequest: &ChangeSetRequest{
					Update: []*Record{
						{DNSName: "", RecordType: "A", Targets: []string{"192.168.1.1"}},
					},
				},
			},
			want:    postRecordsResponse{},
			wantErr: true,
			errMsg:  "invalid record at index 0: missing dnsName",
		},
		{
			name:        "missing recordType in create record",
			mockService: &mockService{},
			request: postRecordsRequest{
				ChangeSetRequest: &ChangeSetRequest{
					Create: []*Record{
						{DNSName: "test.local", RecordType: "", Targets: []string{"192.168.1.1"}},
					},
				},
			},
			want:    postRecordsResponse{},
			wantErr: true,
			errMsg:  "invalid record at index 0: missing recordType (dnsName: test.local)",
		},
		{
			name:        "missing targets in create record",
			mockService: &mockService{},
			request: postRecordsRequest{
				ChangeSetRequest: &ChangeSetRequest{
					Create: []*Record{
						{DNSName: "test.local", RecordType: "A", Targets: []string{}},
					},
				},
			},
			want:    postRecordsResponse{},
			wantErr: true,
			errMsg:  "invalid record at index 0: missing targets (dnsName: test.local)",
		},
		{
			name:        "multiple validation errors first one reported",
			mockService: &mockService{},
			request: postRecordsRequest{
				ChangeSetRequest: &ChangeSetRequest{
					Create: []*Record{
						{DNSName: "", RecordType: "A", Targets: []string{"192.168.1.1"}},           // Missing DNSName
						{DNSName: "test2.local", RecordType: "", Targets: []string{"192.168.1.2"}}, // Missing RecordType
					},
				},
			},
			want:    postRecordsResponse{},
			wantErr: true,
			errMsg:  "invalid record at index 0: missing dnsName", // First error should be reported
		},
		{
			name: "service error",
			mockService: &mockService{
				ApplyChangesFunc: func(ctx context.Context, req *ChangeSetRequest) (*ChangeSetResult, error) {
					return nil, fmt.Errorf("service error")
				},
			},
			request: postRecordsRequest{
				ChangeSetRequest: &ChangeSetRequest{
					Create: []*Record{
						{DNSName: "test.local", RecordType: "A", Targets: []string{"192.168.1.1"}},
					},
				},
			},
			want:    postRecordsResponse{},
			wantErr: true,
			errMsg:  "unable to apply changes",
		},
		{
			name: "partial failure result has errors",
			mockService: &mockService{
				ApplyChangesFunc: func(ctx context.Context, req *ChangeSetRequest) (*ChangeSetResult, error) {
					return &ChangeSetResult{
						Created: 1,
						Updated: 0,
						Deleted: 0,
						Errors:  []error{fmt.Errorf("error1"), fmt.Errorf("error2")},
					}, nil
				},
			},
			request: postRecordsRequest{
				ChangeSetRequest: &ChangeSetRequest{
					Create: []*Record{
						{DNSName: "test.local", RecordType: "A", Targets: []string{"192.168.1.1"}},
					},
				},
			},
			want: postRecordsResponse{
				ChangeSetResult: &ChangeSetResult{
					Created: 1,
					Updated: 0,
					Deleted: 0,
					Errors:  []error{fmt.Errorf("error1"), fmt.Errorf("error2")},
				},
			},
			wantErr: true, // Should return error even though result is populated
			errMsg:  "change set applied with 2 errors",
		},
		{
			name:        "invalid request type",
			mockService: &mockService{},
			request:     "invalid request type",
			want:        postRecordsResponse{},
			wantErr:     true,
			errMsg:      "invalid request type: expected postRecordsRequest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint := makePostRecordsEndpoint(tt.mockService, logger)
			got, err := endpoint(ctx, tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("makePostRecordsEndpoint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("makePostRecordsEndpoint() error = %v, want error containing %v", err, tt.errMsg)
				}
				// For partial failure, we still want to check the response
				if tt.name == "partial failure result has errors" {
					if got != nil {
						resp := got.(postRecordsResponse)
						if resp.ChangeSetResult == nil || len(resp.Errors) != 2 {
							t.Errorf("makePostRecordsEndpoint() partial failure should return result with errors")
						}
					}
				}
				return
			}
			if !tt.wantErr {
				resp := got.(postRecordsResponse)
				if resp.ChangeSetResult == nil && tt.want.ChangeSetResult == nil {
					return
				}
				if resp.ChangeSetResult == nil || tt.want.ChangeSetResult == nil {
					t.Errorf("makePostRecordsEndpoint() ChangeSetResult = %v, want %v", resp.ChangeSetResult, tt.want.ChangeSetResult)
					return
				}
				if resp.Created != tt.want.Created {
					t.Errorf("makePostRecordsEndpoint() Created = %d, want %d", resp.Created, tt.want.Created)
				}
				if resp.Updated != tt.want.Updated {
					t.Errorf("makePostRecordsEndpoint() Updated = %d, want %d", resp.Updated, tt.want.Updated)
				}
				if resp.Deleted != tt.want.Deleted {
					t.Errorf("makePostRecordsEndpoint() Deleted = %d, want %d", resp.Deleted, tt.want.Deleted)
				}
				if len(resp.Errors) != len(tt.want.Errors) {
					t.Errorf("makePostRecordsEndpoint() Errors length = %d, want %d", len(resp.Errors), len(tt.want.Errors))
				} else {
					for i := range resp.Errors {
						if resp.Errors[i] == nil && tt.want.Errors[i] == nil {
							continue
						}
						if resp.Errors[i] == nil || tt.want.Errors[i] == nil {
							t.Errorf("makePostRecordsEndpoint() Errors[%d] = %v, want %v", i, resp.Errors[i], tt.want.Errors[i])
							continue
						}
						if resp.Errors[i].Error() != tt.want.Errors[i].Error() {
							t.Errorf("makePostRecordsEndpoint() Errors[%d] = %v, want %v", i, resp.Errors[i], tt.want.Errors[i])
						}
					}
				}
			}
		})
	}
}

func TestMakeAdjustEndpointsEndpoint(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name        string
		mockService *mockService
		request     interface{}
		want        adjustEndpointsResponse
		wantErr     bool
		errMsg      string
	}{
		{
			name: "valid records adjustment",
			mockService: &mockService{
				AdjustEndpointsFunc: func(ctx context.Context, records []*Record) ([]*Record, error) {
					return []*Record{
						{DNSName: "test.local", RecordType: "A", Targets: []string{"192.168.1.1"}, RecordTTL: 0},
					}, nil
				},
			},
			request: adjustEndpointsRequest{
				Records: []*Record{
					{DNSName: "test.local", RecordType: "A", Targets: []string{"192.168.1.1"}, RecordTTL: 300},
				},
			},
			want: adjustEndpointsResponse{
				Records: []*Record{
					{DNSName: "test.local", RecordType: "A", Targets: []string{"192.168.1.1"}, RecordTTL: 0},
				},
			},
			wantErr: false,
		},
		{
			name: "empty records",
			mockService: &mockService{
				AdjustEndpointsFunc: func(ctx context.Context, records []*Record) ([]*Record, error) {
					return []*Record{}, nil
				},
			},
			request: adjustEndpointsRequest{
				Records: []*Record{},
			},
			want: adjustEndpointsResponse{
				Records: []*Record{},
			},
			wantErr: false,
		},
		{
			name: "service error",
			mockService: &mockService{
				AdjustEndpointsFunc: func(ctx context.Context, records []*Record) ([]*Record, error) {
					return nil, fmt.Errorf("service error")
				},
			},
			request: adjustEndpointsRequest{
				Records: []*Record{
					{DNSName: "test.local", RecordType: "A", Targets: []string{"192.168.1.1"}},
				},
			},
			want:    adjustEndpointsResponse{},
			wantErr: true,
			errMsg:  "unable to adjust endpoints",
		},
		{
			name:        "invalid request type",
			mockService: &mockService{},
			request:     "invalid request type",
			want:        adjustEndpointsResponse{},
			wantErr:     true,
			errMsg:      "invalid request type: expected adjustEndpointsRequest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint := makeAdjustEndpointsEndpoint(tt.mockService, logger)
			got, err := endpoint(ctx, tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("makeAdjustEndpointsEndpoint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("makeAdjustEndpointsEndpoint() error = %v, want error containing %v", err, tt.errMsg)
				}
				return
			}
			if !tt.wantErr {
				resp := got.(adjustEndpointsResponse)
				if !reflect.DeepEqual(resp, tt.want) {
					t.Errorf("makeAdjustEndpointsEndpoint() = %v, want %v", resp, tt.want)
				}
			}
		})
	}
}
