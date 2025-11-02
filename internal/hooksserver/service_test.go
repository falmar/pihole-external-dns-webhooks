package hooksserver

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/falmar/pihole-external-dns-webhooks/internal/piholeapi"
)

// mockDNSSyncer is a mock implementation of the DNSSyncer interface
type mockDNSSyncer struct{}

// setupService creates a service instance with the given mocks and filters
func setupService(t *testing.T, mockAPI *mockPiholeAPI, filters []string) Service {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	syncer := &mockDNSSyncer{}
	return NewService(logger, mockAPI, syncer, filters)
}

func TestNewService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockAPI := &mockPiholeAPI{}
	syncer := &mockDNSSyncer{}

	tests := []struct {
		name    string
		filters []string
		want    []string
	}{
		{
			name:    "nil filters normalization",
			filters: nil,
			want:    []string{},
		},
		{
			name:    "empty filters",
			filters: []string{},
			want:    []string{},
		},
		{
			name:    "non-empty filters",
			filters: []string{"kind.local", "cluster.local"},
			want:    []string{"kind.local", "cluster.local"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewService(logger, mockAPI, syncer, tt.filters)
			if svc == nil {
				t.Fatal("NewService() returned nil")
			}

			// Verify filters are normalized correctly
			got := svc.GetFilters()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetFilters() = %v, want %v", got, tt.want)
			}

			// Verify filters are not nil (even when input was nil)
			if tt.filters == nil && got == nil {
				t.Error("GetFilters() returned nil, expected empty slice")
			}
		})
	}
}

func TestService_GetRecords(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		mockGetDomains func(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error)
		want           []*Record
		wantErr        bool
		errMsg         string
	}{
		{
			name: "successfully fetch and convert records",
			mockGetDomains: func(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error) {
				return []*piholeapi.LocalDNSRecord{
					{Name: "test.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.1"},
				}, nil
			},
			want: []*Record{
				{DNSName: "test.local", RecordType: "A", Targets: []string{"192.168.1.1"}, RecordTTL: 0},
			},
			wantErr: false,
		},
		{
			name: "empty result when no records exist",
			mockGetDomains: func(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error) {
				return []*piholeapi.LocalDNSRecord{}, nil
			},
			want:    []*Record{},
			wantErr: false,
		},
		{
			name: "multiple records",
			mockGetDomains: func(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error) {
				return []*piholeapi.LocalDNSRecord{
					{Name: "test1.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.1"},
					{Name: "test2.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.2"},
					{Name: "test3.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.3"},
				}, nil
			},
			want: []*Record{
				{DNSName: "test1.local", RecordType: "A", Targets: []string{"192.168.1.1"}, RecordTTL: 0},
				{DNSName: "test2.local", RecordType: "A", Targets: []string{"192.168.1.2"}, RecordTTL: 0},
				{DNSName: "test3.local", RecordType: "A", Targets: []string{"192.168.1.3"}, RecordTTL: 0},
			},
			wantErr: false,
		},
		{
			name: "API error propagation",
			mockGetDomains: func(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error) {
				return nil, fmt.Errorf("api error")
			},
			want:    nil,
			wantErr: true,
			errMsg:  "unable to get domains",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAPI := &mockPiholeAPI{
				GetDomainsFunc: tt.mockGetDomains,
			}
			svc := setupService(t, mockAPI, nil)

			got, err := svc.GetRecords(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetRecords() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("GetRecords() error = %v, want error containing %v", err, tt.errMsg)
				}
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetRecords() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestService_ApplyChanges(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name             string
		req              *ChangeSetRequest
		mockGetDomains   func(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error)
		mockSetDomain    func(ctx context.Context, r *piholeapi.LocalDNSRecord) error
		mockDeleteDomain func(ctx context.Context, r *piholeapi.LocalDNSRecord) error
		want             *ChangeSetResult
		wantErr          bool
		errMsg           string
	}{
		{
			name: "valid change set with creates only",
			req: &ChangeSetRequest{
				Create: []*Record{
					{DNSName: "new.local", RecordType: "A", Targets: []string{"192.168.1.1"}},
				},
			},
			mockGetDomains: func(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error) {
				return []*piholeapi.LocalDNSRecord{}, nil
			},
			mockSetDomain: func(ctx context.Context, r *piholeapi.LocalDNSRecord) error {
				return nil
			},
			want: &ChangeSetResult{
				Created: 1,
				Updated: 0,
				Deleted: 0,
				Errors:  []error{},
			},
			wantErr: false,
		},
		{
			name: "valid change set with updates only",
			req: &ChangeSetRequest{
				Update: []*Record{
					{DNSName: "existing.local", RecordType: "A", Targets: []string{"192.168.1.2"}},
				},
			},
			mockGetDomains: func(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error) {
				return []*piholeapi.LocalDNSRecord{
					{Name: "existing.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.1"},
				}, nil
			},
			mockSetDomain: func(ctx context.Context, r *piholeapi.LocalDNSRecord) error {
				return nil
			},
			want: &ChangeSetResult{
				Created: 0,
				Updated: 1,
				Deleted: 0,
				Errors:  []error{},
			},
			wantErr: false,
		},
		{
			name: "valid change set with deletes only",
			req: &ChangeSetRequest{
				Delete: []*Record{
					{DNSName: "to-delete.local", RecordType: "A", Targets: []string{"192.168.1.1"}},
				},
			},
			mockGetDomains: func(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error) {
				return []*piholeapi.LocalDNSRecord{
					{Name: "to-delete.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.1"},
				}, nil
			},
			mockDeleteDomain: func(ctx context.Context, r *piholeapi.LocalDNSRecord) error {
				return nil
			},
			want: &ChangeSetResult{
				Created: 0,
				Updated: 0,
				Deleted: 1,
				Errors:  []error{},
			},
			wantErr: false,
		},
		{
			name: "mixed operations",
			req: &ChangeSetRequest{
				Create: []*Record{
					{DNSName: "new1.local", RecordType: "A", Targets: []string{"192.168.1.1"}},
				},
				Update: []*Record{
					{DNSName: "existing.local", RecordType: "A", Targets: []string{"192.168.1.3"}},
				},
				Delete: []*Record{
					{DNSName: "old.local", RecordType: "A", Targets: []string{"192.168.1.2"}},
				},
			},
			mockGetDomains: func(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error) {
				return []*piholeapi.LocalDNSRecord{
					{Name: "existing.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.2"},
					{Name: "old.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.2"},
				}, nil
			},
			mockSetDomain: func(ctx context.Context, r *piholeapi.LocalDNSRecord) error {
				return nil
			},
			mockDeleteDomain: func(ctx context.Context, r *piholeapi.LocalDNSRecord) error {
				return nil
			},
			want: &ChangeSetResult{
				Created: 1,
				Updated: 1,
				Deleted: 1,
				Errors:  []error{},
			},
			wantErr: false,
		},
		{
			name: "empty change set",
			req: &ChangeSetRequest{
				Create: []*Record{},
				Update: []*Record{},
				Delete: []*Record{},
			},
			mockGetDomains: func(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error) {
				return []*piholeapi.LocalDNSRecord{}, nil
			},
			want: &ChangeSetResult{
				Created: 0,
				Updated: 0,
				Deleted: 0,
				Errors:  []error{},
			},
			wantErr: false,
		},
		{
			name: "delete record conversion error (logged, not fatal)",
			req: &ChangeSetRequest{
				Delete: []*Record{
					{DNSName: "invalid.local", RecordType: "CNAME", Targets: []string{}},
				},
			},
			mockGetDomains: func(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error) {
				return []*piholeapi.LocalDNSRecord{}, nil
			},
			want: &ChangeSetResult{
				Created: 0,
				Updated: 0,
				Deleted: 0, // CNAME delete record skipped due to conversion error
				Errors:  []error{},
			},
			wantErr: false,
		},
		{
			name: "duplicate deletes (explicit + computed)",
			req: &ChangeSetRequest{
				Delete: []*Record{
					{DNSName: "test.local", RecordType: "A", Targets: []string{"192.168.1.1"}},
				},
			},
			mockGetDomains: func(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error) {
				return []*piholeapi.LocalDNSRecord{
					{Name: "test.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.1"},
				}, nil
			},
			mockDeleteDomain: func(ctx context.Context, r *piholeapi.LocalDNSRecord) error {
				return nil
			},
			want: &ChangeSetResult{
				Created: 0,
				Updated: 0,
				Deleted: 1, // Should only be deleted once
				Errors:  []error{},
			},
			wantErr: false,
		},
		{
			name: "delete + create same record (cancel out)",
			req: &ChangeSetRequest{
				Create: []*Record{
					{DNSName: "test.local", RecordType: "A", Targets: []string{"192.168.1.1"}},
				},
				Delete: []*Record{
					{DNSName: "test.local", RecordType: "A", Targets: []string{"192.168.1.1"}},
				},
			},
			mockGetDomains: func(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error) {
				return []*piholeapi.LocalDNSRecord{}, nil
			},
			mockDeleteDomain: func(ctx context.Context, r *piholeapi.LocalDNSRecord) error {
				return nil
			},
			want: &ChangeSetResult{
				Created: 0, // Create should be removed
				Updated: 0,
				Deleted: 1, // Delete should still happen
				Errors:  []error{},
			},
			wantErr: false,
		},
		{
			name: "delete + update same record",
			req: &ChangeSetRequest{
				Update: []*Record{
					{DNSName: "test.local", RecordType: "A", Targets: []string{"192.168.1.2"}},
				},
				Delete: []*Record{
					{DNSName: "test.local", RecordType: "A", Targets: []string{"192.168.1.1"}},
				},
			},
			mockGetDomains: func(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error) {
				return []*piholeapi.LocalDNSRecord{
					{Name: "test.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.1"},
				}, nil
			},
			mockDeleteDomain: func(ctx context.Context, r *piholeapi.LocalDNSRecord) error {
				return nil
			},
			want: &ChangeSetResult{
				Created: 0,
				Updated: 0, // Update should be removed
				Deleted: 1, // Delete should still happen
				Errors:  []error{},
			},
			wantErr: false,
		},
		{
			name: "multiple records in each operation",
			req: &ChangeSetRequest{
				Create: []*Record{
					{DNSName: "new1.local", RecordType: "A", Targets: []string{"192.168.1.1"}},
					{DNSName: "new2.local", RecordType: "A", Targets: []string{"192.168.1.2"}},
				},
				Update: []*Record{
					{DNSName: "existing1.local", RecordType: "A", Targets: []string{"192.168.1.3"}},
					{DNSName: "existing2.local", RecordType: "A", Targets: []string{"192.168.1.4"}},
				},
				Delete: []*Record{
					{DNSName: "old1.local", RecordType: "A", Targets: []string{"192.168.1.5"}},
					{DNSName: "old2.local", RecordType: "A", Targets: []string{"192.168.1.6"}},
				},
			},
			mockGetDomains: func(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error) {
				return []*piholeapi.LocalDNSRecord{
					{Name: "existing1.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.1"},
					{Name: "existing2.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.2"},
					{Name: "old1.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.5"},
					{Name: "old2.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.6"},
				}, nil
			},
			mockSetDomain: func(ctx context.Context, r *piholeapi.LocalDNSRecord) error {
				return nil
			},
			mockDeleteDomain: func(ctx context.Context, r *piholeapi.LocalDNSRecord) error {
				return nil
			},
			want: &ChangeSetResult{
				Created: 2,
				Updated: 2,
				Deleted: 2,
				Errors:  []error{},
			},
			wantErr: false,
		},
		{
			name: "CreateChangeSet error (API failure)",
			req: &ChangeSetRequest{
				Create: []*Record{
					{DNSName: "new.local", RecordType: "A", Targets: []string{"192.168.1.1"}},
				},
			},
			mockGetDomains: func(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error) {
				return nil, fmt.Errorf("api error")
			},
			want:    nil,
			wantErr: true,
			errMsg:  "unable to create change set",
		},
		{
			name: "ApplyChangeSet partial failures",
			req: &ChangeSetRequest{
				Create: []*Record{
					{DNSName: "new1.local", RecordType: "A", Targets: []string{"192.168.1.1"}},
					{DNSName: "new2.local", RecordType: "A", Targets: []string{"192.168.1.2"}},
				},
			},
			mockGetDomains: func(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error) {
				return []*piholeapi.LocalDNSRecord{}, nil
			},
			mockSetDomain: func(ctx context.Context, r *piholeapi.LocalDNSRecord) error {
				if r.Name == "new1.local" {
					return fmt.Errorf("create error")
				}
				return nil
			},
			want: &ChangeSetResult{
				Created: 1, // One succeeded
				Updated: 0,
				Deleted: 0,
				Errors:  []error{fmt.Errorf("create new1.local: create error")},
			},
			wantErr: false, // ApplyChanges doesn't return error, result contains errors
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAPI := &mockPiholeAPI{
				GetDomainsFunc:   tt.mockGetDomains,
				SetDomainFunc:    tt.mockSetDomain,
				DeleteDomainFunc: tt.mockDeleteDomain,
			}
			svc := setupService(t, mockAPI, nil)

			got, err := svc.ApplyChanges(ctx, tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ApplyChanges() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ApplyChanges() error = %v, want error containing %v", err, tt.errMsg)
				}
				return
			}
			if !tt.wantErr {
				if got == nil {
					t.Fatal("ApplyChanges() returned nil result")
				}
				if got.Created != tt.want.Created {
					t.Errorf("ApplyChanges() Created = %d, want %d", got.Created, tt.want.Created)
				}
				if got.Updated != tt.want.Updated {
					t.Errorf("ApplyChanges() Updated = %d, want %d", got.Updated, tt.want.Updated)
				}
				if got.Deleted != tt.want.Deleted {
					t.Errorf("ApplyChanges() Deleted = %d, want %d", got.Deleted, tt.want.Deleted)
				}
				if len(got.Errors) != len(tt.want.Errors) {
					t.Errorf("ApplyChanges() Errors length = %d, want %d", len(got.Errors), len(tt.want.Errors))
				} else {
					// Compare error messages
					for i, gotErr := range got.Errors {
						if i < len(tt.want.Errors) {
							gotErrMsg := gotErr.Error()
							wantErrMsg := tt.want.Errors[i].Error()
							if !strings.Contains(gotErrMsg, strings.TrimPrefix(wantErrMsg, "create ")) {
								t.Errorf("ApplyChanges() Errors[%d] = %v, want %v", i, gotErr, tt.want.Errors[i])
							}
						}
					}
				}
			}
		})
	}
}

func TestService_AdjustEndpoints(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name    string
		records []*Record
		want    []*Record
		wantErr bool
	}{
		{
			name: "single record normalization",
			records: []*Record{
				{DNSName: "test.local", RecordType: "A", Targets: []string{"192.168.1.1"}, RecordTTL: 300},
			},
			want: []*Record{
				{DNSName: "test.local", RecordType: "A", Targets: []string{"192.168.1.1"}, RecordTTL: 0},
			},
			wantErr: false,
		},
		{
			name: "multiple records normalization",
			records: []*Record{
				{DNSName: "test1.local", RecordType: "A", Targets: []string{"192.168.1.1"}, RecordTTL: 300},
				{DNSName: "test2.local", RecordType: "A", Targets: []string{"192.168.1.2"}, RecordTTL: 600},
				{DNSName: "test3.local", RecordType: "A", Targets: []string{"192.168.1.3"}, RecordTTL: 900},
			},
			want: []*Record{
				{DNSName: "test1.local", RecordType: "A", Targets: []string{"192.168.1.1"}, RecordTTL: 0},
				{DNSName: "test2.local", RecordType: "A", Targets: []string{"192.168.1.2"}, RecordTTL: 0},
				{DNSName: "test3.local", RecordType: "A", Targets: []string{"192.168.1.3"}, RecordTTL: 0},
			},
			wantErr: false,
		},
		{
			name:    "empty records slice",
			records: []*Record{},
			want:    []*Record{},
			wantErr: false,
		},
		{
			name:    "nil records slice",
			records: nil,
			want:    []*Record{},
			wantErr: false,
		},
		{
			name: "records with extra fields",
			records: []*Record{
				{
					DNSName:          "test.local",
					RecordType:       "A",
					Targets:          []string{"192.168.1.1"},
					RecordTTL:        300,
					SetIdentifier:    "set1",
					Labels:           map[string]string{"key": "value"},
					ProviderSpecific: []any{"extra"},
				},
			},
			want: []*Record{
				{
					DNSName:          "test.local",
					RecordType:       "A",
					Targets:          []string{"192.168.1.1"},
					RecordTTL:        0,  // TTL reset to 0
					SetIdentifier:    "", // Extra fields cleared by NormalizeDNSRecord
					Labels:           nil,
					ProviderSpecific: nil,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAPI := &mockPiholeAPI{}
			svc := setupService(t, mockAPI, nil)

			got, err := svc.AdjustEndpoints(ctx, tt.records)
			if (err != nil) != tt.wantErr {
				t.Errorf("AdjustEndpoints() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AdjustEndpoints() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestService_GetFilters(t *testing.T) {
	tests := []struct {
		name    string
		filters []string
		want    []string
	}{
		{
			name:    "returns configured filters",
			filters: []string{"kind.local", "cluster.local"},
			want:    []string{"kind.local", "cluster.local"},
		},
		{
			name:    "returns empty slice when no filters",
			filters: []string{},
			want:    []string{},
		},
		{
			name:    "returns empty slice when filters were nil (normalized)",
			filters: nil,
			want:    []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAPI := &mockPiholeAPI{}
			svc := setupService(t, mockAPI, tt.filters)

			got := svc.GetFilters()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetFilters() = %v, want %v", got, tt.want)
			}
		})
	}
}
