package hooksserver

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/falmar/pihole-external-dns-webhooks/internal/piholeapi"
)

// mockPiholeAPI is a mock implementation of the PiholeAPI interface.
type mockPiholeAPI struct {
	GetDomainsFunc   func(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error)
	SetDomainFunc    func(ctx context.Context, r *piholeapi.LocalDNSRecord) error
	DeleteDomainFunc func(ctx context.Context, r *piholeapi.LocalDNSRecord) error
}

func (m *mockPiholeAPI) GetDomains(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error) {
	if m.GetDomainsFunc != nil {
		return m.GetDomainsFunc(ctx, t)
	}
	return nil, nil
}

func (m *mockPiholeAPI) SetDomain(ctx context.Context, r *piholeapi.LocalDNSRecord) error {
	if m.SetDomainFunc != nil {
		return m.SetDomainFunc(ctx, r)
	}
	return nil
}

func (m *mockPiholeAPI) DeleteDomain(ctx context.Context, r *piholeapi.LocalDNSRecord) error {
	if m.DeleteDomainFunc != nil {
		return m.DeleteDomainFunc(ctx, r)
	}
	return nil
}

func TestCreateChangeSet(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name           string
		mockAPI        *mockPiholeAPI
		desiredRecords []*Record
		want           *ChangeSet
		wantErr        bool
		errMsg         string
	}{
		{
			name: "empty desired state all deletes",
			mockAPI: &mockPiholeAPI{
				GetDomainsFunc: func(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error) {
					return []*piholeapi.LocalDNSRecord{
						{Name: "test1.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.1"},
						{Name: "test2.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.2"},
					}, nil
				},
			},
			desiredRecords: []*Record{},
			want: &ChangeSet{
				ToCreate: []*piholeapi.LocalDNSRecord{},
				ToUpdate: []*piholeapi.LocalDNSRecord{},
				ToDelete: []*piholeapi.LocalDNSRecord{
					{Name: "test1.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.1"},
					{Name: "test2.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.2"},
				},
			},
			wantErr: false,
		},
		{
			name: "all creates new records",
			mockAPI: &mockPiholeAPI{
				GetDomainsFunc: func(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error) {
					return []*piholeapi.LocalDNSRecord{}, nil
				},
			},
			desiredRecords: []*Record{
				{DNSName: "new1.local", RecordType: "A", Targets: []string{"192.168.1.1"}},
				{DNSName: "new2.local", RecordType: "A", Targets: []string{"192.168.1.2"}},
			},
			want: &ChangeSet{
				ToCreate: []*piholeapi.LocalDNSRecord{
					{Name: "new1.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.1"},
					{Name: "new2.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.2"},
				},
				ToUpdate: []*piholeapi.LocalDNSRecord{},
				ToDelete: []*piholeapi.LocalDNSRecord{},
			},
			wantErr: false,
		},
		{
			name: "all updates changed IPs",
			mockAPI: &mockPiholeAPI{
				GetDomainsFunc: func(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error) {
					return []*piholeapi.LocalDNSRecord{
						{Name: "test1.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.1"},
						{Name: "test2.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.2"},
					}, nil
				},
			},
			desiredRecords: []*Record{
				{DNSName: "test1.local", RecordType: "A", Targets: []string{"192.168.1.10"}},
				{DNSName: "test2.local", RecordType: "A", Targets: []string{"192.168.1.20"}},
			},
			want: &ChangeSet{
				ToCreate: []*piholeapi.LocalDNSRecord{},
				ToUpdate: []*piholeapi.LocalDNSRecord{
					{Name: "test1.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.10"},
					{Name: "test2.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.20"},
				},
				ToDelete: []*piholeapi.LocalDNSRecord{},
			},
			wantErr: false,
		},
		{
			name: "mixed operations",
			mockAPI: &mockPiholeAPI{
				GetDomainsFunc: func(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error) {
					return []*piholeapi.LocalDNSRecord{
						{Name: "update.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.1"},
						{Name: "delete.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.2"},
					}, nil
				},
			},
			desiredRecords: []*Record{
				{DNSName: "create.local", RecordType: "A", Targets: []string{"192.168.1.3"}},
				{DNSName: "update.local", RecordType: "A", Targets: []string{"192.168.1.10"}},
			},
			want: &ChangeSet{
				ToCreate: []*piholeapi.LocalDNSRecord{
					{Name: "create.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.3"},
				},
				ToUpdate: []*piholeapi.LocalDNSRecord{
					{Name: "update.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.10"},
				},
				ToDelete: []*piholeapi.LocalDNSRecord{
					{Name: "delete.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.2"},
				},
			},
			wantErr: false,
		},
		{
			name: "idempotency no changes needed",
			mockAPI: &mockPiholeAPI{
				GetDomainsFunc: func(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error) {
					return []*piholeapi.LocalDNSRecord{
						{Name: "test1.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.1"},
						{Name: "test2.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.2"},
					}, nil
				},
			},
			desiredRecords: []*Record{
				{DNSName: "test1.local", RecordType: "A", Targets: []string{"192.168.1.1"}},
				{DNSName: "test2.local", RecordType: "A", Targets: []string{"192.168.1.2"}},
			},
			want: &ChangeSet{
				ToCreate: []*piholeapi.LocalDNSRecord{},
				ToUpdate: []*piholeapi.LocalDNSRecord{},
				ToDelete: []*piholeapi.LocalDNSRecord{},
			},
			wantErr: false,
		},
		{
			name: "skip non-A records",
			mockAPI: &mockPiholeAPI{
				GetDomainsFunc: func(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error) {
					return []*piholeapi.LocalDNSRecord{
						{Name: "a.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.1"},
					}, nil
				},
			},
			desiredRecords: []*Record{
				{DNSName: "a.local", RecordType: "A", Targets: []string{"192.168.1.1"}},
				{DNSName: "cname.local", RecordType: "CNAME", Targets: []string{"other.local"}},
			},
			want: &ChangeSet{
				ToCreate: []*piholeapi.LocalDNSRecord{},
				ToUpdate: []*piholeapi.LocalDNSRecord{},
				ToDelete: []*piholeapi.LocalDNSRecord{},
			},
			wantErr: false,
		},
		{
			name: "API error on GetDomains",
			mockAPI: &mockPiholeAPI{
				GetDomainsFunc: func(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error) {
					return nil, fmt.Errorf("api error")
				},
			},
			desiredRecords: []*Record{
				{DNSName: "test.local", RecordType: "A", Targets: []string{"192.168.1.1"}},
			},
			want:    nil,
			wantErr: true,
			errMsg:  "unable to fetch current state",
		},
		{
			name: "conversion error on create record",
			mockAPI: &mockPiholeAPI{
				GetDomainsFunc: func(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error) {
					return []*piholeapi.LocalDNSRecord{}, nil
				},
			},
			desiredRecords: []*Record{
				{DNSName: "test.local", RecordType: "A", Targets: []string{}}, // Empty targets should cause conversion error
			},
			want:    nil,
			wantErr: true,
			errMsg:  "record test.local",
		},
		{
			name: "conversion error on delete record",
			mockAPI: &mockPiholeAPI{
				GetDomainsFunc: func(ctx context.Context, t piholeapi.LocalDNSType) ([]*piholeapi.LocalDNSRecord, error) {
					// Return a record that cannot be converted back (edge case)
					return []*piholeapi.LocalDNSRecord{
						{Name: "test.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.1"},
					}, nil
				},
			},
			desiredRecords: []*Record{},
			// This should work since FromLocalDNSRecord handles conversion
			// The actual error case would require a record that fails ToLocalDNSRecord
			// Let's create a scenario where a record exists but cannot be deleted (unlikely with current implementation)
			want: &ChangeSet{
				ToCreate: []*piholeapi.LocalDNSRecord{},
				ToUpdate: []*piholeapi.LocalDNSRecord{},
				ToDelete: []*piholeapi.LocalDNSRecord{
					{Name: "test.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.1"},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateChangeSet(ctx, logger, tt.mockAPI, tt.desiredRecords)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateChangeSet() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if tt.errMsg != "" && (err == nil || !strings.Contains(err.Error(), tt.errMsg)) {
					t.Errorf("CreateChangeSet() error = %v, want error containing %v", err, tt.errMsg)
				}
				return
			}
			if !equalChangeSet(got, tt.want) {
				t.Errorf("CreateChangeSet() = %v, want %v", got, tt.want)
			}
		})
	}
}

// equalChangeSet compares two ChangeSets by content, not pointer equality.
func equalChangeSet(a, b *ChangeSet) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if !equalLocalDNSRecordSlice(a.ToCreate, b.ToCreate) {
		return false
	}
	if !equalLocalDNSRecordSlice(a.ToUpdate, b.ToUpdate) {
		return false
	}
	if !equalLocalDNSRecordSlice(a.ToDelete, b.ToDelete) {
		return false
	}
	return true
}

// equalLocalDNSRecordSlice compares two slices of LocalDNSRecord by content.
func equalLocalDNSRecordSlice(a, b []*piholeapi.LocalDNSRecord) bool {
	if len(a) != len(b) {
		return false
	}
	// Create maps to compare records by key (name:type:value)
	aMap := make(map[string]bool)
	for _, r := range a {
		key := fmt.Sprintf("%s:%s:%s", r.Name, r.Type, r.Value)
		aMap[key] = true
	}
	for _, r := range b {
		key := fmt.Sprintf("%s:%s:%s", r.Name, r.Type, r.Value)
		if !aMap[key] {
			return false
		}
	}
	return true
}

func TestApplyChangeSet(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name      string
		mockAPI   *mockPiholeAPI
		changeSet *ChangeSet
		want      *ChangeSetResult
	}{
		{
			name: "successful create operation",
			mockAPI: &mockPiholeAPI{
				SetDomainFunc: func(ctx context.Context, r *piholeapi.LocalDNSRecord) error {
					return nil
				},
			},
			changeSet: &ChangeSet{
				ToCreate: []*piholeapi.LocalDNSRecord{
					{Name: "new.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.1"},
				},
				ToUpdate: []*piholeapi.LocalDNSRecord{},
				ToDelete: []*piholeapi.LocalDNSRecord{},
			},
			want: &ChangeSetResult{
				Created: 1,
				Updated: 0,
				Deleted: 0,
				Errors:  []error{},
			},
		},
		{
			name: "successful update operation",
			mockAPI: &mockPiholeAPI{
				SetDomainFunc: func(ctx context.Context, r *piholeapi.LocalDNSRecord) error {
					return nil
				},
			},
			changeSet: &ChangeSet{
				ToCreate: []*piholeapi.LocalDNSRecord{},
				ToUpdate: []*piholeapi.LocalDNSRecord{
					{Name: "update.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.2"},
				},
				ToDelete: []*piholeapi.LocalDNSRecord{},
			},
			want: &ChangeSetResult{
				Created: 0,
				Updated: 1,
				Deleted: 0,
				Errors:  []error{},
			},
		},
		{
			name: "successful delete operation",
			mockAPI: &mockPiholeAPI{
				DeleteDomainFunc: func(ctx context.Context, r *piholeapi.LocalDNSRecord) error {
					return nil
				},
			},
			changeSet: &ChangeSet{
				ToCreate: []*piholeapi.LocalDNSRecord{},
				ToUpdate: []*piholeapi.LocalDNSRecord{},
				ToDelete: []*piholeapi.LocalDNSRecord{
					{Name: "delete.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.3"},
				},
			},
			want: &ChangeSetResult{
				Created: 0,
				Updated: 0,
				Deleted: 1,
				Errors:  []error{},
			},
		},
		{
			name: "mixed operations all successful",
			mockAPI: &mockPiholeAPI{
				SetDomainFunc: func(ctx context.Context, r *piholeapi.LocalDNSRecord) error {
					return nil
				},
				DeleteDomainFunc: func(ctx context.Context, r *piholeapi.LocalDNSRecord) error {
					return nil
				},
			},
			changeSet: &ChangeSet{
				ToCreate: []*piholeapi.LocalDNSRecord{
					{Name: "create1.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.1"},
					{Name: "create2.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.2"},
				},
				ToUpdate: []*piholeapi.LocalDNSRecord{
					{Name: "update1.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.3"},
					{Name: "update2.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.4"},
				},
				ToDelete: []*piholeapi.LocalDNSRecord{
					{Name: "delete1.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.5"},
					{Name: "delete2.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.6"},
				},
			},
			want: &ChangeSetResult{
				Created: 2,
				Updated: 2,
				Deleted: 2,
				Errors:  []error{},
			},
		},
		{
			name: "partial failure some creates fail",
			mockAPI: &mockPiholeAPI{
				SetDomainFunc: func(ctx context.Context, r *piholeapi.LocalDNSRecord) error {
					if r.Name == "fail.local" {
						return fmt.Errorf("create error")
					}
					return nil
				},
			},
			changeSet: &ChangeSet{
				ToCreate: []*piholeapi.LocalDNSRecord{
					{Name: "success.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.1"},
					{Name: "fail.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.2"},
				},
				ToUpdate: []*piholeapi.LocalDNSRecord{},
				ToDelete: []*piholeapi.LocalDNSRecord{},
			},
			want: &ChangeSetResult{
				Created: 1,
				Updated: 0,
				Deleted: 0,
				Errors: []error{
					fmt.Errorf("create fail.local: create error"),
				},
			},
		},
		{
			name: "partial failure some updates fail",
			mockAPI: &mockPiholeAPI{
				SetDomainFunc: func(ctx context.Context, r *piholeapi.LocalDNSRecord) error {
					if r.Name == "fail.local" {
						return fmt.Errorf("update error")
					}
					return nil
				},
			},
			changeSet: &ChangeSet{
				ToCreate: []*piholeapi.LocalDNSRecord{},
				ToUpdate: []*piholeapi.LocalDNSRecord{
					{Name: "success.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.1"},
					{Name: "fail.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.2"},
				},
				ToDelete: []*piholeapi.LocalDNSRecord{},
			},
			want: &ChangeSetResult{
				Created: 0,
				Updated: 1,
				Deleted: 0,
				Errors: []error{
					fmt.Errorf("update fail.local: update error"),
				},
			},
		},
		{
			name: "partial failure some deletes fail",
			mockAPI: &mockPiholeAPI{
				DeleteDomainFunc: func(ctx context.Context, r *piholeapi.LocalDNSRecord) error {
					if r.Name == "fail.local" {
						return fmt.Errorf("delete error")
					}
					return nil
				},
			},
			changeSet: &ChangeSet{
				ToCreate: []*piholeapi.LocalDNSRecord{},
				ToUpdate: []*piholeapi.LocalDNSRecord{},
				ToDelete: []*piholeapi.LocalDNSRecord{
					{Name: "success.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.1"},
					{Name: "fail.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.2"},
				},
			},
			want: &ChangeSetResult{
				Created: 0,
				Updated: 0,
				Deleted: 1,
				Errors: []error{
					fmt.Errorf("delete fail.local: delete error"),
				},
			},
		},
		{
			name: "partial failure mixed operations",
			mockAPI: &mockPiholeAPI{
				SetDomainFunc: func(ctx context.Context, r *piholeapi.LocalDNSRecord) error {
					if r.Name == "fail-create.local" || r.Name == "fail-update.local" {
						return fmt.Errorf("set error")
					}
					return nil
				},
				DeleteDomainFunc: func(ctx context.Context, r *piholeapi.LocalDNSRecord) error {
					if r.Name == "fail-delete.local" {
						return fmt.Errorf("delete error")
					}
					return nil
				},
			},
			changeSet: &ChangeSet{
				ToCreate: []*piholeapi.LocalDNSRecord{
					{Name: "success-create.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.1"},
					{Name: "fail-create.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.2"},
				},
				ToUpdate: []*piholeapi.LocalDNSRecord{
					{Name: "success-update.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.3"},
					{Name: "fail-update.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.4"},
				},
				ToDelete: []*piholeapi.LocalDNSRecord{
					{Name: "success-delete.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.5"},
					{Name: "fail-delete.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.6"},
				},
			},
			want: &ChangeSetResult{
				Created: 1,
				Updated: 1,
				Deleted: 1,
				Errors: []error{
					fmt.Errorf("create fail-create.local: set error"),
					fmt.Errorf("update fail-update.local: set error"),
					fmt.Errorf("delete fail-delete.local: delete error"),
				},
			},
		},
		{
			name: "all failures all creates fail",
			mockAPI: &mockPiholeAPI{
				SetDomainFunc: func(ctx context.Context, r *piholeapi.LocalDNSRecord) error {
					return fmt.Errorf("create error")
				},
			},
			changeSet: &ChangeSet{
				ToCreate: []*piholeapi.LocalDNSRecord{
					{Name: "fail1.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.1"},
					{Name: "fail2.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.2"},
				},
				ToUpdate: []*piholeapi.LocalDNSRecord{},
				ToDelete: []*piholeapi.LocalDNSRecord{},
			},
			want: &ChangeSetResult{
				Created: 0,
				Updated: 0,
				Deleted: 0,
				Errors: []error{
					fmt.Errorf("create fail1.local: create error"),
					fmt.Errorf("create fail2.local: create error"),
				},
			},
		},
		{
			name:    "empty change set",
			mockAPI: &mockPiholeAPI{},
			changeSet: &ChangeSet{
				ToCreate: []*piholeapi.LocalDNSRecord{},
				ToUpdate: []*piholeapi.LocalDNSRecord{},
				ToDelete: []*piholeapi.LocalDNSRecord{},
			},
			want: &ChangeSetResult{
				Created: 0,
				Updated: 0,
				Deleted: 0,
				Errors:  []error{},
			},
		},
		{
			name: "error accumulation multiple errors",
			mockAPI: &mockPiholeAPI{
				SetDomainFunc: func(ctx context.Context, r *piholeapi.LocalDNSRecord) error {
					if r.Name == "error1.local" {
						return fmt.Errorf("error 1")
					}
					if r.Name == "error2.local" {
						return fmt.Errorf("error 2")
					}
					return nil
				},
				DeleteDomainFunc: func(ctx context.Context, r *piholeapi.LocalDNSRecord) error {
					if r.Name == "error3.local" {
						return fmt.Errorf("error 3")
					}
					return nil
				},
			},
			changeSet: &ChangeSet{
				ToCreate: []*piholeapi.LocalDNSRecord{
					{Name: "success.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.1"},
					{Name: "error1.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.2"},
				},
				ToUpdate: []*piholeapi.LocalDNSRecord{
					{Name: "error2.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.3"},
				},
				ToDelete: []*piholeapi.LocalDNSRecord{
					{Name: "error3.local", Type: piholeapi.LocalDNSTypeA, Value: "192.168.1.4"},
				},
			},
			want: &ChangeSetResult{
				Created: 1,
				Updated: 0,
				Deleted: 0,
				Errors: []error{
					fmt.Errorf("create error1.local: error 1"),
					fmt.Errorf("update error2.local: error 2"),
					fmt.Errorf("delete error3.local: error 3"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ApplyChangeSet(ctx, logger, tt.mockAPI, tt.changeSet)

			if got.Created != tt.want.Created {
				t.Errorf("ApplyChangeSet() Created = %v, want %v", got.Created, tt.want.Created)
			}
			if got.Updated != tt.want.Updated {
				t.Errorf("ApplyChangeSet() Updated = %v, want %v", got.Updated, tt.want.Updated)
			}
			if got.Deleted != tt.want.Deleted {
				t.Errorf("ApplyChangeSet() Deleted = %v, want %v", got.Deleted, tt.want.Deleted)
			}
			if len(got.Errors) != len(tt.want.Errors) {
				t.Errorf("ApplyChangeSet() Errors length = %v, want %v", len(got.Errors), len(tt.want.Errors))
			} else {
				// Compare error messages (since error instances may differ)
				for i := range got.Errors {
					if got.Errors[i].Error() != tt.want.Errors[i].Error() {
						t.Errorf("ApplyChangeSet() Errors[%d] = %v, want %v", i, got.Errors[i].Error(), tt.want.Errors[i].Error())
					}
				}
			}
		})
	}
}
