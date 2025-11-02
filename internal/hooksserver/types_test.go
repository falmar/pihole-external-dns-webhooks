package hooksserver

import (
	"reflect"
	"strings"
	"testing"

	"github.com/falmar/pihole-external-dns-webhooks/internal/piholeapi"
)

func TestRecord_ToLocalDNSRecord(t *testing.T) {
	tests := []struct {
		name    string
		record  *Record
		want    *piholeapi.LocalDNSRecord
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid A record",
			record: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    []string{"192.168.1.1"},
			},
			want: &piholeapi.LocalDNSRecord{
				Name:  "test.local",
				Type:  piholeapi.LocalDNSTypeA,
				Value: "192.168.1.1",
			},
			wantErr: false,
		},
		{
			name: "A record with multiple targets uses first",
			record: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    []string{"192.168.1.1", "192.168.1.2"},
			},
			want: &piholeapi.LocalDNSRecord{
				Name:  "test.local",
				Type:  piholeapi.LocalDNSTypeA,
				Value: "192.168.1.1",
			},
			wantErr: false,
		},
		{
			name: "unsupported record type CNAME",
			record: &Record{
				DNSName:    "test.local",
				RecordType: "CNAME",
				Targets:    []string{"other.local"},
			},
			want:    nil,
			wantErr: true,
			errMsg:  "unsupported record type: CNAME",
		},
		{
			name: "empty record type",
			record: &Record{
				DNSName:    "test.local",
				RecordType: "",
				Targets:    []string{"192.168.1.1"},
			},
			want:    nil,
			wantErr: true,
			errMsg:  "unsupported record type",
		},
		{
			name: "missing targets empty slice",
			record: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    []string{},
			},
			want:    nil,
			wantErr: true,
			errMsg:  "record test.local has no targets",
		},
		{
			name: "nil targets",
			record: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    nil,
			},
			want:    nil,
			wantErr: true,
			errMsg:  "has no targets",
		},
		{
			name: "empty DNSName still works",
			record: &Record{
				DNSName:    "",
				RecordType: "A",
				Targets:    []string{"192.168.1.1"},
			},
			want: &piholeapi.LocalDNSRecord{
				Name:  "",
				Type:  piholeapi.LocalDNSTypeA,
				Value: "192.168.1.1",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.record.ToLocalDNSRecord()
			if (err != nil) != tt.wantErr {
				t.Errorf("ToLocalDNSRecord() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ToLocalDNSRecord() error = %v, want error containing %v", err, tt.errMsg)
				}
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ToLocalDNSRecord() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFromLocalDNSRecord(t *testing.T) {
	tests := []struct {
		name  string
		input *piholeapi.LocalDNSRecord
		want  *Record
	}{
		{
			name: "valid A record conversion",
			input: &piholeapi.LocalDNSRecord{
				Name:  "test.local",
				Type:  piholeapi.LocalDNSTypeA,
				Value: "192.168.1.1",
			},
			want: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    []string{"192.168.1.1"},
				RecordTTL:  0,
			},
		},
		{
			name: "empty value creates nil targets",
			input: &piholeapi.LocalDNSRecord{
				Name:  "test.local",
				Type:  piholeapi.LocalDNSTypeA,
				Value: "",
			},
			want: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    nil, // When Value is empty, targets is nil
				RecordTTL:  0,
			},
		},
		{
			name: "CNAME record type",
			input: &piholeapi.LocalDNSRecord{
				Name:  "test.local",
				Type:  piholeapi.LocalDNSTypeCNAME,
				Value: "other.local",
			},
			want: &Record{
				DNSName:    "test.local",
				RecordType: "CNAME",
				Targets:    []string{"other.local"},
				RecordTTL:  0,
			},
		},
		{
			name: "empty name",
			input: &piholeapi.LocalDNSRecord{
				Name:  "",
				Type:  piholeapi.LocalDNSTypeA,
				Value: "192.168.1.1",
			},
			want: &Record{
				DNSName:    "",
				RecordType: "A",
				Targets:    []string{"192.168.1.1"},
				RecordTTL:  0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FromLocalDNSRecord(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FromLocalDNSRecord() = %v, want %v", got, tt.want)
			}
			// Verify other fields are empty/zero
			if got.SetIdentifier != "" {
				t.Errorf("FromLocalDNSRecord() SetIdentifier = %v, want empty", got.SetIdentifier)
			}
			if got.Labels != nil {
				t.Errorf("FromLocalDNSRecord() Labels = %v, want nil", got.Labels)
			}
			if got.ProviderSpecific != nil {
				t.Errorf("FromLocalDNSRecord() ProviderSpecific = %v, want nil", got.ProviderSpecific)
			}
		})
	}
}

func TestNormalizeDNSRecord(t *testing.T) {
	tests := []struct {
		name  string
		input *Record
		want  *Record
	}{
		{
			name: "normal record normalization",
			input: &Record{
				DNSName:          "test.local",
				RecordType:       "A",
				Targets:          []string{"192.168.1.1"},
				RecordTTL:        300,
				SetIdentifier:    "id1",
				Labels:           map[string]string{"env": "prod"},
				ProviderSpecific: []any{"extra"},
			},
			want: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    []string{"192.168.1.1"},
				RecordTTL:  0,
			},
		},
		{
			name: "minimal record only required fields",
			input: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    []string{"192.168.1.1"},
			},
			want: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    []string{"192.168.1.1"},
				RecordTTL:  0,
			},
		},
		{
			name: "empty targets",
			input: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    []string{},
			},
			want: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    []string{},
				RecordTTL:  0,
			},
		},
		{
			name: "nil targets",
			input: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    nil,
			},
			want: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    nil,
				RecordTTL:  0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeDNSRecord(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NormalizeDNSRecord() = %v, want %v", got, tt.want)
			}
			// Verify extra fields are not preserved
			if got.SetIdentifier != "" {
				t.Errorf("NormalizeDNSRecord() SetIdentifier = %v, want empty", got.SetIdentifier)
			}
			if got.Labels != nil {
				t.Errorf("NormalizeDNSRecord() Labels = %v, want nil", got.Labels)
			}
			if got.ProviderSpecific != nil {
				t.Errorf("NormalizeDNSRecord() ProviderSpecific = %v, want nil", got.ProviderSpecific)
			}
		})
	}
}

func TestRecord_RecordKey(t *testing.T) {
	tests := []struct {
		name   string
		record *Record
		want   string
	}{
		{
			name: "valid A record",
			record: &Record{
				DNSName:    "test.local",
				RecordType: "A",
			},
			want: "test.local:A",
		},
		{
			name: "different record types with same DNSName",
			record: &Record{
				DNSName:    "test.local",
				RecordType: "CNAME",
			},
			want: "test.local:CNAME",
		},
		{
			name: "empty DNSName",
			record: &Record{
				DNSName:    "",
				RecordType: "A",
			},
			want: ":A",
		},
		{
			name: "empty RecordType",
			record: &Record{
				DNSName:    "test.local",
				RecordType: "",
			},
			want: "test.local:",
		},
		{
			name: "special characters in DNSName",
			record: &Record{
				DNSName:    "test-with-dash.local",
				RecordType: "A",
			},
			want: "test-with-dash.local:A",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.record.RecordKey()
			if got != tt.want {
				t.Errorf("RecordKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRecord_Equals(t *testing.T) {
	tests := []struct {
		name   string
		record *Record
		other  *Record
		want   bool
	}{
		{
			name: "equal records same DNSName type and first target",
			record: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    []string{"192.168.1.1"},
			},
			other: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    []string{"192.168.1.1"},
			},
			want: true,
		},
		{
			name: "different target lengths returns false",
			record: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    []string{"192.168.1.1"},
			},
			other: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    []string{"192.168.1.1", "192.168.1.2"},
			},
			want: false, // Equals checks length first, so different lengths return false
		},
		{
			name: "different DNSName",
			record: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    []string{"192.168.1.1"},
			},
			other: &Record{
				DNSName:    "other.local",
				RecordType: "A",
				Targets:    []string{"192.168.1.1"},
			},
			want: false,
		},
		{
			name: "different RecordType",
			record: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    []string{"192.168.1.1"},
			},
			other: &Record{
				DNSName:    "test.local",
				RecordType: "CNAME",
				Targets:    []string{"192.168.1.1"},
			},
			want: false,
		},
		{
			name: "different first target",
			record: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    []string{"192.168.1.1"},
			},
			other: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    []string{"192.168.1.2"},
			},
			want: false,
		},
		{
			name: "both records have empty targets",
			record: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    []string{},
			},
			other: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    []string{},
			},
			want: true,
		},
		{
			name: "both records have nil targets",
			record: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    nil,
			},
			other: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    nil,
			},
			want: true,
		},
		{
			name: "different target lengths",
			record: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    []string{"192.168.1.1"},
			},
			other: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    []string{},
			},
			want: false,
		},
		{
			name: "one has targets other doesn't",
			record: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    []string{"192.168.1.1"},
			},
			other: &Record{
				DNSName:    "test.local",
				RecordType: "A",
				Targets:    nil,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.record.Equals(tt.other)
			if got != tt.want {
				t.Errorf("Equals() = %v, want %v", got, tt.want)
			}
		})
	}
}
