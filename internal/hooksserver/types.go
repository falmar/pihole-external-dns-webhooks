package hooksserver

import (
	"fmt"

	"github.com/falmar/pihole-external-dns-webhooks/internal/piholeapi"
)

// Record represents an ExternalDNS webhook record format.
type Record struct {
	DNSName string `json:"DNSName,omitempty"`

	Targets []string `json:"targets,omitempty"`

	RecordType string `json:"recordType,omitempty"`

	SetIdentifier    string            `json:"setIdentifier,omitempty"`
	RecordTTL        int64             `json:"recordTTL,omitempty"`
	Labels           map[string]string `json:"labels,omitempty"`
	ProviderSpecific []any             `json:"providerSpecific,omitempty"`
}

// ChangeSetRequest represents the ExternalDNS POST /records request format.
// which includes create, update, and delete operations.
type ChangeSetRequest struct {
	Create []*Record `json:"create,omitempty"`
	Update []*Record `json:"update,omitempty"`
	Delete []*Record `json:"delete,omitempty"`
}

// ToLocalDNSRecord converts an ExternalDNS Record to a Pi-hole LocalDNSRecord.
// Only supports A records for now (CNAME is on roadmap).
func (r *Record) ToLocalDNSRecord() (*piholeapi.LocalDNSRecord, error) {
	if r.RecordType != string(piholeapi.LocalDNSTypeA) {
		return nil, fmt.Errorf("unsupported record type: %s (only A records are supported)", r.RecordType)
	}

	if len(r.Targets) == 0 {
		return nil, fmt.Errorf("record %s has no targets", r.DNSName)
	}

	// For A records, use the first target as the IP address
	// ExternalDNS may send multiple targets, but Pi-hole local DNS only supports one IP per domain
	return &piholeapi.LocalDNSRecord{
		Name:  r.DNSName,
		Type:  piholeapi.LocalDNSTypeA,
		Value: r.Targets[0],
	}, nil
}

// FromLocalDNSRecord converts a Pi-hole LocalDNSRecord to an ExternalDNS Record.
func FromLocalDNSRecord(lr *piholeapi.LocalDNSRecord) *Record {
	var targets []string
	if lr.Value != "" {
		targets = []string{lr.Value}
	}

	return &Record{
		DNSName:    lr.Name,
		RecordType: string(lr.Type),
		Targets:    targets,
		RecordTTL:  0, // Pi-hole local DNS doesn't use TTL
	}
}

func NormalizeDNSRecord(r *Record) *Record {
	return &Record{
		DNSName:    r.DNSName,
		RecordType: r.RecordType,
		Targets:    r.Targets,
		RecordTTL:  0, // Pi-hole local DNS doesn't use TTL
	}
}

// RecordKey creates a unique key for a record (dnsName + recordType).
// This is used for comparing records in change set processing.
func (r *Record) RecordKey() string {
	return fmt.Sprintf("%s:%s", r.DNSName, r.RecordType)
}

// Equals checks if two records are equal (same dnsName, recordType, and targets).
func (r *Record) Equals(other *Record) bool {
	if r.DNSName != other.DNSName {
		return false
	}
	if r.RecordType != other.RecordType {
		return false
	}

	// Compare targets (order-insensitive comparison)
	if len(r.Targets) != len(other.Targets) {
		return false
	}

	// For A records, we compare the first target (Pi-hole only supports one IP per domain)
	if len(r.Targets) > 0 && len(other.Targets) > 0 {
		return r.Targets[0] == other.Targets[0]
	}

	return len(r.Targets) == 0 && len(other.Targets) == 0
}
