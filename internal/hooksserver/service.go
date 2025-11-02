package hooksserver

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/falmar/pihole-external-dns-webhooks/internal/dnssyncer"
	"github.com/falmar/pihole-external-dns-webhooks/internal/piholeapi"
)

// Service is the domain service interface for DNS record management
type Service interface {
	GetRecords(ctx context.Context) ([]*Record, error)
	ApplyChanges(ctx context.Context, req *ChangeSetRequest) (*ChangeSetResult, error)
	AdjustEndpoints(ctx context.Context, records []*Record) ([]*Record, error)
	GetFilters() []string
}

// serviceImpl implements the Service interface
type serviceImpl struct {
	logger  *slog.Logger
	piAPI   piholeapi.PiholeAPI
	syncer  dnssyncer.DNSSyncer
	filters []string
}

// NewService creates a new service instance
func NewService(logger *slog.Logger, piAPI piholeapi.PiholeAPI, syncer dnssyncer.DNSSyncer, filters []string) Service {
	if filters == nil {
		filters = []string{}
	}

	return &serviceImpl{
		logger:  logger,
		piAPI:   piAPI,
		syncer:  syncer,
		filters: filters,
	}
}

// GetRecords fetches current DNS records from Pi-hole and converts them to ExternalDNS format
func (s *serviceImpl) GetRecords(ctx context.Context) ([]*Record, error) {
	// Fetch A records from Pi-hole
	piRecords, err := s.piAPI.GetDomains(ctx, piholeapi.LocalDNSTypeA)
	if err != nil {
		return nil, fmt.Errorf("unable to get domains: %w", err)
	}

	// Convert Pi-hole records to ExternalDNS format
	records := make([]*Record, 0, len(piRecords))
	for _, piRecord := range piRecords {
		records = append(records, FromLocalDNSRecord(piRecord))
	}

	return records, nil
}

// ApplyChanges processes a change set request by computing diffs and applying changes
func (s *serviceImpl) ApplyChanges(ctx context.Context, req *ChangeSetRequest) (*ChangeSetResult, error) {
	// Extract all records from create, update, and delete operations
	// The desired state is the union of create and update operations
	// (delete operations are handled separately)
	var desiredRecords []*Record
	desiredRecords = append(desiredRecords, req.Create...)
	desiredRecords = append(desiredRecords, req.Update...)

	// Create change set (compute diff)
	// desiredRecords is the union of create and update operations
	changeSet, err := CreateChangeSet(ctx, s.logger, s.piAPI, desiredRecords)
	if err != nil {
		return nil, fmt.Errorf("unable to create change set: %w", err)
	}

	// Add explicit delete operations from ExternalDNS request
	// These are records that ExternalDNS explicitly wants to delete
	for _, deleteRecord := range req.Delete {
		localRecord, err := deleteRecord.ToLocalDNSRecord()
		if err != nil {
			s.logger.Warn("unable to convert delete record", "error", err, "dnsName", deleteRecord.DNSName)
			continue
		}
		// Check if this record is already in the delete list to avoid duplicates
		found := false
		for _, existingDelete := range changeSet.ToDelete {
			if existingDelete.Name == localRecord.Name && existingDelete.Value == localRecord.Value {
				found = true
				break
			}
		}
		if !found {
			changeSet.ToDelete = append(changeSet.ToDelete, localRecord)
		}
	}

	// Remove from create/update any records that are explicitly being deleted
	// (ExternalDNS might send both create and delete for the same record)
	deleteKeys := make(map[string]bool)
	for _, deleteRecord := range req.Delete {
		deleteKeys[deleteRecord.RecordKey()] = true
	}

	filteredCreates := make([]*piholeapi.LocalDNSRecord, 0)
	for _, create := range changeSet.ToCreate {
		record := FromLocalDNSRecord(create)
		if !deleteKeys[record.RecordKey()] {
			filteredCreates = append(filteredCreates, create)
		}
	}
	changeSet.ToCreate = filteredCreates

	filteredUpdates := make([]*piholeapi.LocalDNSRecord, 0)
	for _, update := range changeSet.ToUpdate {
		record := FromLocalDNSRecord(update)
		if !deleteKeys[record.RecordKey()] {
			filteredUpdates = append(filteredUpdates, update)
		}
	}
	changeSet.ToUpdate = filteredUpdates

	// Apply change set (persist changes)
	result := ApplyChangeSet(ctx, s.logger, s.piAPI, changeSet)

	return result, nil
}

// AdjustEndpoints normalizes a set of records
func (s *serviceImpl) AdjustEndpoints(_ context.Context, records []*Record) ([]*Record, error) {
	normalized := make([]*Record, 0, len(records))
	for _, r := range records {
		normalized = append(normalized, NormalizeDNSRecord(r))
	}
	return normalized, nil
}

// GetFilters returns the configured domain filters
func (s *serviceImpl) GetFilters() []string {
	return s.filters
}
