package hooksserver

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/falmar/pihole-external-dns-webhooks/internal/piholeapi"
)

// ChangeSet represents a set of DNS record operations to be applied
// It separates the logic of computing the diff from applying it
type ChangeSet struct {
	ToCreate []*piholeapi.LocalDNSRecord
	ToUpdate []*piholeapi.LocalDNSRecord
	ToDelete []*piholeapi.LocalDNSRecord
}

// ChangeSetResult represents the result of applying a change set
type ChangeSetResult struct {
	Created int
	Updated int
	Deleted int
	Errors  []error
}

// CreateChangeSet computes the diff between desired state and current state
// It fetches current state from Pi-hole and returns a ChangeSet with operations to perform
// This function does NOT apply any changes - it only computes what needs to be done
func CreateChangeSet(
	ctx context.Context,
	logger *slog.Logger,
	piAPI piholeapi.PiholeAPI,
	desiredRecords []*Record,
) (*ChangeSet, error) {
	// Fetch current state from Pi-hole (only A records for now)
	currentPiRecords, err := piAPI.GetDomains(ctx, piholeapi.LocalDNSTypeA)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch current state: %w", err)
	}

	// Convert Pi-hole records to ExternalDNS format
	currentRecords := make(map[string]*Record)
	for _, piRecord := range currentPiRecords {
		record := FromLocalDNSRecord(piRecord)
		currentRecords[record.RecordKey()] = record
	}

	// Create a map of desired records by key
	desiredMap := make(map[string]*Record)
	for _, record := range desiredRecords {
		// Only process A records (skip CNAME for now)
		if record.RecordType != string(piholeapi.LocalDNSTypeA) {
			logger.Debug("skipping non-A record", "recordType", record.RecordType, "dnsName", record.DNSName)
			continue
		}

		key := record.RecordKey()
		desiredMap[key] = record
	}

	changeSet := &ChangeSet{
		ToCreate: make([]*piholeapi.LocalDNSRecord, 0),
		ToUpdate: make([]*piholeapi.LocalDNSRecord, 0),
		ToDelete: make([]*piholeapi.LocalDNSRecord, 0),
	}

	// Process creates and updates (records in desired but not in current, or different)
	for key, desiredRecord := range desiredMap {
		currentRecord, exists := currentRecords[key]

		// Convert to LocalDNSRecord for Pi-hole API
		localRecord, err := desiredRecord.ToLocalDNSRecord()
		if err != nil {
			logger.Error("unable to convert record", "error", err, "dnsName", desiredRecord.DNSName)
			return nil, fmt.Errorf("record %s: %w", desiredRecord.DNSName, err)
		}

		if !exists {
			// Record needs to be created
			changeSet.ToCreate = append(changeSet.ToCreate, localRecord)
		} else if !currentRecord.Equals(desiredRecord) {
			// Record needs to be updated (targets differ)
			changeSet.ToUpdate = append(changeSet.ToUpdate, localRecord)
		} else {
			// Record already matches desired state (idempotency)
			logger.Debug("record already matches", "dnsName", localRecord.Name)
		}
	}

	// Process deletes (records in current but not in desired)
	for key, currentRecord := range currentRecords {
		if _, exists := desiredMap[key]; !exists {
			// Record should be deleted
			localRecord, err := currentRecord.ToLocalDNSRecord()
			if err != nil {
				logger.Error("unable to convert record for deletion", "error", err, "dnsName", currentRecord.DNSName)
				return nil, fmt.Errorf("delete %s: %w", currentRecord.DNSName, err)
			}

			changeSet.ToDelete = append(changeSet.ToDelete, localRecord)
		}
	}

	return changeSet, nil
}

// ApplyChangeSet applies a ChangeSet to Pi-hole by executing all operations
// This function only handles persistence - it does not compute diffs
func ApplyChangeSet(
	ctx context.Context,
	logger *slog.Logger,
	piAPI piholeapi.PiholeAPI,
	changeSet *ChangeSet,
) *ChangeSetResult {
	res := &ChangeSetResult{
		Errors: make([]error, 0),
	}

	// Apply creates
	for _, record := range changeSet.ToCreate {
		logger.Info("creating record", "dnsName", record.Name, "ip", record.Value)
		if err := piAPI.SetDomain(ctx, record); err != nil {
			logger.Error("unable to create record", "error", err, "dnsName", record.Name)
			res.Errors = append(res.Errors, fmt.Errorf("create %s: %w", record.Name, err))
			continue
		}
		res.Created++
	}

	// Apply updates
	for _, record := range changeSet.ToUpdate {
		logger.Info("updating record", "dnsName", record.Name, "ip", record.Value)
		if err := piAPI.SetDomain(ctx, record); err != nil {
			logger.Error("unable to update record", "error", err, "dnsName", record.Name)
			res.Errors = append(res.Errors, fmt.Errorf("update %s: %w", record.Name, err))
			continue
		}
		res.Updated++
	}

	// Apply deletes
	for _, record := range changeSet.ToDelete {
		logger.Info("deleting record", "dnsName", record.Name, "ip", record.Value)
		if err := piAPI.DeleteDomain(ctx, record); err != nil {
			logger.Error("unable to delete record", "error", err, "dnsName", record.Name)
			res.Errors = append(res.Errors, fmt.Errorf("delete %s: %w", record.Name, err))
			continue
		}
		res.Deleted++
	}

	logger.Info("change set applied",
		"created", res.Created,
		"updated", res.Updated,
		"deleted", res.Deleted,
		"errors", len(res.Errors))

	return res
}
