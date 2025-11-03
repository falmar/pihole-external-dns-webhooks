package hooksserver

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/falmar/pihole-external-dns-webhooks/internal/piholeapi"
)

// ChangeSet represents a set of DNS record operations to be applied.
// It separates the logic of computing the diff from applying it.
type ChangeSet struct {
	ToCreate []*piholeapi.LocalDNSRecord
	ToUpdate []*piholeapi.LocalDNSRecord
	ToDelete []*piholeapi.LocalDNSRecord
}

// ChangeSetResult represents the result of applying a change set.
type ChangeSetResult struct {
	Created int
	Updated int
	Deleted int
	Errors  []error
}

// buildCurrentRecordsMap converts Pi-hole records to ExternalDNS format and returns a map.
func buildCurrentRecordsMap(currentPiRecords []*piholeapi.LocalDNSRecord) map[string]*Record {
	currentRecords := make(map[string]*Record)
	for _, piRecord := range currentPiRecords {
		record := FromLocalDNSRecord(piRecord)
		currentRecords[record.RecordKey()] = record
	}
	return currentRecords
}

// buildDesiredRecordsMap processes desired records into a map, filtering for A records only.
func buildDesiredRecordsMap(logger *slog.Logger, desiredRecords []*Record) map[string]*Record {
	desiredMap := make(map[string]*Record)
	for _, record := range desiredRecords {
		if record.RecordType != string(piholeapi.LocalDNSTypeA) {
			logger.Debug("skipping non-A record", "recordType", record.RecordType, "dnsName", record.DNSName)
			continue
		}
		desiredMap[record.RecordKey()] = record
	}
	return desiredMap
}

// processCreatesAndUpdates processes creates and updates, adding them to the change set.
func processCreatesAndUpdates(
	logger *slog.Logger,
	changeSet *ChangeSet,
	desiredMap map[string]*Record,
	currentRecords map[string]*Record,
) error {
	for key, desiredRecord := range desiredMap {
		currentRecord, exists := currentRecords[key]

		localRecord, err := desiredRecord.ToLocalDNSRecord()
		if err != nil {
			logger.Error("unable to convert record", "error", err, "dnsName", desiredRecord.DNSName)
			return fmt.Errorf("record %s: %w", desiredRecord.DNSName, err)
		}

		if !exists {
			changeSet.ToCreate = append(changeSet.ToCreate, localRecord)
		} else if !currentRecord.Equals(desiredRecord) {
			changeSet.ToUpdate = append(changeSet.ToUpdate, localRecord)
		} else {
			logger.Debug("record already matches", "dnsName", localRecord.Name)
		}
	}
	return nil
}

// processDeletes processes deletes, adding them to the change set.
func processDeletes(
	logger *slog.Logger,
	changeSet *ChangeSet,
	desiredMap map[string]*Record,
	currentRecords map[string]*Record,
) error {
	for key, currentRecord := range currentRecords {
		if _, exists := desiredMap[key]; !exists {
			localRecord, err := currentRecord.ToLocalDNSRecord()
			if err != nil {
				logger.Error("unable to convert record for deletion", "error", err, "dnsName", currentRecord.DNSName)
				return fmt.Errorf("delete %s: %w", currentRecord.DNSName, err)
			}
			changeSet.ToDelete = append(changeSet.ToDelete, localRecord)
		}
	}
	return nil
}

// CreateChangeSet computes the diff between desired state and current state.
// It fetches current state from Pi-hole and returns a ChangeSet with operations to perform.
// This function does NOT apply any changes - it only computes what needs to be done.
func CreateChangeSet(
	ctx context.Context,
	logger *slog.Logger,
	piAPI piholeapi.PiholeAPI,
	desiredRecords []*Record,
) (*ChangeSet, error) {
	currentPiRecords, err := piAPI.GetDomains(ctx, piholeapi.LocalDNSTypeA)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch current state: %w", err)
	}

	currentRecords := buildCurrentRecordsMap(currentPiRecords)
	desiredMap := buildDesiredRecordsMap(logger, desiredRecords)

	changeSet := &ChangeSet{
		ToCreate: make([]*piholeapi.LocalDNSRecord, 0),
		ToUpdate: make([]*piholeapi.LocalDNSRecord, 0),
		ToDelete: make([]*piholeapi.LocalDNSRecord, 0),
	}

	if err := processCreatesAndUpdates(logger, changeSet, desiredMap, currentRecords); err != nil {
		return nil, err
	}

	if err := processDeletes(logger, changeSet, desiredMap, currentRecords); err != nil {
		return nil, err
	}

	return changeSet, nil
}

// ApplyChangeSet applies a ChangeSet to Pi-hole by executing all operations.
// This function only handles persistence - it does not compute diffs.
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
