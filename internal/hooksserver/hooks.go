package hooksserver

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/falmar/pihole-external-dns-webhooks/internal/dnssyncer"
	"github.com/falmar/pihole-external-dns-webhooks/internal/piholeapi"
)

// Config contains configuration for the hooks server
type Config struct {
	Logger  *slog.Logger
	PiAPI   piholeapi.PiholeAPI
	Syncer  dnssyncer.DNSSyncer
	Filters []string // Domain filters to return in negotiation endpoint
}

const (
	// ContentType is the ExternalDNS webhook content type
	ContentType = "application/external.dns.webhook+json;version=1"
)

// HooksServer is the interface for the hooks server
// It provides HTTP handler methods for the ExternalDNS webhook protocol
type HooksServer interface {
	HandleNegotiation(http.ResponseWriter, *http.Request)
	HandleGetRecords(http.ResponseWriter, *http.Request)
	HandlePostRecords(http.ResponseWriter, *http.Request)
	HandleAdjustments(http.ResponseWriter, *http.Request)
}

// New creates a new hooks server instance
// It returns the HooksServer interface
// Filters can be nil or empty - if so, the negotiation endpoint will return an empty filters array
func New(cfg *Config) HooksServer {
	// Normalize nil to empty slice for consistent behavior
	filters := cfg.Filters
	if filters == nil {
		filters = []string{}
	}

	return &hooksServer{
		logger:  cfg.Logger,
		piAPI:   cfg.PiAPI,
		syncer:  cfg.Syncer,
		filters: filters,
	}
}

type hooksServer struct {
	logger  *slog.Logger
	piAPI   piholeapi.PiholeAPI
	syncer  dnssyncer.DNSSyncer
	filters []string
}

// HandleNegotiation handles GET / - returns supported filters
func (h *hooksServer) HandleNegotiation(wr http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	wr.Header().Set("content-type", ContentType)
	wr.WriteHeader(http.StatusOK)

	response := map[string]interface{}{
		"filters": h.filters,
	}

	if err := json.NewEncoder(wr).Encode(response); err != nil {
		h.logger.Error("unable to encode negotiation response", "error", err)
	}
}

// HandleGetRecords handles GET /records - fetches current state from Pi-hole
func (h *hooksServer) HandleGetRecords(wr http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	ctx := req.Context()

	// Fetch A records from Pi-hole
	piRecords, err := h.piAPI.GetDomains(ctx, piholeapi.LocalDNSTypeA)
	if err != nil {
		h.logger.Error("unable to get domains", "error", err)
		wr.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Convert Pi-hole records to ExternalDNS format
	records := make([]*Record, 0, len(piRecords))
	for _, piRecord := range piRecords {
		records = append(records, FromLocalDNSRecord(piRecord))
	}

	wr.Header().Set("content-type", ContentType)
	wr.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(wr).Encode(records); err != nil {
		h.logger.Error("unable to encode records response", "error", err)
	}
}

// HandlePostRecords handles POST /records - processes change sets
func (h *hooksServer) HandlePostRecords(wr http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	ctx := req.Context()

	// Validate content type
	if req.Header.Get("content-type") != ContentType {
		h.logger.Warn("invalid content type", "content-type", req.Header.Get("content-type"))
		wr.WriteHeader(http.StatusBadRequest)
		return
	}

	// Read request body
	body, err := io.ReadAll(req.Body)
	if err != nil {
		h.logger.Error("error reading body", "err", err)
		wr.WriteHeader(http.StatusBadRequest)
		return
	}

	h.logger.Debug("POST /records request body", "content", string(body))

	// Parse request body as ChangeSetRequest (ExternalDNS format)
	var changeSetReq ChangeSetRequest
	if err := json.Unmarshal(body, &changeSetReq); err != nil {
		h.logger.Error("error decoding body", "err", err)
		wr.WriteHeader(http.StatusBadRequest)
		return
	}

	// Extract all records from create, update, and delete operations
	// The desired state is the union of create and update operations
	// (delete operations are handled separately)
	var desiredRecords []*Record
	desiredRecords = append(desiredRecords, changeSetReq.Create...)
	desiredRecords = append(desiredRecords, changeSetReq.Update...)

	// Validate records
	for i, record := range desiredRecords {
		if record.DNSName == "" {
			h.logger.Error("invalid record: missing dnsName", "index", i)
			wr.WriteHeader(http.StatusBadRequest)
			return
		}
		if record.RecordType == "" {
			h.logger.Error("invalid record: missing recordType", "index", i, "dnsName", record.DNSName)
			wr.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(record.Targets) == 0 {
			h.logger.Error("invalid record: missing targets", "index", i, "dnsName", record.DNSName)
			wr.WriteHeader(http.StatusBadRequest)
			return
		}
	}

	// Create change set (compute diff)
	// desiredRecords is the union of create and update operations
	changeSet, err := CreateChangeSet(ctx, h.logger, h.piAPI, desiredRecords)
	if err != nil {
		h.logger.Error("unable to create change set", "error", err)
		wr.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Add explicit delete operations from ExternalDNS request
	// These are records that ExternalDNS explicitly wants to delete
	for _, deleteRecord := range changeSetReq.Delete {
		localRecord, err := deleteRecord.ToLocalDNSRecord()
		if err != nil {
			h.logger.Warn("unable to convert delete record", "error", err, "dnsName", deleteRecord.DNSName)
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
	for _, deleteRecord := range changeSetReq.Delete {
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
	result := ApplyChangeSet(ctx, h.logger, h.piAPI, changeSet)

	// Determine HTTP status based on errors
	status := http.StatusOK
	if len(result.Errors) > 0 {
		// Partial failure - return 207 Multi-Status or 500 depending on severity
		// For now, return 500 if any errors occurred
		status = http.StatusInternalServerError
		h.logger.Warn("change set applied with errors",
			"created", result.Created,
			"updated", result.Updated,
			"deleted", result.Deleted,
			"errors", len(result.Errors))
	}

	wr.Header().Set("content-type", ContentType)
	wr.WriteHeader(status)
}

// HandleAdjustments handles POST /adjustendpoints - echoes posted records (for debugging)
func (h *hooksServer) HandleAdjustments(wr http.ResponseWriter, req *http.Request) {
	wr.Header().Set("content-type", ContentType)

	body, err := io.ReadAll(req.Body)
	if err != nil {
		wr.WriteHeader(http.StatusBadRequest)
		h.logger.Error("error reading body", "err", err)
		return
	}

	h.logger.Debug("POST /adjustendpoints request body", "content", string(body))

	var records []*Record
	if err := json.Unmarshal(body, &records); err != nil {
		wr.WriteHeader(http.StatusBadRequest)
		h.logger.Error("error decoding body", "err", err)
		return
	}

	piholeRecords := make([]*Record, 0, len(records))

	for _, r := range records {
		piholeRecords = append(piholeRecords, NormalizeDNSRecord(r))
	}

	wr.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(wr).Encode(records); err != nil {
		h.logger.Error("error encoding body", "err", err)
	}
}
