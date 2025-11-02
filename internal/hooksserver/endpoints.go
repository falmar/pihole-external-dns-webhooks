package hooksserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/falmar/pihole-external-dns-webhooks/internal/kit"
)

// Endpoint request/response types

// negotiationRequest is empty (no input needed)
type negotiationRequest struct{}

// negotiationResponse contains the filters for negotiation
type negotiationResponse struct {
	Filters []string `json:"filters"`
}

// getRecordsRequest is empty (no input needed)
type getRecordsRequest struct{}

// getRecordsResponse contains the list of records
type getRecordsResponse struct {
	Records []*Record `json:"records,omitempty"`
}

// postRecordsRequest contains the change set request
type postRecordsRequest struct {
	*ChangeSetRequest
}

// postRecordsResponse contains the change set result
type postRecordsResponse struct {
	*ChangeSetResult
}

// adjustEndpointsRequest contains the list of records to adjust
type adjustEndpointsRequest struct {
	Records []*Record `json:"records"`
}

// adjustEndpointsResponse contains the adjusted records
type adjustEndpointsResponse struct {
	Records []*Record `json:"records"`
}

// makeNegotiationEndpoint creates an endpoint for the negotiation handler
func makeNegotiationEndpoint(svc Service, _ *slog.Logger) kit.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		_ = request.(negotiationRequest) // Validate request type

		filters := svc.GetFilters()

		return negotiationResponse{
			Filters: filters,
		}, nil
	}
}

// makeGetRecordsEndpoint creates an endpoint for the get records handler
func makeGetRecordsEndpoint(svc Service, logger *slog.Logger) kit.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		_ = request.(getRecordsRequest) // Validate request type

		records, err := svc.GetRecords(ctx)
		if err != nil {
			logger.Error("unable to get records", "error", err)
			return nil, fmt.Errorf("unable to get records: %w", err)
		}

		return getRecordsResponse{
			Records: records,
		}, nil
	}
}

// makePostRecordsEndpoint creates an endpoint for the post records handler
func makePostRecordsEndpoint(svc Service, logger *slog.Logger) kit.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(postRecordsRequest)

		if req.ChangeSetRequest == nil {
			return nil, errors.New("change set request is required")
		}

		// Validate records - extract all records from create, update, and delete operations
		// The desired state is the union of create and update operations
		var desiredRecords []*Record
		desiredRecords = append(desiredRecords, req.ChangeSetRequest.Create...)
		desiredRecords = append(desiredRecords, req.ChangeSetRequest.Update...)

		// Validate records
		for i, record := range desiredRecords {
			if record.DNSName == "" {
				logger.Error("invalid record: missing dnsName", "index", i)
				return nil, fmt.Errorf("invalid record at index %d: missing dnsName", i)
			}
			if record.RecordType == "" {
				logger.Error("invalid record: missing recordType", "index", i, "dnsName", record.DNSName)
				return nil, fmt.Errorf("invalid record at index %d: missing recordType (dnsName: %s)", i, record.DNSName)
			}
			if len(record.Targets) == 0 {
				logger.Error("invalid record: missing targets", "index", i, "dnsName", record.DNSName)
				return nil, fmt.Errorf("invalid record at index %d: missing targets (dnsName: %s)", i, record.DNSName)
			}
		}

		result, err := svc.ApplyChanges(ctx, req.ChangeSetRequest)
		if err != nil {
			logger.Error("unable to apply changes", "error", err)
			return nil, fmt.Errorf("unable to apply changes: %w", err)
		}

		// Check if there were any errors in the result
		if len(result.Errors) > 0 {
			logger.Warn("change set applied with errors",
				"created", result.Created,
				"updated", result.Updated,
				"deleted", result.Deleted,
				"errors", len(result.Errors))
			// Return the result but also an error to indicate partial failure
			return postRecordsResponse{
				ChangeSetResult: result,
			}, fmt.Errorf("change set applied with %d errors", len(result.Errors))
		}

		return postRecordsResponse{
			ChangeSetResult: result,
		}, nil
	}
}

// makeAdjustEndpointsEndpoint creates an endpoint for the adjust endpoints handler
func makeAdjustEndpointsEndpoint(svc Service, logger *slog.Logger) kit.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(adjustEndpointsRequest)

		adjusted, err := svc.AdjustEndpoints(ctx, req.Records)
		if err != nil {
			logger.Error("unable to adjust endpoints", "error", err)
			return nil, fmt.Errorf("unable to adjust endpoints: %w", err)
		}

		return adjustEndpointsResponse{
			Records: adjusted,
		}, nil
	}
}
