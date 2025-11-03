package hooksserver

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/falmar/pihole-external-dns-webhooks/internal/kit"
)

// HTTPTransport implements the HooksServer interface using go-kit architecture.
type HTTPTransport struct {
	negotiationEndpoint     kit.Endpoint
	getRecordsEndpoint      kit.Endpoint
	postRecordsEndpoint     kit.Endpoint
	adjustEndpointsEndpoint kit.Endpoint
	logger                  *slog.Logger
}

// NewHTTPTransport creates a new HTTP transport.
func NewHTTPTransport(
	negotiationEndpoint kit.Endpoint,
	getRecordsEndpoint kit.Endpoint,
	postRecordsEndpoint kit.Endpoint,
	adjustEndpointsEndpoint kit.Endpoint,
	logger *slog.Logger,
) *HTTPTransport {
	return &HTTPTransport{
		negotiationEndpoint:     negotiationEndpoint,
		getRecordsEndpoint:      getRecordsEndpoint,
		postRecordsEndpoint:     postRecordsEndpoint,
		adjustEndpointsEndpoint: adjustEndpointsEndpoint,
		logger:                  logger,
	}
}

// HandleNegotiation handles GET / - returns supported filters.
func (t *HTTPTransport) HandleNegotiation(wr http.ResponseWriter, req *http.Request) {
	defer func() {
		if err := req.Body.Close(); err != nil {
			t.logger.Warn("error closing request body", "error", err)
		}
	}()

	ctx := req.Context()
	request := negotiationRequest{}

	response, err := t.negotiationEndpoint(ctx, request)
	if err != nil {
		t.logger.Error("negotiation endpoint error", "error", err)
		http.Error(wr, "internal server error", http.StatusInternalServerError)
		return
	}

	resp := response.(negotiationResponse)

	wr.Header().Set("content-type", ContentType)
	wr.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(wr).Encode(resp); err != nil {
		t.logger.Error("unable to encode negotiation response", "error", err)
	}
}

// HandleGetRecords handles GET /records - fetches current state from Pi-hole.
func (t *HTTPTransport) HandleGetRecords(wr http.ResponseWriter, req *http.Request) {
	defer func() {
		if err := req.Body.Close(); err != nil {
			t.logger.Warn("error closing request body", "error", err)
		}
	}()

	ctx := req.Context()
	request := getRecordsRequest{}

	response, err := t.getRecordsEndpoint(ctx, request)
	if err != nil {
		t.logger.Error("get records endpoint error", "error", err)
		wr.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp := response.(getRecordsResponse)

	wr.Header().Set("content-type", ContentType)
	wr.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(wr).Encode(resp.Records); err != nil {
		t.logger.Error("unable to encode records response", "error", err)
	}
}

// HandlePostRecords handles POST /records - processes change sets.
func (t *HTTPTransport) HandlePostRecords(wr http.ResponseWriter, req *http.Request) {
	defer func() {
		if err := req.Body.Close(); err != nil {
			t.logger.Warn("error closing request body", "error", err)
		}
	}()

	// Validate content type
	if req.Header.Get("content-type") != ContentType {
		t.logger.Warn("invalid content type", "content-type", req.Header.Get("content-type"))
		wr.WriteHeader(http.StatusBadRequest)
		return
	}

	ctx := req.Context()

	// Read request body
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.logger.Error("error reading body", "err", err)
		wr.WriteHeader(http.StatusBadRequest)
		return
	}

	t.logger.Debug("POST /records request body", "content", string(body))

	// Parse request body as ChangeSetRequest (ExternalDNS format)
	var changeSetReq ChangeSetRequest
	if err := json.Unmarshal(body, &changeSetReq); err != nil {
		t.logger.Error("error decoding body", "err", err)
		wr.WriteHeader(http.StatusBadRequest)
		return
	}

	request := postRecordsRequest{
		ChangeSetRequest: &changeSetReq,
	}

	response, err := t.postRecordsEndpoint(ctx, request)
	if err != nil {
		// Check if it's a validation error (should be 400) or server error (500)
		// For now, treat all errors as server errors, but we could inspect the error type
		t.logger.Error("post records endpoint error", "error", err)

		// If the response contains a result, we had partial failure
		if response != nil {
			resp := response.(postRecordsResponse)
			if len(resp.Errors) > 0 {
				// Partial failure - return 500 for now
				wr.Header().Set("content-type", ContentType)
				wr.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		// Validation errors should be 400, but we'll check in the endpoint
		// For now, default to 500
		wr.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Success - no response body needed for POST /records
	wr.Header().Set("content-type", ContentType)
	wr.WriteHeader(http.StatusOK)
}

// HandleAdjustments handles POST /adjustendpoints - normalizes posted records.
func (t *HTTPTransport) HandleAdjustments(wr http.ResponseWriter, req *http.Request) {
	defer func() {
		if err := req.Body.Close(); err != nil {
			t.logger.Warn("error closing request body", "error", err)
		}
	}()

	ctx := req.Context()

	body, err := io.ReadAll(req.Body)
	if err != nil {
		wr.WriteHeader(http.StatusBadRequest)
		t.logger.Error("error reading body", "err", err)
		return
	}

	t.logger.Debug("POST /adjustendpoints request body", "content", string(body))

	var records []*Record
	if err := json.Unmarshal(body, &records); err != nil {
		wr.WriteHeader(http.StatusBadRequest)
		t.logger.Error("error decoding body", "err", err)
		return
	}

	request := adjustEndpointsRequest{
		Records: records,
	}

	response, err := t.adjustEndpointsEndpoint(ctx, request)
	if err != nil {
		t.logger.Error("adjust endpoints endpoint error", "error", err)
		wr.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp := response.(adjustEndpointsResponse)

	wr.Header().Set("content-type", ContentType)
	wr.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(wr).Encode(resp.Records); err != nil {
		t.logger.Error("error encoding body", "err", err)
	}
}
