package hooksserver

import (
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

	// Create service layer
	svc := NewService(cfg.Logger, cfg.PiAPI, cfg.Syncer, filters)

	// Create endpoints
	negotiationEndpoint := makeNegotiationEndpoint(svc, cfg.Logger)
	getRecordsEndpoint := makeGetRecordsEndpoint(svc, cfg.Logger)
	postRecordsEndpoint := makePostRecordsEndpoint(svc, cfg.Logger)
	adjustEndpointsEndpoint := makeAdjustEndpointsEndpoint(svc, cfg.Logger)

	// Create HTTP transport
	return NewHTTPTransport(
		negotiationEndpoint,
		getRecordsEndpoint,
		postRecordsEndpoint,
		adjustEndpointsEndpoint,
		cfg.Logger,
	)
}
