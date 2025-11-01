package piholeapi

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type LocalDNSType string

const (
	LocalDNSTypeA     = "A"
	LocalDNSTypeCNAME = "CNAME"
)

type LocalDNSRecord struct {
	Name  string
	Type  LocalDNSType
	Value string
}

type PiholeAPI interface {
	GetDomains(ctx context.Context, t LocalDNSType) ([]*LocalDNSRecord, error)
	SetDomain(ctx context.Context, r *LocalDNSRecord) error
	DeleteDomain(ctx context.Context, r *LocalDNSRecord) error
}

type Config struct {
	Logger   *slog.Logger
	Password string
	Endpoint string
}

func NewPiholeAPI(cfg *Config) PiholeAPI {
	return &piholeAPI{
		endpoint: cfg.Endpoint,
		pass:     cfg.Password,
		logger:   cfg.Logger,

		authTimeout: time.Minute * 55,

		mu:     &sync.RWMutex{},
		client: &http.Client{},
	}
}

type piholeAPI struct {
	endpoint    string
	pass        string
	sessionID   string
	authTimeout time.Duration
	lastAuth    time.Time

	mu     *sync.RWMutex
	logger *slog.Logger
	client *http.Client
}

func (p *piholeAPI) getRequest(ctx context.Context, sessID string) (*http.Request, error) {
	u, _ := url.Parse(p.endpoint)

	headers := http.Header{}
	headers.Set("accept", "application/json")
	if sessID != "" {
		headers.Set("sid", sessID)
	}

	req := &http.Request{
		URL:    u,
		Header: headers,
	}

	return req.WithContext(ctx), nil
}

func (p *piholeAPI) GetDomains(ctx context.Context, t LocalDNSType) ([]*LocalDNSRecord, error) {
	if t == LocalDNSTypeA {
		return p.fetchARecords(ctx)
	}

	return nil, fmt.Errorf("not implemented for dns type: %s", t)
}

func (p *piholeAPI) SetDomain(ctx context.Context, r *LocalDNSRecord) error {
	// Placeholder: implement create/update for A and CNAME records via Pi-hole v6 API
	return fmt.Errorf("SetDomain not implemented for type %s", r.Type)
}

func (p *piholeAPI) DeleteDomain(ctx context.Context, r *LocalDNSRecord) error {
	// Placeholder: implement delete for A and CNAME records via Pi-hole v6 API
	return fmt.Errorf("DeleteDomain not implemented for type %s", r.Type)
}
