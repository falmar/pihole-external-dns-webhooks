package piholeapi

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	DefaultAuthTimeout = 55 * time.Minute
	DefaultHTTPTimeout = 30 * time.Second
)

// HTTPDoer is an interface for making HTTP requests.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

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
	Logger      *slog.Logger
	Password    string
	Endpoint    string
	Client      HTTPDoer
	AuthTimeout time.Duration
}

func NewPiholeAPI(cfg *Config) PiholeAPI {
	client := cfg.Client
	if client == nil {
		client = &http.Client{
			Timeout: DefaultHTTPTimeout,
		}
	}

	authTimeout := cfg.AuthTimeout
	if authTimeout <= 0 {
		authTimeout = DefaultAuthTimeout
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	return &piholeAPI{
		endpoint: cfg.Endpoint,
		pass:     cfg.Password,
		logger:   logger,

		authTimeout: authTimeout,

		mu:     &sync.RWMutex{},
		client: client,
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
	client HTTPDoer
}

func (p *piholeAPI) getRequest(ctx context.Context, sessID string) (*http.Request, error) {
	u, err := url.Parse(p.endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint URL: %w", err)
	}

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
