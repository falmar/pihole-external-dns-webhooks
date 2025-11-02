package piholeapi

import (
	"context"
	"fmt"
	"net/http"
)

func (p *piholeAPI) setDomain(ctx context.Context, r *LocalDNSRecord) error {
	if r.Type != LocalDNSTypeA {
		return fmt.Errorf("SetDomain not implemented for type %s", r.Type)
	}

	if r.Name == "" || r.Value == "" {
		return fmt.Errorf("domain name and IP address are required")
	}

	sid, err := p.authenticate(ctx)
	if err != nil {
		return fmt.Errorf("unable to authenticate: %w", err)
	}

	// Value: {ip} {domain}
	value := fmt.Sprintf("%s %s", r.Value, r.Name)

	// Build URL path: /api/config/{config}/{value}
	req, err := p.getRequest(ctx, sid)
	if err != nil {
		return fmt.Errorf("unable to create request: %w", err)
	}

	req.URL.Path = fmt.Sprintf("/api/config/%s/%s", "dns/hosts", value)
	req.Method = "PUT"

	p.logger.Info("setting domain", "name", r.Name, "ip", r.Value)

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("unable to set domain: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}
