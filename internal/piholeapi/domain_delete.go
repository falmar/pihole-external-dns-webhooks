package piholeapi

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

func (p *piholeAPI) deleteDomain(ctx context.Context, r *LocalDNSRecord) error {
	if r.Type != LocalDNSTypeA {
		return fmt.Errorf("DeleteDomain not implemented for type %s", r.Type)
	}

	if r.Name == "" || r.Value == "" {
		return fmt.Errorf("domain name and IP address are required")
	}

	sid, err := p.authenticate(ctx)
	if err != nil {
		return fmt.Errorf("unable to authenticate: %w", err)
	}

	// URL encode components
	// Config: dns/hosts -> dns%2Fhosts
	configEncoded := url.PathEscape("dns/hosts")
	// Value: {ip} {domain} -> {ip}%20{domain}
	value := fmt.Sprintf("%s %s", r.Value, r.Name)
	valueEncoded := url.PathEscape(value)

	// Build URL path: /api/config/{config}/{value}
	req, err := p.getRequest(ctx, sid)
	if err != nil {
		return fmt.Errorf("unable to create request: %w", err)
	}

	req.URL.Path = fmt.Sprintf("/api/config/%s/%s", configEncoded, valueEncoded)
	req.Method = "DELETE"

	p.logger.Info("deleting domain", "name", r.Name, "ip", r.Value)

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("unable to delete domain: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}
