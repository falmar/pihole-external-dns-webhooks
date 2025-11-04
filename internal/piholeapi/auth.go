package piholeapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type authRequest struct {
	Password string `json:"password"`
}
type authResponse struct {
	Session struct {
		Valid   bool   `json:"valid"`
		Message string `json:"message"`

		ID string `json:"sid"`
	} `json:"session"`
}

func (p *piholeAPI) authenticate(ctx context.Context) (string, error) {
	if sid := p.isAuthenticated(); sid != "" {
		return sid, nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring lock
	if p.sessionID != "" && time.Since(p.lastAuth) < p.authTimeout {
		return p.sessionID, nil
	}

	p.logger.Info("authenticating with pihole", "endpoint", p.endpoint)

	req, err := p.getRequest(ctx, "")
	if err != nil {
		return "", err
	}

	body := authRequest{
		Password: p.pass,
	}
	b, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("unable to encode request body: %w", err)
	}

	req.URL.Path = "/api/auth"
	req.Method = "POST"
	req.Body = io.NopCloser(bytes.NewReader(b))

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("unable to authenticate: %w", err)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			p.logger.Warn("error closing response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	respBody := authResponse{}
	err = json.NewDecoder(resp.Body).Decode(&respBody)
	if err != nil {
		return "", fmt.Errorf("unable to decode response body: %w", err)
	}

	if !respBody.Session.Valid {
		return "", fmt.Errorf("unable to authenticate: %s", respBody.Session.Message)
	}

	p.logger.Info("authentication successful")
	p.sessionID = respBody.Session.ID
	p.lastAuth = time.Now()

	return p.sessionID, nil
}

func (p *piholeAPI) isAuthenticated() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.sessionID != "" && time.Since(p.lastAuth) < p.authTimeout {
		return p.sessionID
	}

	return ""
}
