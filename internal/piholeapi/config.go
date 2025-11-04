package piholeapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type hostsResponse []string
type dnsResponse struct {
	Hosts hostsResponse `json:"hosts"`
}
type configResponse struct {
	Config struct {
		DNS *dnsResponse `json:"dns"`
	} `json:"config"`

	Took float64 `json:"took"`
}

func (p *piholeAPI) getConfig(ctx context.Context, element string, sid string) (*configResponse, error) {
	req, err := p.getRequest(ctx, sid)
	if err != nil {
		return nil, err
	}

	req.URL.Path = fmt.Sprintf("/api/config/%s", element)
	req.Method = "GET"

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to execute request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			p.logger.Warn("error closing response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	configRes := &configResponse{}
	if err := json.NewDecoder(resp.Body).Decode(configRes); err != nil {
		return nil, fmt.Errorf("unable to decode config response: %w", err)
	}

	return configRes, nil
}
