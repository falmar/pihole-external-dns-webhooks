package piholeapi

import (
	"context"
	"fmt"
	"strings"
)

func (p *piholeAPI) GetDomains(ctx context.Context, t LocalDNSType) ([]*LocalDNSRecord, error) {
	if t != LocalDNSTypeA {
		return nil, fmt.Errorf("not implemented for dns type: %s", t)
	}

	sid, err := p.authenticate(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to authenticate: %w", err)
	}

	return p.fetchARecords(ctx, sid)
}

func (p *piholeAPI) fetchARecords(ctx context.Context, sid string) ([]*LocalDNSRecord, error) {
	configRes, err := p.getConfig(ctx, "dns/hosts", sid)
	if err != nil {
		return nil, err
	}

	if configRes.Config.DNS == nil || configRes.Config.DNS.Hosts == nil {
		return nil, nil
	}

	records := make([]*LocalDNSRecord, 0, len(configRes.Config.DNS.Hosts))
	for _, host := range configRes.Config.DNS.Hosts {
		split := strings.SplitN(host, " ", 2)
		if len(split) < 2 {
			// Pi-hole API should always return "[ip] [domain]" format
			continue
		}

		records = append(records, &LocalDNSRecord{
			Type:  LocalDNSTypeA,
			Name:  split[1],
			Value: split[0],
		})
	}

	return records, nil
}
