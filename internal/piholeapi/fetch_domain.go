package piholeapi

import (
	"context"
	"strings"
)

func (p *piholeAPI) fetchARecords(ctx context.Context) ([]*LocalDNSRecord, error) {
	configRes, err := p.getConfig(ctx, "dns/hosts")
	if err != nil {
		return nil, err
	}

	if configRes.Config.DNS == nil || configRes.Config.DNS.Hosts == nil {
		return nil, nil
	}

	var records []*LocalDNSRecord
	for _, host := range configRes.Config.DNS.Hosts {
		split := strings.Split(host, " ")

		records = append(records, &LocalDNSRecord{
			Type:  LocalDNSTypeA,
			Name:  split[1],
			Value: split[0],
		})
	}

	return records, nil
}
