### pihole-external-dns-webhooks (PEW)

PEW is a lightweight webhook service intended to bridge Kubernetes ExternalDNS with one or more Pi-hole instances. It exposes an ExternalDNS-compatible webhook API and talks to the Pi-hole HTTP API (v6) to list and, in future iterations, create/delete local DNS records.

The long-term goal is to act as a proxy/synchronizer that discovers multiple Pi-hole replicas via DNS (nslookup), applies changes across all of them, and keeps their local DNS entries in sync for HA/stability when running Pi-hole as a replicated app (e.g., in Kubernetes or on multiple hosts).

This README documents the current capabilities, how to run the service, and the roadmap towards multi-instance synchronization.

---

### Features (current)
- ExternalDNS webhook negotiation endpoint and record endpoints
  - GET / negotiation returns supported filters
  - GET /records lists existing Pi-hole local DNS A records via Pi-hole v6 API
  - POST /records placeholder (request body is logged; no writes yet)
  - POST /adjustendpoints echo endpoint (helps debug ExternalDNS webhook traffic)
- Pi-hole v6 API authentication with session caching
- Minimal, structured logging (text or JSON)

### Planned features (roadmap)
- Multi-Pi-hole proxy/synchronization
  - Discover target instances using DNS lookups (nslookup) on a configurable name
  - Fan-out write operations (create/delete) to all discovered Pi-hole instances
  - Health checks and partial failure handling
- Full POST /records implementation
  - Translate ExternalDNS change sets into Pi-hole local DNS A/CNAME operations
  - Idempotency and conflict handling
- Support for CNAME records in addition to A
- Optional TLS/ingress and auth for the webhook itself

---

### Architecture overview
- CLI: pew serve starts an HTTP server
- Webhook server (cmd/serve.go):
  - Implements ExternalDNS webhook endpoints
  - Uses internal/piholeapi to talk to Pi-hole
- Pi-hole client (internal/piholeapi):
  - Authenticates to Pi-hole v6 (POST /api/auth) and caches session ID
  - Reads config elements like local hosts from GET /api/config/dns/hosts
  - Currently implements read (A records). Write/delete are TODO.

---

### API compatibility
PEW speaks the ExternalDNS webhook protocol (content type application/external.dns.webhook+json;version=1). Negotiation and GET /records are implemented. The POST /records semantics are stubbed and will be implemented to apply changes.

- Negotiation: GET /
  - Returns supported filters. Currently returns kind.local as an example filter.
- Read: GET /records
  - Returns a list of records sourced from Pi-hole local DNS (A records only for now).
- Write: POST /records
  - Currently logs the posted change set and returns 200. No mutation against Pi-hole yet.
- Debug: POST /adjustendpoints
  - Echoes the posted records; helps inspect ExternalDNS payloads.

---

### Configuration
You can configure PEW via flags or environment variables. Environment variables use the PEW_ prefix and . becomes _.

Core options:
- --port (env: PEW_PORT)
  - HTTP port to listen on. Default: 8080
- --pihole.endpoint (env: PEW_PIHOLE_ENDPOINT)
  - Base URL of the Pi-hole instance (v6 API). Example: http://pihole.local:80
- --pihole.password (env: PEW_PIHOLE_PASSWORD)
  - Password for Pi-hole web UI; used to obtain sid via POST /api/auth.
- Logging
  - --log.level (env: PEW_LOG_LEVEL): info or debug (default info)
  - --log.format (env: PEW_LOG_FORMAT): text or json (default text)
- Config file
  - --config / -c or CONFIG_PATH env var: optional path to a YAML config consumed by Viper. CLI flags/env still take precedence.

Examples:
- Environment
  - PEW_PIHOLE_ENDPOINT=http://192.168.1.10:80
  - PEW_PIHOLE_PASSWORD=supersecret
  - PEW_PORT=8080
- CLI
  - pew serve --pihole.endpoint=http://192.168.1.10:80 --pihole.password=$PEW_PIHOLE_PASSWORD --port=8080

---

### Build and run
Requirements:
- Go 1.25+

Build:
```
go build -o pew ./cmd
```

Run locally:
```
./pew serve \
  --pihole.endpoint=http://192.168.1.10:80 \
  --pihole.password=$PEW_PIHOLE_PASSWORD \
  --port=8080 \
  --log.level=debug \
  --log.format=text
```

Docker (example Dockerfile snippet you can create):
```
# syntax=docker/dockerfile:1
FROM golang:1.25 as build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/pew ./cmd

FROM gcr.io/distroless/base-debian12
COPY --from=build /out/pew /usr/local/bin/pew
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/pew", "serve"]
```

---

### HTTP endpoints
- GET /
  - Content-Type: application/external.dns.webhook+json;version=1
  - Returns:
    { "filters": ["kind.local"] }
- GET /records
  - Lists A records from Pi-hole local DNS (derived from GET /api/config/dns/hosts).
  - Response shape:
    [
      {
        "dnsName": "host.local",
        "recordTTL": 0,
        "recordType": "A",
        "targets": ["192.168.1.2"]
      }
    ]
- POST /records
  - Current behavior: reads and logs the payload; returns 200.
  - Will later apply creates/updates/deletes across one or more Pi-hole instances.
- POST /adjustendpoints
  - Echoes back the posted records. Useful for debugging payloads from ExternalDNS.

cURL examples:
```
curl -s localhost:8080/

curl -s localhost:8080/records | jq .

curl -s -X POST localhost:8080/records \
  -H 'content-type: application/external.dns.webhook+json;version=1' \
  -d '[{"dnsName":"test.local","recordTTL":0,"recordType":"A","targets":["10.0.0.10"]}]'

curl -s -X POST localhost:8080/adjustendpoints \
  -H 'content-type: application/external.dns.webhook+json;version=1' \
  -d '[{"dnsName":"test.local","recordTTL":0,"recordType":"A","targets":["10.0.0.10"]}]' | jq .
```

---

### Using with ExternalDNS (preview)
ExternalDNS supports a webhook source/registry. Configure ExternalDNS to point to this service and use the negotiation/content-type headers.

Example flags (adjust to your deployment):
- --source=service
- --source=ingress
- --registry=webhook
- --webhook-endpoint=http://pew.default.svc.cluster.local:8080
- --webhook-graphql-endpoint= (not used)
- --webhook-insecure-skip-tls-verify (if you run HTTP)

Note: Since POST /records is not yet applying changes, running ExternalDNS against PEW today only enables read/list operations. Writes are on the roadmap.

---

### Multi-instance discovery and sync (design)
Target behavior (not yet implemented in code):
- Discovery
  - Resolve a configurable DNS name (e.g., pihole-servers.local) at a configurable interval
  - Use A/AAAA records returned by nslookup to build the set of Pi-hole endpoints
- Write fan-out
  - On POST /records, apply each change to all discovered Pi-hole instances
  - Aggregate errors; succeed if a quorum or all succeed (configurable)
- Read aggregation
  - When GET /records, either read from a primary or read from all and merge
- Resilience
  - Per-endpoint timeouts, retries, and blacklisting until healthy

Planned configuration keys:
- --discovery.domain (env: PEW_DISCOVERY_DOMAIN): DNS name to resolve for Pi-hole instances
- --discovery.interval (env: PEW_DISCOVERY_INTERVAL): refresh period
- --sync.mode (env: PEW_SYNC_MODE): all (default) or quorum

---

### Security notes
- PEW talks to Pi-hole over HTTP by default. For production, prefer a network path you trust or put PEW and Pi-hole behind TLS/ingress.
- The Pi-hole password grants admin access; store it as a Kubernetes Secret or environment variable managed by your secret store.
- PEW does not yet implement authentication/authorization on its own endpoints. If exposed beyond the cluster, front it with an ingress that enforces auth.

---

### Development
- Code layout:
  - cmd/ – CLI and HTTP server
  - internal/piholeapi/ – Pi-hole client (auth, config fetch, domain record translation)
  - internal/slogger/ – minimal logger wrapper and context injection
- Useful commands:
  - go run ./cmd --help

---

### Status
- Alpha. Read path is functional for A records; write and multi-instance sync are in progress.

---

### Troubleshooting
- Authentication failures
  - Ensure PEW_PIHOLE_ENDPOINT points to Pi-hole v6 base URL (e.g., http://host:80), and PEW_PIHOLE_PASSWORD matches the admin password
- Empty GET /records
  - PEW reads from Pi-hole dns/hosts; if Pi-hole has no local hosts configured, the list will be empty
- Debug mode
  - Set --log.level=debug to see request logs and payloads

---

### License
MIT (or the license you prefer; update this section accordingly).
