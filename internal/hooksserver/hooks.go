package hooksserver

import (
	"log/slog"

	"github.com/falmar/pihole-external-dns-webhooks/internal/dnssyncer"
)

type HookServer interface{}

func NewHooksServer(logger *slog.Logger, syncer dnssyncer.DNSSyncer) HookServer {
	return &hooksServer{logger: logger, syncer: syncer}
}

type hooksServer struct {
	logger *slog.Logger
	syncer dnssyncer.DNSSyncer
}
