package dnssyncer

import "log/slog"

type DNSSyncer interface{}

func NewSyncer(logger *slog.Logger) DNSSyncer {
	return &dnsSyncer{
		logger: logger,
	}
}

type dnsSyncer struct {
	logger *slog.Logger
}
