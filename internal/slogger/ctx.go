package slogger

import (
	"context"
	"log/slog"
)

type contextKey struct{}

var ctxKey = contextKey{}

func FromContext(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(ctxKey).(*slog.Logger); ok {
		return logger
	}

	return slog.New(slog.DiscardHandler)
}

func WithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxKey, logger)
}
