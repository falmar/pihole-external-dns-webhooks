package slogger

import (
	"log/slog"
	"os"
	"strings"
)

func New(format string, level string) *slog.Logger {
	var opts *slog.HandlerOptions = &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	var h slog.Handler

	if strings.ToLower(level) == "debug" {
		opts.Level = slog.LevelDebug
	}

	if strings.ToLower(format) == "json" {
		h = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		h = slog.NewTextHandler(os.Stderr, opts)
	}

	logger := slog.New(
		h,
	)

	return logger
}
