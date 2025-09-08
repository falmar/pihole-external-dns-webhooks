package slogger

import (
	"log/slog"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"
	"go.uber.org/zap/zapcore"
)

func New(format string, level string) *slog.Logger {
	var lConfig zap.Config

	if format == "text" {
		lConfig = zap.NewDevelopmentConfig()
		lConfig.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	} else {
		lConfig = zap.NewProductionConfig()
	}

	lConfig.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	if strings.ToUpper(level) == "DEBUG" {
		lConfig.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	}

	zapLog, _ := lConfig.Build()
	logger := slog.New(
		zapslog.NewHandler(
			zapLog.Core(),
			zapslog.AddStacktraceAt(9999),
		),
	)

	return logger
}
