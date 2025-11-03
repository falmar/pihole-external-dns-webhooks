package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"

	"github.com/falmar/pihole-external-dns-webhooks/internal/slogger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	logger  *slog.Logger

	rootCmd = &cobra.Command{
		Use:   "pew",
		Short: "pihole external dns webhooks",
		Long:  "PEW helps with pihole multi replica deployment local dns synchronization",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			err := initConfig()
			if err != nil {
				return err
			}

			logger = slogger.New(
				viper.GetString("log.format"),
				viper.GetString("log.level"),
			)
			ctx = slogger.WithLogger(ctx, logger)

			cmd.SetContext(ctx)

			return nil
		},
	}
)

func init() {
	v := viper.GetViper()
	v.SetEnvPrefix("PEW")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	_ = viper.BindEnv("config", "CONFIG_PATH")
	_ = viper.BindEnv("debug", "DEBUG")
	_ = viper.BindEnv("log.level", "LOG_LEVEL")
	_ = viper.BindEnv("log.format", "LOG_FORMAT")
}

func initConfig() error {
	v := viper.GetViper()

	if cfgFile != "" {
		slog.Info("reading config", "path", cfgFile)
		v.SetConfigFile(cfgFile)
		if err := v.ReadInConfig(); err != nil {
			return fmt.Errorf("unable to read config: %w", err)
		}

		return nil
	}

	return nil
}

func setFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default: ./.config.yaml)")
	cmd.PersistentFlags().BoolP("debug", "d", false, "Debug mode")
	cmd.PersistentFlags().String("log.level", "info", "Log level (info|debug)")
	cmd.PersistentFlags().String("log.format", "text", "Log level (text|json)")

	cmd.PersistentFlags().StringP("port", "p", "8080", "HTTP server port")
	cmd.PersistentFlags().String("pihole.endpoint", "http://127.0.0.1:80", "Pihole base URL")
	cmd.PersistentFlags().String("pihole.password", "", "Pihole password used for authentication")

	cmd.PersistentFlags().StringSlice("filters", nil, "Domain filters for ExternalDNS negotiation (can be empty)")

	_ = viper.BindPFlags(cmd.PersistentFlags())
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	rootCmd.AddCommand(serveCmd)

	setFlags(rootCmd)

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		if logger != nil {
			logger.Error(err.Error())
		} else {
			slog.Error(err.Error())
		}

		os.Exit(1)
	}
}
