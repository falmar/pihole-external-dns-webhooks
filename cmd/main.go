package main

import (
	"context"
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

	rootCmd = &cobra.Command{
		Use:   "pew",
		Short: "pihole external dns webhooks",
		Long:  "PEW helps with pihole multi replica deployment local dns synchronization",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return initConfig()
		},
	}
)

var initCmd = &cobra.Command{}

func init() {
	v := viper.GetViper()
	v.SetEnvPrefix("PEW")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// pre-run flags to parse
	initCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default: ./.config.yaml)")
	initCmd.PersistentFlags().BoolP("debug", "d", false, "Debug mode")
	initCmd.PersistentFlags().String("log.level", "info", "Log level (info|debug)")
	initCmd.PersistentFlags().String("log.format", "text", "Log level (text|json)")

	_ = viper.BindPFlag("config", initCmd.PersistentFlags().Lookup("config"))
	_ = viper.BindEnv("config", "CONFIG_PATH")

	_ = viper.BindEnv("debug", "DEBUG")
	_ = viper.BindEnv("log.level", "PEW_LOG_LEVEL")
	_ = viper.BindEnv("log.format", "PEW_LOG_FORMAT")

	_ = initCmd.ParseFlags(os.Args)
	// --
}

func initConfig() error {
	v := viper.GetViper()

	if cfgFile != "" {
		slog.Info("reading config", "path", cfgFile)
		v.SetConfigFile(cfgFile)

		return v.ReadInConfig()
	}

	return nil
}

func setFlags(cmd *cobra.Command) {
	rootCmd.PersistentFlags().StringP("config", "c", "", "config file (default: ./.config.yaml)")
	rootCmd.PersistentFlags().BoolP("debug", "d", false, "Debug mode")
	rootCmd.PersistentFlags().String("log.level", "info", "Log level (info|debug)")
	rootCmd.PersistentFlags().String("log.format", "text", "Log level (text|json)")

	rootCmd.PersistentFlags().StringP("port", "p", "8080", "HTTP server port")
	rootCmd.PersistentFlags().String("pihole.endpoint", "http://127.0.0.1:80", "Pihole base URL")
	rootCmd.PersistentFlags().String("pihole.password", "", "Pihole password used for authentication")

	_ = viper.BindPFlags(rootCmd.PersistentFlags())
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	rootCmd.AddCommand(serveCmd)

	setFlags(rootCmd)

	logger := slogger.New(
		viper.GetString("log.format"),
		viper.GetString("log.level"),
	)
	ctx = slogger.WithLogger(ctx, logger)

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		logger.Error("unexpected error", "err", err)
		os.Exit(1)
	}
}
