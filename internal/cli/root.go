package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/denysvitali/gh-proxy/internal/config"
	"github.com/denysvitali/gh-proxy/internal/server"
)

// NewRootCmd returns the gh-proxy root command.
func NewRootCmd() *cobra.Command {
	var cfgFile string

	root := &cobra.Command{
		Use:   "gh-proxy",
		Short: "Multi-tenant Git/GitHub proxy backed by Kubernetes policy",
	}
	root.PersistentFlags().StringVar(&cfgFile, "config", "", "path to config file (yaml)")

	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the proxy HTTP server",
		RunE: func(_ *cobra.Command, _ []string) error {
			v := viper.New()
			if cfgFile != "" {
				v.SetConfigFile(cfgFile)
			} else {
				v.SetConfigName("gh-proxy")
				v.AddConfigPath(".")
				v.AddConfigPath("/etc/gh-proxy")
			}
			v.SetEnvPrefix("GH_PROXY")
			v.AutomaticEnv()

			cfg, err := config.Load(v)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}

			log := logrus.New()
			log.SetFormatter(&logrus.JSONFormatter{})
			if cfg.LogLevel != "" {
				if lvl, err := logrus.ParseLevel(cfg.LogLevel); err == nil {
					log.SetLevel(lvl)
				}
			}

			srv, err := server.New(cfg, log)
			if err != nil {
				return err
			}

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			return srv.Run(ctx)
		},
	}

	validateCmd := &cobra.Command{
		Use:   "validate-policy [file]",
		Short: "Validate a policy YAML document",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			b, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			return config.ValidatePolicyYAML(b)
		},
	}

	root.AddCommand(serveCmd, validateCmd)
	return root
}
