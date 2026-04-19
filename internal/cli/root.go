// Package cli wires Cobra commands for the gh-proxy binary.
package cli

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/denysvitali/gh-proxy/internal/config"
	"github.com/denysvitali/gh-proxy/internal/server"
	"github.com/denysvitali/gh-proxy/internal/token"
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

			logrus.SetFormatter(&logrus.JSONFormatter{})
			if cfg.LogLevel != "" {
				if lvl, err := logrus.ParseLevel(cfg.LogLevel); err == nil {
					logrus.SetLevel(lvl)
				}
			}

			srv, err := server.New(cfg)
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

	var (
		hashConsumer string
		hashSecret   string
		hashGenerate bool
	)
	hashCmd := &cobra.Command{
		Use:   "hash-token",
		Short: "Generate a consumer token and its bcrypt hash for policy.yaml",
		Long: strings.TrimSpace(`
Generate a static consumer token and a bcrypt hash of its secret. Put the hash
under consumers[].token_hashes in policy.yaml; give the full token to the
consumer. The token format on the wire is "<consumer-id>.<secret>".
`),
		RunE: func(_ *cobra.Command, _ []string) error {
			if hashConsumer == "" {
				return fmt.Errorf("--consumer is required")
			}
			if strings.Contains(hashConsumer, ".") {
				return fmt.Errorf("consumer id must not contain '.'")
			}
			secret := hashSecret
			if hashGenerate || secret == "" {
				var b [32]byte
				if _, err := rand.Read(b[:]); err != nil {
					return err
				}
				secret = base64.RawURLEncoding.EncodeToString(b[:])
			}
			h, err := token.Hash(secret)
			if err != nil {
				return err
			}
			fmt.Printf("token:      %s.%s\n", hashConsumer, secret)
			fmt.Printf("token_hash: %s\n", h)
			return nil
		},
	}
	hashCmd.Flags().StringVar(&hashConsumer, "consumer", "", "consumer id (must match policy.yaml)")
	hashCmd.Flags().StringVar(&hashSecret, "secret", "", "secret to hash (default: random 32 bytes)")
	hashCmd.Flags().BoolVar(&hashGenerate, "generate", false, "force generation of a random secret even if --secret is set")

	root.AddCommand(serveCmd, validateCmd, hashCmd)
	return root
}
