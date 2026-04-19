package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"github.com/kaiko-ai/gh-proxy/internal/policy"
)

// Config is the top-level runtime config for gh-proxy.
type Config struct {
	ListenAddr string `mapstructure:"listen_addr"`
	LogLevel   string `mapstructure:"log_level"`

	// TokenSigningKey is used to HMAC-sign short-lived consumer tokens.
	// In Kubernetes this is sourced from a Secret.
	TokenSigningKey string `mapstructure:"token_signing_key"`

	// PolicyPath points at a directory or file containing policy YAML
	// (typically a mounted ConfigMap).
	PolicyPath string `mapstructure:"policy_path"`

	// GitHub describes how to authenticate as a GitHub App.
	GitHub GitHubAppConfig `mapstructure:"github"`

	// OTel endpoint for OTLP/HTTP export (optional).
	OTelEndpoint string `mapstructure:"otel_endpoint"`

	// WebhookSecret validates GitHub webhook deliveries (optional).
	WebhookSecret string `mapstructure:"webhook_secret"`

	// Upstream configures the guard in front of /v1/tokens.
	Upstream UpstreamAuthConfig `mapstructure:"upstream"`
}

// UpstreamAuthConfig configures the /v1/tokens guard.
type UpstreamAuthConfig struct {
	Header         string `mapstructure:"header"`
	ExpectedPrefix string `mapstructure:"expected_prefix"`
	SharedToken    string `mapstructure:"shared_token"`
	TokenHeader    string `mapstructure:"token_header"`
	Disabled       bool   `mapstructure:"disabled"` // opt-out, for dev only
}

// GitHubAppConfig holds GitHub App credentials.
type GitHubAppConfig struct {
	AppID          int64  `mapstructure:"app_id"`
	PrivateKeyPath string `mapstructure:"private_key_path"`
	APIBaseURL     string `mapstructure:"api_base_url"`
}

// Load reads the config via viper, applying defaults.
func Load(v *viper.Viper) (*Config, error) {
	v.SetDefault("listen_addr", ":8080")
	v.SetDefault("log_level", "info")
	v.SetDefault("github.api_base_url", "https://api.github.com")

	if err := v.ReadInConfig(); err != nil {
		// Missing file is OK if env vars provide everything.
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	var c Config
	if err := v.Unmarshal(&c); err != nil {
		return nil, err
	}
	if c.TokenSigningKey == "" {
		return nil, fmt.Errorf("token_signing_key is required")
	}
	if !c.Upstream.Disabled && c.Upstream.Header == "" && c.Upstream.SharedToken == "" {
		return nil, fmt.Errorf("upstream auth is required: set upstream.header, upstream.shared_token, or upstream.disabled=true")
	}
	return &c, nil
}

// ValidatePolicyYAML parses a policy document and returns an error if invalid.
func ValidatePolicyYAML(b []byte) error {
	var doc policy.Document
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return err
	}
	return doc.Validate()
}

// ReadPolicyFile is a small helper for bootstrapping.
func ReadPolicyFile(path string) (*policy.Document, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc policy.Document
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	if err := doc.Validate(); err != nil {
		return nil, err
	}
	return &doc, nil
}
