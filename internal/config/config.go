// Package config loads the gh-proxy YAML/env configuration.
package config

import (
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"github.com/denysvitali/gh-proxy/internal/policy"
)

// mapstructureKeys walks t and returns every dotted key reachable via
// `mapstructure` tags. Used to BindEnv every config key so env overrides
// work even when the key is absent from the config file — Viper's
// AutomaticEnv alone does not do this (spf13/viper#761).
func mapstructureKeys(t reflect.Type, prefix string) []string {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		if prefix == "" {
			return nil
		}
		return []string{prefix}
	}
	var keys []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("mapstructure")
		if tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		key := name
		if prefix != "" {
			key = prefix + "." + name
		}
		keys = append(keys, mapstructureKeys(f.Type, key)...)
	}
	return keys
}

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

	// Map nested keys like github.app_id to GH_PROXY_GITHUB_APP_ID, and
	// explicitly bind every key so env overrides work even when the key is
	// absent from the config file.
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	for _, k := range mapstructureKeys(reflect.TypeOf(Config{}), "") {
		_ = v.BindEnv(k)
	}

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
