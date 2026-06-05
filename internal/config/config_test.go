// Coverage goal: drive internal/config to 90%+ by exercising all the
// branches in Load, ReadPolicyFile, ValidatePolicyYAML, and the
// mapstructure tag walker. Each subtest names the branch it covers
// (e.g. "env-overrides-file", "missing-policy-file", "default-values")
// so a future contributor can see at a glance what the test is
// protecting.
package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/spf13/viper"

	"github.com/denysvitali/gh-proxy/internal/policy"
)

func reflectTypeOfConfig() reflect.Type { return reflect.TypeOf(Config{}) }
func reflectTypeOfString() reflect.Type { return reflect.TypeOf("") }

func TestLoad_EnvOverridesWithoutConfigFile(t *testing.T) {
	t.Setenv("GH_PROXY_GITHUB_APP_ID", "42")
	t.Setenv("GH_PROXY_LOG_LEVEL", "debug")

	v := viper.New()
	v.SetEnvPrefix("GH_PROXY")
	v.AutomaticEnv()

	cfg, err := Load(v)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.GitHub.AppID != 42 {
		t.Errorf("github.app_id = %d, want 42", cfg.GitHub.AppID)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("log_level = %q, want debug", cfg.LogLevel)
	}
}

// TestLoad_Defaults confirms Load sets the documented default values
// when no config file and no env vars are present.
func TestLoad_Defaults(t *testing.T) {
	// Clear all GH_PROXY_* env vars that could affect defaults.
	for _, k := range []string{
		"GH_PROXY_LISTEN_ADDR", "GH_PROXY_LOG_LEVEL",
		"GH_PROXY_GITHUB_API_BASE_URL", "GH_PROXY_POLICY_PATH",
		"GH_PROXY_OTEL_ENDPOINT", "GH_PROXY_WEBHOOK_SECRET",
		"GH_PROXY_GITHUB_APP_ID", "GH_PROXY_GITHUB_PRIVATE_KEY_PATH",
	} {
		t.Setenv(k, "")
	}
	v := viper.New()
	v.SetEnvPrefix("GH_PROXY")
	v.AutomaticEnv()
	cfg, err := Load(v)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != ":8080" {
		t.Errorf("listen_addr default = %q, want :8080", cfg.ListenAddr)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("log_level default = %q, want info", cfg.LogLevel)
	}
	if cfg.GitHub.APIBaseURL != "https://api.github.com" {
		t.Errorf("github.api_base_url default = %q", cfg.GitHub.APIBaseURL)
	}
}

// TestLoad_EnvOverridesListenAddr covers the env var precedence for a
// non-github key (proves the BindEnv loop walks all mapstructure tags).
func TestLoad_EnvOverridesListenAddr(t *testing.T) {
	t.Setenv("GH_PROXY_LISTEN_ADDR", ":9999")
	v := viper.New()
	v.SetEnvPrefix("GH_PROXY")
	v.AutomaticEnv()
	cfg, err := Load(v)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != ":9999" {
		t.Errorf("listen_addr = %q, want :9999", cfg.ListenAddr)
	}
}

// TestLoad_BadConfigFile confirms Load returns a non-ConfigFileNotFound
// error when the file exists but is unparseable.
func TestLoad_BadConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "gh-proxy.yaml")
	if err := os.WriteFile(cfg, []byte(": not: yaml: ::\n - oops"), 0o600); err != nil {
		t.Fatal(err)
	}
	v := viper.New()
	v.SetConfigFile(cfg)
	v.SetEnvPrefix("GH_PROXY")
	v.AutomaticEnv()
	if _, err := Load(v); err == nil {
		t.Fatal("expected error parsing bad config")
	}
}

func TestReadPolicyFile_Happy(t *testing.T) {
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(pol, []byte("version: 1\ntenants:\n  - name: a\n    installation_id: 1\n    org: a\n    repos:\n      - name: app\n        access: read\n        endpoints: [git.read]\nconsumers:\n  - id: c\n    tenant: a\n    token_hashes: [\"$2a$10$xxx\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err := ReadPolicyFile(pol)
	if err != nil {
		t.Fatalf("ReadPolicyFile: %v", err)
	}
	if len(doc.Tenants) != 1 || doc.Tenants[0].Name != "a" {
		t.Fatalf("unexpected doc: %+v", doc)
	}
}

func TestReadPolicyFile_Missing(t *testing.T) {
	if _, err := ReadPolicyFile("/nope/policy.yaml"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestReadPolicyFile_BadYAML(t *testing.T) {
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(pol, []byte("a: b: c\n - d"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPolicyFile(pol); err == nil {
		t.Fatal("expected yaml error")
	}
}

func TestReadPolicyFile_SchemaError(t *testing.T) {
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy.yaml")
	// Valid YAML, but version is missing → Validate() error.
	if err := os.WriteFile(pol, []byte("tenants: []\nconsumers: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPolicyFile(pol); err == nil {
		t.Fatal("expected schema error")
	}
}

func TestValidatePolicyYAML(t *testing.T) {
	// Bare version:1 is valid (no tenants/consumers is allowed in v1).
	if err := ValidatePolicyYAML([]byte("version: 1\n")); err != nil {
		t.Fatalf("empty-but-versioned policy should pass: %v", err)
	}
	if err := ValidatePolicyYAML([]byte("not: valid: yaml: ::")); err == nil {
		t.Fatal("bad yaml should fail")
	}
	if err := ValidatePolicyYAML([]byte(`version: 1
tenants:
  - name: a
    installation_id: 1
    org: a
    repos:
      - name: app
        access: read
        endpoints: [git.read]
consumers:
  - id: c
    tenant: a
    token_hashes: ["$2a$10$xxx"]
`)); err != nil {
		t.Fatalf("valid policy should pass: %v", err)
	}
}

// TestReadPolicyFile_ThenEngineReplace covers the round-trip used by
// server.New: read a policy file, hand it to a policy.Engine, and verify
// the engine exposes it.
func TestReadPolicyFile_ThenEngineReplace(t *testing.T) {
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(pol, []byte("version: 1\ntenants:\n  - name: a\n    installation_id: 1\n    org: a\n    repos:\n      - name: app\n        access: read\n        endpoints: [git.read]\nconsumers:\n  - id: c\n    tenant: a\n    token_hashes: [\"$2a$10$xxx\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err := ReadPolicyFile(pol)
	if err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(doc)
	if _, ok := eng.Tenant("a"); !ok {
		t.Fatal("engine should expose tenant a after Replace")
	}
}

// TestMapstructureKeys exercises the reflect walker: it must produce
// keys for every exported field with a mapstructure tag, including
// nested ones prefixed with the parent name.
func TestMapstructureKeys(t *testing.T) {
	keys := mapstructureKeys(reflectTypeOfConfig(), "")
	want := map[string]bool{
		"listen_addr":             true,
		"log_level":               true,
		"policy_path":             true,
		"github.app_id":           true,
		"github.private_key_path": true,
		"github.api_base_url":     true,
		"otel_endpoint":           true,
		"webhook_secret":          true,
	}
	for k := range want {
		found := false
		for _, kk := range keys {
			if kk == k {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("mapstructureKeys missing %q (got %v)", k, keys)
		}
	}
}

func TestMapstructureKeys_ScalarType(t *testing.T) {
	// A non-struct top-level returns just the prefix (empty here).
	if k := mapstructureKeys(reflectTypeOfString(), ""); k != nil {
		t.Errorf("expected nil for scalar type, got %v", k)
	}
	if k := mapstructureKeys(reflectTypeOfString(), "prefix"); len(k) != 1 || k[0] != "prefix" {
		t.Errorf("scalar with prefix = %v, want [prefix]", k)
	}
}
