package config

import (
	"testing"

	"github.com/spf13/viper"
)

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
