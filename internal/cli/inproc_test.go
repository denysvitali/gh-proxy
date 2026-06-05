// Coverage goal: drive statement coverage of internal/cli/root.go beyond
// what the exec tests in root_test.go achieve. Exec tests launch a
// separate process, so Go's coverage tool cannot see NewRootCmd's code.
// These in-process tests call NewRootCmd and exercise the cobra command
// tree directly, with stdout/stderr captured to buffers so the test
// runner's terminal stays clean.
package cli

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// captureStdout runs fn with os.Stdout redirected to an in-memory buffer
// and returns whatever fn writes to stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() {
		var b bytes.Buffer
		_, _ = io.Copy(&b, r)
		done <- b.String()
	}()
	fn()
	_ = w.Close()
	os.Stdout = old
	return <-done
}

func TestNewRootCmd(t *testing.T) {
	cmd := NewRootCmd()
	if cmd == nil {
		t.Fatal("NewRootCmd returned nil")
	}
	if cmd.Use != "gh-proxy" {
		t.Errorf("Use = %q, want gh-proxy", cmd.Use)
	}
	subs := map[string]bool{}
	for _, c := range cmd.Commands() {
		subs[c.Name()] = true
	}
	for _, want := range []string{"serve", "validate-policy", "hash-token"} {
		if !subs[want] {
			t.Errorf("missing subcommand %q", want)
		}
	}
}

func TestValidatePolicyCmd_Good(t *testing.T) {
	dir := t.TempDir()
	pol := dir + "/policy.yaml"
	if err := os.WriteFile(pol, []byte("version: 1\ntenants:\n  - name: a\n    installation_id: 1\n    org: a\n    repos:\n      - name: app\n        access: read\n        endpoints: [git.read]\nconsumers:\n  - id: c\n    tenant: a\n    token_hashes: [\"$2a$10$xxx\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"validate-policy", pol})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("validate-policy: %v", err)
	}
}

func TestValidatePolicyCmd_MissingFile(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"validate-policy", "/nope.yaml"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidatePolicyCmd_NoArgs(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"validate-policy"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("validate-policy without arg should fail (cobra.ExactArgs)")
	}
}

func TestHashTokenCmd_DefaultGenerates(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"hash-token", "--consumer", "ci-runner"})
	var out string
	capture := func() {
		out = captureStdout(t, func() { _ = cmd.Execute() })
	}
	capture()
	_ = out
	cmd = NewRootCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"hash-token", "--consumer", "ci-runner"})
	stdout := captureStdout(t, func() { _ = cmd.Execute() })
	if !strings.Contains(stdout, "ci-runner.") {
		t.Fatalf("expected token line with ci-runner., got %s", stdout)
	}
}

func TestHashTokenCmd_ProvidedSecret(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"hash-token", "--consumer", "ci", "--secret", "pinned"})
	stdout := captureStdout(t, func() { _ = cmd.Execute() })
	if !strings.Contains(stdout, "ci.pinned") {
		t.Fatalf("expected token 'ci.pinned', got %s", stdout)
	}
}

func TestHashTokenCmd_DotInConsumerID(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"hash-token", "--consumer", "has.dot"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for consumer id with dot")
	}
}

func TestHashTokenCmd_MissingConsumer(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"hash-token"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for missing --consumer")
	}
}

func TestServeCmd_RequiresAppID(t *testing.T) {
	// serve should fail fast when no AppID is configured. We keep this
	// hermetic by clearing the env vars that Load would read.
	t.Setenv("GH_PROXY_GITHUB_APP_ID", "")
	t.Setenv("GH_PROXY_GITHUB_PRIVATE_KEY_PATH", "")
	cmd := NewRootCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"serve"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected serve to fail when no app_id is configured")
	}
}
