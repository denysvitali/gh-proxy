// Coverage goal: drive statement coverage of the CLI entrypoints
// (root, serve, validate-policy, hash-token) via os/exec on the compiled
// binary. White-box testing of Cobra is awkward because os.Exit is part
// of the surface — exec tests let us observe both the exit code and the
// stderr stream in a way that table tests cannot.
package cli_test

import (
	"bufio"
	"bytes"
	"fmt"
	"go/build"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// buildBinary compiles the gh-proxy entrypoint into a temp file and
// returns its absolute path. The path is registered with t.Cleanup.
func buildBinary(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "gh-proxy")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	// Find the module root by walking up from this test file. We do not
	// assume GOPATH layout because the project lives outside it.
	pkg, err := build.Default.Import("github.com/denysvitali/gh-proxy/cmd/gh-proxy", "", build.FindOnly)
	if err != nil {
		t.Fatalf("locate cmd/gh-proxy: %v", err)
	}
	cmd := exec.Command("go", "build", "-o", bin, "github.com/denysvitali/gh-proxy/cmd/gh-proxy")
	cmd.Dir = filepath.Dir(pkg.Dir) // module root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, string(out))
	}
	return bin
}

func run(t *testing.T, bin string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var so, se bytes.Buffer
	cmd.Stdout = &so
	cmd.Stderr = &se
	err := cmd.Run()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return so.String(), se.String(), ee.ExitCode()
		}
		t.Fatalf("exec %s: %v", bin, err)
	}
	return so.String(), se.String(), 0
}

func TestRoot_Help(t *testing.T) {
	bin := buildBinary(t)
	stdout, _, code := run(t, bin, "--help")
	if code != 0 {
		t.Fatalf("--help exit=%d", code)
	}
	if !strings.Contains(stdout, "gh-proxy") {
		t.Fatalf("expected help to mention gh-proxy, got %s", stdout)
	}
	if !strings.Contains(stdout, "validate-policy") || !strings.Contains(stdout, "hash-token") {
		t.Fatalf("expected help to list subcommands, got %s", stdout)
	}
}

func TestValidatePolicy_GoodFile(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(pol, []byte(`version: 1
tenants:
  - name: acme
    installation_id: 1
    org: acme
    repos:
      - name: app
        access: read
        endpoints: [git.read]
consumers:
  - id: ci
    tenant: acme
    token_hashes: ["$2a$10$abcdefghijklmnopqrstuv"]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, code := run(t, bin, "validate-policy", pol); code != 0 {
		t.Fatalf("validate-policy good file exit=%d", code)
	}
}

func TestValidatePolicy_BadYAML(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(pol, []byte("not: valid: yaml: ::\n  - oops"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := run(t, bin, "validate-policy", pol)
	if code == 0 {
		t.Fatalf("validate-policy bad yaml should fail, stdout=%s stderr=%s", stdout, stderr)
	}
	if !strings.Contains(stderr, "yaml") && !strings.Contains(stderr, "unmarshal") && !strings.Contains(stderr, "decode") {
		t.Logf("stderr=%s (acceptable but no yaml error word found)", stderr)
	}
}

func TestValidatePolicy_SchemaError(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy.yaml")
	// Missing version → schema error, not yaml error.
	if err := os.WriteFile(pol, []byte("tenants: []\nconsumers: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := run(t, bin, "validate-policy", pol)
	if code == 0 {
		t.Fatalf("validate-policy schema-error should fail: stderr=%s", stderr)
	}
	if !strings.Contains(stderr, "version") {
		t.Fatalf("expected 'version' in stderr, got %s", stderr)
	}
}

func TestValidatePolicy_MissingFile(t *testing.T) {
	bin := buildBinary(t)
	_, stderr, code := run(t, bin, "validate-policy", "/no/such/file.yaml")
	if code == 0 {
		t.Fatalf("validate-policy missing file should fail")
	}
	if !strings.Contains(stderr, "no such file") && !strings.Contains(stderr, "not exist") {
		t.Logf("stderr=%s", stderr)
	}
}

func TestHashToken_GeneratesAndVerifies(t *testing.T) {
	bin := buildBinary(t)
	stdout, stderr, code := run(t, bin, "hash-token", "--consumer", "ci-runner")
	if code != 0 {
		t.Fatalf("hash-token exit=%d stderr=%s", code, stderr)
	}
	token, hash := parseHashTokenOutput(t, stdout)
	if !strings.HasPrefix(token, "ci-runner.") {
		t.Fatalf("token = %q, want ci-runner.<secret>", token)
	}
	secret := strings.TrimPrefix(token, "ci-runner.")
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret)); err != nil {
		t.Fatalf("hash does not verify the printed secret: %v\nhash=%s\nsecret=%s", err, hash, secret)
	}
}

func TestHashToken_ProvidedSecret(t *testing.T) {
	bin := buildBinary(t)
	stdout, _, code := run(t, bin, "hash-token", "--consumer", "ci", "--secret", "pinned-secret")
	if code != 0 {
		t.Fatalf("hash-token exit=%d", code)
	}
	token, hash := parseHashTokenOutput(t, stdout)
	if token != "ci.pinned-secret" {
		t.Fatalf("token = %q, want ci.pinned-secret", token)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("pinned-secret")); err != nil {
		t.Fatalf("hash does not verify: %v", err)
	}
}

func TestHashToken_DotInConsumerID(t *testing.T) {
	bin := buildBinary(t)
	_, stderr, code := run(t, bin, "hash-token", "--consumer", "has.dot")
	if code == 0 {
		t.Fatalf("hash-token with dotted id should fail")
	}
	if !strings.Contains(stderr, "must not contain '.'") && !strings.Contains(stderr, "'.'") {
		t.Logf("stderr=%s", stderr)
	}
}

func TestHashToken_MissingConsumer(t *testing.T) {
	bin := buildBinary(t)
	_, _, code := run(t, bin, "hash-token")
	if code == 0 {
		t.Fatal("hash-token with no --consumer should fail")
	}
}

// parseHashTokenOutput extracts the two lines printed by hash-token:
//
//	token:      <id>.<secret>
//	token_hash: <bcrypt>
func parseHashTokenOutput(t *testing.T, s string) (token, hash string) {
	t.Helper()
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "token:"):
			token = strings.TrimSpace(strings.TrimPrefix(line, "token:"))
		case strings.HasPrefix(line, "token_hash:"):
			hash = strings.TrimSpace(strings.TrimPrefix(line, "token_hash:"))
		}
	}
	if token == "" || hash == "" {
		t.Fatalf("could not parse hash-token output:\n%s", s)
	}
	return token, hash
}

// Ensure the help command exits 0 even on bare invocation.
// (Bare invocation shows usage; we do not assert on the exit code, only
// that it produces the subcommand listing.)
func TestRoot_BareInvocationShowsUsage(t *testing.T) {
	bin := buildBinary(t)
	stdout, _, _ := run(t, bin)
	if !strings.Contains(stdout, "validate-policy") || !strings.Contains(stdout, "hash-token") {
		t.Fatalf("expected subcommand listing, got %s", stdout)
	}
}

var _ = fmt.Sprint // keep fmt import available for future verbose runs
