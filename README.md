# gh-proxy

Multi-tenant Git/GitHub proxy that sits between internal consumers and GitHub
App installations. Consumers authenticate to gh-proxy with short-lived tokens;
gh-proxy enforces repo- and endpoint-scoped policy loaded from Kubernetes
ConfigMaps and forwards allowed requests using a GitHub App installation token.

Consumers never see GitHub credentials.

## Quick start

```bash
go build -o bin/gh-proxy ./cmd/gh-proxy
./bin/gh-proxy serve --config ./examples/gh-proxy.yaml
```

Validate a policy file:

```bash
./bin/gh-proxy validate-policy ./examples/policy.yaml
```

Issue a token and call through the proxy:

```bash
curl -s http://localhost:8080/v1/tokens \
  -d '{"tenant":"acme","consumer":"ci-runner"}' \
  -H 'content-type: application/json'

# Git clone through the proxy
git clone http://<token>@localhost:8080/git/acme/app
```

## Kubernetes

- Mount your policy document as a ConfigMap at `policy_path`.
- Mount the GitHub App private key and token signing key as Secrets.
- Deploy `gh-proxy serve` with a readiness probe on `/healthz`.

Example snippets live in `examples/`.

## Configuration

Loaded via Viper (YAML + env vars prefixed `GH_PROXY_`). Keys:

| Key | Description |
| --- | --- |
| `listen_addr` | HTTP listen address (default `:8080`) |
| `log_level` | `debug`/`info`/`warn`/`error` |
| `token_signing_key` | HMAC key for consumer tokens |
| `policy_path` | Path to policy YAML (ConfigMap mount) |
| `github.app_id` | GitHub App ID |
| `github.private_key_path` | Path to the App private key PEM |
| `github.api_base_url` | GitHub API base (default `https://api.github.com`) |

## Observability

Structured JSON logs via logrus. OpenTelemetry traces and metrics are wired
in at the middleware level (see `ARCHITECTURE.md`).

## Local development

```bash
go test ./...
go run ./cmd/gh-proxy serve --config examples/gh-proxy.yaml
```

See `ARCHITECTURE.md` for system shape and `DESIGN.md` for the security model.
