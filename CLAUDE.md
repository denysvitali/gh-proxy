# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
go build -o bin/gh-proxy ./cmd/gh-proxy
go test ./...
go test ./internal/policy -run TestEngine_Allow    # single test
go run ./cmd/gh-proxy serve --config examples/gh-proxy.yaml
go run ./cmd/gh-proxy validate-policy examples/policy.yaml
golangci-lint run                                   # config in .golangci.yml
```

Release/CI: GoReleaser (`.goreleaser.yaml`) publishes binaries and a Docker image to GHCR. CI runs on the `master` branch only (`.github/workflows`).

## Architecture

gh-proxy is a stateless, Kubernetes-first HTTP service that brokers Git smart-HTTP and a curated subset of the GitHub API between internal consumers and GitHub App installations. Consumers never see GitHub credentials — they authenticate with static bearer tokens of the form `<consumer-id>.<secret>` whose secret is bcrypt-hashed under `consumers[].token_hashes` in the policy document; the proxy exchanges its App JWT for installation tokens and forwards allowed requests upstream.

Read `ARCHITECTURE.md` and `DESIGN.md` before making non-trivial changes — they define the trust boundaries and authorization model that the code implements.

### Package layout (`internal/`)

- `cli` / `cmd/gh-proxy` — Cobra entrypoints (`serve`, `validate-policy`, `hash-token`). Viper loads YAML + `GH_PROXY_*` env vars.
- `server` — Gin HTTP server wiring: middleware, route mounts, health.
- `proxy` — data plane. Classifies the request into an endpoint class (`git.read`, `git.write`, `actions.workflows`, `api.refs`, `api.pulls`, `*`), consults policy, rewrites to `github.com`/`api.github.com`, and streams the response.
- `policy` — parses the policy document and evaluates `(tenant, org, repo, endpoint, write?)`. RW-lock protected so ConfigMap hot-swaps are safe. Resolution is exact-repo first, then `*` fallback.
- `token` — static bearer-token verifier. Parses `<consumer-id>.<secret>`, looks the consumer up via `policy.Engine.Consumer`, and bcrypt-compares the secret against `token_hashes`.
- `ghapp` — GitHub App JWT → installation token exchange with an in-memory cache (evicted ~1m before expiry).
- `webhook` — optional receiver for installation sync / revocation / cache invalidation.
- `telemetry` — OpenTelemetry traces + metrics middleware; spans are labeled with `tenant`, `repo`, `endpoint`.
- `config` — Viper config struct and `ReadPolicyFile`.

### Key invariants

- **Default deny**: unknown endpoint classes return 403. Authorization requires *both* repo-level access (`read`/`write`) and an explicit endpoint-class match.
- **Stateless**: no database. Only in-memory caches (installation tokens, compiled policy). Do not introduce persistent state without updating `DESIGN.md`.
- **Out of scope**: path/branch-level Git authorization, per-consumer blocklists, general-purpose GitHub proxying.

## Conventions

- Conventional Commits (`feat(proxy): …`, `fix(policy): …`).
- Branches: `type/what` (e.g. `feature/webhook-revocation`).
- When editing GitHub Actions workflows, pin to the latest versions listed at https://raw.githubusercontent.com/simonw/actions-latest/refs/heads/main/versions.txt
