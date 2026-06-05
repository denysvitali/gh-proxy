# gh-proxy

Multi-tenant Git/GitHub proxy that sits between internal consumers and GitHub
App installations. Consumers authenticate to gh-proxy with static bearer
tokens whose secret is bcrypt-hashed in the policy document; gh-proxy enforces
repo- and endpoint-scoped policy loaded from Kubernetes ConfigMaps and
forwards allowed requests using a GitHub App installation token.

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

Mint a token, store its hash in policy.yaml, and call through the proxy:

```bash
# 1. Generate a token + bcrypt hash
./bin/gh-proxy hash-token --consumer ci-runner
# token:      ci-runner.<secret>
# token_hash: $2a$10$...

# 2. Paste token_hash under consumers[id=ci-runner].token_hashes in policy.yaml.
# 3. Hand the full token to the consumer.

# Git clone through the proxy
git clone http://ci-runner.<secret>@localhost:8080/git/acme/app
```

Tokens are static: rotate by adding a new hash, distributing the new token,
then removing the old hash. Multiple hashes per consumer are allowed to enable
overlap during rotation.

## Kubernetes

- Mount your policy document as a ConfigMap at `policy_path`. Consumer token
  hashes live in that document — either in the ConfigMap (bcrypt hashes are
  not secret) or, if you prefer, render the policy from a Secret.
- Mount the GitHub App private key as a Secret.
- Deploy `gh-proxy serve` with a readiness probe on `/healthz`.

Example snippets live in `examples/`.

## Configuration

Loaded via Viper (YAML + env vars prefixed `GH_PROXY_`). Keys:

| Key | Description |
| --- | --- |
| `listen_addr` | HTTP listen address (default `:8080`) |
| `log_level` | `debug`/`info`/`warn`/`error` |
| `policy_path` | Path to policy YAML (ConfigMap mount) |
| `github.app_id` | GitHub App ID |
| `github.private_key_path` | Path to the App private key PEM |
| `github.api_base_url` | GitHub API base (default `https://api.github.com`) |
| `git_push_max_body_bytes` | Cap on a single git-receive-pack body (default 1 MiB) |
| `body_limit_bytes` | Global per-path request body cap (16 MiB `/api/*`, 4 MiB `/git/*` by default) |

## Policy features

The policy document supports these per-repo fields, in addition to
`name`, `access`, and `endpoints`:

```yaml
tenants:
  - name: acme
    installation_id: 12345678
    org: acme
    repos:
      - name: app
        access: write
        endpoints: [git.read, git.write, api.refs, api.pulls]
        # Optional: filter pushed ref names against the receive-pack
        # body. Patterns are Git-style single-segment globs.
        ref_allow: [refs/heads/feature/*, refs/heads/fix/*]
        ref_deny: [refs/heads/wip/*]
        protected_refs: [master, main]   # short names → refs/heads/<name>
consumers:
  - id: ci-runner
    tenant: acme
    token_hashes: ["$2a$10$..."]
    # Optional: pin this consumer to specific source IPs.
    ip_allow: [10.0.0.0/8, 192.168.1.0/24]
```

The `endpoints` list understands the following classes:

| Class                | Covers                                                       |
| -------------------- | ------------------------------------------------------------ |
| `git.read`           | `GET` on `/info/refs?service=git-upload-pack`, fetch pack    |
| `git.write`          | `POST` on `/git-receive-pack`, push                          |
| `actions.workflows`  | `GET`/`POST` on `/actions/...`                               |
| `api.refs`           | `GET`/`POST` on `/git/refs/...`, `/contents/...`             |
| `api.pulls`          | read PRs (umbrella — also grants `api.pulls.create` and `api.pulls.review` for backwards compat) |
| `api.pulls.create`   | `POST /pulls`, `PATCH /pulls/{id}`                           |
| `api.pulls.review`   | `POST /pulls/{id}/reviews`, `/pulls/{id}/comments`           |
| `api.pulls.merge`    | `PUT/POST /pulls/{id}/merge`, approve/request-changes events |
| `*`                  | everything, including `api.pulls.merge`                      |

See `DESIGN.md` for the parser-based push check, the parse-fail-allow
trade-off, and the reasoning behind the `api.pulls.merge` opt-in.

## Observability

Structured JSON logs via logrus. OpenTelemetry traces and metrics are wired
in at the middleware level (see `ARCHITECTURE.md`).

## Local development

```bash
go test ./...
go run ./cmd/gh-proxy serve --config examples/gh-proxy.yaml
```

See `ARCHITECTURE.md` for system shape and `DESIGN.md` for the security model.
