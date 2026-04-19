# Architecture

## System overview

gh-proxy is a Kubernetes-first HTTP service that proxies both Git smart HTTP
traffic and a curated subset of the GitHub API on behalf of internal
consumers. It authenticates as one or more GitHub Apps, holds the App private
keys itself, and authenticates consumers with static bearer tokens whose
secret is bcrypt-hashed in the policy document.

Trust boundaries:

- **Outside the cluster**: GitHub. gh-proxy speaks to it over TLS using App
  JWTs and installation access tokens.
- **Inside the cluster**: consumers (CI jobs, operators, services). They hold
  only gh-proxy-minted tokens, not GitHub credentials.
- **The proxy itself** is the only component that sees both.

## Data plane vs control plane

- **Data plane**: the HTTP handlers in `internal/proxy` that validate tokens,
  consult policy, and forward requests to GitHub.
- **Control plane**: policy documents in Kubernetes ConfigMaps and
  credentials in Secrets. Policy is loaded at startup and can be re-read on
  signal or via webhooks.

The proxy is stateless outside in-memory caches (installation tokens and the
compiled policy). No database is required in v1.

## Request flow: Git fetch/push

1. Consumer runs `git clone http://<consumer-id>.<secret>@proxy/git/<org>/<repo>`.
2. gh-proxy looks up the consumer by id, bcrypt-compares the secret against
   the stored hashes, and extracts tenant + consumer identity from the policy.
3. The Git subpath and query (`service=git-upload-pack` vs
   `git-receive-pack`) are classified as `git.read` or `git.write`.
4. Policy engine evaluates `(tenant, org, repo, endpoint, write?)`.
5. On allow, gh-proxy fetches a cached installation token for the tenant's
   installation ID and rewrites the upstream URL to `github.com/<org>/<repo>.git`.
6. The request is forwarded with `Authorization: x-access-token <token>`;
   the response is streamed back unchanged.

## Request flow: GitHub API

Consumers call `POST /api/repos/<org>/<repo>/pulls`, etc. The handler maps
the trailing path to an endpoint class (`actions.workflows`, `api.refs`,
`api.pulls`, …), checks policy, and forwards to `api.github.com` with an
installation token.

## Policy loading

`internal/config.ReadPolicyFile` parses a YAML document (see
`examples/policy.yaml`) into `policy.Document` and hands it to a
`policy.Engine`. Engine reads are RW-lock protected so the document can be
hot-swapped when the ConfigMap changes.

## Token model

- Static bearer tokens of the form `<consumer-id>.<secret>`.
- `<consumer-id>` is a plaintext index; `<secret>` is bcrypt-compared against
  `consumers[].token_hashes` in the policy document.
- Multiple hashes per consumer are supported so that rotation can overlap new
  and old secrets.
- Tokens do not expire on their own. Rotation = publish a new token, add its
  hash, distribute, remove the old hash from the ConfigMap.
- `gh-proxy hash-token --consumer <id>` generates a random secret and the
  matching bcrypt hash.

## Telemetry, logging, deployment

- Structured JSON logs via logrus, request-scoped in the Gin middleware.
- OpenTelemetry traces + metrics hooks live in the same middleware so every
  proxied request emits a span with `tenant`, `repo`, and `endpoint` labels.
- Deployed as a standard `Deployment` with a `Service`, readiness probe on
  `/healthz`, and ConfigMap/Secret mounts for policy and credentials.

## Multi-tenancy

One gh-proxy instance serves many tenants. A tenant corresponds to a single
GitHub App installation and is resolved from the consumer token. Installation
token caches are keyed by `installation_id`.
