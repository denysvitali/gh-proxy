# Design

## Authorization model

Two orthogonal axes:

1. **Repo access**: `none`, `read`, `write`. Applies to Git operations and is
   also the coarse gate for API calls that mutate repo state.
2. **Endpoint class**: a named capability group that must be explicitly
   listed on the repo. Supported in v1:
   - `git.read`, `git.write`
   - `actions.workflows`
   - `api.refs`
   - `api.pulls`
   - `*` (wildcard for trusted tenants)

A request is allowed only if *both* the access level and the endpoint class
pass. This keeps “read-only” and “may read PRs” as separate decisions.

## GitHub App installation model

Each tenant in the policy document pins exactly one `installation_id`. The
proxy holds one App (or more, if keyed per tenant) and exchanges its JWT for
an installation token on demand. Installation tokens are cached in memory
until ~1 minute before expiry.

## Policy schema

```yaml
version: 1
tenants:
  - name: acme
    installation_id: 12345678
    org: acme
    repos:
      - name: app
        access: read
        endpoints: [git.read, actions.workflows]
      - name: "*"
        access: read
        endpoints: [git.read]
consumers:
  - id: ci-runner
    tenant: acme
```

Resolution order for repos is exact match first, then `*` fallback.

## Webhooks (optional in v1)

Webhooks are supported but not required. They are documented as the
preferred path for:

- **Installation sync** — add/remove installations without a restart.
- **Revocation** — invalidate installation-token caches on suspension.
- **Cache invalidation** — flush repo metadata when permissions change.

Without webhooks, cache TTLs (≤1h for installation tokens, ≤5m for policy)
bound staleness.

## Failure modes

| Failure | Behavior |
| --- | --- |
| Policy file missing at boot | serve fails fast |
| Policy file invalid on reload | keep previous doc, log error |
| GitHub App token fetch fails | 502 to consumer, no cache poisoning |
| Consumer token expired | 401, consumer must re-issue |
| Tenant mismatch in token | 401 |
| Endpoint not modeled | 403 (default-deny on unknown classes) |

## Revocation semantics

- Consumer tokens are short-lived; revocation is achieved by rotating the
  signing key (Secret) and letting tokens expire.
- Installation-level revocation is driven by webhooks or by restart.
- Per-consumer blocklists are out of scope in v1.

## Security assumptions / threat model

- The network between consumers and the proxy is trusted enough that
  short-lived bearer tokens over TLS are acceptable.
- Upstream authentication (who may call `/v1/tokens`) is enforced outside
  gh-proxy (mTLS, OIDC proxy, SA projection). gh-proxy treats `/v1/tokens`
  callers as already authenticated at the transport layer.
- Kubernetes Secrets protect the GitHub App private key and HMAC signing key
  at rest and in transit within the cluster.
- The proxy is **not** a general-purpose GitHub proxy: only classified
  endpoint classes are forwarded. Everything else is 403.
- Path-level Git authorization (per-branch, per-file) is explicitly out of
  scope.
