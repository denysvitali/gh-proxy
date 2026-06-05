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
   - `api.pulls` (read umbrella — see "Per-ref and per-method
     authorization" below)
   - `api.pulls.create`, `api.pulls.review`, `api.pulls.merge`
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
    # Optional: limit this consumer to specific source IPs.
    ip_allow: [10.0.0.0/8, 192.168.1.0/24]
```

Resolution order for repos is exact match first, then `*` fallback.

## Per-ref and per-method authorization

v1 treated the policy as a binary decision per (consumer, repo, endpoint).
Three additions narrow that decision without changing the trust model:

### Per-method PR class split

The `/pulls` sub-tree maps to a family of endpoint classes that are
checked independently:

| Method | Path                                       | Class                |
| ------ | ------------------------------------------ | -------------------- |
| GET    | `/pulls`, `/pulls/{id}`                    | `api.pulls`          |
| GET    | `/pulls/{id}/*` (any sub-path)             | `api.pulls`          |
| POST   | `/pulls`                                   | `api.pulls.create`   |
| PATCH  | `/pulls/{id}`                              | `api.pulls.create`   |
| POST   | `/pulls/{id}/reviews`                      | `api.pulls.review`   |
| POST   | `/pulls/{id}/comments`                     | `api.pulls.review`   |
| POST   | `/pulls/{id}/reviews/{rid}/events`         | `api.pulls.merge`    |
| PUT    | `/pulls/{id}/merge`                        | `api.pulls.merge`    |
| POST   | `/pulls/{id}/merge`                        | `api.pulls.merge`    |
| *      | `/pulls/{id}/*` (other writes)             | `api.pulls.create`   |

Backwards compatibility: the legacy `api.pulls` umbrella class is
preserved. A repo that lists `api.pulls` still grants reads, creates,
and review-class actions, so policies written for v1 keep working
unchanged for those three classes. It does **not** grant
`api.pulls.merge` — that is an explicit opt-in. The motivation is to
let a tenant give a consumer the ability to comment on PRs without
letting it approve or merge them, which is the relevant boundary for
AI agents.

The wildcard `*` still grants everything, including
`api.pulls.merge`. If a tenant uses `*` and does not want merge
access, they must switch to an explicit list of classes and omit
`api.pulls.merge`. This is documented here because users tend to
assume `*` is the most restrictive; in fact it is the least
restrictive. Read the endpoint list in your policy carefully.

### Per-ref push filter

Git pushes are authorized in two layers. The first layer is the
existing endpoint check (`git.write` and the repo's `access: write`).
The second layer is a ref-name filter evaluated against every ref
parsed out of the receive-pack body:

```yaml
repos:
  - name: app
    access: write
    endpoints: [git.write]
    ref_allow: [refs/heads/feature/*, refs/heads/fix/*]
    ref_deny: [refs/heads/wip/*]
    protected_refs: [master, main]
```

Filter semantics, evaluated per ref in order:

1. `protected_refs` short names are expanded to `refs/heads/<name>`
   and treated as implicit denials. The example above forbids pushes
   to `refs/heads/master` and `refs/heads/main`.
2. `ref_deny`: a ref matching any pattern is denied.
3. `ref_allow`: if non-empty, a ref must match at least one pattern.

Empty fields impose no additional restriction. Patterns are Git-style
single-segment globs (the same rules as `git check-ref-format`):
`*` matches exactly one path segment and does not cross `/`. So
`refs/heads/feature/*` matches `refs/heads/feature/foo` but **not**
`refs/heads/feature/foo/bar`. The implementation uses Go's
`path/filepath.Match`, which has these semantics out of the box.

The filter check is implemented in `internal/proxy/gitrefs.go`. The
pkt-line parser reads the first flush-delimited section of the
receive-pack body and extracts the `(old, new, refname)` tuples. The
refname is taken from the third whitespace-separated field of each
push line, terminated at the first NUL (capabilities) or newline.

#### Parse-fail-allow

The pkt-line parser is conservative. On any framing error — bad
hex, truncated payload, missing flush — the parser returns
`errInvalidPktLine` and the proxy logs a structured warning and
**falls back to allowing the write**. This is a deliberate trade-off:

- **Fail closed** would reject every push from a Git client that
  emits even slightly non-standard framing. That would block
  legitimate work and is unacceptable for a CI/CD control plane.
- **Fail open** accepts the cost that a deliberately malformed
  body bypasses the filter. The endpoint check still runs, so a
  consumer that does not have `git.write` is still denied at the
  class level. The filter is defense in depth, not the primary
  authorization gate.

The fallback is logged at WARN level with a stable reason string
(`gitrefs: parse failed; falling back to allow (DESIGN.md
§parse-fail-allow)`) so operators can grep for it. The decision is
documented here so a future security review can locate it without
reading the parser source.

### Per-consumer IP allowlist

A consumer can pin its accepted source IPs with `consumers[].ip_allow`,
a list of CIDR blocks. The auth middleware checks the request's
client IP (Gin's `c.ClientIP`, which honours `X-Forwarded-For` when
trusted proxies are configured) against the list. An empty list
imposes no restriction. A CIDR that fails to parse is rejected at
policy load time, so a typo fails the validate step rather than
silently locking the consumer out.

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
| Consumer token fails bcrypt compare | 401 |
| Consumer id not in policy | 401 |
| Endpoint not modeled | 403 (default-deny on unknown classes) |

## Revocation semantics

- Consumer tokens are static. Revocation = remove the consumer's token hash
  from the policy document (or remove the consumer entirely). The change
  takes effect on the next policy reload.
- Rotation = add a new hash, distribute the new token, then remove the old
  hash. Multiple hashes per consumer enable overlap during rotation.
- Installation-level revocation is driven by webhooks or by restart.
- Per-consumer blocklists are out of scope in v1.

## Security assumptions / threat model

- The network between consumers and the proxy is trusted enough that
  long-lived bearer tokens over TLS are acceptable. If you need time-bounded
  credentials, mint fresh tokens and rotate via policy reload.
- Only bcrypt *hashes* of token secrets are stored in the policy document.
  A compromised ConfigMap does not leak usable credentials.
- Kubernetes Secrets protect the GitHub App private key at rest and in
  transit within the cluster.
- The proxy is **not** a general-purpose GitHub proxy: only classified
  endpoint classes are forwarded. Everything else is 403.
- Path-level Git authorization (per-branch, per-file) is now narrowly
  scoped: the per-ref push filter checks the refname but not the file
  contents of the push. File-level authorization remains out of scope.
- The `body_limit_bytes` middleware caps request bodies (16 MiB for
  `/api/*`, 4 MiB for `/git/*`, both overridable) so an unauthenticated
  attacker cannot exhaust proxy memory with oversized uploads.
- The per-consumer `ip_allow` list is a coarse network-level control
  on top of token authentication. It assumes the operator has set up
  trusted proxies in Gin so `c.ClientIP` reports a meaningful source
  address; behind a misconfigured proxy the check is meaningless.
