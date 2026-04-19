  # GitHub Proxy Architecture and Documentation

  ## Summary

  Build a Kubernetes-first Git/GitHub proxy in Go that sits between consumers and GitHub App installations. The proxy will enforce repo-scoped and endpoint-scoped
  policy from Kubernetes ConfigMaps, issue/validate short-lived consumer tokens, and proxy both Git smart HTTP traffic and selected GitHub API/actions endpoints.
  The docs will be split so ARCHITECTURE.md explains the system, DESIGN.md explains the security and request model, and README.md explains how to run and
  configure it.

  ## Key Changes

  - Define a shared multi-tenant architecture: one proxy service handles multiple GitHub App installations, keyed by installation/org/repo context.
  - Standardize on a stateless core with in-memory caches only; no durable app database in v1.
  - Treat Kubernetes ConfigMaps as the policy source of truth and Kubernetes Secrets as the place for GitHub App private keys and shared secrets.
  - Use Gin for the HTTP layer, with Cobra for CLI entrypoints, Viper for config loading, Logrus for structured logs, and OpenTelemetry for traces and metrics.
  - Model authorization at two levels:
      - repo-level read/write access
      - endpoint-class access for GitHub actions like workflow results, refs, pull requests, and other allowed API calls
  - Make webhooks optional in the first design, but document them as the preferred path for installation sync, revocation, and cache invalidation.
  - Document the token model as short-lived consumer tokens that are only meaningful in the context of the proxy and the tenant policy; consumers do not receive
    GitHub secrets.

  ## Documentation Contents

  - ARCHITECTURE.md
      - system overview and trust boundaries
      - data plane vs control plane
      - request flow for Git fetch/push and GitHub API proxying
      - policy loading from ConfigMaps
      - token lifecycle and validation
      - telemetry, logging, and deployment model
  - DESIGN.md
      - authorization model
      - GitHub App installation model
      - policy schema concepts and examples
      - webhook handling as optional but recommended
      - failure modes, cache behavior, and revocation semantics
      - security assumptions and threat model
  - README.md
      - quick start
      - example Kubernetes YAML snippets
      - configuration overview
      - local development flow
      - how to observe traces/metrics/logs

  ## Test Plan

  - Validate policy parsing and authorization decisions for:
      - repo read allowed, repo write denied
      - endpoint-class access allowed/denied
      - mixed org/repo policy resolution
  - Validate token behavior for:
      - expiry
      - replay/invalid token rejection
      - tenant mismatch rejection
  - Validate proxy routing for:
      - Git clone/fetch/push paths
      - selected GitHub API endpoints
  - Validate telemetry middleware:
      - trace/span creation
      - metric emission
      - request labels for tenant/repo/endpoint class
  - Validate config loading via Cobra/Viper and YAML examples in the docs.

  ## Assumptions

  - The initial design is Kubernetes-first and uses ConfigMaps for policy plus Secrets for credentials.
  - Gin is the HTTP framework standard for the first version.
  - The proxy remains stateless except for in-memory caches; Redis/Postgres are out of scope unless later required.
  - Webhooks are documented and supported as optional in v1, not mandatory.
  - Repo-level and endpoint-class authorization is sufficient; path-level Git authorization is intentionally out of scope.
