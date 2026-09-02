# ADR 0003: Secure the Admin API with persisted opaque Bearer tokens and RBAC

## Context

`admin-api` owns management-plane operations such as policy CRUD. It is a
headless HTTP API intended for operators and automation, not an interactive
browser application. Leaving it unauthenticated is unsafe even when it binds to
loopback by default: deployment topology can change, and policy operations need
an attributable least-privilege identity.

The platform needs revocable credentials that survive restarts, require no
external identity provider for local and early deployment use, and do not
introduce sessions, cookies, or credentials into the DNS data plane.

## Decision

Persist administrator identities, their roles, and opaque API-token metadata in
the admin database through a Flyway migration. Each raw token is generated from
cryptographically secure random bytes, supplied only as an `Authorization:
Bearer <token>` header, and stored only as a cryptographic hash. The raw token
is returned once when it is issued and is never stored, logged, or returned by
subsequent API responses.

The roles are deliberately small and explicit:

| Role | Permissions |
| --- | --- |
| `VIEWER` | Read admin status, resolver configuration, and policy records |
| `POLICY_EDITOR` | `VIEWER` permissions plus policy creation, update, and deletion |
| `ADMIN` | All management-plane permissions, including identity and token lifecycle |

The API applies those roles to explicit routes. `GET /api/v1/admin/auth/me`
requires any authenticated role. `GET`/`POST /api/v1/admin/users`,
`GET`/`POST /api/v1/admin/users/{id}/tokens`, and
`DELETE /api/v1/admin/tokens/{id}` require `ADMIN`. The policy and operational
route matrix follows the role permissions above.

Token checks are stateless at the HTTP layer: the API does not create sessions,
accept form login, or enable HTTP Basic authentication. An identity or token
lookup occurs for each authenticated management request so a revocation takes
effect immediately.

On first startup against an empty identity store, the service requires both
`DNS_ADMIN_BOOTSTRAP_USERNAME` and `DNS_ADMIN_BOOTSTRAP_TOKEN`. It creates one
enabled `ADMIN` identity and stores only the bootstrap token hash. There are no
defaults, no anonymous fallback, and no switch to disable authentication. If
either value is absent on this first start, startup fails before the service can
be used. On later starts the bootstrap values never overwrite, rotate, or
recreate an existing identity.

`GET /actuator/health` is permitted anonymously as a minimal health probe. All
other endpoints require an authenticated, authorized Bearer token. The security
chain ends with an explicit deny rule, so unknown application paths and
unlisted actuator paths are not accidentally exposed.

The default bind address remains loopback. A deployment that exposes the admin
service beyond localhost must terminate TLS, restrict network access to trusted
operator paths, rate-limit ingress, protect the database, and redact
`Authorization` headers from logs. Bearer tokens are never safe over an
untrusted plain-HTTP connection.

## Consequences

Management requests require a bootstrap secret on first deployment and callers
must migrate from unauthenticated requests to Bearer headers. Operators need a
secure process for preserving a newly issued token because it cannot be read
back from the API. A database lookup on authenticated requests is accepted for
this low-volume control plane in exchange for persistent state and immediate
revocation.

The authentication boundary applies only to `admin-api`. `dns-server` and
`dns-core` remain free of identity, web, and database dependencies. Policy
records are still `PERSISTED_NOT_APPLIED`; Week 12 secures their management but
does not cause a running DNS server to enforce them. Future policy-snapshot
distribution and data-plane enforcement remain separate work.
