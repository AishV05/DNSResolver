# Private staging operations

## Scope

Private staging deploys one verified release to a private Linux/AMD64 Docker
host. It consumes the immutable GitHub Release and the two published
application-image digests. The host never rebuilds source, and the deployment
never substitutes a mutable image tag for a digest.

This is a staging environment, not a public recursive DNS service. DNS uses
UDP and TCP on one private port. The tracked staging bundle runs policy in
fail-closed `REQUIRED` mode. Only DNS and the Admin API share an internal
policy-distribution network, and only DNS receives the dedicated snapshot-reader
token. Prometheus and Admin API share a separate internal
`admin-observability` network, and only Prometheus receives the fleet-metrics
reader token. The host is a single failure domain, and management HTTP has no public
TLS ingress.

The design is recorded in
[ADR 0012](../adr/0012-private-single-host-staging.md).

## External prerequisites

Before the first deployment:

1. Complete and publish an immutable release such as `v0.1.0`. Both GHCR
   packages must remain linked to this repository and readable by the staging
   deployment identity.
2. Prepare one dedicated, patched Linux/AMD64 host with Docker Engine, the
   Docker Compose plugin, Python 3, Git, `flock`, and sufficient persistent
   storage. Do not reuse a developer workstation or a general pull-request
   runner.
3. Assign the host a private RFC1918 address. Allow inbound UDP and TCP 5354
   only from approved test-client CIDRs. Allow outbound UDP/TCP 53 for recursion
   and TCP 443 for registry access. Keep TCP 8081, 9090, and 3000 on host loopback.
   Check the cloud/network ACL and Docker firewall path explicitly.
4. Register a dedicated GitHub Actions runner with labels
   `self-hosted`, `linux`, `x64`, and `dns-staging`. It must accept only trusted
   staging deployment work, never pull-request jobs. Access to Docker is
   root-equivalent; isolate and patch the runner accordingly.
5. Create a GitHub environment named `staging`. Require a reviewer, prevent
   self-review and administrator bypass where supported, and allow only `v*`
   tags. Add no runtime secret. Optionally set the non-secret environment
   variable `STAGING_CONFIG_FILE`; the default is
   `/etc/dns-platform/staging/staging.env`.
6. Provide encrypted/off-host storage for database backups. A Compose volume
   is persistent state, not a backup.

GitHub environment approvals gate a job before its environment values become
available. Feature availability varies by repository visibility and plan, so
confirm the actual repository settings rather than assuming the YAML created
them. See [GitHub deployment environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).

## Host configuration and secrets

Create an owner-only configuration outside the checkout:

```bash
sudo install -d -m 700 -o "$(id -un)" -g "$(id -gn)" \
  /etc/dns-platform/staging /etc/dns-platform/staging/secrets \
  /var/lib/dns-platform-staging /var/backups/dns-platform-staging
install -m 600 deploy/staging/staging.env.example \
  /etc/dns-platform/staging/staging.env
${EDITOR:-vi} /etc/dns-platform/staging/staging.env
```

Set `STAGING_DNS_BIND_ADDRESS` to an address actually assigned to the private
host. The validation rejects wildcard, public, hostname, and non-RFC1918
addresses. Keep the three management ports on their defaults unless local port
conflicts require another loopback port.

Create the first-start values without placing them in shell history or Git.
Run these as the deployment identity; if the directory is root-owned, use a
restricted host setup step to grant that identity access first:

```bash
umask 077
openssl rand -base64 48 > /etc/dns-platform/staging/secrets/postgres-password
openssl rand -base64 48 > /etc/dns-platform/staging/secrets/grafana-admin-password
openssl rand -base64 48 > /etc/dns-platform/staging/secrets/admin-bootstrap-token
chmod 444 /etc/dns-platform/staging/secrets/*
```

The deployment user—or root when a restricted host command is used—must own
the configuration, secret directory, and secret files. The directory must be
`0700`, symlinks are rejected, and each container-mounted source file must be
exactly `0444`. Native Docker Compose implements file-backed secrets as bind
mounts and does not apply the long-form `uid`, `gid`, or `mode`, so this lets
the non-root service read its mount while the private directory prevents every
other host user from reaching the source. The host-only
`admin-operator-token` remains `0600`. Secrets are mounted only into the
services that use them:

- PostgreSQL reads `postgres-password` through `POSTGRES_PASSWORD_FILE`.
- Spring Boot imports `spring.datasource.password` and, during first start,
  `dns.admin.bootstrap.token` from `/run/secrets` as a configuration tree.
- Grafana reads `grafana-admin-password` through
  `GF_SECURITY_ADMIN_PASSWORD__FILE`.
- DNS reads the newline-free `policy-snapshot-reader-token` from its own
  Compose secret mount. Bootstrap deployment creates this file only after the
  Admin API is healthy and the issued reader credential has fetched a valid
  snapshot.
- DNS reads the separate newline-free `resolver-agent-token` from its own
  Compose secret mount. Bootstrap deployment registers `STAGING_RESOLVER_ID`,
  verifies the agent can read the snapshot, and writes this file only after
  the Admin API is healthy.
- Prometheus reads the newline-free `fleet-metrics-reader-token`. Bootstrap
  creates and verifies this least-privilege identity before Prometheus starts;
  it cannot read management JSON or submit resolver reports.
- The host smoke test reads either `admin-bootstrap-token` on first start or
  `admin-operator-token` on normal deployments. The operator token is never
  mounted into a container.

`postgres-password` and `grafana-admin-password` initialize persistent service
state; replacing either source file alone is not credential rotation. For
PostgreSQL, change the database role password and the file as one controlled
operation before restarting the Admin API. For Grafana, change the persisted
administrator password through Grafana and then update the file to the same
value. Run the complete smoke test immediately afterward. Likewise, replacing
an Admin API token file does not issue or revoke its database-backed token.

Compose secrets are file mounts, not an encrypted host vault. Keep their source
directory protected; a `0444` file outside that `0700` directory is not an
acceptable substitute. Docker documents both the per-service mount behavior
and the fact that `_FILE` support belongs to each image: [Docker Compose secrets](https://docs.docker.com/compose/how-tos/use-secrets/).

## Prepare a deployment bundle manually

From a clean checkout of the exact annotated release tag:

```bash
export RELEASE_TAG=v0.1.0
export SOURCE_COMMIT="$(git rev-list -n 1 "refs/tags/${RELEASE_TAG}")"

./scripts/verify-github-release.sh \
  "${RELEASE_TAG}" "${SOURCE_COMMIT}" verified-release-v0.1.0

./scripts/create-staging-deployment-bundle.sh \
  verified-release-v0.1.0 staging-deployment-v0.1.0

./scripts/staging-preflight.sh \
  staging-deployment-v0.1.0 \
  /etc/dns-platform/staging/staging.env \
  --bootstrap --pull
```

Bundle creation requires a clean, complete checkout whose `HEAD`, annotated
tag, canonical `origin/main`, immutable release identity, and publication receipt
all agree. The output contains exactly:

```text
SHA256SUMS
compose.bootstrap.yaml
compose.release.yaml
compose.yaml
container-publication-manifest.json
observability/grafana/dashboards/dns-resolver-operations.json
observability/grafana/provisioning/dashboards/dns-resolver.yml
observability/grafana/provisioning/datasources/prometheus.yml
observability/prometheus/prometheus.yml
observability/prometheus/rules/dns-alerts.yml
release-assets-manifest.json
staging-deployment-manifest.json
staging.env.example
```

There are no secrets, registry credentials, database contents, resolved Compose
output, or image archives in the bundle. `compose.release.yaml` supplies the
two exact GHCR `repository@sha256:digest` references; `compose.yaml` supplies
three separately digest-pinned infrastructure images. Docker Compose supports
digest image references directly. See the official [`image` reference](https://docs.docker.com/reference/compose-file/services/#image).

## First deployment

The bootstrap overlay is only for an empty identity database:

```bash
./scripts/staging-deploy.sh \
  staging-deployment-v0.1.0 \
  /etc/dns-platform/staging/staging.env \
  --bootstrap
```

The deployment command:

1. verifies the bundle, schema, checksums, release identity, and exact five
   image references;
2. validates the private bind address, owner-only configuration and secret
   directory, and exact per-file modes;
3. acquires an exclusive deployment lock and retains the verified bundle;
4. pulls and inspects all digest-addressed Linux/AMD64 images;
5. backs up PostgreSQL before an update;
6. on first start, brings up only PostgreSQL and the Admin API, provisions and
   verifies the least-privilege policy reader, registered resolver agent, and
   fleet-metrics reader,
   and removes the bootstrap overlay from the normal Compose invocation;
7. starts both application digests as one release unit with `--no-build`;
8. waits for container health and runs the deterministic staging smoke; and
9. records `current` only after every check succeeds.

The smoke first requires `GET /api/v1/admin/fleet` to report a non-empty
`DATA_PLANE_CONVERGED` expected fleet. This proves the deployed DNS process has
established its fenced session and submitted a fresh report for the exact
published revision and rule count. The smoke then sends an EDNS version 1 query
for `transport-check.invalid`. The DNS server
returns `BADVERS` before recursive resolution, so this verifies the real UDP
listener, fragmented TCP framing, same-connection TCP reuse, and both transport
counters without contacting public DNS servers. It also requires a loaded
initial snapshot, required-mode policy metrics, and a successful sync. It
also authenticates an `ADMIN` identity, checks the provisioned Grafana
Prometheus datasource and DNS operations dashboard, checks Prometheus
readiness, both DNS and Admin targets, the converged aggregate fleet metric,
both listener states, every expected alert rule, and
the DNS process's automatically persisted runtime report. It also proves that
the deterministic probe did not increment resolver failures.

Inspect the fleet manually without exposing the token:

```bash
curl -fsS \
  -H "Authorization: Bearer $DNS_ADMIN_TOKEN" \
  http://127.0.0.1:8081/api/v1/admin/fleet \
  | python3 -m json.tool
```

`DNS_ADMIN_FLEET_REPORT_FRESHNESS_MILLIS` defaults to `120000`. Staging
preflight rejects a value smaller than the report request timeout plus three
times the larger of the report interval and maximum retry backoff. A fresh
resolver whose policy synchronizer reports `DEGRADED` or `STALE` can still be
converged when its loaded last-known-good revision and rule count exactly match
the publication target.

After first start, use the bootstrap token to create a separately labelled,
expiring administrator token through `POST /api/v1/admin/users/{id}/tokens`.
The raw value is returned once: write it directly to
`/etc/dns-platform/staging/secrets/admin-operator-token` with mode `0600`; do
not print it or retain the issuance response. Verify that file-backed token
through `/api/v1/admin/auth/me`, then use it to revoke the token whose label is
`bootstrap`. Never revoke the final known `ADMIN` token.

Reapply the same release without `--bootstrap`. The normal smoke requires the
new `admin-operator-token`, and the Admin API container no longer receives the
bootstrap secret:

```bash
./scripts/staging-deploy.sh \
  /var/lib/dns-platform-staging/releases/v0.1.0-"${SOURCE_COMMIT}" \
  /etc/dns-platform/staging/staging.env
```

Only after that deployment succeeds, remove the host
`admin-bootstrap-token` file. Deleting a raw token file does not revoke its
persisted hash, which is why API revocation comes first.

## Policy reader rotation

Rotate the machine credential with an active administrator token, never by
editing the token file to an arbitrary value:

```bash
python3 scripts/provision-policy-reader.py \
  --admin-url http://127.0.0.1:8081 \
  --admin-token-file /etc/dns-platform/staging/secrets/admin-operator-token \
  --output-file /etc/dns-platform/staging/secrets/policy-snapshot-reader-token
```

The provisioner validates the existing identity has exactly the enabled
`POLICY_SNAPSHOT_READER` role, issues a new token, proves it can fetch the
snapshot, atomically writes it with mode `0444` inside the `0700` secret
directory and with no trailing newline, and
only then revokes older active tokens with the same label. It never prints the
raw token. Recreate the DNS container immediately afterward so its Compose
secret mount uses the replaced source file, then run the staging smoke. During
that brief transition the already-running resolver retains its last-known-good
policy, but synchronization reports failures until the new file is mounted.

## Resolver-agent rotation

Rotate the reporting credential independently from the policy reader:

```bash
python3 scripts/provision-resolver-agent.py \
  --admin-url http://127.0.0.1:8081 \
  --admin-token-file /etc/dns-platform/staging/secrets/admin-operator-token \
  --resolver-id staging-dns-1 \
  --output-file /etc/dns-platform/staging/secrets/resolver-agent-token
```

Use the exact `STAGING_RESOLVER_ID` configured for the host. The provisioner
keeps that server-side identity stable, verifies the replacement credential,
atomically writes the newline-free `0444` file inside the private directory,
and only then revokes older
label-matched tokens. Recreate the DNS container so the Compose secret mount
uses the replacement file. Until then, reporting may degrade, but DNS
readiness and last-known-good policy enforcement are intentionally unchanged.

## Fleet-metrics reader rotation

Rotate the Prometheus credential independently and then recreate Prometheus so
its file-backed secret mount observes the replacement inode:

```bash
python3 scripts/provision-fleet-metrics-reader.py \
  --admin-url http://127.0.0.1:8081 \
  --admin-token-file /etc/dns-platform/staging/secrets/admin-operator-token \
  --output-file /etc/dns-platform/staging/secrets/fleet-metrics-reader-token
./scripts/staging-deploy.sh \
  /var/lib/dns-platform-staging/releases/v0.1.0-"${SOURCE_COMMIT}" \
  /etc/dns-platform/staging/staging.env
```

Use the actual retained verified bundle for the active release. The normal
deployment recreates services as necessary and reruns smoke. The provisioner verifies the new
endpoint access and writes a newline-free `0444` file before revoking older
label-matched credentials. A normal deployment requires this secret.

## One-time upgrade from a pre-fleet-metrics release

An already-applied staging release created before Week 19E has neither the V5
role nor a fleet-metrics token. Do not copy the administrator token into the
Prometheus secret path and do not create a placeholder token. Use the explicit
upgrade mode with the new verified candidate bundle:

```bash
./scripts/staging-preflight.sh \
  staging-deployment-v0.1.1 \
  /etc/dns-platform/staging/staging.env \
  --initialize-fleet-metrics --pull

./scripts/staging-deploy.sh \
  staging-deployment-v0.1.1 \
  /etc/dns-platform/staging/staging.env \
  --initialize-fleet-metrics
```

This mode is deliberately narrow. It requires a retained `current` bundle that
passes the pre-fleet-metrics contract, an active operator token, and all other
normal secrets. Under the normal deployment lock it verifies and backs up the
current PostgreSQL database, starts only the candidate PostgreSQL and Admin API
so Flyway can apply V5, provisions and verifies the dedicated
`FLEET_METRICS_READER` credential, then reruns strict current-contract
validation before starting Prometheus or the full candidate stack. The
`current` record moves only after the complete smoke passes.

If the command fails after candidate Admin startup, it preserves the database,
backup, and previous `current` record and intentionally refuses automatic image
rollback because migration state may have changed. Correct the failure and
rerun the same explicit mode; an already-valid generated token is validated and
rotated safely. Once the candidate succeeds, the retained current bundle no
longer qualifies for this mode and all later deployments use the normal strict
path.

## GitHub Actions deployment

Run **Staging deploy** manually from the release tag, not from `main`, and enter
the same tag in the `tag` input. Select `bootstrap` only for the first empty
database initialization. Select `initialize_fleet_metrics` only for the
one-time verified transition described above; the two options are mutually
exclusive.

The hosted preparation job independently verifies the immutable GitHub Release,
GHCR digests, SBOMs, and attestations, then uploads a seven-day deployment
handoff. The protected job runs only on the dedicated `dns-staging` runner,
rechecks the handoff checksum, logs into GHCR with a temporary Docker config and
read-only job token, invokes the same host deployment script, logs out, and
uploads non-secret deployment evidence. It has no package-write, contents-write,
OIDC, SSH, cloud, or production permission.

The workflow cannot create the host, firewall, runner, GitHub environment,
secret files, GHCR package access, or off-host backup target. Until those
external prerequisites exist and a real run succeeds, repository validation is
evidence of deployment readiness—not evidence of a deployed remote service.

## Health verification

Run the smoke independently at any time:

```bash
python3 scripts/staging-smoke.py \
  --dns-host 10.0.0.25 \
  --dns-port 5354 \
  --admin-url http://127.0.0.1:8081 \
  --admin-token-file /etc/dns-platform/staging/secrets/admin-operator-token \
  --prometheus-url http://127.0.0.1:9090 \
  --grafana-url http://127.0.0.1:3000 \
  --grafana-username admin \
  --grafana-password-file /etc/dns-platform/staging/secrets/grafana-admin-password \
  --timeout 120
```

For remote operator access, tunnel the loopback ports over the authenticated
management channel. Do not change the Compose bindings to `0.0.0.0`.

## Backups

Create an on-demand pre-change backup with the currently retained bundle:

```bash
./scripts/staging-backup.sh \
  /var/lib/dns-platform-staging/releases/v0.1.0-"${SOURCE_COMMIT}" \
  /etc/dns-platform/staging/staging.env
```

The script uses `pg_dump --format=custom`, checks the archive with `pg_restore
--list`, and writes an owner-only dump, JSON metadata, and checksum. PostgreSQL
documents that `pg_dump` produces an internally consistent snapshot without
blocking normal readers or writers: [PostgreSQL backup documentation](https://www.postgresql.org/docs/current/backup-dump.html).

Rehearse restoration without touching the live project or its volumes:

```bash
./scripts/staging-rehearse-restore.sh \
  /var/backups/dns-platform-staging/postgres-v0.1.0-TIMESTAMP.dump \
  /var/backups/dns-platform-staging/postgres-v0.1.0-TIMESTAMP.json \
  /var/backups/dns-platform-staging/postgres-v0.1.0-TIMESTAMP.sha256
```

The rehearsal validates the tracked metadata schema and checksum, starts the
same digest-pinned PostgreSQL image with no published port and `--network
none`, restores into a temporary in-memory data directory, checks the Flyway,
identity, and policy tables, and removes only its uniquely named disposable
container. Use `--verify-only` as a fourth argument when Docker is unavailable
and only the evidence contract should be checked.

Copy verified backups to encrypted storage outside the host and test restore
into an isolated empty database. A practical staging retention starting point
is seven daily and four weekly backups, adjusted to the project recovery
objective. The dump contains token hashes, identities, and policies and must be
treated as sensitive. Its checksum detects accidental corruption; it is not an
authenticity signature. Do not call a local named volume a backup.

## Resolver session retention

The Admin API keeps detailed superseded resolver sessions for 30 days by
default and cleans them hourly in bounded batches. Configure the policy in the
owner-only staging environment file with:

```dotenv
DNS_ADMIN_FLEET_SESSION_RETENTION_ENABLED=true
DNS_ADMIN_FLEET_SESSION_RETENTION_MILLIS=2592000000
DNS_ADMIN_FLEET_SESSION_CLEANUP_INTERVAL_MILLIS=3600000
DNS_ADMIN_FLEET_SESSION_CLEANUP_BATCH_SIZE=500
DNS_ADMIN_FLEET_SESSION_CLEANUP_MAX_BATCHES_PER_RUN=10
```

Preflight requires retention from one day through ten years, an interval from
one minute through one day that is shorter than retention, a batch from 1
through 5,000, and 1 through 100 batches per run. Cleanup removes only detailed
rows with `superseded_at` strictly older than the cutoff. The permanent
`resolver_boot_fences` ledger is not pruned: it is what prevents an old process
from reclaiming a lease after detailed history expires.

Flyway V6 creates and backfills the ledger before cleanup can run. Treat this as
a schema-changing deployment: keep the pre-deploy PostgreSQL backup and do not
roll an older Admin API image onto V6 without an explicit compatibility review.
The staging smoke checks lifecycle metrics and alert rules; the local Compose
smoke additionally ages a superseded row, verifies physical cleanup, confirms
the fence remains, and proves the old boot still receives HTTP `409`.

## Application rollback

Deploy automatically attempts the previous application release only when the
candidate fails and the complete Flyway history (including failed entries) is
unchanged. It still exits nonzero after a successful automatic rollback so
automation cannot report the failed candidate as deployed.

For an operator-requested rollback, select a retained verified bundle and make
the database-compatibility decision explicit:

```bash
./scripts/staging-rollback.sh \
  /var/lib/dns-platform-staging/releases/v0.1.0-"${SOURCE_COMMIT}" \
  /etc/dns-platform/staging/staging.env \
  --acknowledge-database-compatibility
```

Rollback first creates another verified database backup. It changes both
application digests together and runs the same smoke test. It never restores a
database automatically. If Flyway state changed, stop and review migration
compatibility. Restoring a backup can discard later writes and therefore needs
a separate approval, an isolated restore rehearsal, and an explicit recovery
procedure.

Never use `docker compose down -v`, volume pruning, a moved image tag, direct
database edits, or release deletion as rollback.

## Incident checks

During an incident, preserve the volumes and inspect only the affected project:

```bash
docker compose \
  --project-name dns-platform-staging \
  --project-directory /var/lib/dns-platform-staging/releases/RELEASE-ID \
  --env-file /etc/dns-platform/staging/staging.env \
  --file /var/lib/dns-platform-staging/releases/RELEASE-ID/compose.yaml \
  --file /var/lib/dns-platform-staging/releases/RELEASE-ID/compose.release.yaml \
  ps
```

Add `logs --no-color --tail=200 SERVICE` to inspect one service. Do not print
the resolved Compose configuration, environment, secret files, authorization
headers, or database dumps into workflow logs or tickets.

For a policy incident, check `dns_policy_ready`,
`dns_policy_snapshot_revision`, `dns_policy_sync_stale`, and the result counters
through Prometheus before restarting anything. If a snapshot was already
loaded, Admin API or credential failure should leave DNS ready and continue
enforcing that last-known-good revision. If no initial snapshot ever loaded,
the resolver correctly stays unready and returns `SERVFAIL`; repair Admin
reachability, the internal policy network, or the reader credential rather than
disabling required mode.
