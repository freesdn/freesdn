# Security Policy

FreeSDN is maintained by its sole owner and developer. Automated tests, release
acceptance gates, internal review and the maintainer's own production use do not
establish independent security certification, commercial support coverage or
acceptance of every firmware and deployment.
Read the [release support boundary](docker/RELEASE-SUPPORT) before deploying.

## Versions and maintenance

This checkout's application version is recorded in `backend/app/__init__.py`. A
version in source is not by itself evidence that a public release and its images
have been qualified and published. Use the release's actual source commit, image digests and acceptance
record when deciding what to install. The current appliance qualification scope
is Linux amd64; agent platforms have separate qualification requirements.

Security work targets the current code line. There is no promised security
backport window for older releases. Keep recoverable backups, review upgrade
instructions and validate the candidate in your environment before upgrading.

## Reporting a vulnerability

**Do not open a public issue containing vulnerability details or credentials.**

- Use the repository's Security tab and "Report a vulnerability" when GitHub
  Private Vulnerability Reporting is available. The project's reporting link is
  [private vulnerability reporting](https://github.com/freesdn/freesdn/security/advisories/new).
- If that option is unavailable, contact **security@freesdn.org**. Ordinary email
  is not a project-managed end-to-end encrypted channel. No project PGP key is
  published here; agree on an appropriate channel before transferring secrets.

Include the affected version or commit, relevant image digests, module/adapter,
reproduction steps, impact and redacted logs. Never send production passwords,
tokens, encryption keys, unredacted backups or customer data in a public report.

The sole maintainer handles reports as capacity permits. No acknowledgment,
assessment or remediation deadline, 24-hour coverage or enterprise security SLA
is promised. See [SUPPORT.md](SUPPORT.md) for the support policy.

## Controls and their limits

### Tenant and operation authority

Organization, site and role checks are implemented in the application. There is
no PostgreSQL Row-Level Security isolation boundary. Automated tests cover
selected cross-tenant, site-grant and privilege-escalation cases; passing them is
not proof that every route, background job or plugin is free of authorization
defects. Restrict direct database and broker access to trusted operators.

Current resource checks in a background task do not necessarily revalidate the
initiating user's session or API-key grants. A check before network I/O cannot
undo an external effect after authority changes. Review operation-specific
limits, including [discovery job scope](docker/DISCOVERY-JOB-SCOPE),
[controller onboarding](docker/CONTROLLER-INITIAL-AUTHORITY) and
[automation authority](docker/AUTOMATION-RUNTIME-AUTHORITY).

### Managed-device writes

Staged adapter operations use explicit apply/force checks and the global
`ADAPTER_READ_ONLY` flag. The base Compose configuration defaults that flag to
`false`; the application setting's fallback outside Compose is `true`. Set it
explicitly for the intended deployment. Use device credentials with only the
required privileges and restrict management-network reachability.

Do not treat the flag, a UI confirmation or an adapter's maturity label as proof
that every write family is supported or safe. Some operations have additional
refusal paths; Proxmox SDN apply remains blocked. Qualify destructive workflows
on authorized disposable resources before enabling them on production devices.

### Credentials and diagnostic data

Credential helpers use Fernet encryption. Device/controller credentials derive
their key from `SECRET_KEY` and `ENCRYPTION_SALT`; the separate `fernet:` secret
format uses a distinct derivation from `SECRET_KEY`. Both use PBKDF2-HMAC-SHA256
with 260,000 iterations. Protect and back up the required keys separately from
the database. Changing a key or salt without migrating encrypted values can make
stored credentials unreadable; changing one derivation does not rotate both.

Legacy plaintext compatibility exists. This is not database-wide encryption,
and it does not encrypt every setting, audit record, task result or backup.
Selected API and provider paths redact secrets or return fixed diagnostics, but
there is no universal redaction boundary covering every log. Celery's raw result
storage and built-in worker exception logs remain sensitive even when the tenant
task API hides failure details. Restrict access and retention accordingly; see
[task failure privacy](docker/TASK-FAILURE-PRIVACY) and
[controller credential handling](docker/CONTROLLER-CREDENTIAL-DECRYPTION).

### Outbound network access

External-download and webhook paths use SSRF guards, including a request helper
that validates resolved addresses at connection time. Managed-device paths
intentionally allow suitable private management addresses. The policies differ
by operation; not every outbound call blocks all private address space.

URL validation alone is not a DNS-rebinding boundary. Use restricted egress,
separate management networks and least-privilege credentials. Trusted plugins
have backend network access and are not constrained by a process sandbox.

### Authentication

- Passwords use Argon2id with a 64 MiB memory setting.
- The configured JWT path uses HS256 and `SECRET_KEY`; access-token revocation
  depends on Valkey and the checks applicable to that request.
- TOTP MFA and backup codes are implemented. Secure enrollment, recovery codes
  and administrative recovery access as authentication credentials.
- Request limits use Valkey. Authentication routes fail closed when their
  limiting store is unavailable; general request limiting has a fail-open
  outage policy. Rate limiting is not a guarantee against credential attacks
  or denial of service.

Database rollback and restore need separate authentication and key-recovery
planning; an old backup can restore old authorization state. Follow the recovery
instructions and validate the actual restored deployment before exposing it.

### Deployment exposure

Production profiles use controls such as non-root application processes,
read-only filesystems, resource limits and `no-new-privileges` where applicable.
They are not universal across all services. For example, the VPN sidecar needs
root/network capabilities, and stateful services need writable storage.

The edge HTTP/HTTPS ports and optional UDP collectors can bind host interfaces;
not all published ports are loopback-only. Inspect the resolved Compose
configuration and firewall rules for the chosen profiles. Do not expose database,
broker, worker-management or collector endpoints directly to the Internet.
Collector source-IP filtering does not cryptographically authenticate a sender.

TLS and security headers depend on the selected edge configuration and the
deployment's certificates and proxy settings. Test the public endpoint itself;
a backend response or a configuration file alone does not prove end-to-end TLS.

## Plugin trust and registry integrity

Plugins execute with backend privileges and can access its credentials, database,
network and filesystem. Import hygiene in the loader is not an isolation boundary.
Only install code from publishers you trust, and review the package and manifest.

The remote marketplace catalog is authenticated with the pinned Ed25519 publisher
key. Catalog entries bind plugin package hashes, and marketplace downloads are
checked against those hashes. Serial, expiry and retained state checks limit
rollback; they require an accurate clock and preservation of trust state during
restore. See [marketplace freshness](docker/MARKETPLACE-FRESHNESS).

This is authentication through a signed catalog, not a separate signature file
on every ZIP and not a guarantee that a plugin is safe. An explicit unsigned
private/development-registry override weakens that trust policy. Keep production
signature verification enabled; review publisher/feed changes and preserve the
accepted serial floor rather than resetting trust to make an error disappear.

## Release integrity

Source archives, agent binaries, plugin catalogs and container images have
different verification mechanisms. Check the record for the specific artifact.
A checksum downloaded from the same host detects changed bytes; by itself it
does not establish an independently trusted publisher.

Do not infer that an image is signed because a signing workflow exists. A
published-image acceptance record must identify the registry digest, verified
signer, SBOMs and source/build relationship, and an independent installation of
those artifacts. The flattened public CI runs source/build checks; it is not an
image publisher. A local source ZIP is not a signed public release.

The in-app agent update mechanism signs release manifests with a deployment's
ECDSA P-256 key. The manifest binds the binary hash, version, platform, agent
type and channel. Agents require a public-key pin provisioned through an
authenticated, operator-approved path and verify the applicable update policy.
That deployment key is separate from the marketplace publisher and container
signing identities. It does not establish project signatures for arbitrary
agent binaries or every release-host download.

## Security review and project governance

No independent security audit, compliance certification, zero-vulnerability
guarantee, multi-day capacity qualification or enterprise availability SLA is
claimed. Package and image scans describe specific artifacts at a particular
time; updates and new advisories can change the result. Lockfiles record selected
dependencies but do not make builds immune to upstream or tooling compromise.

FreeSDN is owned and developed by one maintainer. External code pull requests
are not currently accepted; bug reports, vulnerability reports and hardware
field reports are welcome. This contribution policy does not remove supply-chain
risk or substitute for independent review. Hardware support and any commercial
arrangements require their own explicit terms; this security policy promises
neither permanent model support nor a funding policy.
