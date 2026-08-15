# Changelog

All notable changes to FreeSDN are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Calendar Versioning](https://calver.org/) (`YY.MM.PATCH`).

FreeSDN is a Community Edition / Early Access project. Releases may contain
breaking changes between versions - **back up your data before upgrading.**

## [26.08.1] - 2026-08-15 - Security and correctness

A patch release. No new features, no schema changes, no migration required.
Every change is a security fix, a correctness fix, or a documentation correction.

### Security

- Cleared every open dependency advisory across the project (28 high, 20
  moderate at the start of the sweep; 0 remaining). Backend `cryptography`
  49.0.0 to 50.0.0 (PKCS#7 Bleichenbacher oracle) and `aiohttp` 3.14.1 to
  3.14.3 (out-of-bounds read in the C HTTP parser); frontend `nanoid`,
  `js-yaml`, `postcss`, `brace-expansion` and `react-router`; agent `pyasn1`
  0.6.3 to 0.6.4 (three BER/DER decoder denial-of-service advisories),
  `pysnmp` 7.1.28 and `setuptools` 84.0.0.
- Base images updated: PostgreSQL 18.6, Node 26.7.0, nginx 1.31.3.
- Removed five expired CVE suppressions that had outlived the upstream block
  they were waiting on, so the dependency gate is no longer blind to future
  advisories carrying those identifiers.

### Fixed

- **Webhook retries were never delivered.** Failed deliveries were queued to a
  Celery queue that no worker declared or consumed, so they sat in `RETRYING`
  forever and never reached the dead-letter table. No error surfaced anywhere.
- **Single sign-on could not be started from the login screen.** OIDC, SAML and
  LDAP providers could be configured and the callback route worked, but the
  login page offered password authentication only, so a configured provider was
  unreachable.
- **An access-control relock task was never registered with any worker**, so a
  door unlock window could elapse without the database row being restored.
- **`freesdn-agent register` failed against any current controller**, ending in
  a traceback. This is the first command an operator runs.
- The agent's self-updater could overwrite the Python interpreter of a source
  install; it now refuses to run unless it is a frozen build.
- Documentation search on docs.freesdn.org returned an empty dialog and has been
  restored.

### Changed

- Documentation now states the shipped write-safety default correctly. The
  Compose stack runs read-write (`ADAPTER_READ_ONLY=false`) so FreeSDN manages
  your gear out of the box; set `ADAPTER_READ_ONLY=true` for a monitor-only
  deployment. Staged changes still require an explicit apply, and destructive
  operations still require a separate per-action confirmation. Roughly thirty
  pages previously described the opposite default.
- `SECURITY.md` corrected: release downloads are checksummed, not signed (the
  in-app agent update feed is genuinely ECDSA-P256 signed); tokens are HS256;
  rate limiting is 600 requests/minute, Valkey-backed.
- Install documentation corrected: container images are not published to a
  public registry yet, so `docker compose pull` will not work for the FreeSDN
  services; build from source with `./install.sh`. The agent ships a `.deb` and
  standalone binaries, with no MSI or `.pkg` installer.
- Added `AUTHORS`, naming PyPV (Python Platform Ventures) as sole author.

### Removed

- 1,322 lines of backend framework that nothing imported.

## [26.06.1] - 2026-06-01 - First public release

The first public, source-available release. This entry is the baseline;
subsequent releases will document changes relative to it.

### What's in this release

- **Multi-tenant infrastructure controller** - a single pane over network,
  cameras, VoIP, firewall, access control, backup, observability, compute,
  and AI, organized as discoverable modules.
- **Vendor adapters** across tiers - Omada, OPNsense, MikroTik, Proxmox, and
  Hikvision (Production); FreePBX, Grandstream, UniFi, and pfSense (Beta);
  OpenWrt, TrueNAS, generic ONVIF (Preview).
  See the [adapter overview](https://docs.freesdn.org/adapters/overview/)
  for the current support matrix.
- **Staged-write safety** - every device write rides a stage → review → apply
  pipeline behind a dual gate (`ADAPTER_READ_ONLY` + explicit force), with
  audit and rollback.
- **Security model** - app-layer tenant isolation, role/permission RBAC,
  encrypted credential storage, and an SSRF-guarded outbound HTTP path.
  Documented at [docs.freesdn.org/security](https://docs.freesdn.org/security/model/).
- **Deployment tiers** - `lite` (homelab), `pro` (SMB), and `max` (enterprise,
  with an optional HA overlay), all driven by a single `install.sh`. See the
  [deployment tiers guide](https://docs.freesdn.org/deploy/deployment-tiers/).
- **Plugin SDK + Fabric** - extend the platform with your own MIT-licensed
  plugins (no fork required) and wire apps together through the Fabric
  operation catalog.

### Licensing

- Core is licensed **AGPL-3.0-only**. The companion agent and SDK are MIT.

> Honest scope: FreeSDN has been exercised primarily in homelab and small
> lab environments. Treat it as Early Access, validate it against your own
> setup, and report what you find.
