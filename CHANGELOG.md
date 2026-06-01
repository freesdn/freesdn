# Changelog

All notable changes to FreeSDN are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Calendar Versioning](https://calver.org/) (`YY.MM.PATCH`).

FreeSDN is a Community Edition / Early Access project. Releases may contain
breaking changes between versions - **back up your data before upgrading.**

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
