<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2024-2026 FreeSDN -->

> **Existing database installations:** upgrading from 26.09.0 is an image-only
> update. The database stays on the Debian runtime, so your existing volume is
> adopted in place -- no logical migration, no new volume, no locale change.
> [The database runtime guide](docker/postgres/UPGRADING) covers the exceptional
> case where the entrypoint refuses a cluster it cannot safely serve.

> **Existing site OpenVPN profiles:** older site create/update paths could store
> profile content without encryption. Upgrade all writers and follow the
> [profile credential audit and maintenance guide](docker/VPN-PROFILE-MAINTENANCE).
> Rewriting current rows does not remove credentials from historical backups.


# FreeSDN

**Development target: 26.10.0 (unreleased).** This release prepares the recovered,
reconciled and internally qualified hardening work for the next release cycle.
See the [draft changelog](CHANGELOG.md) for scope and remaining qualification.

> **Candidate support scope:** Linux **amd64** only; ARM64 appliance releases are
> not qualified. FreeSDN remains Community / Early Access, with no enterprise-stable
> or third-party-audit claim. The HA overlay provides single-host service failover,
> not host-loss protection. Proxmox SDN apply stays blocked, and scheduled reports
> offer opt-in, authenticated SMTP notices (no attachments or external recipients). Read the [candidate support boundary](docker/RELEASE-SUPPORT)
> before planning deployment or an existing-site upgrade.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![CI](https://github.com/freesdn/freesdn/actions/workflows/ci.yml/badge.svg)](https://github.com/freesdn/freesdn/actions/workflows/ci.yml)

**A vendor-neutral, self-hosted infrastructure controller. One UI, one API, one credential vault -- for the hardware you already own.**

[Live demo](https://demo.freesdn.org) - [Full documentation](https://docs.freesdn.org) - [Quickstart](#quick-start)

---

## What is FreeSDN

FreeSDN is a unified management plane for mixed-vendor infrastructure: network switches and APs, firewalls, cameras, VoIP, hypervisors, storage, and more -- from a single web UI and REST API. It does not replace your vendors' native controllers; it sits in front of them, normalizes their APIs, and gives you a single place to observe and act across all of them at once.

The core idea is simple: most real-world environments run gear from three or four vendors. Omada switches, OPNsense firewalls, a Proxmox cluster, a Hikvision NVR, a FreePBX box. Today you log in to five different UIs. FreeSDN collapses that into one, with a shared org/site data model, RBAC, credential vault, audit log, and automation fabric underneath.

**Who it is for:** Homelabbers and small MSPs with mixed-vendor stacks who want one UI instead of eight. SMBs that have outgrown "log into each box" but cannot justify a five-figure commercial NMS. Infrastructure engineers who want to inspect how a vendor-agnostic abstraction layer is structured. If you are an enterprise buyer evaluating a commercial NMS, FreeSDN is probably not the right fit yet.

> **Early software, honestly.** FreeSDN is built and maintained by its sole owner and developer, who runs it in production on a mixed-vendor stack (Omada, Hikvision, Proxmox, OPNsense, and more). It's young software, but not a toy -- the maintainer runs it on real hardware. This release includes automated tests and internal review, but no third-party security audit or certification is claimed, and it has limited field exposure beyond the maintainer's deployment. The vendor matrix below shows each adapter's maturity tier and scope -- and "Production" there means the contract is enforced and test-covered, not field-hardened across every vendor. Evaluate it carefully for your environment before you depend on it, and please file bugs.

---

## Features at a glance

FreeSDN is organized into 10 modules. Each module is an independently loadable domain; you enable what you need.

| Module | What it does |
|---|---|
| **Network** | Switches, APs, VLANs, LAGs, PoE, RF health, rogue-AP detection, config backup with diff viewer, cross-controller VLAN alignment, firmware lifecycle |
| **Firewall** | Firewall rules, NAT, DHCP, DNS, VPN, IDS/IPS, routing, services, traffic shaper; VLAN distribution across sites (brain/limb Layer 2 orchestration); drift detection |
| **Cameras** | IP cameras and NVRs -- live MJPEG/snapshot streaming, PTZ, recording playback, motion/LPR events, forensic export, legal hold |
| **VoIP** | PBX extensions, trunks, ring groups, queues, IVR, voicemail, CDR; SIP desk phone provisioning and fleet management |
| **Hypervisor** | VMs, containers, snapshots, storage, cluster HA, SDN zones, Ceph, per-VM and node-level firewall rules |
| **Backup** | Two tiers: `pg-backup` container for encrypted Postgres dumps with rclone off-site sync; in-app config-snapshot export (`.fsdn`) for instance migration and restore |
| **Observability** | SNMP/syslog/NetFlow collector; real-time event stream; Prometheus metrics endpoint; importable Grafana dashboard and Prometheus alert rules |
| **AI Assistant** | Multi-provider LLM chat with tool calling against live infrastructure data -- experimental, useful for triage |
| **Access Control** *(coming soon)* | Data model, RBAC, and doors/readers schema ship, but the module is disabled by default and cannot be enabled yet -- physical door control has no adapter (endpoints return HTTP 501). |
| **Fabric** | App-interconnect layer: operations/events catalog, n8n workflow bridge, plugin hooks. Makes automation scriptable without touching core code. |

The architecture uses an organization -> site -> device hierarchy, application role and site-grant checks, credential encryption helpers, and staged adapter operations with explicit apply checks. These controls have operation-specific limits; they do not establish complete tenant isolation or universal device-write safety. Review [SECURITY.md](SECURITY.md) and the [release support boundary](docker/RELEASE-SUPPORT).

---

## Vendor support

The **Production** label below describes an internal adapter maturity tier. It is not an enterprise certification, a support SLA or acceptance of every listed operation on every firmware version. Adapter tests cover selected read, staging, authorization and failure paths, often with recorded or synthetic vendor responses. The maintainer reports real production use, but each new release still needs acceptance against its actual image digests, supported firmware and intended workflows. Consult the operation-specific limitations and [release support boundary](docker/RELEASE-SUPPORT); no third-party security audit is claimed.

| Vendor | Tier | Manages |
|---|---|---|
| Omada (TP-Link) | **Production** | Controller-managed switches, APs, gateways -- ports, VLAN matrix, LAGs, PoE, RF health, hotspot, 802.1X, voucher portal, firmware lifecycle, config backup/restore with diff viewer, polling-based controller event/alert monitoring |
| OPNsense | **Production** | Firewall, NAT, DHCP, DNS, VPN (OpenVPN + IPsec + WireGuard), routing (static + OSPF + BGP), IDS/IPS, traffic shaper, system, diagnostics, interfaces -- 13 feature domains, full read/stage/apply; drift detection; VLAN distribution; config.xml backup |
| pfSense | **Beta** | Firewall, NAT, DHCP, DNS, VPN, routing, services, system, diagnostics, interfaces -- 10 feature domains; reads + staging are wired (shares OPNsense client plumbing), but several apply paths (e.g. routing, VPN) are not yet implemented. Not validated against real pfSense hardware -- tier is Beta on test strength, not field use. |
| MikroTik / RouterOS | **Production** | Router, switch, wireless, hotspot, VPN -- 13 feature domains including CAPsMAN, BGP/OSPF, PPP/PPPoE, SNMP, topology/neighbor discovery, firmware lifecycle, config backup |
| Proxmox VE | **Production** | VMs, containers, snapshots, storage, backups, cluster, HA groups, nodes, replication, Ceph, and firewall workflows. SDN zones/vnets/subnets are visible/stageable; **SDN apply is blocked**. Advanced and remaining write families require workflow-specific acceptance. |
| Hikvision | **Production** | IP cameras and NVRs via ISAPI -- live streaming, PTZ, recording playback, NVR channel import, motion/line-crossing/intrusion events, LPR tagging, forensic clip export |
| FreePBX / Asterisk | **Beta** | Extensions, trunks, ring groups, queues, IVR, voicemail, DIDs, CDR, active calls -- via AMI + ARI + FreePBX REST; toll-fraud guard; encrypted credentials |
| Grandstream | **Beta** | SIP desk phone provisioning via CGI -- discovery, templated XML config, bulk reboot/factory-reset/firmware push, per-phone status |
| UniFi (Ubiquiti) | **Production** | Sites, devices, clients, networks, WLANs, firewall (legacy + zone-based), RADIUS, hotspot vouchers -- full reference contract. Reads and device discovery are live-validated on a real UCG Fiber (UniFi OS 5.1.19 / Network 10.4.57), across both the classic (v1) and modern (v2) API lanes. Writes are staged + dual-gated; VLAN/network create+delete is proven live with a persisted cassette, the broader write surface is exercised live but not yet persisted per domain. |
| OpenWrt | **Preview** | ubus/UCI client -- basic system info, interfaces, wireless status. Gold-standard contract not completed; do not deploy against production fleets. |
| TrueNAS (iXsystems) | **Preview** | Pool health, alerts, disk temperatures, RAIDZ redundancy via WS JSON-RPC (read paths). Staged blob writes (e.g. camera snapshots) land via the Fabric `storage.store_blob` operation through the staged-change pipeline. Live-verified against a real SCALE system. |
| ONVIF generic | **Preview** | Protocol shim used as fallback by the camera module for non-Hikvision cameras. |
| Door controllers | **Not implemented** | `access_control` module data model ships, but `_get_door_adapter()` returns `None` for all vendors -- lock/unlock endpoints return HTTP 501. |

Tier meanings:
- **Production** -- Gold-standard contract enforced, verified by the automated test suite.
- **Beta** -- Functional and covered by the automated test suite, but missing one or more reference items, or lacks the same field exposure. Use it; file bugs.
- **Preview** -- Partial or unaudited. Treat as a developer preview. Expect missing endpoints.
- **Not implemented** -- Module architecture ships; the adapter does not.

The full per-adapter detail (what exactly works, what does not, route prefixes, how to test) is in the [adapters reference](https://docs.freesdn.org/adapters/overview/) on docs.freesdn.org.

---

## Quick start

Full instructions with TLS, production hardening, and upgrade notes are at [docs.freesdn.org](https://docs.freesdn.org). The short version:

```bash
git clone https://github.com/freesdn/freesdn.git
cd freesdn
./install.sh
```

The installer generates random secrets in an owner-only environment file (mode 0600), preserves existing credentials on reruns, builds all images, brings up the stack, and waits for the edge health check. Edge health alone does not prove recovery or production readiness. `./install.sh` defaults to the `lite` tier; pick a tier with `--tier lite|pro|max`. For a production (SMB) deployment with a public domain and automatic Let's Encrypt TLS:

```bash
./install.sh --tier pro --domain freesdn.example.com --email you@example.com
```

After boot, open the URL `install.sh` prints -- `http://localhost:8080` for the default lite tier, or `https://<your-domain>` when you pass `--domain` -- and the first-run wizard walks through: admin account, organization, site, and initial controller configuration.

Access from another machine requires HTTPS with a certificate trusted by that client: production authentication uses Secure cookies. Do not expose the default local HTTP mode on an untrusted network. See [installation and recovery acceptance](docker/INSTALL-ACCEPTANCE) for the supported rehearsal and its limits.


FreeSDN **manages** your gear out of the box -- once you add a controller it can stage and apply configuration changes (behind login + RBAC; destructive actions need a confirmation), the same as the OPNsense, pfSense, Omada, or UniFi UIs once you're signed in. To kick the tires in **monitor-only** mode first, set `ADAPTER_READ_ONLY=true` in your `.env` (FreeSDN reads and shows everything but never writes to a device); flip it off when you're ready to let it manage.

See the [documentation](https://docs.freesdn.org) for the full setup walkthrough, day-two operations, and disaster recovery.

**Live demo:** [demo.freesdn.org](https://demo.freesdn.org) -- pre-seeded with synthetic data across all modules; read-only, no device credentials.

---

## System requirements

FreeSDN runs as a Docker Compose stack on a Linux host (Docker Engine + Compose v2). Rough sizing by tier:

| Tier | Use | Minimum | Recommended |
|---|---|---|---|
| `lite` | homelab / evaluation, single node | 2 vCPU, 4 GB RAM, 20 GB disk | 4 vCPU, 8 GB RAM, 40 GB SSD |
| `pro` | small production (TLS, public domain) | 4 vCPU, 8 GB RAM, 40 GB SSD | 4 vCPU, 16 GB RAM, 80 GB SSD |
| `max` | larger / HA (Valkey Sentinel) | 8 vCPU, 16 GB RAM, 100 GB SSD | 8+ vCPU, 32 GB RAM, NVMe |

Requirements scale with retention (metrics, events, camera footage) and device count; the defaults are tuned for roughly a 16 GB / 4-core host. These figures are planning starting points, not measured production capacity or retention guarantees. Full sizing guidance is at [docs.freesdn.org](https://docs.freesdn.org).

---

## Backup, restore & upgrade

These essentials are kept in-repo so they are available offline and during an outage; the complete runbooks live at [docs.freesdn.org](https://docs.freesdn.org).

**Backup.** Coordinate encrypted backups of both application and log databases with the required application volumes, configuration and vault keys. The `pg-backup` service can retain encrypted dumps and optionally copy them off-site. The in-app `.fsdnvault` snapshot covers its supported contributors; it is not a complete installation backup or a substitute for database and file recovery. Verify restoration on isolated targets before relying on either mechanism.

**In-app archive storage and downloads.** Local-file and WebDAV downloads use bounded disk snapshots and shared transfer admission. Review [backup storage and transfer policy](docker/BACKUP-STORAGE-TRANSFERS) before changing filesystem ownership, volume mounts or transfer settings. These component checks do not establish full recovery, all-provider resource limits or enterprise production readiness.

**Restore.** Stop and fence all writers and external effects, preserve the original volumes, and recover both databases and required application files into separate isolated targets. Keep vault encryption keys unchanged, but prepare the [JWT recovery](docker/TOKEN-REVOCATION-UPGRADING), [queue reconciliation](docker/redis/QUEUE-BACKUP-RECOVERY) and [report delivery recovery](docker/SLA-REPORT-DELIVERY) procedures before starting general workers. Reconcile non-JWT credentials and potentially completed device operations. Validate schema, data and application behavior before cutover; starting the entire stack immediately after a database restore can replay jobs or accept restored credentials.

**Upgrade.** Do not run a blind image rebuild against an existing site's only data volumes. Preserve the old images, environment/vault keys, PostgreSQL and queue volumes, Sentinel state and complete backups first. The current database runtime and HA queue changes require the offline procedures in [PostgreSQL upgrading](docker/postgres/UPGRADING) and [HA queue upgrading](docker/redis/HA-UPGRADING); a migration guard must not be bypassed. Rehearse restoration on isolated copies and reconcile any potentially completed hardware jobs before cutover. Keep `SECRET_KEY` and `ENCRYPTION_SALT` unchanged. Restored authentication and report mail require the separate [JWT recovery](docker/TOKEN-REVOCATION-UPGRADING) and [report delivery recovery](docker/SLA-REPORT-DELIVERY) procedures. Coordinated customer migration remains an open release gate; same-image recreation tests do not close it.

**Migration safety.** Startup accepts a dedicated empty database or a single recognized migration revision. Fresh schema creation and revision stamping share one transaction, so interruption before commit does not leave a partial initialization. It refuses existing relations without migration history and empty, multiple or unknown revision metadata before changing schema. This deliberately removes the old automatic guess for unknown historical revisions. Preserve the original database and use its matching release and a reviewed migration plan; never stamp to head to bypass a refusal. See [database startup safety](docker/MIGRATION-STARTUP-SAFETY).

**Gateway certificate status.** Unavailable or unsupported inventory is an error, and unknown expiry dates require attention. The dashboard distinguishes these states from an empty inventory and hides stale health while refreshing. This is read-only expiry monitoring; it does not validate certificate trust or perform renewals. See [certificate inventory and expiry reads](docker/CERTIFICATE-INVENTORY-READS).

**Gateway trust and ACME summaries.** Each overview requires complete successful reads. Failed components cannot be reported as empty, and configuration-enabled badges do not claim successful certificate issuance or renewal. OPNsense CA/CRL and ACME parsing follows explicit version-specific contracts. See [trust-store and ACME inventory reads](docker/TRUST-ACME-INVENTORY-READS).

**Gateway firmware and WAN health.** Live firmware and monitor reads distinguish unavailable, unchecked and observed states. Firmware refresh contacts the adapter again instead of serving a five-minute cache entry. Health uses machine states, actual measurements and explicit active-default configuration; no-alarm monitor samples remain visible, including zero. Each panel validates the selected gateway and hides stale values while refreshing or after failure. See [system, firmware and health reads](docker/GATEWAY-SYSTEM-HEALTH-READS) for the read-only scope and remaining acceptance requirements.

**Gateway summary and complete inventories.** OPNsense device summaries use explicit system identity, interface inventory and active default-route data. Unknown readings stay unknown; measured zero remains zero. HAProxy and VPN reads reject incomplete inventories, validate public field types and mask VPN secrets. These read-only checks do not establish installed-firmware compatibility, monitored gateway health or managed backup durability; see `docker/GATEWAY-SUMMARY-INVENTORIES`.

**Gateway plugin read contracts.** Selected OPNsense Telegraf, CrowdSec, NetFlow, Squid, Monit and Tailscale reads use explicit upstream response contracts. Unknown service states and incomplete required data are unavailable rather than disabled. CrowdSec shows returned rows separately from total matches, with a 50-record limit. Metrics URLs omit user info, query and fragment data. These read-only fixtures do not establish compatibility with your installed plugin versions; see `docker/GATEWAY-PLUGIN-READ-CONTRACTS` and qualify the exact firmware before production use.

**Gateway live status reads.** Required component failures no longer become successful empty aggregate status. The selected status panels show loading, unavailable and retry states, suppress stale values during refresh, and validate the normalized response for the selected gateway. VPN raw-status rendering masks nested secret values. These checks do not establish complete firmware-schema coverage or live operational health; see [gateway aggregate reads](docker/GATEWAY-AGGREGATE-READS).

**Release build dependencies.** The shipped frontend Dockerfiles and CI use the qualified Node 24 LTS line (currently 24.21.0), with npm 12.1.0 and committed npm lockfiles. Node Current and prerelease versions are not release targets. Node is a build tool; the final frontend image serves static assets with Caddy (or the optional NGINX profile). Dependency updates belong in the release Dockerfiles, manifests and lockfiles, followed by fresh image builds, tests and vulnerability scans. Updating Docker or Node on the host does not patch already-built application images. LTS reduces migration risk; it does not mean an image is free of vulnerabilities.


---

## Technology stack

- **Backend:** Python 3.14, FastAPI, SQLAlchemy 2.0 (async), PostgreSQL 18 + TimescaleDB, Valkey (Redis-compatible), Celery 5
- **Frontend:** React 19, TypeScript 6, Vite 8, Tailwind 4, TanStack Query, Zustand, shadcn/ui, i18next (English, Spanish, Chinese)
- **Deploy:** Docker Compose with Caddy as the default TLS edge, an optional NGINX profile, and development/production overlays; Valkey Sentinel HA configuration is included but multihost failover is not yet qualified
- **Testing:** pytest + testcontainers (backend unit + integration); vitest + Playwright (frontend)

---

## Security

This release includes automated tests and internal review, but no third-party security audit or certification is claimed. The security model and threat model are documented at [docs.freesdn.org/security](https://docs.freesdn.org/security/model/). Report vulnerabilities privately -- see [SECURITY.md](SECURITY.md) for the process and the security@freesdn.org inbox.

Key posture points, honestly stated:

- Organization, site and role checks run in the application; PostgreSQL RLS is not an isolation boundary. Selected authorization and failure paths have automated coverage, with operation-specific limits documented in [SECURITY.md](SECURITY.md).
- Staged adapter operations require explicit apply checks. This does not establish that every device-write family is supported or safe; qualify the intended workflow on disposable targets. Proxmox SDN apply remains blocked.
- All plugins run **in-process with backend privileges**, including access to its network, filesystem and credentials. SDK permission declarations and loader import checks are not a process sandbox; install only trusted code.
- Valkey Sentinel provides broker-component failover support. This does not qualify appliance host-loss HA; the deployment still uses single-node PostgreSQL, and Patroni is not shipped.
- No compliance certifications (SOC 2, FedRAMP, etc.)

---

## How this project works

**License:** The core (this repo) is [AGPL-3.0-only](LICENSE). The agent and the SDK are MIT. If you run a modified version of FreeSDN to provide a network service to others, you must offer those users the corresponding source. This is deliberate -- it prevents anyone from taking FreeSDN, closing it, and reselling it as a hosted or embedded product without contributing back.

**Sole maintainer, no external pull requests.** FreeSDN is owned and developed by one maintainer, with AI tooling used for development and review. Independent peer review, a third-party security audit and enterprise support coverage are not claimed. External code PRs are not currently accepted. Bug reports and real-hardware field reports are very welcome via [GitHub Issues](https://github.com/freesdn/freesdn/issues). Code PRs will be closed without review.

**Want to extend it?** Build a plugin with the [MIT-licensed SDK](https://github.com/freesdn/freesdn-sdk) (published to PyPI as `freesdn-sdk`). Plugins can add operations, consume events, and wire into automation -- without touching core code and without needing a PR to land. Forks are allowed under AGPL but are not supported.

**Free and open source.** FreeSDN is free and open source under AGPL-3.0 -- no per-seat or per-device fees, no cloud lock-in.

---

## How to help

There are two ways to help move FreeSDN forward:

### Donate hardware

The depth of each adapter tracks the hardware the maintainer can test against. The Omada adapter is deep because the maintainer runs Omada in production. The pfSense adapter is Beta because the maintainer has not had a pfSense box on the bench.

**The fastest path to getting your vendor supported or promoted is donating hardware.**

Terms (read these before shipping anything):

- Hardware transfers **permanently**. Ownership does not come back.
- During reverse-engineering the device may be modified, reflashed, **bricked, or destroyed**.
- It will **not** be returned under any circumstances.
- No compensation. No warranty. No guarantee of any outcome.
- In return: that vendor/model is permanently supported and tested in FreeSDN, and the donor is credited (opt-in) on the supporters wall.

Contact: [hardware@freesdn.org](mailto:hardware@freesdn.org) before shipping.

Current wishlist and shipping instructions: [DONATE.md](DONATE.md).

### Fuel ongoing development

As FreeSDN grows and we expand vendor coverage, you can help fuel ongoing development. The maintainer builds and reviews with AI tooling, so gifting a Claude or OpenAI Codex subscription to [fuel@freesdn.org](mailto:fuel@freesdn.org) directly funds that work. This is optional.

---

## Related repos

| Repo | License | What it is |
|---|---|---|
| [freesdn/freesdn](https://github.com/freesdn/freesdn) | AGPL-3.0-only | Core -- this repo |
| [freesdn/freesdn-agent](https://github.com/freesdn/freesdn-agent) | MIT | Lightweight edge agent with its own signed release pipeline |
| [freesdn/freesdn-sdk](https://github.com/freesdn/freesdn-sdk) | MIT | Plugin SDK, published to PyPI as `freesdn-sdk` |
| [freesdn/plugins](https://github.com/freesdn/plugins) | MIT | Official plugins (n8n bridge, plugin template, examples) |

The three websites (freesdn.org, docs.freesdn.org, demo.freesdn.org) are built and deployed separately to Cloudflare Pages and are not in these public repos.

---

## License

```
Copyright (C) 2024-2026 FreeSDN
SPDX-License-Identifier: AGPL-3.0-only
```

See [LICENSE](LICENSE) for the full text. The AGPL obligation in plain English: if you run a modified version of this software to provide a network service to others, you must make the source of your modified version available to those users. Running it for yourself or your organization -- with no modifications, or modifications you keep private -- does not trigger this obligation.

---

## Trademarks

All third-party product names, logos, and brands are the property of their respective owners. Product and company names used in FreeSDN (and in this documentation) are for identification purposes only, and their use does not imply endorsement or affiliation.

FreeSDN is an independent open-source project and is not affiliated with, endorsed by, or sponsored by any of the vendors whose products it integrates with, including TP-Link (Omada), Ubiquiti (UniFi and UniFi Protect), Cisco (Meraki), MikroTik, OPNsense, Netgate (pfSense), Proxmox, Sangoma (FreePBX), Grandstream, Hikvision, and iXsystems (TrueNAS).

See [TRADEMARKS.md](TRADEMARKS.md) for the full notice.
