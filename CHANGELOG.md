# Changelog

All notable changes to FreeSDN are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Calendar Versioning](https://calver.org/) (`YY.MM.PATCH`).

FreeSDN is a Community Edition project maintained by its sole owner and
developer. Releases may contain breaking changes between versions -
**back up your data before upgrading.**

## [26.10.4] - 2026-10-26 - What 26.10.3's checks were still red on

26.10.3 shipped with two checks failing and one that never finished, all on
the release commit itself. This release exists to clear them, and it was
proved green on GitHub's own runners, on the exact commit, before it was
published.

### Changed

- **Source-built FFmpeg findings are now reviewed the same way as image
  findings.** The backend and go2rtc images compile FFmpeg 9.0.2 from source,
  and five advisories were published against it after 26.10.3 shipped
  (CVE-2026-107696, high; CVE-2026-107675, -107676, -107677, -107678, medium).
  FFmpeg has not released a fix. The check that scans this component accepted
  no findings at all, so it could not pass until upstream did. It now follows
  the policy introduced in 26.10.3: a finding with a fix always fails, and one
  without a fix needs a written, expiring review in
  `security/image-cve-review.toml`. Without that file the check is as strict as
  before.

  One of the five is reachable in practice, and its review says so:
  **CVE-2026-107696** makes FFmpeg follow RTSP redirects without a limit. A
  malicious camera, or anyone able to tamper with unencrypted RTSP traffic on
  that network, can make one FFmpeg process loop. Short probes are stopped by
  their timeouts; a live-view transcode keeps spinning until the viewing session
  ends. The impact is CPU load, not code execution. It is accepted for 14 days
  only, so it is reviewed again as soon as FFmpeg 9.0.3 is available. The other
  four need inputs FreeSDN does not produce (an `sftp://` stream, a DASH
  manifest, HDR10+ metadata output, or a crafted encrypted MP4).

### Fixed

- **The full backend test suite in public CI was cancelled, not failed.** A
  weekly scheduled run started six hours late, shared a concurrency group with
  the release run, and cancelled it after 149 minutes. Scheduled and push runs
  no longer cancel each other.
- **One more VoIP site-access test failed, and its counterpart passed without
  testing anything,** for the same reason as the two fixed in 26.10.3. Every
  test covering those lookups was found and corrected, rather than the next one
  waiting to surface; disabling the access check now fails exactly the three
  rejection tests.
- The 26.10.3 notes said the database-image review covered 16 advisories; it is
  17.

### Upgrading

No application code changed since 26.10.3. If you already run 26.10.3, nothing
changes for you; this release only corrects the project's own checks.

## [26.10.3] - 2026-10-26 - Security maintenance

The first of the monthly security releases. In the two weeks after 26.10.2,
GitHub raised 108 dependency advisories against the published source, 9 of them
critical, and every image check in CI turned red. They came down to 21 packages,
one Go toolchain patch and one Go library. None was in FreeSDN's own code.

This release also fixes two reasons the 26.10.2 commit showed a failing status
that had nothing to do with vulnerabilities, and changes how image findings are
gated so that a red mark means something can be done about it.

### Security

- **Python runtime dependencies.**
  - `uv` 0.12.23 to 0.13.5 (GHSA-hq85-5cpj-mr62, critical). FreeSDN runs uv at
    runtime to install plugin dependencies into isolated environments.
  - `certifi` 2026.7.22 to 2026.10.23 (GHSA-6q48-6c7w-9gw2, critical). This is
    the CA bundle behind every adapter's outbound TLS connection.
  - `aiohttp` 3.14.3 to 3.14.5 (eight advisories, high). The HTTP client used by
    the device adapters.
  - `Pillow` 12.3.0 to 13.0.0 (41 advisories, five critical). Pulled in by
    reportlab to render SLA report PDFs. FreeSDN does not decode untrusted images,
    so this was not reachable in practice, but the dependency floor is now the
    patched version. This is a major version; the SLA report path is covered by
    the test suite.
  - `opentelemetry-api` 1.44.0 to 1.45.1.
- **Go.** Every Go component FreeSDN builds from source moves from Go 1.27.2 to
  1.27.3 (CVE-2026-111943, standard library). That is ten binaries, including the
  `gosu` helper inside the PostgreSQL and LogDB images. `golang.org/x/net` moves to
  0.60.0 (CVE-2026-78669, HTTP/2) in Tailscale, go2rtc, postgres-exporter,
  Prometheus and rclone, and `go-chi/chi` to 5.4.0 (CVE-2026-114437) in rclone
  and the Caddy edge.
- **nginx** 1.30.5 to 1.30.6 (CVE-2026-15176, CVE-2026-93479, CVE-2026-97205, all
  high, in `ngx_http_core_module` and the `map` directive) for the optional nginx
  frontend and the HA load balancer, including the HA compose default. It stays
  on the stable branch; the 1.31 mainline update Dependabot proposes would be a
  channel change, not a patch. These advisories appeared after the other images
  had been fixed, and were caught by rescanning the images that had last passed.
- **Web interface.** `zod` 4.6.7. `follow-redirects` 1.16.1 is used by
  Node-side tooling only and is not in the browser bundle.
- **Development tooling** (not shipped in any image): vite 8.3.5, storybook
  10.6.3, happy-dom 21.0.4, pypdf 6.21.2, virtualenv 21.14.13, filelock 4.2.4.

Every updated version had been public for at least three days before it was
adopted.

### Fixed

- **The metrics profile could not be built from the 26.10.2 source.** The
  Prometheus image compiles its web UI from a reviewed, pinned lockfile and audits
  it during the build; new advisories against vite and sanitize-html made that
  audit fail, so `docker compose --profile metrics build` stopped. The lock now
  pins vite 6.4.5, sanitize-html 2.18.1 and vitest 4.1.12.
- **The backend test job in public CI had not run a single test since 26.10.2.**
  It invoked pytest in a way that could not import the project's own test plugin
  and stopped before the first test. The product was unaffected; the published
  red status was this, not a test failure.

  Running the suite as a GitHub runner sees it then exposed tests that had never
  run in public CI. None indicated a product defect, and none was caused by this
  release's dependency updates (each was checked against the 26.10.2 versions):
  - The credential network tests need an owned private network interface that the
    runner's hostname resolves to. CI now sets that up explicitly instead of
    relying on the runner's defaults.
  - Two VoIP site-access rejection tests failed against mocks that no longer
    matched how the lookup reads its result; worse, the matching acceptance tests
    were passing without testing anything. They now check real values, and
    disabling the access check makes exactly the rejection tests fail.
  - The TrueNAS login fallback added in 26.10.2 (try the stored secret as an API
    key, then as a password) had no test, and an older test still asserted the
    previous order. It is now covered.
  - A test pinning the CI image-scan layout still expected the redis exporter to
    be pulled from upstream; it has been built from source for some time.
- **The live demo reported an old version** in Settings > About. Its version is
  now derived from the release instead of written into the demo by hand.

### Changed

- **Image vulnerability gate.** CI still scans every image with nothing
  suppressed and keeps the complete list. What fails the build is now:
  - any HIGH or CRITICAL finding that has a fix available, always; and
  - any HIGH or CRITICAL finding with no fix available that is not listed in
    `security/image-cve-review.toml` with a written reason and a review date at
    most 62 days away.

  Previously every finding failed the build, including ones the upstream
  distribution has not fixed. The PostgreSQL and LogDB images run on Debian 13,
  which currently carries 62 such findings, so those checks could never pass
  however current the images were. Each of the 17 underlying advisories is now
  reviewed against how FreeSDN runs the databases (no published ports,
  `no-new-privileges` on every database service, no use of PostgreSQL's XML
  functions). A finding becomes a failure again the moment a fix is published,
  or when its review expires. Every finding is now printed in the CI log.

### Known, not fixed

- NetBird's `pion/dtls` (CVE-2026-26014) and `pion/stun` (CVE-2026-54909)
  advisories have no upstream fix.
- 62 HIGH/CRITICAL findings in the Debian base of the PostgreSQL and LogDB
  images have no Debian fix; they are listed and reasoned in
  `security/image-cve-review.toml`.

### Upgrading

Pull and rebuild every image (`docker compose build --pull`), then restart. There
are no database migrations and no configuration changes.

## [26.10.2] - 2026-10-12 - A controller that imported nothing, quietly

Every fix here was found by running v26.10.1 against real hardware - a TP-Link
Omada controller, a UniFi gateway, an OPNsense firewall, a Hikvision NVR, Proxmox
and TrueNAS - rather than by reading code. The first one had been silently
breaking device discovery for every controller type.

### Fixed

- **Device discovery crashed before contacting any device, for every controller
  type, without reporting it.** Publishing the "discovery started" event raised
  `TypeError: Object of type UUID is not JSON serializable`, so the task died and
  retried forever. Nothing surfaced it: the separate health check kept stamping the
  controller `connected` with a fresh last-sync time and an empty error field, so
  the UI showed a healthy, recently-synced controller that had never imported a
  single device. Only counting the devices revealed it. On the test fleet the
  device count went from 7 to 19 once fixed, including every access point and
  switch behind the Omada controller.
- **A newly created site did not appear when adding a device, hypervisor or NVR**
  for up to five minutes. The dialogs served a cached site list and, because they
  stay mounted, never refetched on reopen.
- **Asking a camera for its RTSP URL returned a server error for every device.**
  The device-type check read an attribute that is a plain string on any device
  loaded from the database.
- **The Omada Open API integration had never worked.** Its token, refresh, site-list
  and introspection calls all read a configuration field that does not exist, so
  each failed on its first line. The site list now returns real data.
- **Pointing an Omada-only endpoint at a controller of another vendor returned a
  server error** instead of saying so. It now answers with a message naming both
  the controller type and the operation, consistent with the rest of the API.
- **Asking an Omada controller for a feature its firmware does not implement
  returned a server error.** The controller answers such requests with an HTML page
  rather than JSON; that now surfaces as an upstream error naming the cause.
- **Three VPN endpoints took more than twelve seconds each whenever NetBird is not
  configured**, which is the default. The result of the failed check was never
  cached and each request re-ran it, so the VPN page appeared frozen. Repeat calls
  are now immediate.
- **Requesting an import session, recording, or camera analytics setting that does
  not exist returned a server error** instead of "not found", and camera errors
  reported only what had failed rather than why.
- **Tailscale could not start inside the API container**, whose filesystem is
  read-only by design, so the sidecar state and socket had nowhere to go.
- **Discovered devices could be recorded with a status the rest of the product does
  not understand.** Adapters report health words such as `ok` and `warning`; those
  were stored verbatim into a field that expects reachability, so a healthy
  appliance counted as offline in every per-controller total.
- **Firmware showed as unavailable for devices whose version had already been
  collected**, and Proxmox node versions were never stored at all, because the code
  path that writes to the database did not gather what the live view does.
- **TrueNAS synchronisation failed while its own controller page reported a
  successful connection.** Credential assembly existed in three places that had
  drifted apart; TrueNAS authenticates with an API key and only one of them passed
  it.
- **Camera detail pages could be opened with an invalid address** from a dialog that
  passed an event object where an identifier was expected.
- **A VoIP discovery scan failed** when more than one provisioning record matched.
- **Pages could fail to load after an upgrade** until a manual refresh, because the
  browser held an asset reference the new release no longer serves.
- **Pressing Disable did nothing for a module nobody had explicitly enabled** -
  which is most of them, and exactly the ones serving traffic. The call found no
  stored record, returned "module not found" for the organization, and wrote
  nothing, so the toggle still misreported; it had only changed which modules it
  misreported. Disabling now records the decision.
- **TrueNAS write support was under-reported in the product for two months.** The
  maturity badge read "mock tested - no real-device write validated yet" while
  the published 26.08.4 notes stated, correctly, that the storage write path had
  been validated end to end against a real appliance. The badge's note predated
  the backup-destination write path and was simply stale. It now reads
  **partial**, not live-validated: the honesty ratchet requires a recorded
  device cassette for that claim and none is in the tree. Under-selling is still
  a defect when the maturity labels are the one thing the project asks you to
  trust.

### Added

- **Disabling a module now actually closes its endpoints.** Until this release
  the Settings > Modules toggle hid the navigation and nothing else: every route
  of a "disabled" module stayed callable by anyone with valid credentials. The
  registry had a `require_enabled` helper written for exactly this job with no
  callers, route registration mounted every discovered module with no dependency,
  and a comment in the frontend asserted the opposite ("the backend enforces real
  module access"). The gate is now applied where routes are registered, so an
  endpoint added later cannot miss it.

  One limit, stated plainly because it decides whether you can rely on this:
  only an **explicit** "off" refuses. An organization that has never recorded a
  choice for a module is still served, because treating a missing record as
  "disabled" would lock such an organization out of the entire product - for
  instance one created through the API, or one that skipped the setup wizard's
  module step. Making absence mean denial needs a data migration first and is a
  separate change.
- **AI provider model lists now come from the provider, using your own API key.**
  Which models a key may call depends on the account, so a list compiled at build
  time is wrong for somebody by definition: it offered models a key cannot use and
  hid ones it can. The settings page says whether a list came from your account or
  from the built-in fallback, and refreshes when a key changes. The fallback list
  itself was also out of date.

### Changed

- `.env.example` documented four settings nothing reads (`DOMAIN`,
  `LETSENCRYPT_EMAIL`, `FRONTEND_HTTP_PORT`, `FRONTEND_HTTPS_PORT`) and omitted the
  ones that actually drive TLS and ports (`CADDY_SITE_ADDRESS`, `CADDY_ACME_EMAIL`,
  `EDGE_HTTP_PORT`, `EDGE_HTTPS_PORT`). Following it to enable Let's Encrypt changed
  nothing. It now describes the real settings, including why browsing `:8080`
  redirects to a port that is not published.
- The `metrics` profile is included in the Max tier preset. It was absent, so an
  enterprise install evaluated no alert rules at all.
- `SECURITY.md` named a specific version in prose and had drifted a release behind.
  It now points at the version file.

### Release engineering

- **The `metrics` profile could not be built from a published release.** The
  vendored Prometheus UI lockfile - which carries a critical `handlebars` pin - was
  copied into the release tree and then silently dropped by a blanket
  `pnpm-lock.yaml` ignore rule, so it never reached the published repository. Every
  existing gate stayed green, because none of them compared what the release copied
  against what it committed. One now does, and the release fails rather than
  publishing a tree that cannot build.
- The frontend lockfile's version metadata was left at `26.10.0` by the 26.10.1
  release and is corrected.
- The integration suite could not reach any of the ten modules; it now exercises
  the module surface, every module write endpoint's authentication, the module
  toggle against a running stack, and login against a real identity provider
  including OIDC callback and multi-factor with recovery codes. A MikroTik test
  appliance that will not boot is now a skip rather than 22 errors.

Unchanged, and still stated plainly: one owner and developer, no commercial support
contract, no SLA, no third-party security audit or compliance certification, Linux
amd64 only with ARM64 unqualified, the HA overlay providing single-host service
failover rather than host-loss protection, asynchronous replication able to lose
acknowledged writes, Proxmox SDN apply blocked, and no adapter claiming
live-validated writes.

## [26.10.1] - 2026-10-09 - Documentation corrected after publication

26.10.0 published with documentation that still described it as unreleased.
There are no application changes in this release.

### Fixed

- `README.md` opened with "Development target: 26.10.0 (unreleased)" on a
  repository that already carried the v26.10.0 tag and release. It now states
  the current release and the gates every release has to clear.
- `SECURITY.md` said a version in source does not mean a public release or its
  images have been qualified. Both had been.
- The support boundary, installation acceptance and upgrade documents described
  the release as a "prepared candidate" and the project as "Early Access".
  `docker/RELEASE-SUPPORT` is retitled from PUBLIC CANDIDATE SUPPORT BOUNDARY.
- Upgrade and quickstart guidance told readers not to invent a tag for the
  prepared candidate. v26.10.0 exists, so the guidance is now the useful one:
  install from a published release tag rather than the default branch.

Unchanged, and still stated plainly in the same documents: one owner and
developer, no commercial support contract, no SLA, no third-party security
audit or compliance certification, Linux amd64 only with ARM64 unqualified, the
HA overlay providing single-host service failover rather than host-loss
protection, asynchronous replication able to lose acknowledged writes, Proxmox
SDN apply blocked, and no adapter claiming live-validated writes.

## [26.10.0] - 2026-10-09 - Guards that did not guard

This release brings together the recovered and reconciled FreeSDN work and the
subsequent qualification fixes. It focuses on authorization, audit integrity,
recovery, dependency security and operational reliability. It is not a claim of
independent certification: there is no third-party security audit, no compliance
attestation and no commercial support contract.

### Release preparation

- Align the backend runtime/package version, frontend package/lock metadata and
  demo version with `26.10.0`. Companion packages retain independent versions.
- Carry the qualified flat repository layout and its preserved recovery and
  qualification evidence onto the private development `main` branch.
- Retain authorization and concurrent-operation fixes, migration and audit
  integrity work, encrypted backup/restore safeguards, queue/restart handling,
  dependency/native-library findings review and more reliable test fixtures.
- The preceding `26.09.1` source qualification completed its actionable internal
  campaign within documented limits. Those observations remain attached to their
  original source and artifact identities; they are not a full `26.10.0` pass.
- Before publication, qualify the new version's artifacts and public exports,
  execute current hosted CI, resolve applicable provider/platform and operational
  acceptance gaps, and bind the reviewed bytes to release signatures and tags.
  See [the support boundary](docker/RELEASE-SUPPORT) for deployment limitations.

### Gateway firmware, system identity and monitor availability — 2026-09-26

- Read documented OPNsense system identity/time and structured firmware product metadata. Distinguish unchecked update availability from a checked negative result; do not infer updates from reboot requirements or invent latest versions.
- Join validated gateway status with complete routing configuration for interface/default flags. Interpret machine states independently of translated labels; raw `none` with measurements means no active monitor alarm, while absent measurements remain unmonitored. Preserve measured zero and reject malformed values.
- Return explicit unavailable/unsupported errors for live firmware and health. Firmware reads no longer use the five-minute application cache; each request rechecks scope and contacts the adapter. Packages/plugins keep their existing cache policy.
- Add independent loading/error/retry states and suppress stale firmware/health data during refresh. Show unknown readings and neutral pending/unmonitored badges; retain sync settings separately.
- These read-only contracts and synthetic fixtures do not establish acceptance on installed firmware, long-duration operation or enterprise readiness. See `docker/GATEWAY-SYSTEM-HEALTH-READS`.

### Gateway summaries and complete inventory reads — 2026-09-26

- Use OPNsense diagnostic identity/time endpoints, nested firmware metadata and complete interface/routing inventories for the device summary. Select the active default gateway explicitly; report the firewall interface address separately from its upstream router.
- Count unknown interface states separately. Preserve absent measurements, unchecked firmware status and uncollected counters as unknown; display measured zero correctly and avoid inventing the missing half of a service or VPN counter.
- Require complete HAProxy and VPN inventories with valid identities and explicit flags. Validate selected HAProxy public text fields and use the documented IPsec SAD/SPD endpoints. Mask VPN secret fields at the adapter boundary.
- Preserve cancellation, generic failures and read-only behavior. Exact firmware/hardware acceptance and the separate firmware, gateway-health and system-information screens still need qualification. See `docker/GATEWAY-SUMMARY-INVENTORIES`.

### Gateway plugin read contracts — 2026-09-26

- Use Telegraf general/output, CrowdSec search and Diagnostics NetFlow endpoints from reviewed upstream definitions. Normalize Squid nested settings, Monit booleans and selected Tailscale/NetFlow options.
- Reject unknown service states and missing or inconsistent required payloads. Preserve cancellation and safe error responses; no device writes are introduced.
- Keep CrowdSec windows bounded at 50 records with explicit totals and truncation, and validate that metadata in the API and browser. Label the decision origin as its source.
- Support InfluxDB v2 endpoint display and omit URL user info, query and fragment data. Keep installed-firmware acceptance, managed gateway backup durability and enterprise readiness as separate gates.

### Gateway aggregate status availability — 2026-09-26

- Require all component reads for OPNsense VPN, device summary, Tailscale, HAProxy, proxy, CrowdSec, Monit, Telegraf and NetFlow aggregates. Preserve cancellation and avoid provider error details in these aggregate failure paths.
- Return safe unavailable/unsupported errors for the twelve selected live-read routes; validate normalized counts, fields and admitted gateway identity. Preserve the separate OpenWrt device-summary contract.
- Render loading, unavailable and explicit retry states; hide stale status during refresh and failures. Correct Monit, Telegraf, NetFlow and CrowdSec field mapping. Keep VPN secret redaction closed at the recursion limit and for structured secret values.
- Keep successful firmware payload validation, device acceptance and enterprise readiness as separate gates. See `docker/GATEWAY-AGGREGATE-READS` for the exact read-only scope.

### Gateway trust-store and ACME inventory correctness — 2026-09-26

- Refuse unsupported, failed, malformed and partial trust/ACME reads instead of reporting successful empty inventories. Preserve gateway admission, identity and safe diagnostics.
- Correct OPNsense ACME search actions and nested settings, normalize both option fields, and count only configured CRLs. Require complete component results and preserve cancellation. No certificate or gateway writes are introduced.
- Show explicit unavailable states and retries, hide stale counts during refresh, validate overview identity/counts, and describe ACME badges as configuration state rather than operational health. See `docker/TRUST-ACME-INVENTORY-READS` for contracts and hardware-acceptance limits.

### Gateway certificate inventory and expiry availability — 2026-09-26

- Use the concrete certificate-inventory adapter method. Return explicit 501/502
  for unsupported, unavailable, malformed or incomplete reads instead of a
  successful empty inventory. Keep existing scope checks and safe diagnostics.
- Validate OPNsense Trust search metadata and preserve public certificate fields.
  Support Unix expiry timestamps and common ISO/UTC formats; count missing or
  invalid expiry dates as unknown and requiring attention.
- Show unavailable, empty and unknown states in the dashboard. Hide cached health
  while refreshing and after failure, bind responses to the selected gateway,
  and retry explicitly. Include English, Spanish and Chinese translations.
- Add 102 backend and 25 frontend regressions/controls. See
  `docker/CERTIFICATE-INVENTORY-READS` for read-only scope and hardware limits.

### Notification verification binding after concurrent configuration changes — 2026-09-26

- Store provider verification and test-send metadata only if the current owner
  and configuration still match the values actually tested. Concurrent edits or
  deletion cannot certify a new configuration or receive stale probe errors.
- Keep management writes independent of slow transport I/O. Stale verification
  returns a retry message; a completed test send retains its actual outcome
  without marking a changed provider verified.
- Add 20 real PostgreSQL regressions covering success/failure, configuration
  replacement, owner changes, deletion and unchanged controls. Synthetic
  transports exercise concurrency without external notifications.

### Notification provider default ownership and concurrent edits — 2026-09-26

- Keep default notification-provider promotion within the record's actual owner
  and channel, including the separate platform group. Preserve administrative
  lookup semantics without clearing unrelated organizations' defaults.
- Serialize provider management through commit/rollback and reload current state
  before edits, preventing duplicate defaults and stale metadata edits from
  restoring old secrets. Preserve encryption and masked API responses.
- Add real PostgreSQL concurrency, scope, secret-merge and rollback regressions.
  See `docker/NOTIFICATION-PROVIDER-SCOPE` for independent-writer and delivery limits.

### Gateway log availability and translation parity — 2026-09-26

- Keep unavailable gateway log reads distinct from successful empty responses.
  Hide cached rows during refresh and after errors, verify gateway/vendor identity
  and render only validated text/number fields. Provide retries for the selected
  log source and display the OPNsense timestamp consistently.
- Complete sixteen missing Spanish/Chinese translation keys for health coverage,
  gateway certificate warnings, backup comparisons and manual OpenVPN profiles.
  Preserve the existing translation checker and all interpolation placeholders.
- Keep this page's REST read behavior separate from the live SSE endpoint. These
  frontend checks do not establish live device, continuous freshness or production
  release acceptance.

### Gateway log delivery and streaming authorization — 2026-09-25

- Return normalized system/firewall log arrays to the dashboard and reject
  failed or malformed vendor responses with a generic 502 instead of empty success.
- Use bounded OPNsense POST log queries; retain read-only protection for log-clear
  actions, including read-like suffixes after the clear action.
- Revalidate the original stream credential, current permissions/site grants and
  active gateway authority before polling and after device I/O. Close the stream
  on revocation, expiry, reassignment or unavailable authority; release database
  sessions between polls and fix delivery from the actual service log envelope.
- Keep streaming explicitly best-effort with bounded duplicate suppression; no
  durable cursor, hardware certification or release-readiness guarantee is added.

### Bounded event-retention qualification — 2026-09-23

- Replace the event cleanup task's unbounded DELETE with independently committed,
  materialized batches of at most 1,000 rows and bounded work per run. Preserve the
  full Timescale primary key and skip locked rows without claiming completion.
- Reject invalid retention inputs; preserve the existing 90-day row cleanup and
  separate 180-day chunk retention policies. Expose incomplete backlog results
  and warnings instead of an unbounded catch-up pass.
- Add an isolated real Timescale acceptance tool and operator runbook. Production
  capacity, whole-platform retention and sustained soak remain separate gates.

### Qualification and hardening passes, September 2026

- Commit fresh schema creation and its Alembic revision in one PostgreSQL transaction. Exceptions or process termination before commit no longer leave an unversioned partial installation that blocks safe retry. Keep the existing incremental/autocommit migration path and refusal of ambiguous restores. Add eight real PostgreSQL startup cases, including six fault-injection cases with normal retries and two successful-startup controls; see `docker/MIGRATION-STARTUP-SAFETY`.

- Refuse startup migration when existing database relations lack migration metadata, or the recorded revision is empty, ambiguous or unknown. Preserve the schema and data instead of stamping an incomplete restore as current or guessing a legacy baseline. Recognized incremental upgrades and dedicated fresh databases remain supported. This changes handling of unknown historical revisions; see `docker/MIGRATION-STARTUP-SAFETY`. Add 27 real PostgreSQL regression/control cases and clarify coordinated database, file, authentication and queue recovery in the offline README.

- Serialize credential management writes per organization and reload each credential before update/delete so concurrent requests cannot leave duplicate defaults or mutate a credential through a stale site binding. Refuse ownerless creation explicitly. Preserve separate organizations, existing duplicate-repair policy and encrypted secrets. Independent restore jobs and direct SQL remain outside this API guarantee. See `docker/CREDENTIAL-DEFAULT-SCOPE`.

- Align the sample Hypervisor cluster and fleet responses with current controller identity, observation freshness, metric coverage, node filesystem capacity and visible HA service fields. Refresh sample timestamps on every demo request; keep the production dashboard validation unchanged.

- Load demo data on demand behind a synchronously installed isolated request adapter, preserving the existing read-only demo behavior and refusing network fallback on load failure. Keep shared identity and camera snapshot helpers separate from the large sample dataset so the demo passes the unchanged initial bundle budget.
- Keep gateway tombstone predicates explicit at each query, while preserving shared parent and site-grant authority. The soft-delete checker and its baseline are unchanged.

- Prepare candidate version `26.09.1` across backend, frontend and demo metadata without reusing the existing public `v26.09.0` tag. Supply the public backend README declared by Python packaging and require `poetry check --lock` during the container build. This version change does not mark the candidate as published or enterprise-qualified.

- Validate current active organization/site destinations for gateway creation and edits, holding PostgreSQL parent locks until commit. Refresh and lock gateways before local updates, reject invalid destinations with a fixed 404, and preserve existing site-grant and null-site semantics. See `docker/GATEWAY-ASSIGNMENT-AUTHORITY` for scope and limits.

- Require current active organization/site ownership for gateway lookup, cache admission, lists and summary totals. Resolve site restrictions against the database and refresh selected gateway rows instead of trusting stale ORM state. Preserve existing unassigned-gateway and zero-explicit-grant behavior. See `docker/GATEWAY-PARENT-AUTHORITY` for scope and limits.

- Combine the reviewed OpenWrt configuration transport, dedicated export control, and gateway cache authorization fixes into one integrated shipping candidate. Preserve individual regression histories and require fresh complete runtime/security qualification. See `docker/INTEGRATED-RELEASE-QUALIFICATION`.

- Check tenant and site access before serving cached gateway firmware, packages, or plugins. Namespace these cache entries by organization so a transferred gateway does not reuse another tenant's inventory. See `docker/GATEWAY-CACHE-AUTHORITY` for regression coverage and limits.

- Add a permission-gated Download Config control to the dedicated OpenWrt gateway page, using the existing cancellable binary-download path. Preserve Sync and explain the separation between export and managed backups. See `docker/OPENWRT-EXPORT-UI` for validation scope and remaining device acceptance work.

- Export OpenWrt configuration through the LuCI session-authenticated CGI endpoint with streaming size limits, gzip integrity checks, a total deadline, no redirects and safe errors. Preserve explicit sysupgrade scope through the privileged API and browser download helper. See `docker/OPENWRT-CONFIG-TRANSPORT` for package requirements and remaining UI/hardware acceptance work.

- Refuse unsupported pfSense saved-backup creation before provider I/O; prevent false success and configuration/diagnostic disclosure. Remove unsupported create controls from the OPNsense/pfSense backup page while preserving separate history/export and confirmation controls. See `docker/BACKUP-CREATION-CAPABILITIES` for tested scope and remaining interoperability limits.

- Separate OpenWrt configuration export from unsupported saved-backup creation. Prevent archive content and provider errors from being returned through the narrower backup permission; retain privileged download controls. See `docker/OPENWRT-BACKUP-EXPORT` for the independently tested scope and remaining stock OpenWrt transport limitation.

- Wait for HLS coordinator startup within the existing request deadline and publish its private socket only after listening is ready. Preserve single dispatch and clean up interrupted election resources. See `docker/HLS-COORDINATOR-STARTUP`.
- Report unsupported OPNsense backup history creation and OpenWrt backup inventory explicitly, preserving configuration exports and existing access checks. See `docker/GATEWAY-BACKUP-CAPABILITIES` for remaining capability and durability limits.
- Combine the reviewed gateway, device, credential and backup changes into an integrated qualification snapshot after retaining the original HLS concurrency failure. No incomplete earlier VM run is counted as passed; see `docker/INTEGRATED-RELEASE-QUALIFICATION`.

- Correct OPNsense backup delete/revert action paths, validate bounded filenames, and require exact device confirmation before reporting success. Preserve read-only and single-dispatch policy; suppress arbitrary provider diagnostics in these adapter outcomes. See `docker/OPNSENSE-BACKUP-MUTATIONS` for remaining creation and hardware-restore limits.

- Distinguish unavailable gateway backup history from a valid empty list, hide stale row actions during refresh, invalidate stale restore/delete confirmations, and display normalized byte sizes. See `docker/GATEWAY-BACKUP-INVENTORY-UI` for the validated browser behavior and remaining device-write/restore limits.

- Correct the OPNsense backup inventory host selector and upstream metadata fields; reject failed or malformed inventories instead of reporting empty success. Return validated metadata only and remove raw gateway cleanup diagnostics. See `docker/GATEWAY-BACKUP-INVENTORY` for remaining hardware, UI and restore limitations.

- Refuse the legacy managed gateway backup trigger with an explicit 501 before device I/O: the former path discarded downloaded configuration while claiming success. Preserve existing admission controls and separate protected export/vendor operations. Managed artifact storage and restore remain unimplemented. See `docker/GATEWAY-BACKUP-TRIGGER`.

- Normalize bracketed IPv6 and IPv4-mapped literals before private-target security checks, and correctly bracket pinned IPv6 HTTP URLs. Qualify real IPv6/IPv4 TLS transport separately from controlled API URL-policy regressions. See `docker/CREDENTIAL-IPV6-TARGETS`.

- Preserve the requested hostname in TLS verification/SNI and HTTP Host while connecting only to the validated pinned private IP. Qualify real hostname certificates, virtual-host routing and rejection of IP-only certificates for hostname requests. See `docker/CREDENTIAL-HOSTNAME-IDENTITY`.

- Make stored-credential connectivity checks inspect HTTP headers without consuming response bodies, and share one elapsed transport deadline across HTTPS and explicitly enabled plaintext fallback. Qualify body closure and slow-response behavior with owned HTTP/TLS listeners. See `docker/CREDENTIAL-RESPONSE-BUDGET`.

- Prevent ambient proxy settings from diverting stored-credential HTTP checks while preserving private CA files/directories and existing certificate verification. Qualify routing with real target/proxy listeners and synthetic secrets. See `docker/CREDENTIAL-PROXY-ISOLATION`.

- Report stored-credential HTTP tests truthfully: 2xx means HTTP reachability, not verified authentication; redirects and HTTP errors fail the check without retrying plaintext. Show the actual diagnostic and limitations in the credentials UI. See `docker/CREDENTIAL-HTTP-OUTCOMES`.

- Enforce per-site write caps before creating, editing, deleting or testing stored credentials, including both sides of a site move. Preserve tenant visibility, administrator behavior and API-key permission ceilings. See `docker/CREDENTIAL-SITE-WRITE-CAPS`.

- Widen encrypted SNMP credential storage with a data-preserving migration. Accepted long/Unicode communities no longer fail writes, and unsafe downgrades refuse to truncate secrets. Cover legacy upgrades, concurrent downgrade checks and encrypted core vault/config restores. See `docker/CREDENTIAL-SNMP-STORAGE`.

- Reject explicit null for required credential update values before persistence, including JSON null options that previously broke later reads. Align vendor/username request limits with database columns and regenerate optional/non-null client types. See `docker/CREDENTIAL-INPUT-VALIDATION`.

- Limit credential default demotion to the owning organization and exact site/scope/vendor group. Preserve neighboring site defaults, handle moves of existing defaults, and validate super-admin destination sites against the credential owner. See `docker/CREDENTIAL-DEFAULT-SCOPE` for concurrency and historical-data limits.

- Reject explicit null for required device name/status flags with HTTP 422 validation instead of HTTP 500. Preserve omitted fields, false values and clearing nullable fields, and regenerate optional/non-null client types. See `docker/DEVICE-UPDATE-NULLABILITY`.

- Intersect explicit device IDs with the selected site when collecting core backups. A device list can no longer pull another site's devices into a site-labeled snapshot; preserve organization-wide and empty-list behavior. Validate encrypted archive contents and manifest counts; see `docker/BACKUP-DEVICE-SITE-SCOPE` for remaining scope limits.

- Make batch device commands return one safe outcome per unique device ID. Preserve accepted results through cleanup failures, propagate cancellation, distinguish unknown outcomes from policy refusal, and avoid leaking provider diagnostics or replaying duplicate IDs. See `docker/DEVICE-BATCH-OUTCOMES` for retry and hardware-verification limits.

- Use the shared controller builder for legacy device operations so Proxmox tokens/realms and Omada/TLS settings are consistent. Return a safe construction error for unusable stored secrets, preserve cancellation and adapter policy errors, and remove two decryption fallbacks. See `docker/DEVICE-CONTROLLER-BUILDER` for evidence and unsupported-operation limits.

- Enforce site permission caps before device deletion or controller actions, including each device in a mixed batch. Read-only or insufficient site grants cannot construct an adapter, invoke a command or mutate device state. Existing role scopes and confirmation gates remain in place; see `docker/DEVICE-ACTION-SITE-CAPS`.

- Enforce device-site write caps and saved-credential site visibility before applying a device edit. Denied PATCH requests leave every submitted field unchanged; organization-wide credentials and authorized administrative edits retain their existing behavior. See `docker/DEVICE-UPDATE-AUTHORITY` for the tested scope and limits.

- Keep users paired with explicit access grants in site-specific backups, preventing unrelated restricted accounts from restoring without their restrictions. Normalize mapped UUID fields at the core restore boundary so bulk restoration succeeds. See `docker/BACKUP-USER-SITE-SCOPE` for partial-snapshot behavior and qualification limits.

- Limit firewall gateway collection to the requested active site before reading credentials, and report vault secret inclusion accurately in the contributor manifest. Organization-wide behavior is preserved; other backup contributors require separate scope review. See `docker/FIREWALL-BACKUP-SCOPE`.

- Make gateway configuration export initiate an actual XML or decoded archive download, with bounded validation, safe filenames, duplicate suppression and cancellation on navigation. Replace misleading per-history-row download icons with one export action. See `docker/GATEWAY-BROWSER-DOWNLOAD` for scope and backup-storage limits.

- Reject failed, empty or malformed gateway configuration downloads with explicit safe errors. Preserve textual exports and deliver OpenWRT archive bytes through explicit base64 JSON encoding with a 16 MiB content bound. See `docker/GATEWAY-CONFIG-DELIVERY` for the download contract and backup/restore limitations.

- Stop treating unavailable gateway configuration comparisons as unchanged. Failed, unsupported or missing baseline data now produce explicit errors; the backup UI shows unavailable instead of a stale or empty success and offers a manual retry. Complete comparisons keep their existing diff behavior. See `docker/GATEWAY-CONFIG-COMPARISON` for vendor-history and backup-storage limits.

- Read OPNsense configuration downloads as bounded, validated XML and preserve the original document. Reject malformed or unsafe payloads with fixed adapter diagnostics that omit response contents and tracebacks. This export does not prove durable backup storage or live-state comparison; see `docker/OPNSENSE-CONFIG-DOWNLOAD`.

- Revalidate saved gateway resource scope and connection state before returning or persisting device-test results. Reject moved, inactive or deleted scope and stale connection revisions, locking the current gateway/organization/site only after device I/O until the result transaction ends. See `docker/GATEWAY-TEST-AUTHORITY` for caller-session and transaction limits.

- Return controlled gateway connection-test failures when adapter construction rejects invalid configuration, including contradictory HTTP/certificate-verification settings. Preserve cancellation, direct adapter refusal and cleanup ownership without exposing raw constructor diagnostics. See `docker/GATEWAY-CONSTRUCTION-FAILURES`.

- Preserve saved gateway vendor transport settings during connection tests, including explicit HTTPS selection on custom ports. Share a case-insensitive filter that protects stored destination, credentials, trust and existing write restrictions without rewriting saved settings. See `docker/GATEWAY-SAVED-TEST-POLICY`.

- Project saved and unsaved gateway connection-test messages to fixed success/failure categories, retaining recognized authentication/connectivity guidance. Stop logging raw test exceptions in the gateway service. Preserve already-withheld error fields, metadata behavior and service-owned cleanup. See `docker/GATEWAY-TEST-DIAGNOSTICS`.

- Release the adapter owned by each standalone gateway connection test on success, error, malformed result handling and cancellation. Ordinary disconnect failures retain the original outcome and a fixed service warning. Qualify actual TLS keepalive closure before probe fallback cleanup; preserve vendor shared-context behavior. See `docker/GATEWAY-TEST-LIFECYCLE`.

- Require HTTPS for verified OpenWRT and MikroTik gateway connections on custom ports, and refuse contradictory explicit HTTP plus certificate verification for MikroTik/pfSense before creating a transport. Preserve deliberate insecure legacy protocol selection without rewriting saved records. See `docker/GATEWAY-HTTPS-POLICY`.

- Default new firewall gateway API requests, service creation and ORM inserts to certificate verification. Preserve explicit opt-outs, saved connection choices and partial-update behavior; refresh the generated API contract. Normal HTTPS vendor-client certificate controls are qualified separately from still-open custom-port and standalone transport-lifecycle work. See `docker/GATEWAY-CERTIFICATE-DEFAULTS`.

- Enable TLS certificate verification by default in firewall gateway onboarding, expose a deliberate opt-out warning, clear credentials when creation closes the form, and hide obsolete connection-test results after edits or reopening. Existing saved gateways and direct API defaults are unchanged. See `docker/FIREWALL-ONBOARDING-TLS`.

- Align public security and adapter-maturity documentation with the sole-maintainer support policy, signed marketplace catalog, deployment exposure and documented limits; remove unsupported blanket security and response-time promises.

- Close failed or cancelled Proxmox logins, reject malformed authentication envelopes and clear stale connection state even when transport cleanup fails.

- Guard delayed controller onboarding checks with current active ownership and connection state; discard stale outcomes and release database transactions during device I/O.
- Reject undecryptable encrypted controller credentials in nine adapter helpers instead of forwarding ciphertext; preserve legacy plaintext and the existing ORM credential guards, with explicit API-token transport coverage.

- Report failed Proxmox node discovery honestly: reject unreadable or malformed inventories, record discovery failures without raw provider diagnostics, and skip deep sync after failure while preserving valid empty inventories.

- Isolate Proxmox connection cooldowns by credential, endpoint, trust and routing context; keep agent/custom-transport failures local to their client, never treat login rejection as network outage, and bound expired failure records.

- Isolate Proxmox authentication caches by credentials and connection settings, prevent cross-site ticket reuse through custom transports, and keep rejected API tokens from falling back to password login.

- Preserve stored Proxmox API tokens and authentication realms in generic controller discovery, deep sync, and the shared adapter factory.

- Align saved TrueNAS controller checks with onboarding API-key authentication; reuse live adapter connections and close test connections on failure.

- Project stored controller errors and bounded error histories through safe diagnostic categories, without rewriting stored records on reads. Connection tests and site probes no longer expose adapter message/error bodies; new connection-failure records and handler logs use fixed hints or bounded HTTP status codes while preserving tenant/site access checks.

- Roll back failed discovery inventory work before recording errors, recheck and lock current controller/site/organization authority for failure bookkeeping, and use fixed safe diagnostics for new failure records/events. Preserve previously committed work, bound and sanitize rewritten error history, and retain a failed outcome when bookkeeping or event transport is unavailable.

- Make discovery lease acquisition fail closed on unavailable or ambiguous Redis responses; retain an acquisition-specific token and compare-and-delete on cleanup so expired workers cannot release a successor. Preserve global/per-organization keys, contention skips and 900-second leases; do not claim renewal or side-effect fencing.

- Prevent discovery MAC matching and insert-conflict recovery from reassigning another tenant’s devices. Recheck and lock current inventory authority after adapter I/O, reject unsafe site mappings, and report controller refusals/exceptions as aggregate failure. The global MAC constraint and post-commit deep-sync/event limits remain explicit in `docker/DISCOVERY-DEVICE-AUTHORITY`.

- Reserve tenant/site ownership before discovery job publication and authorize status reads against current site authority. Expose only bounded discovery aggregates and fixed failure messages; preserve a reviewable task ID after uncertain broker acknowledgement. Legacy unowned IDs now return 404; see `docker/DISCOVERY-JOB-SCOPE`.

- Keep raw worker exceptions out of tenant-visible task failure, retry and revoked records, including legacy reads. Preserve scoped status and retry counts, avoid rendering exceptions in FreeSDN hooks, and stop unowned Celery-result fallback reads. Internal Celery result/log privacy and successful task payload contracts remain separate; see `docker/TASK-FAILURE-PRIVACY`.

- Bind report-recovery qualification to the exact backend image’s single Alembic head instead of a fixed historical revision. Verify every restored database before its mail probe; preserve the existing synthetic restore, quarantine and replay controls. See `docker/REPORT-RECOVERY-SCHEMA`.

- Persist in-app notifications and pending realtime events in the caller-owned transaction. Recover committed publication through a bounded worker with current-recipient checks, per-row locking and stable event identities; explicitly persist post-commit camera, plugin and scan notifications. Migration020 retains legacy bells and refuses pending queue loss. Redis acceptance is not browser acknowledgment, and crash recovery may duplicate publication. External delivery retries remain separate. See `docker/INAPP-EVENT-OUTBOX`.

- Restrict personal notification events to the addressed user on every event WebSocket, including unrestricted organization users. Reject conflicting recipient envelopes while preserving tenant, subscription and site checks. See `docker/NOTIFICATION-RECIPIENT-ROUTING`; transaction/outbox recovery remains separate.

- Retain a separate acquisition token at every solo-lock release site so an expired run cannot release a newer run in the same process. Migrate discovery, monitoring, reconciliation, gateway sync and event replay; preserve task outcomes when release transport fails. Custom helper callers must pass the returned token; lease expiry is not execution fencing. See `docker/SOLO-LOCK-OWNERSHIP`.

- Reserve tenant-owned task progress before broker publication, preserve it throughout worker startup and lifecycle hooks, and isolate cached progress across Celery requests. Refuse unreserved submissions and report uncertain broker acknowledgements with an inspectable task ID without overwriting worker results; see `docker/TASK-PROGRESS-OWNERSHIP` for crash, expiry and outcome-classification limits.

- Bind delayed agent-offline alerts to the exact committed disconnect transition and current live tenant/site/agent state. Reload current destinations and names, retain explicit organization scope, and mark notified only after actual delivery outcomes and a conditional current-state update. Refuse legacy tasks without a transition epoch and retain documented broker/crash/concurrency limits; see `docker/AGENT-OFFLINE-AUTHORITY`.

- Require explicit source-built FFmpeg security coverage alongside image package scans. Inspect immutable local images without starting them, verify bundled source and runtime hashes, generate native CycloneDX inventories, and fail on missing coverage, stale databases, suppressed findings or a failed vulnerable-version scanner control. Gate backend/go2rtc CI and bind the local Docker audit to Trivy’s image ID; see `docker/NATIVE-MEDIA-SECURITY`.

- Build backend and optional go2rtc media tools from signed, SHA-pinned FFmpeg 9.0.2 source against stable Alpine libraries. Include the source, licenses, recipes and runtime hashes in the images, preserve the supported codec/acceleration configuration, and document removed upstream legacy codec names and hardware/architecture qualification limits in `docker/FFMPEG-UPGRADING`.

- Apply requested HLS low, medium and high quality presets to H.264 inputs instead of silently copying the source; preserve explicit source quality. Document the additional encoding cost and add decoded-media regressions for H.264/HEVC live and recorded output. See `docker/HLS-QUALITY-PRESETS`.

- Release recorded HLS sessions and stop heartbeats after terminal playback failure, abort stalled manifest requests at the startup deadline, and isolate cleanup across playback changes. Permission refusals no longer trigger snapshot fallback; demo and source-refusal behavior is preserved. See `docker/CAMERA-PLAYER-LIFECYCLE`.

- Coordinate HLS sessions across API workers on one Linux host through a private shared media volume and bounded same-UID control socket. Preserve current camera authority checks, serialize session metadata during stop, and drain owned media on shutdown. Owner loss requires playback restart; see `docker/HLS-COORDINATOR` for deployment and failover limits.

- Bound private HLS FFmpeg diagnostics to a 64 KiB prefix while continuing to drain excess output, including after diagnostic write failure. Reap capture tasks on stop, replace dead live/failed recorded producers, and retain reuse of successfully completed recordings with media. See `docker/HLS-STREAM-LIFECYCLE`.

- Scope HLS reuse to exact camera, organization, source and encoding identity. Recorded sessions and bounded probe caching also distinguish full start time and duration, so a failed window cannot poison a different recording request. Cache/session keys avoid raw credentials, and playback URL-build warnings omit native exception text. See `docker/CAMERA-SESSION-IDENTITY`.

- Bind HLS FFmpeg and camera FFprobe children to their Linux worker lifetime, with a parent-race check and refusal of privileged executables. A worker crash terminates its directly owned media children; ordinary cancellation cleanup remains intact. See `docker/CAMERA-CHILD-OWNERSHIP` for scope and remaining multiworker/session limitations.

- Recorded-playback discovery now uses the bounded codec-probe runner and reaps canceled children. Nonzero exits, malformed metadata and oversized output remain inconclusive instead of becoming cached playback verdicts. Definitive no-video/zero-dimension results and existing codec normalization are preserved. See `docker/CAMERA-RECORDED-PROBE`.

- Camera codec probes now discard native stderr, bound metadata output, reap their child on timeout or cancellation, and reject malformed response shapes without copying private diagnostics into application logs. Normal codec/resolution/bitrate results remain available. HLS worker ownership and FFmpeg stream lifecycle remain separate work. See `docker/CAMERA-PROBE-LIFECYCLE`.

- Camera access resolution now excludes soft-deleted groups while retaining direct grants, active-group merging and independent role permissions. Historical memberships and grants can remain stored without continuing to confer group access. This is a current-query revocation check, not concurrent-effect fencing or multiworker streaming coordination. See `docker/CAMERA-GROUP-GRANTS`.

- Every HLS continuation route now validates complete session metadata and current camera/site/live-or-playback authority before touching stream state or returning a file path. Camera lookup distinguishes identity from its site value and refuses missing/deleted targets with 404; existing tenant playlist/segment camera checks are retained. Platform access uses the existing unscoped-superadmin policy, so org-less scoped credentials fail closed. Playlists and segments prohibit storage and shared caching. Multiworker stream ownership and per-viewer leases remain separate lifecycle work. See `docker/CAMERA-CURRENT-ACCESS`.

- Production automation execution now resolves committed rule definitions from the database for each scoped event and manual run, and checks the same definition again immediately before each action after any configured delay. Deleted, changed, disabled or unavailable definitions stop the remaining chain even when ordinary action errors may continue. Tenant activity and manual request scope are checked against current records; rolled-back cache edits cannot authorize actions. Explicit manual execution retains disabled/paused-rule compatibility. Cache-based management views, the race after the final check, durable event delivery and exactly-once external effects remain separate limits. See `docker/AUTOMATION-RUNTIME-AUTHORITY`.

- Automation edits now hydrate a validated replacement from the scoped database row instead of assigning raw action/condition dictionaries to the live engine. Missing records no longer report a successful edit, and failed lookups, invalid shapes or failed flushes leave the previous runtime object untouched. Required patch fields reject explicit null while descriptions and conditions can still be cleared. Cross-worker invalidation and rollback after a successful flush remain separate lifecycle work. See `docker/AUTOMATION-EDIT-INTEGRITY`.

- Notification providers now return fixed error categories and numeric protocol status codes instead of raw transport exceptions, private endpoint addresses or vendor reply bodies. SMTP permanent refusals stop retrying while temporary refusals and HTTP rate limits retain retry eligibility. Delivery errors, verification failures and provider logs follow the same privacy boundary. Existing stored diagnostics are not rewritten. See `docker/NOTIFICATION-PROVIDER-ERRORS`.

- Notification batches now send recipients sequentially while using the caller's database session, preserving each tracking identity and avoiding concurrent flushes. Cancellation stops before later recipients start and publishes no batch retries; ordinary provider refusals remain visible while later recipients can proceed. This keeps transaction ownership unchanged and does not provide a transactional outbox or exactly-once delivery. See `docker/NOTIFICATION-DISPATCH-SESSION`.

- Delivery provider loading now selects the exact organization, with platform scope restricted to platform-owned providers. Reloads discard stale authority before resolving enabled providers and install the replacement map only after a complete successful load. Default selection is deterministic. Administrative provider listing retains its separate all-tenant semantics. The support document now consistently identifies the sole maintainer and makes no unsupported funding or service-level promise.

- The isolated HA proxy check now accepts installed Docker image IDs, resolves tagged inputs to immutable IDs before creating containers, and reports both exact tested images. A missing image ID is refused without attempting a registry pull. This remains a single-host proxy smoke check, not multi-host HA qualification.

- Notification retries now verify the persisted delivery organization, channel, subject, lifecycle and next attempt before sending, and serialize competing retries with a database row lock. Explicit providers must remain enabled and correctly scoped; platform retries cannot use tenant providers. Broker rejection no longer appears as successful scheduling, exhausted retries cannot enqueue an extra attempt, provider exceptions are sanitized, and skipped outcomes remain skipped. This does not provide a durable outbox or exactly-once external delivery.

### Notification outcomes and retry identity

- Preserve failed notification attempts, distinguish policy skips from sends,
  and report partial failure through Fabric without exposing transport details.
- Require explicit in-app recipients to be active, non-deleted users of the
  supplied organization before persistence or event publication.
- Refuse in-app persistence failures instead of publishing phantom creation
  events after a failed flush or commit.
- Keep cancellation visible and bind retries to the exact flushed delivery row
  instead of guessing by subject/channel and risking another recipient's row.
- A flush is not a commit or proof of final delivery. Transactional outbox,
  shared-session concurrency and broker-failure qualification remain separate.
  See `docker/NOTIFICATION-OUTCOMES` for the limits.

### Signed marketplace catalog publication

- Refresh the bundled catalog to the first signed, expiring serial with the
  existing publisher identity and 12 reproducible packages at new versioned URLs.
  The live registry retains the previous 12 archives byte-for-byte.
- Require the publisher reproducibility and freshness checks to pass instead of
  treating the legacy catalog defects as expected failures. Keep the SDK author
  example aligned with the published hello-world manifest.
- Catalog signing/deployment is separate from application/container release
  qualification; expiry and independently retained restore floors still apply.

### Fabric staged-write target lifecycle

- Refuse staging against a deleted controller or a controller under a deleted
  site, including when the caller omits site_id. Preserve tenant and per-user
  site filtering and legitimate multi-site controller mappings.
- This checks target state at lookup; it does not claim to prevent a concurrent
  deletion after lookup or replace the final apply authorization checks.

### Fabric executor and handler exception privacy

- Keep raw database, adapter, artifact and plugin exception details out of
  normalized operation results and executor logs. Preserve fixed error codes,
  the invocation API's failure mapping, staged-write cleanup and cancellation.
- Remove raw exception text from the seven VPN and VoIP Fabric handlers. Retain
  their error codes, successful output, site scope and cancellation behavior.
- Normalize built-in notification and webhook dispatch/transport/URL exceptions
  without copying secrets from exception text into results or notification logs.
- Keep successful outputs and declared handler refusals unchanged. This is a
  bounded exception-handling fix, not a claim that all handler output or all
  historical records have been sanitized.

### Optional image security and development dependency volumes

- Update Prometheus's OpenTelemetry modules to 1.45.0 to address
  CVE-2026-81870. Preserve the verified Prometheus 3.14.0 source and UI locks.
- Use Node 24.21.0 LTS on Alpine 3.24 for the optional development environment.
  The production frontend remains compiled assets served by Caddy.
- Install development dependencies with npm ci and invalidate cached dependency
  volumes when the lockfile, npm configuration, Node ABI, libc or package manager
  changes. Failed installs do not start Vite or retain a successful cache stamp.
- This changes the development container's libc. Existing dependency volumes are
  reinstalled; native addon and architecture support requires explicit testing.

### Fabric Connection persistence outcomes

- Report a failed or uncertain final database commit as a failed Connection run,
  retaining individual step outcomes and warning that external effects may
  already have occurred. Attempt rollback and close the session without exposing
  database exception details or automatically retrying uncertain effects.
- Preserve normal commit behavior, failed-step details and cancellation. This is
  an outcome-reporting correction, not transactional delivery or rollback of
  hardware, notifications, webhooks or separately committed staging records.

### Fabric read scoping and firewall result fidelity

- Always intersect network client pages and statistics with their organization,
  any requested site, and any explicit site-grant set. Supplying a site filter
  must not replace tenant authorization, and an empty explicit grant stays empty.
- Pass invocation site restrictions into Fabric network-client and firewall-alert
  reads; filter storage-health reads before contacting providers and exclude
  controllers attached to deleted sites.
- Unpack the firewall service's actual page/total result and expose the real IDS
  signature_name field. Empty pages now return no alert rows instead of two
  placeholders. Read failures return fixed messages without raw client details.


### Camera snapshot authority through Fabric

- Recheck the stored author's active state, organization, current camera-view
  permission, site access and per-camera live grant before a Fabric snapshot can
  open a device connection. Preserve a caller's narrower invocation site scope.
- Refuse unavailable/deleted/foreign targets and authorization lookup failures
  before capture or artifact storage. Authorized snapshots preserve the JPEG
  artifact flow; adapter errors no longer expose raw device/client details.


### Fabric shared coordination refusals

- Require explicit successful shared event and cooldown claims before unattended
  Connection execution. Missing event identities, client failures, timeouts and
  malformed replies now refuse instead of proceeding or using worker-local state.
- Retry failed client construction on a later event, preserve uncertain claims,
  avoid exposing client exception details, and retain the existing shared key
  namespace. Explicit operator test runs still use their existing permission and
  staging gates without an event claim.
- These expiring claims are not durable delivery or exactly-once effects. Upgrade
  every event worker before relying on outage refusal; old workers remain unsafe.


### Fabric scope lookup refusals

- Stop native automation and Fabric Connection steps before the executor when
  a stored author's site grants cannot be verified. Missing, inactive or deleted
  author rows and database failures must not turn into unrestricted access.
- Reject soft-deleted authors in the permission checker, and keep database
  exception details out of permission/scope refusal messages. Preserve the
  existing behavior for resolved administrators, users with no site grants and
  explicitly permission-free native operations with no actor.

### Native camera automation authorization

- Recheck the stored rule author's active account, organization, current module
  permission and camera/site grants before native camera adapter creation,
  including explicit read-only and unknown site permission ceilings.
- Refuse missing or revoked authority and authorization lookup errors without
  copying database exception details into action history. Action parameters
  cannot override the execution context's author or organization.
- Keep authorized adapter behavior unchanged; this does not establish in-flight
  cancellation, rule-cache synchronization or hardware acceptance.

### Stable JavaScript build tools

- Update release Docker builders and CI to npm 12.1.0, and the Prometheus UI
  builder to pnpm 12.6.0. Keep Node 24.21.0 LTS and the reviewed application
  dependency locks; these tool updates do not authorize dependency major bumps.
- Align frontend/n8n package-manager declarations and describe Caddy accurately
  as the default TLS edge, with NGINX as the optional profile.

### Automation rule subscription replacement

- Replace an existing rule's event subscriptions atomically in the local engine
  instead of appending duplicate entries or retaining its previous pattern.
- Remove all obsolete entries on deletion, clear corrected missing-pattern
  diagnostics and refresh the event index after a successful rule-edit flush.
- This fixes local registration and edit behavior; synchronization of cached
  rule state across workers and database rollback remains a separate concern.

### Automation alert-resolution outcomes

- Record missing, foreign, already-resolved or unavailable alert targets as
  failed actions. Preserve `resolved` output while returning the standard
  `success` result, so stop-on-error chains and execution history stay truthful.
- Use the nullable system actor for automated resolution instead of an invented
  user UUID that violates the alert's foreign key. Human API attribution remains
  unchanged; system events use JSON null rather than the string "None".

### API worker route-cache initialization

- Build static trailing-slash aliases from route metadata instead of compiling
  the entire OpenAPI document on each worker's first request. Keep nested router
  prefixes, schema visibility and dynamic plugin cache invalidation unchanged.
- Add real ASGI regression checks for authorization, request bodies, query
  strings, method refusal and complete application path equivalence. This change
  does not alter worker counts, preload, memory budgets or HLS session ownership.

### Event automation coordination

- Refuse unattended actions when event claims, cooldowns or hourly rate-limit
  checks are unavailable, malformed or uncertain. Do not fall back to local
  counters or erase a claim whose response may have been lost.
- Keep same-timestamp attempts distinct in the atomic rate-limit set. Expose
  organization-scoped refusal diagnostics for the responding worker through the
  automation summary API, without counting refused work as an execution.
- Document missed-event, claim-expiry, restore, manual-trigger and diagnostic
  limits in `docker/AUTOMATION-COORDINATION`; no exactly-once claim is made.

### Authentication recovery fixture validation

- Seed a supported username/password credential in the isolated authentication
  recovery rehearsal. Verify that fresh logins before and after recovery can
  list the restored credential through the real API without exposing secrets,
  in addition to checking unchanged ciphertext and both vault derivations.

### Optional NGINX TLS startup

- Refuse startup when TLS is selected but certificate/key files are missing,
  empty or unreadable. Never silently substitute an HTTP-only configuration.
  Explicit `SSL_MODE=off` remains available for separately secured deployments.
- Document certificate ownership, restricted runtime key copies, renewal and
  nonstandard-port limits in `docker/NGINX-TLS`.

### Marketplace freshness and health dashboard routing

- Persist a signed catalog serial floor, reject expired/replayed/substituted
  snapshots, and bind install/update authorization to the current accepted
  snapshot. Recheck freshness after downloading before loading plugin code.
- Make catalog acceptance atomic. A signed empty snapshot withdraws every offer;
  installed plugins keep running. Offline seeds are browse-only, insert-only,
  and cannot replace accepted catalogs or revive withdrawals.
- Migration 019 leaves legacy catalog rows untrusted until a fresh signed sync.
  The old publisher catalog must be re-signed before rollout. Read
  `docker/MARKETPLACE-FRESHNESS` for independent restore floors, publisher trust
  changes, clock requirements and downgrade refusal.
- Separate edge liveness at `/healthz` from dashboard routes at `/health` and its
  tabs, including nginx profiles and installer probes. Installation acceptance
  now checks dashboard HTML and security headers, not only HTTP 200.
- Show backend marketplace refusal reasons and sync receipts. Constrain health
  cards and issue rows on narrow screens so child content is not clipped.
- Show N/A for an unavailable worst health component. Preserve actual zero and
  100 observations instead of labeling missing components "unknown: 100".


### Health observations and production maintenance packaging

- Preserve measured zero health scores and expose missing scores as unavailable.
  Exclude unknown records from device/site/organization/module/WAN/SLA aggregates,
  weight site averages by measured records, and expose measurement coverage.
- Stop injecting perfect firmware/error scores into scheduled health updates and
  require a collected running configuration before scoring drift. Reachability
  is no longer reported as time-window uptime; absent trend history stays unknown.
- Render N/A and chart gaps for unmeasured values. Existing historical assumptions
  cannot be certified retroactively; read `docker/HEALTH-MEASUREMENTS` for limits.
- Include the legacy VPN profile audit/encryption command in the production image
  and execute its default read-only mode during real installation qualification.

### Preserve independent VPN profiles and encrypt site configuration writes

- Scope controller imports to their exact site, organization, VPN type,
  controller and server identity. Preserve unrelated profiles; refuse ambiguous
  duplicates. Manual OpenVPN imports can select an existing profile explicitly
  in the site dialog and cannot convert another VPN type or controller profile.
- Encrypt OpenVPN content through both site create/update paths. Correct site
  profile response types so real database UUIDs and timestamps serialize normally
  instead of failing after a successful create. Secret content remains write-only.
- Show standardized backend conflict messages and field validation details in
  shared form dialogs instead of hiding them behind a generic HTTP status error.
- Provide a bounded, audit-first legacy plaintext encryption tool with an explicit
  apply flag, per-batch transactions, ciphertext verification and resumable counts.
  Read `docker/VPN-PROFILE-MAINTENANCE`; this does not erase old plaintext-bearing
  backups or rotate affected VPN identities automatically.
- Add an owned 512 MiB PostgreSQL tmpfs pressure/restart qualification, independent
  mount/ownership safety checks and CI evidence capture. It does not fill the host
  disk or establish production application/HA failure recovery or RTO/RPO.

### Preserve SLA observations and incident lifecycle

- SLA evaluations no longer infer site/organization uptime or client satisfaction
  from a composite health score, or count missing/non-finite targets as successes.
  Incomplete observations clear current compliance to unavailable and do not write
  numeric snapshots; measured targets retain breach handling. Site health queries
  independently enforce organization ownership. The UI explains observation
  limits and new site policies no longer include an unsupported uptime target.
  Existing historical reports remain unchanged; see `docker/SLA-MEASUREMENTS`.
- Keep acknowledged incidents in the unresolved lifecycle and dashboard count;
  update them without replacement, close retained duplicates on recovery, and
  prevent acknowledgement from reopening resolved incidents. Serialize overlapping
  policy evaluations with transactional row locks and skip already claimed work.
- Honor per-metric consecutive-violation confirmation using persisted complete
  observations. Missing/partial observations and configuration changes restart
  confirmation; legacy snapshots begin a new sequence. Pending violations affect
  compliance without prematurely creating an incident. No schema migration is needed.

### Distinguish zero SLA measurements from missing data

- Evaluate site/organization health scores of zero instead of dropping them as
  missing. Preserve zero compliance in the summary API.
- Show unmeasured policy compliance as unavailable, without a fabricated 0%
  gauge. Use the same measured-value severity for the summary card and policy
  gauges; a measured 0% is not styled as success.
- Preserve measured zero and unavailable values throughout evaluation and display.
  Measurement-source corrections are described above.

### First-time VPN import persistence

- Fix first-time manual OpenVPN and gateway VPN imports failing after validation
  because they referenced a nonexistent database attribute. New configurations
  now inherit the organization from the already validated site, retaining
  encryption at rest and the existing ownership checks.
- Add first-create and reimport ownership/encryption regressions. This fixes
  configuration persistence; it does not certify tunnel connectivity or
  multi-profile/concurrent import behavior.

### Reporting memory bounds and operational qualification

- Count SLA incident severity/status in PostgreSQL instead of loading every
  matching incident and its JSON/text payload into the API or worker. Preserve
  tenant, site-grant and half-open interval filtering and the report format.
- Extend isolated Lite acceptance with a verified 16 MiB report-volume ENOSPC
  drill and bounded concurrent HTTPS/report/event/queue workload. Retain normal
  rate limits and verify generated archives after recreation and encrypted
  recovery. CI runs a short workload; a longer local run is separate evidence.
- Clarify Linux amd64 support in the release guide; building on ARM64 is not
  qualification. See `docker/CAPACITY-ACCEPTANCE` for workload limits.

### Private installer configuration and Lite recovery acceptance

- Mount the backup client's unused inherited PostgreSQL data directory on tmpfs,
  preventing container recreation from leaking anonymous database volumes while
  keeping the actual backup archive volume persistent.

- Create/update installer environment files with verified mode 0600, preserve
  existing vault/password/auth/mail settings, and refuse symlinks, hard links,
  special files, foreign ownership, concurrent changes and unsupported permission
  semantics. Validate CLI hostname/email/required arguments before building.
- Keep the configured HTTPS public and report origins consistent. Keep report
  mail opt-in separate; do not automatically mint or rotate a recovery epoch.
- Add an isolated real Compose rehearsal for HTTPS cookie/CSRF authentication,
  dashboards, PDF/CSV archives, all five worker queues and encrypted recovery of
  PostgreSQL, TimescaleDB and application files with vault-key preservation and
  separate JWT key rotation. Document limits in `docker/INSTALL-ACCEPTANCE`.
- Replace unsafe blanket rebuild/restart advice with explicit existing-site
  database/queue migration requirements and retained-backup/source fencing.
- Update Caddy's three OTLP trace exporter modules from 1.43.0 to 1.46.0,
  matching the existing OpenTelemetry core generation and addressing the upstream
  endpoint-logging advisory CVE-2026-81870. Node remains on the pinned LTS line.

### Report-mail recovery boundary and input validation

- Require an independently managed `SLA_REPORT_DELIVERY_EPOCH` UUID4 for report
  mail. Migration 018 preserves old notice history without approving it. After an
  offline restore with a fresh epoch, old active notices become unknown for relay
  reconciliation; they are not retried. Old schedules pause pending reapproval,
  and reapproval permits future reports only. See `docker/SLA-REPORT-DELIVERY` for
  source fencing, configuration consistency and rollback restrictions. Restoring
  the old epoch still permits replay; automatic restore detection is not claimed.
- Add an isolated real PostgreSQL dump/restore and verified SMTP TLS rehearsal,
  including a duplicate-delivery negative control, empty/rotated epoch protection,
  retained archives/history, fresh approvals and process/cache restart.
- Reject malformed schedule recipient types as validation errors and disallow a
  trailing newline in recipient addresses.
- Correct public authorship and review statements: one owner/developer maintains
  the project with AI tooling; independent peer review and enterprise support
  coverage are not claimed.

### Authorized SLA report notices and SMTP certificate verification

- Add the Reports tab for PDF/CSV generation and downloads, schedule review,
  delivery status and cancellation of pending notices. Notices link to reports
  behind sign-in and live organization/site authorization; no attachments or
  arbitrary external recipients are supported.
- Commit approved notice records with scheduled reports. Recheck actor/recipient
  authority on every attempt, preserve identity/scope ceilings, bound transient
  retries and keep uncertain SMTP acceptance out of automatic retry. Worker and
  DB-result interruptions remain visible as unknown outcomes.
- Require trusted STARTTLS certificates for SMTP send/verification. Migration 017
  requires SMTP re-verification and leaves every existing schedule opted out of
  mail. Read `docker/SLA-REPORT-DELIVERY` before enabling notices, restoring the
  database or downgrading; terminal delivery history is not automatically pruned.

### Queue backup recovery qualification and analytics scope

- Add an isolated saved-backup rehearsal covering RDB, multipart AOF, wrong-mode
  empty/stale loads, corrupt and incomplete backups, expired results, and real
  Celery consumption of an explicit synthetic-only manifest. Original backups
  remain unchanged and reserved work stays quarantined. Read
  `docker/redis/QUEUE-BACKUP-RECOVERY`; customer source selection, migration and
  hardware replay are not authorized by this fixture.
- Keep an explicitly empty analytics site-grant filter empty. It can no longer
  fall through to an organization-wide query, including with a pinned site.

### Offline legacy queue inventory

- Add a guarded read-only inventory for isolated disposable Redis/Valkey copies.
  Account for DB0/1/2 priority queues, FIFO positions, reserved deliveries,
  binding metadata and results; flag duplicate/conflicting jobs and unknown
  completion rather than automatically replaying work against devices.
- Refuse unsafe source containers, changed datasets, unknown formats and bounded
  scan failures with an incomplete receipt. Preserve private evidence separately
  from the shareable aggregate receipt. Read `docker/redis/QUEUE-INVENTORY`;
  backup loading, authoritative-source selection and HA cutover remain separate,
  unqualified operator procedures.

### Authentication recovery without changing vault keys

- Add optional `JWT_SIGNING_KEY` across API, MFA and rate-limit verification and
  all Compose backend services. Once set, only that key validates JWTs; existing
  installations with an empty value preserve their previous behavior. Keep
  `SECRET_KEY` and `ENCRYPTION_SALT` unchanged to preserve encrypted credentials.
- Document a coordinated offline recovery cutover and add a disposable real
  database restore rehearsal. A restored account token-version plus one is not
  sufficient to reject tokens issued after the backup. Key changes require all
  old processes fenced and all replicas recreated; they are not rolling updates
  or automatic incident recovery, and do not revoke non-JWT credentials.

### Durable security decisions and camera discovery

- Move JWT revocation and single-use refresh/reset/MFA claims from the evictable
  Valkey cache to committed PostgreSQL rows. Refuse authentication/claims when
  the security store is unavailable and do not acknowledge failed logout writes.
- Add migration 016 with an account token-version and device-session cutover,
  plus bounded expiry maintenance. Existing sessions, reset links and pending
  MFA challenges must be renewed. Read `docker/TOKEN-REVOCATION-UPGRADING`:
  stop old application processes, preserve encryption keys, and rehearse recovery.
- Correct UniFi Protect discovery to use the defined RTSP, motion and PTZ
  capabilities instead of nonexistent enum members that broke camera inventory.

### Memory pressure and authenticated appliance connections

- Give Lite its own 96 MiB Valkey data budget inside its 256 MiB container.
  Reduce the shipped Pro/Max default data budget to 256 MiB and disallow extra
  swap for data nodes. The prior Pro budget can OOM during persistence without
  swap. Config mounts fail if missing; `REDIS_CONFIG_PATH` selects an operator
  config without a hidden command-line override. Existing env files and HA
  rewritten configuration require review; drain/reconcile work before reducing
  a live queue's budget.
- Add a blocking disposable memory gate: cache eviction, non-expiring queue
  exhaustion, AOF/RDB with concurrent writes, zero OOM/swap, and recreation with
  queue-content verification. These checks do not establish fleet capacity.
- Default new controller/probe and TrueNAS/hypervisor onboarding verification
  to on. TrueNAS REST always uses HTTPS; a WebSocket certificate rejection
  cannot trigger a REST fallback. UniFi Protect's camera service no longer
  disables verification, and authenticated HTTP redirects are refused.
- Support an additional private appliance CA through a read-only mounted PEM
  and `FREESDN_DEVICE_CA_BUNDLE` for TrueNAS and Protect. Existing explicitly
  insecure controller records are preserved for operator review, with warnings;
  this does not certify every other adapter's transport policy.
- Apply the same certificate policy to TrueNAS file transfers, and refuse
  download URLs selecting another origin or protocol. Read `docker/DEVICE-TLS`
  before upgrading appliances that previously relied on unverified certificates.

### Valkey HA recovery and breaking topology change

- Replace DNS-based Sentinel discovery with reserved numeric addresses on the
  existing Compose network. A stopped Docker service no longer sends Sentinel
  into repeated blocking DNS lookups. Keep the normal quorum and TILT safety.
- Persist Sentinel elections and data-node role configuration in five separate
  named volumes. A promoted node no longer reverts to its bootstrap replica
  role when recreated. Both data nodes use the same authenticated persistence,
  memory policy and command restrictions.
- Bound application discovery/connect attempts and disable automatic replay of
  ambiguous HA commands. Existing sync and async clients are exercised through
  real stop, SIGKILL, rejoin, reverse failover and loss of Sentinel majority.
- Specify the broker/result database on every Celery Sentinel URL. Previously
  only the last URL carried it; endpoint rotation could move workers and
  producers to different databases and strand jobs after failover.
- Bound Celery broker, result and Sentinel socket connections so a stale
  master address cannot stall workers on a kernel TCP timeout during recovery.
- Refuse unmarked existing data, changed node identity and uncoordinated
  credential changes. Read `docker/redis/HA-UPGRADING`: migration from the old
  HA volumes and online credential rotation are not qualified. These changes
  are not safe to apply as an unattended image-only upgrade.
- Add a disposable fault qualification to blocking CI. The old shell failover
  drill now invokes that isolated qualification with explicit image/report
  arguments; it no longer pauses an existing deployment.
- This remains a single-host topology with asynchronous replication. It does
  not provide host-loss protection, partition fencing, zero-RPO or a measured
  production RTO. A passing laboratory drill is not enterprise certification.

### Database runtime: upgrades in place

- Keep PostgreSQL and LogDB on the Debian runtime at PostgreSQL 18.6. Build
  TimescaleDB 2.30.2 from checksum-verified source with its license notices,
  retaining the 2.30.1 versioned library and install SQL for exact logical
  restores. Keep GPG available for encrypted backups and rebuild the gosu helper.
- Adopt an existing cluster in place. The collation, sort order, `postgres` uid
  (999) and data checksums are unchanged from 26.09.0, so there is no logical
  migration, no new volume and no locale change on upgrade. An earlier candidate
  for this release moved the database to Alpine/musl; it was withdrawn, because
  it would have forced every deployment through an offline dump and restore,
  changed the locale provider to builtin C.UTF-8 and moved the `postgres` uid to
  70. Its measured benefit was a lower scanner count, not lower risk: the
  remaining findings on the Debian images have no upstream fix, and the
  published 26.09.0 image carries more of them, 25 of them fixable.
- Record which runtime created a cluster, and decide before startup or any
  ownership change: an unmarked PostgreSQL 18 cluster, which is every cluster an
  earlier release created, is adopted and marked; a cluster marked with a
  different runtime, a different major version, or a second cluster layout in
  the volume is refused with exit 78 and a message naming what was found;
  `FREESDN_REFUSE_UNMARKED=1` turns adoption back into a refusal.
- Keep the offline migration tool for a cluster the guard refuses, with strict
  preflight, original bootstrap-role preservation, serial Timescale restore,
  content/permission verification and index checks. It never switches the
  deployment or removes original volumes. It creates the recovered database with
  the builtin C.UTF-8 provider whatever the source used, so it does change
  sorting semantics and requires an explicit acknowledgement.
- Fix the HA standby named-volume mount for PostgreSQL 18 and remove shell
  interpolation from replication bootstrap. CI exercises in-place adoption and
  its refusals, logical migration, refusal/rollback, physical replication,
  recreation and manual promotion.
- Serialize primary and LogDB startup migrations across API replicas with a
  transaction advisory lock. Include the guard in the production image and
  verify concurrent startup and lock-owner failure against real databases.
- Route the HA public edge through both API replicas and preserve HTTPS
  forwarding across the internal proxy. Verify WebSockets and upstream loss.

### Build and dependency maintenance

- Update the Caddy expression library to CEL 0.30.0 with a source-hash-checked
  compatibility patch. Build-time tests cover hidden JSON fields and Caddy
  matcher behavior; module versions remain recorded in the vendored binary.
- Update NetBird's compiled STUN/DTLS dependencies and remove its legacy
  TURN v3 / DTLS v2 path. Preserve NetBird routing hooks and filtered interface
  discovery. Fix STUN error propagation and cancellation callback shutdown;
  run local UDP/TCP transport tests with Go's race detector during Docker builds.
  TURN stays on 4.1.1 until NetBird's ICE transport migration is qualified.
- Gate private release image publication on source-level reachable-vulnerability
  scans for NetBird, Tailscale and Caddy, including advisories below High severity.
  Run the same blocking scans in public CI and retain failure evidence.
- Move the backend to patched Python 3.14.8 / Alpine 3.24 while preserving
  application UID/GID 1001, writable volume paths and the VPN sidecar contract.
  Rebuild NetBird and Tailscale from checksum-verified source; runtime Python
  plugin installs use pinned uv 0.12.17 instead of shipping pip/ensurepip.
- Optional plugin dependency installation remains disabled by default. When
  explicitly enabled, require a complete exact-version requirements lock with
  SHA-256 wheel hashes. Reject nested files, alternate indexes, direct URLs,
  source builds and inherited installer configuration. Install the validated
  lock snapshot into a pip-free virtual environment.
- Use patched Alpine runtimes for optional NGINX and Valkey. Preserve NGINX
  and Valkey UID/GID 999, and verify Valkey RDB/AOF upgrade compatibility.
  PostgreSQL stays on Debian and adopts an existing cluster in place; see above.
- Rebuild go2rtc, rclone, Prometheus (including its embedded UI), the PostgreSQL
  exporter and database gosu helper with Go 1.27.2 and locked dependencies.
  Patch PgBouncer OS packages while preserving its upstream configuration and
  UID 70. Include compiled dependency license notices in each rebuilt image.
- Overlay a reviewed Prometheus UI dependency lock, audit it during each fresh
  security build and regenerate the embedded assets and JavaScript license list.
  Image-only Go scans cannot inventory these bundled JavaScript dependencies.
- The go2rtc runtime uses Python 3.14.8 and current Alpine media tools; pip is
  removed. Bake dependencies for custom Python exec sources into a derived image.
- Source-built services are selected by GO2RTC_IMAGE, RCLONE_IMAGE,
  PROMETHEUS_IMAGE, POSTGRES_EXPORTER_IMAGE and TAILSCALE_IMAGE. Their former
  *_VERSION variables no longer select arbitrary upstream binaries; version
  changes must update and qualify the corresponding committed module locks.
  Explicit third-party image overrides require their own security qualification.
- Keep gRPC on the fixed 1.83.2 release where 1.84 is still advisory-affected;
  latest version numbers do not override security or compatibility checks.

- Use Node 24.21.0 LTS and npm 12.0.2 for JavaScript builds, and Poetry 2.5.1 for
  backend dependency installation. CI uses the same PostgreSQL 18.6 and
  Valkey 9.1.2 service versions as the qualified application stack.
- Keep release Docker builders, development images and CI on the qualified
  Node 24 LTS line, with matching Node 24 type definitions. Node and type-definition
  major updates require explicit LTS migration review.
- Make the local frontend CI gate build the correct Docker stage and fail
  immediately on build failure, without reusing a stale image.
- Refresh compatible frontend, website, documentation and n8n dependencies.
  Keep TypeScript 6.0.3 in the frontend until its lint parser supports 7.x;
  pin the n8n workflow development dependency to the upstream stable channel.
- Update the optional HA NGINX image to 1.31.6 on its existing mainline branch,
  and rebuild Tailscale v1.102.4 with a checksum-locked security dependency graph.
  Rebuild images and qualify upgrades before deploying; current versions alone
  do not establish that an image is free of vulnerabilities.

### Backup observability and verified off-site completion

- Wire a restricted backup-status exporter into the optional Prometheus profile; alert on missing/invalid status, failed or disabled backups, missing pairs, and configurable freshness limits.
- Copy only complete database pairs off-site; verify downloaded contents and a remote completion marker before persisting success. Preserve failed attempts and report retention errors separately.
- Keep source backup age separate from copy time, protect the latest acknowledged pair during retention, and document the combined local/off-site scheduling delay and notification setup requirement.


### Upgrade notice

- Refresh 25 compatible backend lockfile packages, including SQLAlchemy 2.0.54,
  Psycopg 3.3.6, Boto3/Botocore 1.43.99 and the Celery process dependencies.
  Redis 6.4.0, Testcontainers 4.13.3, Pydantic Core 2.46.5 and Filelock 3.x
  retain their upstream compatibility constraints. The backend license inventory
  now matches the refreshed lock.

- SLA report timing now uses weekday/month-day, IANA timezone and local clock
  settings instead of rolling 7/30/90-day intervals. The calendar migration pauses
  enabled schedules for timing review, preserving approvals and timestamps.
  Review `timezone`, `time_of_day` and the completed reporting period before
  explicitly re-enabling. At that checkpoint automatic email delivery remained unimplemented; the later
  opt-in notice implementation is documented above.

- The default cache/broker moves from Valkey 8.1.9 to 9.1.2. Back up the
  persistence volume before upgrading. The tested upgrade preserves AOF/RDB
  data; rolling the same volume back to an older server is not validated.
- Runtime and build dependencies are refreshed, including React 19.3,
  TanStack Table 9.2, Vite 8.3, Vitest 5, Node 24 LTS and npm 12.0.2.
  TypeScript 6 and redis-py 6 remain compatibility holds; do not force their
  newest majors past the parser/Celery constraints.

- Existing SLA report schedules without recorded approval are paused during the
  authorization migration. An authorized operator must review the effective
  policies and re-enable each schedule through the schedule API. Names,
  recipients and audit history are preserved. See
  [SLA schedule upgrade behavior](https://docs.freesdn.org/enterprise/sla-management/#approval-execution-and-upgrade-behavior).

### Security

- Require urllib3 2.8.0, including upstream fixes for HTTPS-proxy TLS settings,
  unbounded chunk-size lines and a Deflate streaming loop. Operators using
  HTTPS proxies should use the documented proxy-specific TLS options; do not
  rely on destination TLS settings applying to the proxy.

- Device and identity XML parsing rejects DTDs/entities and oversized UTF-8
  payloads and cannot fall back to an unsafe parser when defusedxml is missing.
  Grandstream provisioning formats its existing XML tree without reparsing it,
  rejects raw overrides that inject element names, and rejects invalid XML 1.0
  characters. The existing SAML login refusal remains in place.

- Scheduled report execution rechecks the approving account, required permission,
  current site grants and approved policy scope. Revoked or changed authority
  pauses a schedule with an explicit reason; promotion does not widen its saved
  site scope. Inaccessible policy references are rejected at approval time.
- Private and public CI now gate complete backend and default frontend images,
  including their OS and embedded binary dependencies. Scan output is preserved
  on failure. Release publishing scans locally built artifacts and pushes those
  same artifacts only after the checks pass.
- The Caddy 2.11.4 edge is rebuilt with Go 1.27.2 and checksum-locked
  patched modules. Its native HTTP, verified HTTPS, WebSocket and streaming
  paths are checked in `scripts/check_edge_runtime.py`. Bundled module license
  notices ship with the image.
- Image security is **not cleared**. The 2026-09-22 candidate removes the
  backend's prior 228 HIGH / one CRITICAL findings and expands blocking CI
  to every distinct production image, including optional profiles. PostgreSQL
  and TimescaleDB still carry unfixed Debian findings; NetBird and Caddy have
  disclosed dependency compatibility holds. Findings are not suppressed, and
  a clean package audit or High/Critical scan alone is not release approval.
- The local Docker audit fails on HIGH findings, missing images/tools, scanner
  errors and malformed output; an incomplete scan can no longer report success.

### Fixed

- SLA schedules honor local calendar boundaries, month-end clamping and DST
  changes. Missed runs coalesce into one latest due report; explicit first-run
  overrides survive re-enabling. A real two-connection PostgreSQL regression
  covers row locking and restart behavior.

- Shared tables retain sorting, filtering, pagination and row selection after
  migration to TanStack Table 9. Real-browser checks cover the new runtime.
- Backend request tests isolate commits inside savepoints. Setup security tests
  no longer rely on rows leaked from another test, and the finalized-setup
  rejection is an active passing regression test instead of an expected failure.

- A failed report schedule uses a database savepoint so the next schedule can
  still be attempted. Concurrent workers skip schedules already locked by a
  worker; report rows and their next-run times commit together.
- Backup health requires an enabled, nonfailed, recent successful run and its
  specific nonempty application/LogDB file pair. Old archives cannot keep a
  failed or disabled backup green. Status files are atomically replaced and
  retain the last successful completion time after a failed attempt.
- Schedule updates reject null required fields and invalid weekday/month-day
  values instead of letting those values reach the database.

### Remaining limits

- Historical limitation: recipients were metadata only. The opt-in SMTP notice
  implementation above now supersedes this limitation within its stated scope.
  Calendar fields and timezones are not yet honored by the 7/30/90-day cadence.
- Local backup health does not verify off-site completion or restore usability.
  The shipped Prometheus configuration still needs a textfile collector/scrape
  path before backup textfile alert rules can fire.

## [26.09.0] - 2026-08-30 - Guards for the things that were failing quietly

A verification release. Most of its weight is new tests, and that is the point:
the recurring failure mode in this project is not a broken feature but a check
that never ran. 273 files changed.

Reconstructed in October 2026 from the published tag's contents; this release
was tagged without a written changelog section at the time.

### Added

- **A route-shadowing guard.** A literal path registered after a same-shape
  `/{param}` route on the same router is unreachable, and the parameterised
  handler answers instead with a 404 byte-identical to a genuinely unknown id.
  `GET /api/v1/modules/events` had been in that state through three separate
  rounds of org-scoping hardening. The check runs against the assembled app, so
  it also covers shadowing introduced by router include order.
- **A migration-chain-matches-models guard**, a recorded schema baseline and a
  legacy-upgrade behaviour suite, so an upgrade path can be exercised against a
  known starting schema rather than only a fresh `create_all`.
- **A write-path mount guard**, so a container missing a writable directory
  fails at test time rather than at an operator's first write.
- **Fabric actor site-grant, collector agent-report, module event-handler
  wiring and plugin registry freshness coverage.**

### Changed

- Discovery scan storage reworked; the agent endpoints extended.
- Backup service changes ahead of the vault work.

### Fixed

- The version shown in Settings came from a hardcoded fallback rather than the
  running release, so any deployment whose infrastructure health call failed
  displayed a months-old version with full confidence.
- Executable bits were not propagated to everything a roll-forward release
  inherits, so shipped shell scripts could arrive non-executable.

## [26.08.4] - 2026-08-24 - Storage you can write to, and observability that acts

Storage was a very good pair of eyes with almost no hands, and the collector was
a dead end. This release makes both do something. The whole storage write path
was validated live, end to end, against a real TrueNAS 26.0 appliance -- not
just mock-tested.

### Added

- **Back up to the TrueNAS you already monitor.** A new backup destination that
  names a managed controller instead of asking you to retype its address and API
  key. Each backup is stored as its own child dataset, so retention prunes it by
  destroying that dataset -- clean, with per-backup ZFS visibility. Save,
  restore and prune were all proven against the real appliance.
- **Storage writes from the Storage page.** Take a snapshot, create a dataset,
  start a scrub, delete a snapshot -- each staged through the same dual-gate
  review-and-apply flow every other managed write uses, and disabled with a
  clear reason on a legacy REST appliance that cannot do them. A Snapshots
  section lists what is there.
- **Observability can trigger automation.** The collector now publishes
  `collector.syslog.received` / `collector.trap.received` onto the event bus
  (severity-floored and rate-capped per source), so an automation rule can act
  on a device's own logs -- the missing first link between "something happened
  on the network" and "do something about it".
- **Storage is a module, not the TrueNAS module.** Health rollups now span every
  storage vendor through a provider registry; Proxmox node storage is the second
  provider, read-only.
- A capability-maturity record for storage, which had none -- rated honestly for
  what is proven live versus staged-but-unfired.

### Fixed

- **An automation rule created in the UI fired on every event in the
  organisation.** The rule form had no field for the trigger event, so it posted
  an empty trigger and the engine matched everything -- amplified by the new
  collector events. Event rules now require a named pattern (a picker in the
  form), refused at both create and update; a rule that names none is reported
  as not-firing rather than silently matching all.
- **Applying a storage change asked for `network:write`.** Every `storage.*`
  feature fell through to the network tier, so a network operator could apply a
  snapshot delete while the operator holding `storage.write` could not apply
  what they had staged. Now correctly storage-tiered.
- The observability rate cap was per-worker (so the real cap was
  worker-count x limit, and defeated at exactly that), and a UDP burst spawned an
  unbounded task per packet with the allowlist checked only after the task was
  created. The cap is now cluster-wide, and unauthorised floods are refused
  before any work is scheduled.
- `POST /agents/{id}/tasks` created a task and never delivered it.

### Security

- Every recursive dataset delete is rebuilt from a validated base plus one
  sanitised id token, so it can only ever target a direct child of the
  operator-nominated dataset -- never a pool root. Verified against every escape
  attempt.
- The staging path-traversal guard no longer false-rejects a ZFS snapshot id
  (`dataset/path@name`), while still refusing genuine traversal.

## [26.08.3] - 2026-08-23 - The plugin system, and a registry to install from

The typed plugin SDK, a scheduler for plugin-owned periodic work, the install
and review endpoints, and the Plugins page in Settings. It shipped alongside the
signed plugin registry going live, which is what gave the install path somewhere
to install from. 95 files changed, +15,621/-407.

Reconstructed in October 2026 from the published tag's contents; this release
was published with no release notes at all.

### Added

- **The typed plugin SDK** grew to cover the capability surface plugins actually
  need rather than the subset that happened to exist.
- **A plugin scheduler**, so a plugin can own periodic work without a core task
  being added on its behalf.
- **Plugin install and review endpoints, and the Plugins settings page**, so
  installing and inspecting a plugin is a supported operation rather than a
  manual file drop.

## [26.08.2] - 2026-08-21 - Writes that said they worked, and did not

A large patch release: 55 fixes and no schema changes. The theme is device
writes that reported success without the device agreeing, which is the failure
mode this project exists to avoid.

Reconstructed in October 2026; the published release notes are the source.

### Fixed

- **Sessions no longer end after one hour.** The refresh endpoint required the
  token in the request body while documenting itself as accepting the httpOnly
  cookie, so the browser sent an empty object and received a validation error.
  The frontend treats a failed refresh as a dead session, so every user was
  returned to the login screen at token expiry.
- **A device write that a Grandstream phone refused reported success.** Seven
  call sites discarded the result, and the reboot path could not report a
  refusal at all, because every failure branch returned success including
  authentication failure.
- **The edge Content-Security-Policy no longer permits arbitrary WebSocket
  hosts.** The hardening had been applied to API responses and not to the page
  that scripts actually run on.
- A factory reset could be confirmed with the string `"false"`.

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

### Plugin schedule coordination safety

- Pause scheduled plugin methods when a shared claim or operator settings cannot
  be confirmed. Remove the per-worker fallback that could duplicate execution
  during a Redis outage; an unreadable settings row no longer re-enables a
  default-on schedule.
- Surface worker-local refusals separately from executed run counters and mark
  the scheduler subsystem degraded. Retry Redis client construction on later
  ticks without replaying missed slots. See `docker/PLUGIN-SCHEDULE-COORDINATION`
  for the remaining Redis state-loss, restore and external-idempotency limits.

### Camera HLS idle cleanup

- Reap sessions after activity stops even when a disconnected browser leaves a
  positive viewer count. Heartbeat, playlist and segment activity still keep a
  session alive; explicit final-viewer stop and the hard age limit are preserved.
- Document the remaining process-local HLS ownership boundary. This cleanup fix
  does not qualify cross-worker playback or eliminate recycle-related delays.

### Optional NGINX stable channel

- Align the optional frontend and HA proxy defaults with NGINX stable 1.30.5,
  replacing mainline 1.31.6. Both branches contain the latest upstream security
  fixes; this change makes the release channel follow the stable-channel policy.
  Continue applying available Alpine security updates in the image builds.
