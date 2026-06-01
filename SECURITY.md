# Security Policy

## Supported Versions

Only the latest release is actively maintained. Security fixes are applied
to the current release only -- older releases do not receive backports.

| Version | Supported |
|---------|-----------|
| 26.06.x | Active    |

26.06.1 is the first public release. If you are running an older checkout,
upgrade before reporting -- the issue may already be fixed.

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**
Public disclosure before a patch is available puts every self-hosted
installation at risk.

**Two ways to report:**

1. **GitHub Private Vulnerability Reporting** -- open the repository's
   Security tab and click "Report a vulnerability". The report is
   confidential between you and the maintainers until a fix ships, and a
   CVE/GHSA is coordinated through the same advisory.
   Direct link: `https://github.com/freesdn/freesdn/security/advisories/new`

2. **Email** -- send to `security@freesdn.org`. For end-to-end
   encryption, prefer the GitHub Private Vulnerability Reporting path
   above (it is encrypted between you and the maintainers), or ask for
   our PGP key in your first message.

**Please include:**
- Affected version (from `GET /api/v1/health` or `docker inspect`)
- Steps to reproduce
- Potential impact as you understand it
- A suggested fix, if you have one

**Response timeline:**
- Acknowledgement: within 48 hours
- Initial assessment: within 5 business days
- Patch for critical issues: target 30 days

FreeSDN is maintained by a small in-house team. Response is best-effort but
taken seriously -- every report gets a real read, not a template dismissal.

---

## Security Posture

This section describes the security controls that ship today. No compliance
certifications are claimed.

### Tenant isolation

Tenant isolation is enforced at the application layer. Service-layer
queries that touch an org-scoped resource are gated by an explicit `org_id` check in
the service layer. There is no PostgreSQL Row-Level Security -- isolation
is application-layer and fail-closed. Mixing this up matters: "we use RLS" is a claim
FreeSDN does not make.

### Access control

Five assignable RBAC roles: super_admin, org_admin, site_admin, operator, and
viewer. (Two additional internal levels -- admin, platform-scoped, and guest,
zero-privilege -- exist in the permission hierarchy for comparison logic but are
not user-assignable.) Access is further narrowed
by per-user site grants -- a user may hold different roles at different
sites within the same org. Privilege escalation attempts (including
org_admin promoting themselves to super_admin) are blocked server-side
and covered by invariant tests.

### Staged writes -- the dual gate

Every write to a managed device passes a two-condition gate:
`ADAPTER_READ_ONLY` (a per-adapter flag, on by default -- read-only by default)
and an explicit `force` parameter in the request. Both must clear for a
destructive write to proceed. This prevents a misconfigured or
partially-provisioned adapter from silently clobbering live device config.

### Secret handling

Credentials stored in the database (API keys, RADIUS shared secrets,
WPA/WPA2 passphrases, IPsec/WireGuard PSKs, LDAP bind passwords,
VPN credentials) are encrypted at rest with Fernet (AES-128-CBC + HMAC-SHA256)
using a key derived from `SECRET_KEY` via PBKDF2. A central
`redact_secrets` pass runs before any credential material is serialised
to API responses or logs -- including camelCase variants that field-renaming
can introduce.

### SSRF protection

Outbound HTTP calls from the backend block RFC 1918 private ranges,
loopback, link-local, cloud metadata endpoints (AWS/GCP/Azure),
Tailscale/CGNAT ranges, and IPv4-mapped IPv6 addresses. DNS rebinding is
mitigated by resolving and re-checking at connection time.
The block list is not bypassable by percent-encoding or embedded
credentials.

### Authentication and cryptography

- Argon2id password hashing (64 MB memory cost, current OWASP recommendation)
- PBKDF2 key derivation with 260,000 iterations for encryption keys
- JWT tokens with configurable RS256/HS256; JTI-based revocation via Valkey
- MFA: TOTP (pyotp) with backup codes; MFA re-enrolment requires the
  existing credential
- Rate limiting: 300 req/min general, 5 req/min on auth endpoints,
  memory-bounded to 10K clients

### HTTP security headers

Content-Security-Policy (self-origin), Strict-Transport-Security
(2-year max-age when HTTPS), X-Frame-Options: DENY,
X-Content-Type-Options: nosniff, Referrer-Policy:
strict-origin-when-cross-origin, Permissions-Policy disabling camera,
microphone, geolocation, and payment.

### Infrastructure defaults

- All containers run as non-root users in production
- `no-new-privileges` security option on every container
- All host-port bindings restricted to 127.0.0.1 by default
- Read-only filesystems on stateless containers
- Memory and CPU resource limits on every container
- API docs hidden in production; registration disabled by default

### Plugin trust model

Plugins run with full backend permissions. FreeSDN does not provide
process-level isolation for plugins. A plugin you install has the same
access to your database, credentials, network, and filesystem as the
FreeSDN backend itself.

The plugin loader (`backend/app/plugins/sandbox.py`) performs load-time
import hygiene -- it refuses imports of a blocklist of OS/process/network
modules while a plugin is being loaded and strips accident-prone builtins
(`exec`, `eval`, `compile`, `open`, `__import__`). This catches ordinary
mistakes from cooperative plugin authors. It is not a security boundary:
a malicious plugin can reach `subprocess.Popen` at runtime through Python
introspection, and nothing in the current design prevents that.

Only install plugins from sources you trust. Review the plugin code and
manifest before installation. Plugin installation is restricted to
`super_admin` users.

### Signed releases

The FreeSDN agent binary and official plugin releases are signed. Signature
verification instructions and the signing public key (with its fingerprint)
are included in each GitHub Release; the agent pins that fingerprint on first
use and refuses a later key swap.

### Security testing and review

This release includes automated tests and internal review, but no third-party
security audit or certification is claimed. The areas given the most attention
during development include tenant isolation, privilege escalation, secret
redaction, SSRF, cross-tenant data access, and authentication flow edge cases.
The security model is documented at
[docs.freesdn.org/security/model](https://docs.freesdn.org/security/model/).

---

## Dependency management

- Dependabot is configured for weekly Python, npm, and Docker image
  dependency updates
- `poetry.lock` and `package-lock.json` provide deterministic, auditable
  builds
- Security-critical packages are explicitly pinned with minimum versions

---

## A note on project governance

FreeSDN is developed in-house by the small team that runs it in production --
every line is authored and reviewed inside that team. No external pull
requests are accepted. That is a deliberate trust and security choice: a
controlled, in-house codebase with full context is a stronger guarantee than
a committee of outside contributors with mixed incentives and uneven review
standards. There is no supply-chain risk from drive-by contributions because
there are no drive-by contributions.

Bug reports and vulnerability reports are welcome and taken seriously.
If you want to extend FreeSDN, the MIT-licensed SDK lets you build and
ship your own plugin without touching core.

The project accepts no money. No sponsorships, no tips, no Patreon.
The two ways to contribute materially are:

- **Donate hardware** -- permanently transfer a device to
  `hardware@freesdn.org`. Ownership transfers, the device may be modified,
  reflashed, bricked, or destroyed during reverse-engineering and will not
  be returned. In exchange, that vendor and model becomes permanently
  supported and tested in FreeSDN, and donors are credited on the
  supporters page (opt-in).

- **Fuel the build** -- gift a Claude or OpenAI Codex subscription to
  `fuel@freesdn.org`. Those are the only two AI products the project uses.
  This funds the AI-assisted development and review pipeline.
