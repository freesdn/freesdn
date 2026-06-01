# Contributing to FreeSDN

FreeSDN is developed in-house by the small team that runs it in
production. This document explains exactly what that means, what you can
do, and how to do it well. It is written to be honest and direct - no
vague "we may consider it in the future" hedging.

---

## Why no external code contributions?

The short answer: FreeSDN is developed in-house by the team that runs it
in production. Every line is authored and reviewed inside that team. That
is a deliberate architectural and security decision, not a project
maturity excuse.

Here is the reasoning:

**Trust and supply-chain safety.** FreeSDN manages network infrastructure,
credentials, firewall rules, and VPN configs. A single drive-by PR that
introduces a subtle bug or a backdoor can compromise the environments of
every person running it. Authoring and reviewing every line inside the
team that owns the full codebase keeps the supply chain controlled and the
architecture coherent.

**Architectural coherence.** The codebase has a strict layering contract
(adapter staging gates, 5-role RBAC, app-layer tenant isolation, the
Fabric operation catalog). Maintaining that coherence across external
contributions is expensive and error-prone. Accepting a PR that looks
correct but breaks a cross-cutting invariant is worse than not taking the
PR at all.

**It is not a comment on your code.** If you have built something useful
on top of FreeSDN or against the SDK, that is genuinely great. The answer
to "why won't you merge my adapter?" is never "your code is bad." It is
"we need to own and review every line that ships."

**Bug reports and feature requests ARE welcome** via GitHub Issues. We
read every one. Good ideas get incorporated - with credit.

---

## What IS welcome

### Bug reports

Bug reports are the highest-value contribution you can make.

A good bug report includes:

- **Version** - the CalVer tag from `docker compose exec api python -c
  "from app.core.config import settings; print(settings.APP_VERSION)"`
  or the `version` field in `backend/pyproject.toml`
- **Module or adapter** - e.g., `network/mikrotik`, `cameras/hikvision`,
  `auth`, `fabric`
- **Environment** - Docker (dev/prod), OS, Python version shown in logs
- **Steps to reproduce** - a numbered list precise enough that the
  maintainer can reproduce without guessing
- **Expected behavior** - what you thought would happen
- **Actual behavior** - what actually happened, including any error
  messages verbatim
- **Relevant log lines** - from `docker compose logs api` or
  `docker compose logs worker`; redact secrets and passwords before
  pasting

Use the bug report template:
[`.github/ISSUE_TEMPLATE/bug_report.yml`](.github/ISSUE_TEMPLATE/bug_report.yml)

Open an issue at: <https://github.com/freesdn/freesdn/issues/new/choose>

### Feature requests

Open an issue describing the use case - not the implementation. "I want a
button that does X" is less useful than "I manage 40 MikroTik routers and
currently I have to do Y manually every week - if FreeSDN could do Y it
would save me N hours." We will assess whether it fits the
roadmap and how to build it correctly.

### Testing against real hardware

If you have hardware from a supported vendor and you run FreeSDN against
it - even just to try it - filing a report of what works and what does not
is genuinely useful. The adapter tier list at
[docs.freesdn.org/adapters/overview](https://docs.freesdn.org/adapters/overview/)
documents what each adapter is claimed to do. A report that contradicts that
document is exactly the kind of signal that drives fixes.

Production-tier adapters (Omada, OPNsense, MikroTik, Proxmox, Hikvision) have
their read/monitoring paths live-validated on real hardware; most write paths
are contract- and mock-tested rather than field-proven (see the per-adapter
maturity record). Beta-tier (FreePBX, Grandstream, UniFi, pfSense) and
Preview-tier (OpenWrt, TrueNAS, ONVIF generic) adapters need more coverage -
your reports help.

### Your own plugins via the SDK

You do not need a PR to extend FreeSDN. The MIT-licensed SDK
(`freesdn-sdk` on PyPI) lets you build your own plugins that run inside
FreeSDN's plugin loader. You own your plugin code entirely - distribute
it however you want. A PR to core is not required, expected, or accepted.

If you build something interesting, feel free to post about it in an
issue. We may link to it from the documentation (no
promises).

### Forks

FreeSDN core is AGPL-3.0-only. You are free to fork it under the terms of
the AGPL. Forks are not actively supported - bug reports against a fork
will be closed without comment - but nothing prevents you from running
one.

### Security vulnerabilities

Do NOT open a public issue. See [`SECURITY.md`](SECURITY.md) for the full
disclosure process. The short version: use GitHub Private Vulnerability
Reporting or email security@freesdn.org. Responsible disclosures are
acknowledged within 48 hours.

---

## The two real ways to contribute

### 1. Donate hardware

FreeSDN adapters are only as deep as the hardware we can test against.
The best adapter in the project is the Omada adapter - because we run
Omada in production. The depth of every other adapter is proportional to
the access available during development.

If you want your vendor supported properly, the fastest path by a wide
margin is a hardware donation.

**How it works:**

- Email hardware@freesdn.org with what you have (vendor, model, current
  firmware if known)
- We will confirm whether the hardware is on the priority list
- You ship it. No return. Read the terms below carefully.

**Terms - read before you donate:**

- Ownership transfers permanently and irrevocably upon receipt
- During reverse-engineering and adapter development, the device may be
  modified, reflashed, reconfigured, factory-reset, bricked, or physically
  damaged beyond repair
- The device will NOT be returned under any circumstances
- There is no compensation, no warranty, and no guarantee the adapter will
  be completed within any timeframe
- In return: the vendor/model becomes permanently supported and
  continuously tested in FreeSDN, and the donor is credited by name on
  the supporters page (opt-in - just say so in your email)

Full details and the current priority wishlist are in
[`DONATE.md`](DONATE.md).

This is how new vendor support gets funded: donate the gear, it becomes
everyone's compatibility.

### 2. Fuel the build

FreeSDN is built with the help of AI-assisted development and review
tooling. If you find the project useful and want to support the work,
you can gift a subscription to:

**fuel@freesdn.org**

Only two products are accepted:
- A **Claude** subscription (claude.ai) - the primary development tool
- An **OpenAI Codex** subscription

Nothing else. No PayPal, no Stripe, no GitHub Sponsors, no crypto, no
gift cards for anything else. The project deliberately accepts no cash or
sponsorship of any other kind - that keeps its incentives clean and its
recommendations honest. Fuel-the-build is the one narrow exception because
it directly funds the tooling that builds and reviews the code.

---

## What is not accepted

To be unambiguous:

- Code PRs of any kind (features, adapters, refactors, bug fixes, tests,
  CI changes, dependency bumps) - these will be closed without review
- Sponsorship, donations, tips, or money of any kind except the two
  fuel-the-build subscriptions listed above
- Solicitations to change the governance model

We handle dependency updates on a regular cadence. Dependabot
is configured for automated alerts. If you spot a CVE, open an issue (or
use the security inbox for sensitive ones) rather than submitting a PR.

---

## Code and comment conventions

If you fork FreeSDN (the AGPL permits it), it helps to know the one rule the
codebase holds firmly: code and development history are kept separate.

- **Code comments explain the code** - what an invariant protects, why a branch
  exists, what a non-obvious call does.
- **They never narrate the development process.** Notes about how a change was
  reviewed, tracked, or scheduled live in commit messages, pull requests, and
  the issue tracker - none of which ship in the source distribution - not in the
  code itself.

---

## License

FreeSDN core is AGPL-3.0-only. By submitting a bug report or feature
request you are not granting any license in your idea - you are just
describing a problem or use case. If we implement something
based on your report, the resulting code is AGPL-3.0.

The FreeSDN agent and SDK are MIT-licensed. Their contribution policy is
the same as core (in-house only, no external code PRs), but the MIT
license means you can fork and use them with fewer restrictions.

---

## Questions?

General questions: hello@freesdn.org or open a GitHub Discussion.
Security reports: security@freesdn.org or GitHub Private Vulnerability Reporting.
Hardware donations: hardware@freesdn.org.
Fuel the build: fuel@freesdn.org (Claude or subscriptions only).

Thanks for taking the time to read this. If you have run FreeSDN against
real hardware, filed a detailed bug report, or just told someone about the
project - that matters, and it is appreciated.
