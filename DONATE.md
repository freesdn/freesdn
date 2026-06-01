# How to Support FreeSDN

FreeSDN accepts **no money**. No Patreon. No GitHub Sponsors. No PayPal.
No tips. No sponsorship of any kind. This is a deliberate stance, not an
oversight -- keeping financial interest out of the project keeps the trust
model clean. The software ships because we use it ourselves, not because
someone paid for a feature.

There are exactly two ways to help build FreeSDN. Both are optional.
Both are genuinely impactful.

---

## Section 1 -- Hardware Donations

> **tl;dr:** Ship a device. That vendor becomes permanently supported.
> The device will not come back.

FreeSDN's adapters are only as deep as the hardware we can test against. The
Omada adapter is thorough because we run Omada in production every day. The
UniFi adapter is thinner because real Ubiquiti hardware has never sat on the
lab bench. The TrueNAS adapter is read-only because write testing requires
owning a real array. The pattern is simple: access to hardware = a working,
well-tested adapter. No hardware = best-effort guesswork.

A hardware donation is the highest-leverage contribution a user can make.
One donated device unblocks an entire vendor tier -- real protocol traces,
real edge cases, real test fixtures -- that no amount of community PRs
could replicate without the device in hand.

### The terms (read these)

Hardware donations are **permanent and one-way**. By sending a device you
are transferring ownership to the FreeSDN author permanently. The specific
terms, which you agree to by donating:

- Ownership transfers completely and irrevocably upon receipt.
- During reverse-engineering and adapter development, the device may be
  **reflashed, reconfigured, modified, factory-reset, or irreversibly
  bricked**.
- The device **will not be returned** under any circumstances.
- There is **no compensation and no warranty**. You are giving the device
  away.
- We may use, modify, test, and destroy the device in the course
  of adapter work without restriction.

These terms exist because the development process is adversarial by
design -- adapters are built by pushing devices to their limits, not by
reading datasheets. If you are not comfortable with the device being
permanently consumed by the project, do not donate it.

### What you get in return

- **Permanent vendor support.** That vendor/model enters the test matrix
  and stays there. Future regressions get caught. The adapter gets
  maintained as long as FreeSDN ships.
- **Opt-in credit** on the Supporters Wall below. Name, org, or a
  pseudonym -- your choice. If you prefer anonymity, just say so.
- The knowledge that real users running that hardware will have a working,
  reviewed adapter instead of a stub.

### How to start a hardware donation

Email **hardware@freesdn.org** with:

1. The vendor and model (e.g., "Ubiquiti UDM-Pro").
2. Your rough location (country/region -- for shipping logistics).
3. Whether you want credit on the Supporters Wall and, if so, under what
   name.

We will reply with a shipping address and any specific version or
firmware notes that matter for the target adapter.

Do not ship anything before making contact. Do not send consumables,
accessories, or things that are not on the wishlist below -- they cannot be
used and cannot be returned.

---

### Hardware Wishlist

The following devices would directly unlock new or improved adapter tiers.
"Unlocks" means the adapter moves from stub/Preview toward Production, or
a Roadmap item becomes buildable.

#### Network -- would expand or promote existing adapters

| Device | Current status | What a donation unlocks |
|--------|----------------|-------------------------|
| Ubiquiti UDM-Pro (or UDM-SE) | UniFi adapter is Beta (test-verified, no real hardware) | Field verification, write-path confidence, frontend UI build |
| Ubiquiti US-24 or US-48 switch | Same as above | Switch port + VLAN write testing on real silicon |
| Ubiquiti U6-LR or U6-Pro AP | Same as above | AP radio/client path verification |
| MikroTik CRS326-24G or CCR2004 | MikroTik is Production on routing, switch fabric untested | CAPsMAN, PPP/PPPoE, BGP/OSPF UI tabs |
| OpenWrt device (any model with 256MB+ RAM) | OpenWrt adapter is Preview / unaudited | Completes the reference contract pass |

#### Firewall / Security

| Device | Current status | What a donation unlocks |
|--------|----------------|-------------------------|
| Fortinet FortiGate (any SMB model) | Roadmap -- not started | New Production-tier firewall adapter |
| Sophos XGS (any model) | Roadmap -- not started | New firewall adapter |
| Juniper SSR (Session Smart Router) | Roadmap -- not started | Juniper adapter foundation |

#### Storage

| Device | Current status | What a donation unlocks |
|--------|----------------|-------------------------|
| TrueNAS Mini X+ or similar | TrueNAS is Preview (read-only, WS transport) | Write surface, backup module integration, TrueNAS promotion toward Beta |
| QNAP (any QuTS model) | Roadmap -- not started | New storage adapter |
| Synology DiskStation (any DSM 7.x) | Roadmap -- not started | New storage adapter |

#### Access Control

| Device | Current status | What a donation unlocks |
|--------|----------------|-------------------------|
| ZKTeco BioStar 2 panel (F21/F22 series) | Roadmap -- access_control module ships but door adapter returns HTTP 501 | First working door-control adapter; unlocks the entire access module |
| 2N IP Verso or IP Force | Roadmap | Video intercom + door-release adapter |
| HID Mercury intelligent controller | Roadmap | Enterprise door controller adapter |

#### Cameras

| Device | Current status | What a donation unlocks |
|--------|----------------|-------------------------|
| Axis IP camera (any model with VAPIX) | Roadmap -- ONVIF shim covers basics only | Full Axis VAPIX adapter (analytics, PTZ, edge recording) |
| Dahua NVR or camera | Roadmap | Dahua adapter alongside the Hikvision Production adapter |
| UniFi Protect (NVR or G4 camera) | Roadmap | Protect adapter separate from the UniFi network adapter |

#### VoIP

| Device | Current status | What a donation unlocks |
|--------|----------------|-------------------------|
| Cisco 8800 series SIP phone | Roadmap | Cisco phone provisioning adapter alongside Grandstream |
| Yealink T-series phone (T54W or T57W) | Roadmap | Yealink provisioning adapter |

---

## Section 2 -- Fuel the Build

FreeSDN is developed with AI-assisted tooling -- specifically Claude Code
(Anthropic) and OpenAI Codex. The review passes, invariant test suites,
security reviews, and adapter builds in this project are powered by those
tools running against the actual source code.

If you want to contribute to the development pipeline directly:

**Gift a Claude or OpenAI Codex subscription to fuel@freesdn.org.**

Those are the only two products. No other AI tools, no GPUs, no cloud
credits. Just those two.

This is the "fuel the build" path. It keeps the AI-assisted review and
development pipeline running without the project accepting general money.

---

## Section 3 -- Supporters Wall

*This wall recognizes hardware donors who have opted into public credit.
It will be populated at launch as donations arrive.*

---

### Founding donors

| Donor | Hardware donated | Adapter impact |
|-------|-----------------|----------------|
| *(your name here)* | *(device)* | *(what it unlocked)* |

---

*Want to be first? Email hardware@freesdn.org.*

---

## Contact

| Purpose | Address |
|---------|---------|
| Hardware donations | hardware@freesdn.org |
| Fuel the build (Claude / subscription) | fuel@freesdn.org |
| Security vulnerability reports | security@freesdn.org |
| General / press | hello@freesdn.org |
