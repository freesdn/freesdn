# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Point-of-use check for a camera or NVR host read back from the database.

The create, edit, import and test endpoints validate a host with
``schemas._validate_host_not_ssrf`` (a plain hostname or IP address, never
loopback, link-local or a cloud metadata address). That protects what is
written through those endpoints today. It does not protect a row written before
the check was tightened, or by any other path, and every background task that
contacts a recorder reads ``nvr.ip_address`` straight from the row and pastes it
into an ISAPI or RTSP URL together with the stored login.

So the code that is about to send stored credentials to a stored host checks
that host again, here, with the same validator plus the rule the snapshot path
already applied: the stored camera login is only ever sent to a private
(on-premises) address. ``CameraStreamService._create_camera_adapter`` and the
camera Celery tasks share this one function so the two cannot drift.

The check resolves DNS, so async callers run it in a thread.
"""

from __future__ import annotations

__all__ = ["CameraHostRefused", "check_stored_camera_host"]


class CameraHostRefused(ValueError):
    """A stored camera or NVR host that must not be contacted."""


def check_stored_camera_host(host: object) -> str:
    """Return the stored host if the stored login may be sent to it, else raise.

    Raises :class:`CameraHostRefused` when the host is empty, is not a plain
    hostname or IP address, is a loopback, link-local or metadata address, does
    not resolve, or resolves to a public address.
    """
    from app.core.security_utils import is_private_ip, resolve_and_pin_host
    from app.modules.cameras.schemas import _validate_host_not_ssrf

    text = str(host or "").strip()
    if not text:
        raise CameraHostRefused("No host is stored for this camera or NVR")
    try:
        _validate_host_not_ssrf(text)
        pinned = resolve_and_pin_host(text, allow_private=True)
    except ValueError as exc:
        raise CameraHostRefused(str(exc)) from exc
    if not is_private_ip(pinned):
        raise CameraHostRefused(
            f"Camera host {text!r} resolves to a PUBLIC address. Cameras and NVRs "
            "must live on a private/on-prem network; FreeSDN refuses to send the "
            "stored camera credentials to a public-internet host. Set the camera's "
            "IP/host to its on-prem (RFC1918) address."
        )
    return text
