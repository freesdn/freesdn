# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded recovery metadata, never a credential or permission to perform I/O.

The destination binding must come from the authenticated coordinator's keyed
configuration/trust snapshot. This codec cannot establish that authority.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit
from uuid import UUID

from app.core.security_utils import MAX_BACKUP_IMPORT_BYTES


class InvalidRemoteIntent(ValueError):
    """Invalid bounded metadata; no caller values in the public error."""


@dataclass(frozen=True, repr=False)
class RemoteWriteIntent:
    operation_id: UUID
    backup_id: UUID
    organization_id: UUID
    storage_location_id: UUID
    requested_by: UUID | None
    schedule_id: UUID | None
    include_secrets: bool
    final_location: str
    temporary_location: str
    destination_binding: str
    payload_sha256: str
    payload_size: int

    def encoded(self) -> bytes:
        value: UUID | str
        try:
            for value in (
                self.operation_id,
                self.backup_id,
                self.organization_id,
                self.storage_location_id,
            ):
                if type(value) is not UUID or value.int == 0:
                    raise ValueError
            if (self.requested_by is None) == (self.schedule_id is None):
                raise ValueError
            owner = self.requested_by if self.requested_by is not None else self.schedule_id
            if type(owner) is not UUID or owner.int == 0:
                raise ValueError
            if type(self.include_secrets) is not bool:
                raise ValueError
            # Scheduled secret exports do not inherit interactive step-up.
            if self.schedule_id is not None and self.include_secrets:
                raise ValueError
            if (
                type(self.payload_size) is not int
                or not 0 < self.payload_size <= MAX_BACKUP_IMPORT_BYTES
            ):
                raise ValueError
            for digest in (self.destination_binding, self.payload_sha256):
                if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                    raise ValueError
            for value in (self.final_location, self.temporary_location):
                if type(value) is not str or not 1 <= len(value.encode("utf-8")) <= 3072:
                    raise ValueError
                if any(ord(c) < 32 or ord(c) == 127 for c in value) or any(
                    c in value for c in "\\%?#"
                ):
                    raise ValueError
                parts = urlsplit(value)
                if (
                    parts.scheme not in {"sftp", "ftps"}
                    or parts.username is not None
                    or parts.password is not None
                    or parts.query
                    or parts.fragment
                    or not parts.path.startswith("/")
                    or parts.hostname is None
                    or parts.port is None
                    or not 1 <= parts.port <= 65535
                ):
                    raise ValueError
                address = ipaddress.ip_address(parts.hostname)
                authority = f"[{address}]" if address.version == 6 else str(address)
                if parts.netloc != f"{authority}:{parts.port}":
                    raise ValueError
                segments = parts.path[1:].split("/")
                if any(s in {"", ".", ".."} for s in segments):
                    raise ValueError
            if self.temporary_location != self.final_location + ".partial-" + self.operation_id.hex:
                raise ValueError
            if (
                not urlsplit(self.final_location)
                .path.rsplit("/", 1)[-1]
                .startswith(str(self.backup_id) + "_")
            ):
                raise ValueError
            values = asdict(self)
            encoded = json.dumps(
                {
                    "format_version": 1,
                    **{k: str(v) if isinstance(v, UUID) else v for k, v in values.items()},
                },
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            if len(encoded) > 8192:
                raise ValueError
            return encoded
        except (ValueError, TypeError, AttributeError, UnicodeError):
            raise InvalidRemoteIntent("Invalid remote recovery metadata") from None

    def digest(self) -> str:
        return hashlib.sha256(self.encoded()).hexdigest()


class RemoteProbeIntent(RemoteWriteIntent):
    """Explicit non-secret probe purpose; no claim that a Backup row exists.

    The inherited ``backup_id`` attribute maps to the existing journal's unique
    object UUID column. On the wire it is a probe_id, never a backup_id. Existing
    format1 backup bytes remain unchanged; readers must recognize format2 before
    treating this entry as a connectivity probe.
    """

    def encoded(self) -> bytes:
        raw = super().encoded()
        if (
            self.include_secrets
            or self.schedule_id is not None
            or self.payload_size > 128
            or not self.final_location.endswith("_connectivity_test.txt")
        ):
            raise InvalidRemoteIntent("Invalid remote recovery metadata")
        values = json.loads(raw)
        values["format_version"] = 2
        values["purpose"] = "connectivity_probe"
        values["probe_id"] = values.pop("backup_id")
        encoded = json.dumps(
            values, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        if len(encoded) > 8192:
            raise InvalidRemoteIntent("Invalid remote recovery metadata")
        return encoded
