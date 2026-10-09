# SPDX-License-Identifier: AGPL-3.0-only
"""Copied candidate names and content commitment for one remote write attempt."""

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, repr=False)
class RemoteSavePlan:
    operation_id: UUID
    path: str
    temporary: str
    location: str
    temporary_location: str
    payload_sha256: str
    payload_size: int


class RemotePublicationError(RuntimeError):
    """A mutation was attempted; neither possible location is verified.

    Unlike the local publication error this does not assert that a complete
    final file exists. No automatic replay or speculative cleanup is safe.
    """

    def __init__(self, storage_path: str, temporary_storage_path: str):
        super().__init__(
            "Remote publication could not be confirmed; inspect retained recovery information"
        )
        self.storage_path = storage_path
        self.temporary_storage_path = temporary_storage_path
        self.outcome_unknown = True
