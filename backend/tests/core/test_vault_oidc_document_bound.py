"""BytesIO accepts buffers; bound the byte count rather than element count."""

from array import array

import pytest

from app.core.vault_oidc_reauthentication import (
    _DOCUMENT_BYTES,
    OIDCConfirmationError,
    _BoundedDocument,
)


def test_wide_buffer_cannot_exceed_oidc_document_limit():
    document = _BoundedDocument()
    data = array("I", [0]) * (_DOCUMENT_BYTES // array("I").itemsize + 1)
    assert len(data) <= _DOCUMENT_BYTES < memoryview(data).nbytes
    with pytest.raises(OIDCConfirmationError):
        document.write(data)
    assert document.tell() == 0


def test_document_bound_accepts_exact_bytes_and_refuses_next_byte():
    document = _BoundedDocument()
    assert document.write(b"x" * _DOCUMENT_BYTES) == _DOCUMENT_BYTES
    with pytest.raises(OIDCConfirmationError):
        document.write(b"x")
    assert document.tell() == _DOCUMENT_BYTES
