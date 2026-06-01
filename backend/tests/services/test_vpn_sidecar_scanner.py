# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The VPN sidecar's pre-exec OpenVPN config scanner (``_ovpn_cfg_safe``).

This is the LAST line of defense: the sidecar runs ``openvpn`` as ROOT off configs
that the non-root api writes to a shared volume, so even if a compromised api wrote
a config directly (bypassing the Python schema validator), this awk scanner must
refuse anything carrying a command/file-write directive before exec.

We extract and run the ACTUAL awk program from the shipped entrypoint (no copy — so
the test can't drift from what the sidecar runs) and assert it refuses the
``config <file>`` include bypass. Skipped where ``awk`` isn't available (Windows dev).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(shutil.which("awk") is None, reason="awk not available")

_SCRIPT = Path(__file__).parents[2] / "vpn-sidecar-entrypoint.sh"


def _extract_ovpn_awk_program() -> str:
    """Pull the single-quoted awk program out of ``_ovpn_cfg_safe()`` in the shipped
    entrypoint. The program contains no single quotes, so the quotes delimiting it are
    unambiguous."""
    src = _SCRIPT.read_text(encoding="utf-8")
    fn = src.index("_ovpn_cfg_safe()")
    start = src.index("awk '", fn) + len("awk '")
    end = src.index("'", start)
    prog = src[start:end]
    assert "config" in prog, "scanner program does not mention the config directive"
    return prog


def _scan(prog: str, config_text: str, tmp_path: Path) -> int:
    """Run the awk scanner on ``config_text``; return its exit code (0 safe, 1 bad)."""
    cfg = tmp_path / "test.conf"
    cfg.write_text(config_text, encoding="utf-8")
    return subprocess.run(["awk", prog, str(cfg)], capture_output=True).returncode


def test_sidecar_scanner_refuses_config_include_bypass(tmp_path):
    prog = _extract_ovpn_awk_program()
    # The exact repro: a clean-looking top-level config that includes pwn.inc.
    assert _scan(prog, "dev tun\nconfig pwn.inc\n", tmp_path) == 1
    # `--config` form (awk strips the leading --) and uppercase are caught too.
    assert _scan(prog, "client\n--config /etc/openvpn/client/pwn.inc\n", tmp_path) == 1
    assert _scan(prog, "dev tun\nCONFIG extra.conf\n", tmp_path) == 1


def test_sidecar_scanner_refuses_script_hooks(tmp_path):
    prog = _extract_ovpn_awk_program()
    for bad in (
        "client\nup /bin/sh\n",
        "client\nscript-security 2\n",
        "client\nmanagement 127.0.0.1 7\n",
    ):
        assert _scan(prog, bad, tmp_path) == 1


def test_sidecar_scanner_accepts_benign_config(tmp_path):
    prog = _extract_ovpn_awk_program()
    # A normal client config (inline ca block + safe directives) must pass.
    benign = (
        "client\ndev tun\nremote vpn.example 1194\ncipher AES-256-CBC\n"
        "dh none\nca [inline]\n<ca>\nMIIBfakebase64\n</ca>\n"
    )
    assert _scan(prog, benign, tmp_path) == 0
