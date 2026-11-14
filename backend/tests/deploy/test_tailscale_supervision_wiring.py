# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The api brings an enrolled capless Tailscale node back, under a real init,
and does not wait out a 15-minute dead TCP connection.

Evidence (2026-11 soak): after an api restart tailscaled stayed down although
its state persisted in the tailscale_state volume (nothing started it), and
after a 2-minute upstream outage it stayed offline ~15 minutes on a dead
control connection: the kernel's default tcp_retries2=15. With 8 a black-holed
connection was aborted 105 s after the peer went silent (measured, Linux 6.8).
"""

from __future__ import annotations

import pathlib

import pytest

yaml = pytest.importorskip("yaml")

BACKEND = pathlib.Path(__file__).resolve().parents[2]


def _repo_file(name: str) -> pathlib.Path | None:
    for parent in pathlib.Path(__file__).resolve().parents:
        if (parent / name).is_file():
            return parent / name
    return None


def test_the_entrypoint_starts_the_supervisor_before_gunicorn() -> None:
    text = (BACKEND / "docker-entrypoint.sh").read_text(encoding="utf-8")
    autostart = text.find("python -m app.tailscaled_supervisor --detach --if-enrolled")
    assert autostart > 0, "the api entrypoint no longer brings an enrolled node back"
    assert autostart < text.find("exec gunicorn")
    # The old all-in-one path no longer starts an unsupervised daemon either.
    assert "\n        tailscaled \\" not in text


@pytest.mark.skipif(_repo_file("docker-compose.yml") is None, reason="monorepo checkout only")
def test_the_api_has_an_init_and_a_bounded_dead_connection_timeout() -> None:
    compose = yaml.safe_load(_repo_file("docker-compose.yml").read_text(encoding="utf-8"))
    api = compose["services"]["api"]
    assert api.get("init") is True
    assert str(api["sysctls"]["net.ipv4.tcp_retries2"]) == "8"
    assert not api.get("cap_add"), "the api stays capless"
    vpn = compose["services"]["vpn"]
    assert str(vpn["sysctls"]["net.ipv4.tcp_retries2"]) == "8"
