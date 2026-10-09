# SPDX-License-Identifier: AGPL-3.0-only
"""Actual uv, local wheels, authenticated ASGI and PostgreSQL lifecycle checks.

Only owned loopback package transport is delayed. No installer, subprocess,
clock, authentication or production timeout is mocked. These checks do not
qualify arbitrary subprocess descendants, process crashes or external indexes.
"""
from __future__ import annotations

import asyncio
import base64
import csv
import hashlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from datetime import UTC, datetime, timedelta
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4
from zipfile import ZipFile

import httpx
import pytest
import yaml
from fastapi import FastAPI
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints import plugins as endpoints
from app.core.security import create_access_token, decode_token, get_password_hash
from app.db.session import create_test_engine, get_session
from app.models.core import Organization, User, UserSession
from app.models.plugins import InstalledPlugin, PluginOrganizationState, PluginSetting
from app.models.security_audit import AuditLogRecord
from app.plugins import loader as loader_module
from app.plugins.loader import PluginLoader, PluginLoadError
from tests.plugins.test_plugin_upgrade_rollback import (
    runtime_state,
    subscription_ids,
)
from tests.plugins.test_ticketing_archive_lifecycle import (
    SLUGS,
    archive,
    disk_files,
    settings_rows,
)

DEPENDENCY = "freesdn-release-probe==1.0.0"


def manifest_version(path):
    file = path / "plugin.yaml"
    return yaml.safe_load(file.read_text())["version"] if file.is_file() else None


def native_uv_process(plugin):
    python = str(plugin / ".venv/bin/python")
    installer = str(Path(shutil.which("uv")).resolve())
    rows = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            args = (entry / "cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
            if python not in args or "pip" not in args:
                continue
            status = (entry / "stat").read_text().rsplit(")", 1)[1].split()
            rows.append({"pid": int(entry.name), "ppid": int(status[1]),
                         "start_ticks": status[19], "args": args,
                         "executable": str((entry / "exe").resolve()),
                         "expected_installer": installer})
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    return rows


def same_process_alive(row):
    try:
        return Path(f"/proc/{row['pid']}/stat").read_text().rsplit(")", 1)[1].split()[19] == row["start_ticks"]
    except (FileNotFoundError, ProcessLookupError):
        return False


class OwnedWheelIndex:
    def __init__(self, root, plugin, on_started, request_done, *, slow=False):
        self.plugin = plugin
        self.on_started = on_started
        self.request_done = request_done
        self.slow = slow
        self.release = threading.Event()
        self.stop = threading.Event()
        self.observations = {"wheel_requests": 0, "bytes_sent": 0, "handler_errors": []}
        package = root / "simple/freesdn-release-probe"
        package.mkdir(parents=True)
        self.wheel = package / "freesdn_release_probe-1.0.0-py3-none-any.whl"
        info = "freesdn_release_probe-1.0.0.dist-info"
        files = {
            "freesdn_release_probe.py": b'VALUE = "verified wheel"\n',
            f"{info}/METADATA": b"Metadata-Version: 2.1\nName: freesdn-release-probe\nVersion: 1.0.0\n",
            f"{info}/WHEEL": b"Wheel-Version: 1.0\nGenerator: FreeSDN-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        }
        records = io.StringIO()
        writer = csv.writer(records)
        for name, content in files.items():
            digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=")
            writer.writerow([name, "sha256=" + digest.decode(), len(content)])
        writer.writerow([f"{info}/RECORD", "", ""])
        files[f"{info}/RECORD"] = records.getvalue().encode()
        with ZipFile(self.wheel, "w") as wheel:
            for name, content in files.items():
                wheel.writestr(name, content)
        self.raw = self.wheel.read_bytes()
        (package / "index.html").write_text(f'<a href="{self.wheel.name}">{self.wheel.name}</a>')
        owner = self

        class Handler(SimpleHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                if not self.path.endswith(".whl"):
                    return super().do_GET()
                try:
                    owner.observations["wheel_requests"] += 1
                    processes = native_uv_process(plugin)
                    owner.observations["processes_at_transfer"] = processes
                    owner.observations["version_at_transfer"] = manifest_version(plugin)
                    owner.observations["request_done_at_transfer"] = owner.request_done()
                    if len(processes) == 1:
                        args = processes[0]["args"]
                        lock = Path(args[args.index("-r") + 1])
                        owner.observations["verified_lock"] = {"path": str(lock), "mode": lock.stat().st_mode & 0o777,
                                                               "sha256": hashlib.sha256(lock.read_bytes()).hexdigest()}
                    owner.on_started()
                    if not owner.release.wait(timeout=20):
                        raise RuntimeError("Owned wheel release barrier timed out")
                    owner.observations["version_at_send"] = manifest_version(plugin)
                    owner.observations["request_done_at_send"] = owner.request_done()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(len(owner.raw)))
                    self.end_headers()
                    if owner.slow:
                        # Keep actual HTTP reads active past the unchanged 180s
                        # installer deadline; never shorten the product timeout.
                        for byte in owner.raw:
                            if owner.stop.wait(timeout=0.25):
                                break
                            self.wfile.write(bytes([byte]))
                            self.wfile.flush()
                            owner.observations["bytes_sent"] += 1
                    else:
                        self.wfile.write(owner.raw)
                        self.wfile.flush()
                        owner.observations["bytes_sent"] = len(owner.raw)
                except (BrokenPipeError, ConnectionResetError):
                    owner.observations["peer_closed"] = True
                except Exception as exc:
                    owner.observations["handler_errors"].append(type(exc).__name__ + ": " + str(exc))
                    owner.on_started()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, directory=str(root)))
        self.server.daemon_threads = False
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/simple"

    def close(self):
        self.stop.set()
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        assert not self.thread.is_alive()


def wheel_archive(slug, digest):
    with ZipFile(io.BytesIO(archive(slug, "1.0.4"))) as source:
        files = {name: source.read(name) for name in source.namelist()}
    manifest = yaml.safe_load(files["plugin.yaml"])
    manifest["python_dependencies"] = [DEPENDENCY]
    files["plugin.yaml"] = yaml.safe_dump(manifest, sort_keys=False).encode()
    files["requirements.txt"] = f"{DEPENDENCY} --hash=sha256:{digest}\n".encode()
    target = io.BytesIO()
    with ZipFile(target, "w") as output:
        for name, content in sorted(files.items()):
            output.writestr(name, content)
    return target.getvalue(), files


def native_package_check(plugin, present):
    code = "import importlib.util; assert importlib.util.find_spec('pip') is None; "
    code += ("import freesdn_release_probe; assert freesdn_release_probe.VALUE == 'verified wheel'"
             if present else "assert importlib.util.find_spec('freesdn_release_probe') is None")
    subprocess.run([str(plugin / ".venv/bin/python"), "-I", "-c", code], check=True, capture_output=True, timeout=15)


@pytest.mark.parametrize("slug", SLUGS)
@pytest.mark.parametrize("operation", ["install", "upgrade"])
@pytest.mark.parametrize("outcome", ["cancel_once_ok", "cancel_twice_hash_failure", "valid", "hash_failure"])
async def test_native_installer_finishes_before_cancelled_filesystem_rollback(
    monkeypatch, tmp_path, record_property, slug, operation, outcome,
):
    engine = create_test_engine()
    loop = asyncio.get_running_loop()
    started = asyncio.Event()
    orgs, users = [uuid4() for _ in range(3)], [uuid4() for _ in range(3)]
    tokens, claims = [], []
    for user in users:
        token = create_access_token(str(user), token_version=17, expires_delta=timedelta(minutes=5))
        claim = await decode_token(token)
        assert claim is not None
        tokens.append(token)
        claims.append(claim)
    loader = PluginLoader()
    dest = tmp_path / "installed"
    monkeypatch.setattr(loader_module, "PLUGIN_DIR", dest)
    monkeypatch.setattr(loader_module.settings, "PLUGIN_ALLOW_RUNTIME_PYTHON_DEPS", False)
    monkeypatch.setattr(loader_module, "plugin_loader", loader)
    monkeypatch.setattr(endpoints, "plugin_loader", loader)
    app = FastAPI()
    app.include_router(endpoints.router, prefix="/api/v1/plugins")

    async def independent_session():
        async with AsyncSession(engine, expire_on_commit=False, autoflush=False) as session:
            try:
                yield session
                await session.commit()
            except BaseException:
                await session.rollback()
                raise

    app.dependency_overrides[get_session] = independent_session
    original_subscriptions = subscription_ids()
    request_task = None

    server = OwnedWheelIndex(tmp_path / "index", dest / slug,
                             lambda: loop.call_soon_threadsafe(started.set),
                             lambda: request_task is not None and request_task.done())
    monkeypatch.setattr(loader_module.settings, "PLUGIN_PYPI_INDEX_URL", server.url)
    before_locks = set(Path(tempfile.gettempdir()).glob("freesdn-plugin-lock-*"))

    try:
        async with AsyncSession(engine, expire_on_commit=False) as seed:
            assert not (await seed.scalars(select(Organization.id).where(Organization.is_active.is_(True)))).all()
            assert not (await seed.scalars(select(InstalledPlugin.plugin_id))).all()
            seed.add_all([Organization(id=org, name="Owned cancellation", slug=uuid4().hex, is_active=True) for org in orgs])
            await seed.flush()
            password = get_password_hash("Owned cancellation synthetic password")
            for index, (user, org) in enumerate(zip(users, orgs, strict=True)):
                name = "owned-cancel-" + uuid4().hex
                seed.add(User(id=user, organization_id=org, username=name, email=name + "@example.com",
                              full_name="Owned cancellation operator", hashed_password=password,
                              role="super_admin" if index == 0 else "viewer", is_active=True,
                              is_verified=True, token_version=17))
            await seed.flush()
            seed.add_all([UserSession(user_id=user, access_jti=claim["jti"], created_at=datetime.now(UTC),
                                      expires_at=datetime.now(UTC) + timedelta(minutes=5))
                          for user, claim in zip(users, claims, strict=True)])
            await seed.commit()
            if operation == "upgrade":
                await loader.install_plugin(archive(slug, "1.0.3"), seed, users[0])
            seed.add(PluginOrganizationState(plugin_id=slug, organization_id=orgs[2], is_enabled=False))
            for org in orgs:
                for key, value in {"minimum_severity": "high", "dry_run": True}.items():
                    seed.add(PluginSetting(plugin_id=slug, organization_id=org, key=key, value=value))
            await seed.commit()
            if operation == "upgrade":
                await endpoints._start_plugin_everywhere(slug, seed, app)
                await seed.commit()
        before_files = disk_files(dest)
        async with AsyncSession(engine) as observer:
            before_settings = await settings_rows(observer, slug)
        old_runtime = runtime_state(loader, slug, orgs)
        headers = [{"Authorization": f"Bearer {token}"} for token in tokens]
        digest = "0" * 64 if "hash_failure" in outcome else hashlib.sha256(server.raw).hexdigest()
        raw, candidate_files = wheel_archive(slug, digest)
        monkeypatch.setattr(loader_module.settings, "PLUGIN_ALLOW_RUNTIME_PYTHON_DEPS", True)
        cancellations = []
        request_cancelled = False
        response = None
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url="http://owned.test") as client:
            url = f"/api/v1/plugins/{slug}/upgrade" if operation == "upgrade" else "/api/v1/plugins/install"
            request_task = asyncio.create_task(client.post(url, headers=headers[0], files={"file": ("owned.zip", raw, "application/zip")}))
            await asyncio.wait_for(started.wait(), timeout=15)
            assert not server.observations["handler_errors"] and len(server.observations.get("processes_at_transfer", [])) == 1
            assert server.observations["version_at_transfer"] == "1.0.4"
            if outcome.startswith("cancel_"):
                cancellations.append(request_task.cancel("Owned first cancellation"))
                # wait() observes without cancelling the request a second time.
                # The worker remains blocked at its explicit release barrier.
                await asyncio.wait({request_task}, timeout=1)
                if "twice" in outcome:
                    cancellations.append(request_task.cancel("Owned repeated cancellation"))
                    await asyncio.wait({request_task}, timeout=0.1)
            done_while_blocked = request_task.done()
            server.release.set()
            done, _ = await asyncio.wait({request_task}, timeout=30)
            assert done, "Owned request did not terminate after worker completed"
            try:
                response = request_task.result()
            except asyncio.CancelledError:
                request_cancelled = True
            routes = [await client.get(f"/api/v1/{slug}/", headers=h) for h in headers]
        async with AsyncSession(engine) as observer:
            rows = (await observer.scalars(select(InstalledPlugin).where(InstalledPlugin.plugin_id.in_(SLUGS)))).all()
            actual_rows = sorted((row.plugin_id, row.version, row.status, row.is_active) for row in rows)
            current_settings = await settings_rows(observer, slug)
            fresh = PluginLoader()
            loaded = await fresh.load_all_plugins(observer)
            fresh_versions = sorted((plugin.manifest.id, plugin._plugin_manifest_data.version) for plugin in loaded)
            disabled = (await observer.scalars(select(PluginOrganizationState).where(PluginOrganizationState.organization_id.in_(orgs)))).all()
        processes = server.observations["processes_at_transfer"]
        if outcome == "valid":
            native_package_check(dest / slug, present=True)
        actual = {"operation": operation, "outcome": outcome, "native": server.observations,
                  "native_processes_gone": all(not same_process_alive(row) for row in processes),
                  "no_matching_installer": not native_uv_process(dest / slug),
                  "private_locks_restored": set(Path(tempfile.gettempdir()).glob("freesdn-plugin-lock-*")) == before_locks,
                  "cancellations_requested": cancellations, "request_done_while_worker_blocked": done_while_blocked,
                  "request_cancelled": request_cancelled, "http_status": response.status_code if response else None,
                  "route_statuses": [r.status_code for r in routes], "rows": actual_rows,
                  "runtime": runtime_state(loader, slug, orgs), "files_unchanged": disk_files(dest) == before_files,
                  "destination_files": disk_files(dest / slug), "settings_unchanged": current_settings == before_settings,
                  "fresh_versions": fresh_versions, "missing_on_disk": fresh.missing_on_disk,
                  "disabled_states": [(orgs.index(row.organization_id), row.is_enabled) for row in disabled],
                  "owned_subscription_delta": len(subscription_ids() - original_subscriptions),
                  "preexisting_subscriptions_preserved": original_subscriptions <= subscription_ids(),
                  "rollback_directories": [x.name for x in dest.glob(f".{slug}-rollback-*")]}
        record_property("actual_native_dependency_lifecycle", json.dumps(actual, sort_keys=True))
        assert not server.observations["handler_errors"], actual
        process = processes[0]
        assert process["ppid"] == os.getpid() and process["executable"] == process["expected_installer"], actual
        assert actual["native_processes_gone"] and actual["no_matching_installer"] and actual["private_locks_restored"], actual
        assert server.observations["verified_lock"]["mode"] == 0o600
        assert not Path(server.observations["verified_lock"]["path"]).exists()
        assert server.observations["verified_lock"]["sha256"] == hashlib.sha256(candidate_files["requirements.txt"]).hexdigest()
        assert server.observations["bytes_sent"] == len(server.raw) and server.observations["wheel_requests"] >= 1
        assert not done_while_blocked and not server.observations["request_done_at_send"], actual
        assert server.observations["version_at_send"] == "1.0.4", actual
        cancelled = outcome.startswith("cancel_")
        valid = outcome == "valid"
        assert request_cancelled == cancelled
        if cancelled:
            assert all(cancellations) and len(cancellations) == (2 if "twice" in outcome else 1)
        else:
            assert response.status_code == ((201 if operation == "install" else 200) if valid else 400), actual
        version = "1.0.4" if valid else "1.0.3"
        installed = valid or operation == "upgrade"
        assert actual_rows == ([(slug, version, "installed", True)] if installed else []), actual
        assert fresh_versions == ([(slug, version)] if installed else []) and not fresh.missing_on_disk
        assert actual["settings_unchanged"] and actual["disabled_states"] == [(2, False)]
        assert actual["preexisting_subscriptions_preserved"] and not actual["rollback_directories"]
        if valid:
            expected = {name: hashlib.sha256(content).hexdigest() for name, content in candidate_files.items()}
            assert {name: digest for name, digest in actual["destination_files"].items() if not name.startswith(".venv/")} == expected
            assert any(name.startswith(".venv/") for name in actual["destination_files"])
        else:
            assert actual["files_unchanged"], actual
            assert actual["runtime"] == old_runtime
        if installed:
            assert actual["route_statuses"] == [200, 200, 410]
            assert actual["runtime"] == [{"active": True, "subscriptions": 2, "version": version}] * 2 + [
                {"active": False, "subscriptions": 0, "version": None},
            ]
            assert actual["owned_subscription_delta"] == 4
        else:
            assert actual["route_statuses"] == [404, 404, 404] and actual["owned_subscription_delta"] == 0
    finally:
        server.release.set()
        if request_task is not None:
            done, _ = await asyncio.wait({request_task}, timeout=30)
            assert done, "Owned request leaked"
            if not request_task.cancelled():
                request_task.exception()
        server.close()
        async with AsyncSession(engine) as cleanup:
            await loader.stop_plugin_everywhere(slug, cleanup)
            await cleanup.execute(delete(PluginSetting).where(PluginSetting.organization_id.in_(orgs)))
            await cleanup.execute(delete(PluginOrganizationState).where(PluginOrganizationState.organization_id.in_(orgs)))
            await cleanup.execute(delete(InstalledPlugin).where(InstalledPlugin.installed_by.in_(users)))
            await cleanup.execute(delete(AuditLogRecord).where(AuditLogRecord.actor_id.in_([str(user) for user in users])))
            await cleanup.execute(delete(UserSession).where(UserSession.user_id.in_(users)))
            await cleanup.execute(delete(User).where(User.id.in_(users)))
            await cleanup.execute(delete(Organization).where(Organization.id.in_(orgs)))
            await cleanup.commit()
        await engine.dispose()
        from app.db.session import engine as sdk_engine
        await sdk_engine.dispose()
        assert subscription_ids() == original_subscriptions


def test_native_installer_unchanged_timeout_reaps_real_uv(tmp_path, monkeypatch, record_property):
    plugin = tmp_path / "plugin"
    plugin.mkdir()
    started = threading.Event()
    server = OwnedWheelIndex(tmp_path / "index", plugin, started.set, lambda: False, slow=True)
    server.release.set()
    digest = hashlib.sha256(server.raw).hexdigest()
    (plugin / "requirements.txt").write_text(f"{DEPENDENCY} --hash=sha256:{digest}\n")
    monkeypatch.setattr(loader_module.settings, "PLUGIN_PYPI_INDEX_URL", server.url)
    before_locks = set(Path(tempfile.gettempdir()).glob("freesdn-plugin-lock-*"))
    begin = time.monotonic()
    error = None
    try:
        try:
            loader_module._install_python_deps(plugin, [DEPENDENCY])
        except PluginLoadError as exc:
            error = exc
        elapsed = time.monotonic() - begin
        server.close()
        native_package_check(plugin, present=False)
        processes = server.observations.get("processes_at_transfer", [])
        actual = {"elapsed_seconds": elapsed, "native": server.observations,
                  "error_type": type(error).__name__, "error_message": str(error),
                  "cause_type": type(error.__cause__).__name__ if error else None,
                  "cause_timeout": getattr(error.__cause__, "timeout", None) if error else None,
                  "native_processes_gone": all(not same_process_alive(row) for row in processes),
                  "no_matching_installer": not native_uv_process(plugin),
                  "private_locks_restored": set(Path(tempfile.gettempdir()).glob("freesdn-plugin-lock-*")) == before_locks}
        record_property("actual_native_installer_timeout", json.dumps(actual, sort_keys=True))
        assert started.is_set() and len(processes) == 1 and not server.observations["handler_errors"], actual
        assert processes[0]["ppid"] == os.getpid() and processes[0]["executable"] == processes[0]["expected_installer"]
        assert actual["cause_type"] == "TimeoutExpired" and actual["cause_timeout"] == 180, actual
        assert 179 <= elapsed <= 220, actual
        assert 0 < server.observations["bytes_sent"] < len(server.raw)
        assert actual["native_processes_gone"] and actual["no_matching_installer"] and actual["private_locks_restored"]
        assert actual["error_message"] == "Plugin dependency installation failed; verify the wheel lock and index."
    finally:
        if server.thread.is_alive():
            server.close()
