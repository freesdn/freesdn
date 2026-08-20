# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
One bug class, found four ways: the code declared something and never did it.

A parameter in a signature, a field in a request schema, a bool returned by a
client -- each is a promise the surrounding code simply dropped. None of them
fail loudly, which is why a green suite never noticed: the endpoint answers
200, the write "succeeds", the filter is accepted. The product just quietly
does something other than what it says.

Four shapes, all fixed here:

1. A DEVICE SAID NO AND WE SAID OK
   ``GrandstreamPhoneClient.set_config`` returns ``bool`` -- False when the
   phone rejects the write -- and it does NOT raise. Seven adapter call sites
   discarded that bool and returned ``AdapterResult.ok``. ``factory_reset_phone``
   in the same class got it right, which is what makes the others a slip
   rather than a design.

   ``client.reboot()`` was worse: every exception path ended in ``return True``,
   including auth failure, so it could not report a refusal at all.

2. A FILTER THE SCHEMA CANNOT SUPPORT
   Thirteen endpoints accepted ``site_id`` and never passed it on. Twelve of
   them query records with no site column at all (security events are about
   users and IPs; a PBX sub-resource already belongs to one site), so the
   honest fix is to stop advertising the filter. The thirteenth --
   recording search -- joins Camera, which does have ``site_id``, so that one
   is implemented rather than removed.

3. PAGINATION THAT RETURNS PAGE ONE FOREVER
   ``search_pbx_call_logs`` passed ``limit`` and dropped ``offset``, and
   reported ``total = len(items)`` -- the size of the page, not the result set.

4. A REQUEST BODY NOBODY READ
   ``PhoneProvisionRequest`` carries ``force`` and ``reboot_after`` (default
   True). Both were ignored: an unchanged checksum skipped the file write with
   no way to override, and the phone was never rebooted -- so a freshly
   provisioned config was never actually applied.

Plus ``get_client_analytics``, which validated ``hours`` (ge=1, le=720) and
then counted every client ever seen, so 1 hour and 30 days returned the same
two numbers.
"""

from __future__ import annotations

import inspect
import pathlib
from datetime import UTC, datetime, timedelta

import pytest

from app.adapters.grandstream.adapter import GrandstreamAdapter


def _src(obj) -> str:
    """Source with comment lines stripped -- fixes quote the old code in comments."""
    return "\n".join(
        line for line in inspect.getsource(obj).splitlines() if not line.strip().startswith("#")
    )


def _body(obj) -> str:
    """Source with the docstring removed as well.

    Several of these fixes quote the code they replaced inside their own
    docstring, so a naive substring search finds the OLD code in the NEW
    source and fails for a reason that has nothing to do with behaviour.
    """
    src = _src(obj)
    for quote in ('"""', "'" * 3):
        first = src.find(quote)
        if first != -1:
            end = src.find(quote, first + 3)
            if end != -1:
                return src[:first] + src[end + 3 :]
    return src


# ══════════════════════════════════════════════════════════════════
# 1. the device said no
# ══════════════════════════════════════════════════════════════════


class _RefusingClient:
    """A phone that answers every write with 'no' the way the real one does.

    The real client returns False (and logs a warning) when the phone replies
    with anything other than ``{"response": "success"}``. It does not raise --
    that is the entire reason the bug was invisible.
    """

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def set_config(self, *_a, **_k) -> bool:
        self.calls.append("set_config")
        return False

    async def reboot(self) -> bool:
        self.calls.append("reboot")
        return False

    async def factory_reset(self) -> bool:
        self.calls.append("factory_reset")
        return False


@pytest.fixture
def refusing_adapter(monkeypatch):
    """A write-enabled adapter whose phone refuses everything."""
    adapter = GrandstreamAdapter(host="192.168.0.2", username="admin", password="x")
    adapter._read_only = False  # pin the gate open; gate behaviour is tested elsewhere
    client = _RefusingClient()

    async def _fake_connect(_mac):
        return client

    monkeypatch.setattr(adapter, "_get_or_connect", _fake_connect)
    return adapter, client


_MAC = "00:0b:82:11:22:33"


async def test_set_phone_config_fails_when_the_phone_refuses(refusing_adapter):
    adapter, client = refusing_adapter
    # P-values inside the safe allowlist, so we reach the write rather than
    # bouncing off the allowlist guard.
    result = await adapter.set_phone_config(_MAC, {"P64": "UTC-5"}, force=True)

    assert "set_config" in client.calls, "never reached the write"
    assert result.success is False, "a refused config write reported success"
    assert "refused" in (result.error or "").lower()


async def test_reboot_phone_fails_when_the_phone_refuses(refusing_adapter):
    adapter, client = refusing_adapter
    result = await adapter.reboot_phone(_MAC, force=True)

    assert "reboot" in client.calls
    assert result.success is False, "a refused reboot reported 'Reboot sent'"


async def test_configure_blf_keys_fails_when_the_phone_refuses(refusing_adapter):
    adapter, client = refusing_adapter
    result = await adapter.configure_blf_keys(_MAC, [], force=True)

    assert "set_config" in client.calls
    assert result.success is False, "a refused line-key write reported success"


async def test_configure_sip_account_fails_when_the_phone_refuses(refusing_adapter):
    adapter, client = refusing_adapter
    result = await adapter.configure_sip_account(
        _MAC, "pbx.example.com", "201", "s3cret", force=True
    )

    assert "set_config" in client.calls
    assert result.success is False, "a refused SIP credential write reported success"
    # The failure must not leak the password it was trying to write.
    assert "s3cret" not in (result.error or "")


async def test_provision_phone_refusal_is_not_downgraded_to_xml_only(refusing_adapter):
    """
    provision_phone legitimately degrades to XML-only when a phone is
    UNREACHABLE. A refusal is not unreachability -- it is the phone saying no,
    and it must fail rather than report ``direct_push: False`` as a success.
    """
    adapter, client = refusing_adapter
    from app.adapters.grandstream.models import PhoneConfig

    result = await adapter.provision_phone(_MAC, PhoneConfig(accounts=[]), force=True)

    assert "set_config" in client.calls
    assert result.success is False, "a refused push was reported as successful provisioning"


async def test_bulk_reboot_counts_refusals_as_failures(refusing_adapter):
    adapter, client = refusing_adapter
    result = await adapter.bulk_reboot([_MAC], force=True)

    assert result.success is True, "the bulk op itself completed"
    assert result.data == {_MAC: False}, "a refused reboot was tallied as rebooted"
    assert "0/1" in (result.message or "")


async def test_a_phone_that_accepts_still_succeeds(monkeypatch):
    """
    Negative control. The fix must not make every write fail -- an accepting
    phone must still produce AdapterResult.ok, or the tests above would pass
    for the wrong reason.
    """
    adapter = GrandstreamAdapter(host="192.168.0.2", username="admin", password="x")
    adapter._read_only = False

    class _AcceptingClient:
        async def set_config(self, *_a, **_k) -> bool:
            return True

        async def reboot(self) -> bool:
            return True

    async def _fake_connect(_mac):
        return _AcceptingClient()

    monkeypatch.setattr(adapter, "_get_or_connect", _fake_connect)

    assert (await adapter.set_phone_config(_MAC, {"P64": "UTC-5"}, force=True)).success is True
    assert (await adapter.reboot_phone(_MAC, force=True)).success is True
    assert (await adapter.bulk_reboot([_MAC], force=True)).data == {_MAC: True}


def test_no_grandstream_write_discards_its_result():
    """
    Guard the class rather than the seven instances. A bare ``await
    client.set_config(...)`` as a statement throws the answer away; the fix is
    only durable if a new call site cannot reintroduce it.
    """
    import app.adapters.grandstream.adapter as mod

    src = inspect.getsource(mod)
    offenders = [
        line.strip()
        for line in src.splitlines()
        if line.strip().startswith(("await client.set_config", "await client.reboot"))
    ]
    assert offenders == [], f"write result discarded at: {offenders}"


def test_client_reboot_can_report_a_refusal():
    """
    The adapter check above is only meaningful if the client can ever say no.
    ``reboot`` used to end in a blanket ``except Exception: return True``,
    which made every failure -- including auth -- indistinguishable from
    success. It must now mirror ``factory_reset``.
    """
    from app.adapters.grandstream.client import GrandstreamPhoneClient

    code = _body(GrandstreamPhoneClient.reboot)
    assert "return False" in code, "reboot() can still never report a failure"
    assert "except Exception" not in code, "blanket handler still swallows refusals"


def test_reboot_still_treats_a_dropped_connection_as_success():
    """
    The distinction that makes this correct: a real reboot kills the socket
    mid-response, so that specific case must stay a success. Tightening the
    contract must not turn every successful reboot into a reported failure.
    """
    from app.adapters.grandstream.client import GrandstreamPhoneClient

    code = _body(GrandstreamPhoneClient.reboot)
    assert "ServerDisconnectedError" in code
    disconnected = code.index("ServerDisconnectedError")
    assert "return True" in code[disconnected:], "dropped connection no longer counts as sent"


# ══════════════════════════════════════════════════════════════════
# 2. a filter the schema cannot support
# ══════════════════════════════════════════════════════════════════

# (module, function) pairs that used to accept site_id and silently drop it.
_DEADS = [
    ("app.api.v1.endpoints.security", "list_security_events"),
    ("app.api.v1.endpoints.security", "get_security_summary"),
    ("app.api.v1.endpoints.security", "list_anomalies"),
    ("app.api.v1.endpoints.security", "list_blocked_ips"),
    ("app.api.v1.endpoints.security", "list_failed_logins"),
    ("app.api.v1.endpoints.audit", "get_security_summary"),
    ("app.modules.cameras.api", "get_stream_stats"),
    ("app.modules.voip.api", "list_extensions"),
    ("app.modules.voip.api", "list_pbx_trunks"),
    ("app.modules.voip.api", "list_pbx_queues"),
    ("app.modules.voip.api", "list_pbx_ivrs"),
    ("app.modules.voip.api", "list_pbx_dids"),
]


@pytest.mark.parametrize(("module", "func"), _DEADS)
def test_endpoints_no_longer_advertise_a_filter_they_drop(module: str, func: str):
    """
    Accepting a filter and ignoring it is worse than not offering it: the
    caller gets a 200 and unfiltered data, with nothing to indicate the
    difference.
    """
    mod = __import__(module, fromlist=[func])
    params = inspect.signature(getattr(mod, func)).parameters
    assert "site_id" not in params, f"{func} still accepts a site_id it never applies"


def test_the_records_behind_them_really_have_no_site_column():
    """
    Premise check -- this is why the fix is removal rather than plumbing. If
    someone later adds ``site_id`` to these models, this test fails and the
    filter should be implemented instead of dropped.
    """
    from app.models.security_audit import (
        FailedLoginRecord,
        IPBlockRecord,
        SecurityAnomalyRecord,
        SecurityEventRecord,
    )

    for model in (
        SecurityEventRecord,
        SecurityAnomalyRecord,
        FailedLoginRecord,
        IPBlockRecord,
    ):
        assert not hasattr(model, "site_id"), (
            f"{model.__name__} now has site_id -- implement the filter instead of removing it"
        )


def test_audit_logs_keep_the_site_filter_they_can_actually_honour():
    """
    Negative control for the removal. ``AuditLogRecord`` DOES have site_id and
    ``get_activity_summary`` threads it -- that must survive untouched, or the
    sweep removed too much.
    """
    from app.api.v1.endpoints.audit import get_activity_summary
    from app.models.security_audit import AuditLogRecord

    assert hasattr(AuditLogRecord, "site_id")
    assert "site_id" in inspect.signature(get_activity_summary).parameters
    assert "site_id=site_id" in _src(get_activity_summary)


def test_recording_search_actually_applies_site_id():
    """
    The one that WAS implementable: Recording joins Camera, and Camera has
    site_id. Removing it here would have dropped a working feature.
    """
    from app.modules.cameras.api import search_recordings
    from app.modules.cameras.service import RecordingService

    assert "site_id" in inspect.signature(search_recordings).parameters
    assert "site_id=site_id" in _src(search_recordings), "endpoint still drops site_id"

    svc = _src(RecordingService.search_recordings)
    assert "site_id: UUID | None = None" in svc
    assert "Camera.site_id == site_id" in svc, "service accepts site_id without filtering on it"


def test_site_id_narrows_but_never_widens_a_site_limited_caller():
    """
    The security-relevant half. ``accessible_site_ids`` is a permission
    ceiling; ``site_id`` is a user preference. Both predicates must be ANDed
    onto the same query so a site-limited caller cannot pass ``site_id`` for a
    site they were never granted and reach it.
    """
    from app.modules.cameras.service import RecordingService

    svc = _src(RecordingService.search_recordings)
    assert "Camera.site_id.in_(list(accessible_site_ids))" in svc
    assert "Camera.site_id == site_id" in svc
    # Independent `if`s, not elif/else -- an else would let one replace the other.
    assert "elif" not in svc.split("if site_id is not None")[0][-400:]


def test_the_join_is_reached_when_site_id_is_the_only_scope():
    """
    The Camera join is conditional. If site_id did not extend that condition,
    an unscoped super-admin passing site_id would skip the join entirely and
    the filter would silently do nothing -- the original bug, reintroduced.
    """
    from app.modules.cameras.service import RecordingService

    svc = _body(RecordingService.search_recordings)
    before_join = svc.split("query = query.join(Camera")[0]
    guard = next(
        line.strip()
        for line in reversed(before_join.splitlines())
        if line.strip().startswith("if ")
    )
    assert "site_id is not None" in guard, f"join guard ignores site_id: {guard!r}"


# ══════════════════════════════════════════════════════════════════
# 3. pagination that returns page one forever
# ══════════════════════════════════════════════════════════════════


def test_call_log_offset_reaches_the_adapter():
    """offset was accepted at the edge and dropped at every layer below it."""
    from app.adapters.freepbx.adapter import FreePBXAdapter
    from app.modules.voip.api import search_pbx_call_logs
    from app.modules.voip.service import VoIPService

    assert "offset=offset" in _src(search_pbx_call_logs), "endpoint drops offset"
    assert "offset" in inspect.signature(VoIPService.search_pbx_call_logs).parameters
    assert "offset=offset" in _src(VoIPService.search_pbx_call_logs), "service drops offset"
    assert "offset" in inspect.signature(FreePBXAdapter.search_call_logs).parameters
    assert "offset=offset" in _src(FreePBXAdapter.search_call_logs), "adapter drops offset"


def test_total_no_longer_reports_the_page_size():
    """
    ``total = len(items)`` made every full page look like the whole result
    set, so the UI rendered one page and a 'next' that changed nothing.
    """
    from app.modules.voip.api import search_pbx_call_logs

    code = _src(search_pbx_call_logs)
    assert '"total": len(items)' not in code, "total still reports the page size"
    assert "has_more" in code, "no way for a caller to know more rows exist"


# ══════════════════════════════════════════════════════════════════
# 4. a request body nobody read
# ══════════════════════════════════════════════════════════════════


def test_force_reaches_the_provisioning_service():
    from app.modules.voip.api import provision_phone
    from app.modules.voip.provisioning import ProvisioningService

    assert "force=data.force" in _src(provision_phone), "endpoint ignores force"
    assert "force" in inspect.signature(ProvisioningService.generate_phone_config).parameters


def test_force_rewrites_a_config_whose_checksum_is_unchanged():
    """
    The reason force exists. Without it, a config file deleted or corrupted on
    disk can never be regenerated: the checksum still matches, so the write is
    skipped and re-provisioning is a silent no-op.
    """
    from app.modules.voip.provisioning import ProvisioningService

    code = _src(ProvisioningService.generate_phone_config)
    assert "if write_file and (config_changed or force):" in code, (
        "an unchanged checksum still skips the write with no override"
    )


def test_reboot_after_is_honoured_and_reported():
    """
    Default True, and it never happened -- so a phone kept running its old
    config after a 'successful' provision. The reboot is best-effort because
    the config is already written by then, but the caller must be told.
    """
    from app.modules.voip.api import provision_phone

    code = _src(provision_phone)
    assert "if data.reboot_after:" in code, "reboot_after still ignored"
    assert "reboot_phone" in code, "nothing actually reboots the phone"
    assert '"rebooted"' in code, "caller cannot tell whether the reboot happened"


def test_a_failed_reboot_does_not_fail_a_written_config():
    """
    Ordering matters: the config write has already succeeded and been
    committed. Turning a refused reboot into a 4xx would tell the operator the
    provision failed when it did not.
    """
    from app.modules.voip.api import provision_phone

    code = _src(provision_phone)
    reboot_at = code.index("if data.reboot_after:")
    tail = code[reboot_at:]
    assert "except (PhoneNotFoundError, VoIPError)" in tail
    assert 'result["rebooted"] = False' in tail
    assert "raise HTTPException" not in tail.split("except ProvisioningError")[0]


def test_provision_defaults_are_still_what_the_schema_declares():
    """Pin the contract being honoured, so a silent default flip is visible."""
    from app.modules.voip.schemas import PhoneProvisionRequest

    body = PhoneProvisionRequest()
    assert body.force is False
    assert body.reboot_after is True


# ══════════════════════════════════════════════════════════════════
# 5. a validated range that changed nothing
# ══════════════════════════════════════════════════════════════════


def test_client_analytics_applies_its_hours_window():
    """
    ``hours`` was declared with ge=1/le=720, validated on every request, and
    then never used -- so the range selector moved and the two numbers on the
    page did not.
    """
    from app.api.v1.endpoints.analytics import get_client_analytics

    code = _src(get_client_analytics)
    assert "timedelta(hours=hours)" in code, "hours still unused"
    assert code.count("DeviceClient.last_seen >= cutoff") == 2, (
        "the window must bound BOTH the total and the active count"
    )


def test_client_analytics_excludes_clients_that_never_reported():
    """
    ``last_seen`` is nullable. A NULL is not 'recent' -- without the explicit
    guard those rows would be dropped by the comparison anyway, but stating it
    keeps the intent from being optimised away later.
    """
    from app.api.v1.endpoints.analytics import get_client_analytics

    assert _src(get_client_analytics).count("DeviceClient.last_seen.is_not(None)") == 2


def test_the_window_is_a_real_cutoff_not_a_constant():
    """Guards against a fix that computes a cutoff and hardcodes the span."""
    from app.api.v1.endpoints.analytics import get_client_analytics

    code = _src(get_client_analytics)
    assert "datetime.now(UTC) - timedelta(hours=hours)" in code
    # sanity: the arithmetic the endpoint performs really does move with hours
    assert (datetime.now(UTC) - timedelta(hours=1)) > (datetime.now(UTC) - timedelta(hours=720))


# ══════════════════════════════════════════════════════════════════
# 6. a generated contract that covered two thirds of the API
# ══════════════════════════════════════════════════════════════════


def test_the_openapi_export_mounts_module_routes():
    """
    ``export_openapi.py`` produces the contract the frontend types are
    generated from, and its docstring claimed importing the app "loads the
    full router stack". It does not: the 10 loadable modules mount their
    routers from the lifespan, which never runs on a bare import. The export
    was missing ~500 paths -- every voip, cameras, firewall and hypervisor
    endpoint -- so the drift check compared only the core routes and silently
    passed on the majority of the API.
    """
    script = (
        pathlib.Path(__file__).resolve().parents[2] / "scripts" / "export_openapi.py"
    ).read_text(encoding="utf-8")

    assert "ModuleLoader" in script, "export still skips the module routers"
    assert "load_all_modules" in script, "discovery alone registers nothing"
    assert "register_routes" in script
    # The cached schema must be dropped, or app.openapi() returns the
    # pre-module spec it built on the first call.
    assert "openapi_schema = None" in script


def test_registering_routes_needs_a_loaded_registry():
    """
    Premise for the fix above, and the reason ``discover_modules()`` alone was
    not enough: ``register_routes`` walks the loader's REGISTRY, which only
    ``load_all_modules()`` populates. Discovery finds 10 modules and registers
    zero routes -- which looks like success and produces an empty result.
    """
    from app.modules.loader import ModuleLoader

    assert "self.registry.modules" in _src(ModuleLoader.register_routes)


def test_the_committed_contract_covers_the_modules():
    """
    The artifact, not just the generator. If someone regenerates with a broken
    export, this fails rather than shipping a contract that quietly omits most
    of the API.
    """
    generated = (
        pathlib.Path(__file__).resolve().parents[3]
        / "frontend"
        / "src"
        / "lib"
        / "api"
        / "generated"
        / "openapi.d.ts"
    )
    if not generated.is_file():  # pragma: no cover - backend-only checkout
        pytest.skip("frontend source not present")

    text = generated.read_text(encoding="utf-8", errors="replace")
    for prefix in ("/api/v1/voip/", "/api/v1/cameras/", "/api/v1/firewall/"):
        assert prefix in text, f"generated contract has no {prefix} paths"
