# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Properties the first-party plugins must hold at production scale.

Everything here was a real defect in a plugin that worked perfectly on a
40-device lab estate. That is the pattern worth naming: none of these fail in
development, and all of them fail once someone runs the thing for real.

  SILENT TRUNCATION
    ``DeviceSDK.list`` caps at 500 per call no matter what you ask for. Three
    plugins passed ``limit=500``, ``limit=2000`` and ``limit=1000`` and believed
    they had the whole inventory. A drift report or an inventory sync built on
    that is wrong above 500 devices and right below it, which is the worst way
    for a bug to behave. ``iter_all()`` pages properly.

  ALERT IDENTITY
    config-drift-guard titled its alerts ``Config drift: offline (3)``. The
    count is not identity: a fourth offline device produced a title matching
    nothing open, raised a SECOND alert, and left the first. A week of
    fluctuating counts leaves a wall of alerts describing one condition.
    new-device-watch had the mirror image -- it titled by device NAME, and this
    estate has nine devices called "192.168.1.1", so eight unrecognised
    devices were silently never reported.

  ALERTS THAT NEVER CLEAR
    Nothing resolved. After a month the alert list describes the past and the
    one that matters is lost in it.

  N QUERIES PER ITEM
    ``_is_allowed`` issued three settings queries PER DEVICE, so auditing 40
    devices meant 120 database round trips to answer three questions whose
    answers cannot change mid-loop.

  RETRY WITHOUT CLASSIFICATION
    A sync that gives up on one 502 is one an operator learns to distrust. A
    sync that retries a 403 locks an account. And a retried POST that actually
    succeeded creates a duplicate.

  CLAIMING WHAT YOU DO NOT DO
    The retired ai-ops-tools plugin declared ``alerts.read``, described itself
    to the ASSISTANT as combining "devices and alerts", and read no alerts at
    all -- so it would answer "no alerts at site B" having never looked. The
    plugin is gone (its tools are native now, in
    ``app/modules/ai/tools/estate.py``) but the class of bug is not, which is
    why ``test_every_declared_capability_is_actually_used`` still runs against
    every shipped plugin.
"""

from __future__ import annotations

import pathlib

import pytest

PLUGINS = (
    "new-device-watch",
    "config-drift-guard",
    "netbox-sync",
    "librenms-sync",
    "home-assistant-bridge",
    "port-hygiene",
    "snipe-it-sync",
    "zabbix-sync",
)


def _source(plugin: str) -> str | None:
    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent / "registry" / "plugins" / plugin / "plugin.py"
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    return None


def _manifest(plugin: str) -> str | None:
    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent / "registry" / "plugins" / plugin / "plugin.yaml"
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    return None


@pytest.fixture(params=PLUGINS)
def plugin(request) -> str:
    src = _source(request.param)
    if src is None:  # pragma: no cover - backend-only checkout
        pytest.skip("registry plugins are not present in this checkout")
    return request.param


# ── the SDK must make correct scanning possible ─────────────────


def test_the_sdk_offers_a_paging_iterator():
    """
    Without this there is no correct way to scan an estate, and every plugin
    that tries is silently wrong above the cap.
    """
    import inspect

    from app.plugins.sdk import DeviceSDK, SiteSDK

    assert inspect.isasyncgenfunction(DeviceSDK.iter_all)
    assert inspect.isasyncgenfunction(SiteSDK.iter_all)
    assert "offset" in inspect.signature(DeviceSDK.list).parameters
    assert "offset" in inspect.signature(SiteSDK.list).parameters


def test_paging_is_deterministically_ordered():
    """
    Offset paging over an unordered query skips and duplicates rows between
    pages, so ``iter_all`` would return a WRONG set rather than a truncated
    one -- worse than the bug it exists to fix.
    """
    import inspect

    from app.plugins.sdk import DeviceSDK, SiteSDK

    assert "order_by(Device.id)" in inspect.getsource(DeviceSDK.list)
    assert "order_by(Site.id)" in inspect.getsource(SiteSDK.list)


def test_the_iterator_refuses_rather_than_truncating():
    """A ceiling that silently stops is the same bug one level up."""
    import inspect

    from app.plugins.sdk import DeviceSDK

    src = inspect.getsource(DeviceSDK.iter_all)
    assert "MAX_ITER_ROWS" in src
    assert "raise RuntimeError" in src


# ── no plugin may silently truncate ─────────────────────────────


def test_no_plugin_scans_the_estate_with_a_capped_list(plugin: str):
    """
    ``list(limit=N)`` for a FULL scan is the bug. It is fine for "show me a few"
    -- which is why this checks the large limits that mean "I want them all".
    """
    src = _source(plugin) or ""
    offenders = [
        line.strip()
        for line in src.splitlines()
        if "devices.list(" in line or "sites.list(" in line
        for cap in ["limit=200", "limit=500", "limit=1000", "limit=2000"]
        if cap in line
    ]
    assert not offenders, (
        f"{plugin} scans with a capped list() instead of iter_all(): {offenders}. "
        "list() returns at most 500 however much you ask for."
    )


@pytest.mark.parametrize("plugin", ["config-drift-guard", "netbox-sync", "new-device-watch"])
def test_full_scans_use_the_iterator(plugin: str):
    src = _source(plugin)
    if src is None:  # pragma: no cover
        pytest.skip("registry plugins are not present in this checkout")
    assert "iter_all()" in src, f"{plugin} does not page its full scan"


# ── alert identity and lifecycle ────────────────────────────────


def test_drift_alert_titles_carry_no_count():
    """
    The count is not identity. With it in the title, every change in the
    number of findings raised a NEW alert and orphaned the previous one.
    """
    src = _source("config-drift-guard")
    if src is None:  # pragma: no cover
        pytest.skip("registry plugins are not present in this checkout")
    assert 'title = f"{ALERT_PREFIX}: {check}"' in src
    assert "({len(group)})" not in src, "the finding count is back in the alert title"


def test_drift_alerts_resolve_when_the_condition_clears():
    src = _source("config-drift-guard")
    if src is None:  # pragma: no cover
        pytest.skip("registry plugins are not present in this checkout")
    assert "alerts.resolve(" in src, "drift alerts never resolve"
    # And only for checks that actually ran: a disabled check cannot observe
    # that its drift cleared, so resolving on its silence closes an alert about
    # a condition nobody looked at.
    assert "if enabled and check not in grouped" in src


def test_the_scan_reports_even_with_no_findings():
    """
    A scan that finds nothing is precisely the scan that should clear the alert
    raised by the scan that found something. Short-circuiting on
    ``if findings:`` means an alert can never resolve.
    """
    src = _source("config-drift-guard")
    if src is None:  # pragma: no cover
        pytest.skip("registry plugins are not present in this checkout")
    assert "if raise_alerts and findings:" not in src, (
        "the scan skips reporting when there are no findings, so nothing ever resolves"
    )


def test_device_alerts_are_identified_by_mac_not_name():
    """
    A controller-supplied name is not unique. This estate has nine devices
    reported as "192.168.1.1"; titling by name collapses them onto one alert
    and silently drops eight unrecognised devices.
    """
    src = _source("new-device-watch")
    if src is None:  # pragma: no cover
        pytest.skip("registry plugins are not present in this checkout")
    assert "identity = _normalise_mac(" in src
    assert "{identity}" in src


def test_a_discovery_sweep_cannot_produce_an_alert_per_device():
    src = _source("new-device-watch")
    if src is None:  # pragma: no cover
        pytest.skip("registry plugins are not present in this checkout")
    assert "MAX_ALERTS_PER_WINDOW" in src, "no burst budget; a sweep alerts per device"
    # Suppressing silently would be worse than the flood: ten alerts with no
    # hint that four hundred followed.
    assert "_summarise_suppressed" in src, "the burst budget suppresses without saying so"


# ── efficiency ──────────────────────────────────────────────────


def test_the_allowlist_is_not_re_read_per_device():
    src = _source("new-device-watch")
    if src is None:  # pragma: no cover
        pytest.skip("registry plugins are not present in this checkout")
    # _is_allowed must be pure: settings arrive as an argument.
    body = src.split("def _is_allowed(", 1)[1].split("\n    async def", 1)[0]
    assert "settings.get(" not in body, (
        "_is_allowed reads settings per device; auditing 500 devices means 1500 queries"
    )


def test_the_drift_scan_reads_settings_once():
    src = _source("config-drift-guard")
    if src is None:  # pragma: no cover
        pytest.skip("registry plugins are not present in this checkout")
    assert "async def _settings(self)" in src, "the scan has no settings snapshot"
    for check in ("_naming", "_offline"):
        body = (
            src.split(f"def {check}(", 1)[1]
            .split("\n    def ", 1)[0]
            .split("\n    async def ", 1)[0]
        )
        assert "settings.get(" not in body, f"{check} reads settings inside the scan"


# ── retry classification ────────────────────────────────────────


def test_reads_retry_and_writes_do_not():
    """
    A retried POST that actually succeeded creates a duplicate device. That is
    worse than the failure it was trying to paper over.
    """
    src = _source("netbox-sync")
    if src is None:  # pragma: no cover
        pytest.skip("registry plugins are not present in this checkout")
    assert 'attempts = MAX_RETRIES if method == "get" else 1' in src, (
        "writes are retried, or reads are not"
    )


def test_only_transient_failures_are_retried():
    """Retrying a 403 locks an account."""
    src = _source("netbox-sync")
    if src is None:  # pragma: no cover
        pytest.skip("registry plugins are not present in this checkout")
    assert "_is_transient" in src
    for permanent in ("401", "403", "404"):
        assert permanent in src, f"{permanent} is not classified as permanent"


def test_netbox_pagination_follows_next():
    """
    NetBox caps page size server-side whatever you ask for. Reading one page and
    treating it as the whole inventory makes this plugin propose to re-create
    every device NetBox already had.
    """
    src = _source("netbox-sync")
    if src is None:  # pragma: no cover
        pytest.skip("registry plugins are not present in this checkout")
    assert 'body.get("next")' in src, "NetBox reads do not paginate"
    assert "MAX_PAGES" in src


# ── honesty ─────────────────────────────────────────────────────


def test_every_declared_capability_is_actually_used(plugin: str):
    """
    An unused capability is an unnecessary grant and a claim the plugin does not
    honour. The consent dialog shows it to an operator as something this plugin
    does.
    """
    manifest = _manifest(plugin) or ""
    src = _source(plugin) or ""
    uses = {
        "devices.read": ("devices.list", "devices.get", "devices.iter_all", "_visible_devices"),
        "devices.register": ("register_device",),
        "devices.stage": ("stage_change",),
        "sites.read": ("sites.list", "sites.get", "sites.iter_all", "_visible_sites"),
        "alerts.read": ("alerts.list", "_open_alerts"),
        "alerts.write": ("alerts.create", "alerts.resolve"),
        "metrics.read": (
            "metrics.query",
            "metrics.series",
            "metrics.latest",
            "_availability_trend",
        ),
    }
    declared = [code for code in uses if f"code: {code}" in manifest]
    assert declared, f"{plugin} declares no capabilities"

    unused = [code for code in declared if not any(marker in src for marker in uses[code])]
    assert not unused, f"{plugin} declares capabilities it never uses: {unused}"


# ---------------------------------------------------------------------------
# Every ctx.<sdk>.<method>(...) call must bind against the real signature
# ---------------------------------------------------------------------------
#
# The shipped plugins are the first thing a new user installs, and they fail in
# the quietest possible way: the call raises, the plugin's own broad `except`
# logs it at debug, and the operator sees a plugin that runs, reports success,
# and does nothing. An audit found four separate instances at once --
#
#   ctx.alerts.list(status="firing")   TypeError    5 plugins, resolve never ran
#   ctx.http.patch(...)                AttributeError  incidents never closed
#   device.get("serial")               always None  100% of devices skipped
#   getattr(device, "name")            always None  bare UUIDs in every ticket
#
# -- none of which any test could see, because nothing executed the plugins
# against the real SDK. This binds every call site to the actual runtime
# signature, so the next drift fails here instead of in someone's estate.

import ast as _ast
import inspect as _inspect
import pathlib as _pathlib

import pytest as _pytest

#: ctx attribute -> the runtime class that actually serves it.
_CTX_SDK_CLASSES = {
    "devices": "DeviceSDK",
    "alerts": "AlertSDK",
    "sites": "SiteSDK",
    "metrics": "MetricsSDK",
    "settings": "PluginSettingsSDK",
    "events": "EventSDK",
    "http": "PluginHTTPClient",
}


def _registry_plugin_files():
    for parent in _pathlib.Path(__file__).resolve().parents:
        d = parent / "registry" / "plugins"
        if d.is_dir():
            return sorted(d.glob("*/plugin.py"))
    return []


def _ctx_calls(tree):
    """Yield (sdk_attr, method, kwarg_names, positional_count, lineno)."""
    for node in _ast.walk(tree):
        if not isinstance(node, _ast.Call):
            continue
        fn = node.func
        if not isinstance(fn, _ast.Attribute):
            continue
        owner = fn.value
        if not (isinstance(owner, _ast.Attribute) and owner.attr in _CTX_SDK_CLASSES):
            continue
        # owner.value is `self.ctx` / `ctx` / `self.context` -- accept any of them
        base = owner.value
        base_ok = (isinstance(base, _ast.Name) and base.id in {"ctx", "context"}) or (
            isinstance(base, _ast.Attribute) and base.attr in {"ctx", "context"}
        )
        if not base_ok:
            continue
        kwargs = [k.arg for k in node.keywords if k.arg]
        yield owner.attr, fn.attr, kwargs, len(node.args), node.lineno


def test_every_plugin_sdk_call_matches_the_runtime_signature() -> None:
    """Fails on `alerts.list(status=)` and on `http.patch` before the fix."""
    files = _registry_plugin_files()
    if not files:
        _pytest.skip("registry/ is absent in a backend-only checkout")

    from app.plugins import sdk as runtime_sdk

    problems: list[str] = []
    for path in files:
        tree = _ast.parse(path.read_text(encoding="utf-8"))
        for attr, method, kwargs, n_pos, lineno in _ctx_calls(tree):
            cls = getattr(runtime_sdk, _CTX_SDK_CLASSES[attr], None)
            if cls is None:
                continue
            fn = getattr(cls, method, None)
            if fn is None:
                problems.append(
                    f"{path.parent.name}/plugin.py:{lineno}: "
                    f"ctx.{attr}.{method}() does not exist on {_CTX_SDK_CLASSES[attr]}"
                )
                continue
            try:
                sig = _inspect.signature(fn)
            except (TypeError, ValueError):  # pragma: no cover - builtins
                continue
            try:
                # +1 positional for `self`, which the bound call supplies.
                sig.bind_partial(*([None] * (n_pos + 1)), **dict.fromkeys(kwargs))
            except TypeError as exc:
                problems.append(
                    f"{path.parent.name}/plugin.py:{lineno}: "
                    f"ctx.{attr}.{method}({', '.join(kwargs)}) does not match "
                    f"{_CTX_SDK_CLASSES[attr]}.{method}{sig}: {exc}"
                )

    assert not problems, (
        "shipped plugins call the SDK with signatures it does not have. Each of "
        "these raises at runtime and is swallowed by the plugin's own except:\n  "
        + "\n  ".join(problems)
    )


def test_no_plugin_getattrs_a_dict_returned_by_the_sdk() -> None:
    """`getattr(device, "name")` on a dict is always the default.

    Every SDK read method returns plain dicts. Three ticketing plugins used
    attribute access on them, so every page, ticket and incident carried a bare
    UUID where the device or site name should have been -- and never errored.
    """
    files = _registry_plugin_files()
    if not files:
        _pytest.skip("registry/ is absent in a backend-only checkout")

    # ctx.http.* returns an httpx Response, NOT a dict, so
    # getattr(response, "status_code", 0) is the CORRECT idiom there and must not
    # be flagged. Only the SDKs whose read methods serialise to plain dicts count.
    dict_returning = {k for k in _CTX_SDK_CLASSES if k != "http"}

    problems: list[str] = []
    for path in files:
        tree = _ast.parse(path.read_text(encoding="utf-8"))
        # names bound from an SDK call are dicts (or lists of dicts)
        dict_names: set[str] = set()
        for node in _ast.walk(tree):
            if isinstance(node, (_ast.Assign, _ast.AnnAssign)):
                value = node.value
                if isinstance(value, _ast.Await):
                    value = value.value
                if isinstance(value, _ast.Call) and isinstance(value.func, _ast.Attribute):
                    owner = value.func.value
                    if isinstance(owner, _ast.Attribute) and owner.attr in dict_returning:
                        targets = node.targets if isinstance(node, _ast.Assign) else [node.target]
                        for t in targets:
                            if isinstance(t, _ast.Name):
                                dict_names.add(t.id)
            if isinstance(node, (_ast.For, _ast.AsyncFor)) and isinstance(node.target, _ast.Name):
                it = node.iter
                if isinstance(it, _ast.Call) and isinstance(it.func, _ast.Attribute):
                    owner = it.func.value
                    if isinstance(owner, _ast.Attribute) and owner.attr in dict_returning:
                        dict_names.add(node.target.id)

        for node in _ast.walk(tree):
            if (
                isinstance(node, _ast.Call)
                and isinstance(node.func, _ast.Name)
                and node.func.id == "getattr"
                and node.args
                and isinstance(node.args[0], _ast.Name)
                and node.args[0].id in dict_names
            ):
                problems.append(
                    f"{path.parent.name}/plugin.py:{node.lineno}: "
                    f"getattr({node.args[0].id}, ...) -- {node.args[0].id} is a dict "
                    "from the SDK, so this always returns the default"
                )

    assert not problems, "attribute access on SDK dicts:\n  " + "\n  ".join(problems)


def test_every_plugin_that_makes_http_calls_reads_the_status_code() -> None:
    """An unread status code is a plugin that reports success having done nothing.

    ``ctx.http`` returns the response object, so the status is right there. A
    plugin that returns ``response.json()`` without looking at it cannot tell a
    result from an error body -- and NetBox, Jira, PagerDuty and ServiceNow all
    answer errors with perfectly well-formed JSON. netbox-sync did exactly that:

      * a 401/403 on the device list returned ``{"detail": ...}``, so
        ``.get("results", [])`` gave ``[]`` and a revoked token was
        indistinguishable from an empty NetBox;
      * ``async_validate_config`` therefore greenlit a dead token;
      * every rejected POST was counted as a created device, so a sync reported
        ``{"ok": true, "created": [...40 devices...], "failures": []}`` having
        written nothing at all.

    The signal is unambiguous: of the twelve shipped plugins, the nine that call
    ``ctx.http`` all read ``status_code`` -- netbox-sync was the sole exception --
    and the three that never make HTTP calls are correctly exempt.
    """
    files = _registry_plugin_files()
    if not files:
        _pytest.skip("registry/ is absent in a backend-only checkout")

    offenders = []
    for path in files:
        source = path.read_text(encoding="utf-8")
        tree = _ast.parse(source)
        # Detect the ATTRIBUTE ACCESS `ctx.http`, not a call through it.
        # netbox-sync dispatches with `getattr(self.ctx.http, method)`, so a
        # call-shaped walk does not see it -- and netbox-sync is the one plugin
        # this test exists to catch. Any reference to ctx.http counts.
        makes_http = any(
            isinstance(n, _ast.Attribute)
            and n.attr == "http"
            and (
                (isinstance(n.value, _ast.Name) and n.value.id in {"ctx", "context"})
                or (isinstance(n.value, _ast.Attribute) and n.value.attr in {"ctx", "context"})
            )
            for n in _ast.walk(tree)
        )
        if makes_http and "status_code" not in source:
            offenders.append(path.parent.name)

    assert not offenders, (
        f"these plugins call ctx.http but never read a status code: {offenders}. "
        "They cannot distinguish a result from an error body, so an auth failure "
        "reads as an empty result and a rejected write reads as a successful one."
    )
