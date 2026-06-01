# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - NetFlow Receiver
================================

asyncio UDP server for NetFlow v5/v9 and IPFIX.
Aggregates flows into 1-minute buckets before bulk DB insert.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import struct
from collections import OrderedDict
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


def _task_error_handler(task: asyncio.Task[Any]) -> None:
    if task.cancelled():
        return
    exc = task.exception()
    if exc:
        logger.error("Background task failed: %s", exc, exc_info=exc)


# NetFlow v5 header: version(2) + count(2) + sysUptime(4) + unix_secs(4) + unix_nsecs(4) + flow_seq(4) + engine_type(1) + engine_id(1) + sampling(2)
_NF5_HEADER = struct.Struct("!HHIIIIBBH")
# NetFlow v5 record: 48 bytes
_NF5_RECORD = struct.Struct("!IIIHHIIIIHHBBBBHHBBH")

# NOTE(H6): per-source template cap. The previous global 1000-entry
# cap let a single hostile source flood the cache and evict legit
# templates from other sources.
_MAX_TEMPLATES_PER_SOURCE = 256


def _parse_v5(data: bytes) -> list[dict[str, Any]]:
    if len(data) < _NF5_HEADER.size:
        return []
    hdr = _NF5_HEADER.unpack_from(data)
    version, count = hdr[0], hdr[1]
    if version != 5:
        return []

    flows = []
    offset = _NF5_HEADER.size
    for _ in range(min(count, 30)):  # cap at 30 per packet
        if offset + _NF5_RECORD.size > len(data):
            break
        rec = _NF5_RECORD.unpack_from(data, offset)
        offset += _NF5_RECORD.size
        flows.append(
            {
                "source_ip": socket.inet_ntoa(rec[0].to_bytes(4, "big")),
                "dest_ip": socket.inet_ntoa(rec[1].to_bytes(4, "big")),
                "source_port": rec[10],
                "dest_port": rec[11],
                "protocol": rec[14],
                "bytes_in": rec[8],
                "bytes_out": 0,
                "packets": rec[7],
            }
        )
    return flows


def _parse_v9(
    data: bytes,
    template_cache: OrderedDict[int, list[tuple[int, int]]],
) -> list[dict[str, Any]]:
    """
    Parse NetFlow v9 template-based records.
    Very simplified — handles only basic template learning and data flowsets.

    NOTE(H6): ``template_cache`` is now an ``OrderedDict`` so we can
    LRU-evict the OLDEST entry when over capacity. The previous
    implementation kept the oldest and evicted newest, which is exactly
    backwards.
    """
    if len(data) < 20:
        return []

    version = struct.unpack_from("!H", data, 0)[0]
    if version != 9:
        return []

    flows = []
    struct.unpack_from("!H", data, 2)[0]
    offset = 20  # skip header

    while offset + 4 <= len(data):
        flowset_id, flowset_len = struct.unpack_from("!HH", data, offset)
        if flowset_len < 4:
            break
        flowset_data = data[offset + 4 : offset + flowset_len]
        offset += flowset_len

        if flowset_id == 0:
            # Template FlowSet — store template definitions
            fs_offset = 0
            while fs_offset + 4 <= len(flowset_data):
                tmpl_id, field_count = struct.unpack_from("!HH", flowset_data, fs_offset)
                fs_offset += 4
                fields = []
                for _ in range(field_count):
                    if fs_offset + 4 > len(flowset_data):
                        break
                    ftype, flen = struct.unpack_from("!HH", flowset_data, fs_offset)
                    fields.append((ftype, flen))
                    fs_offset += 4
                # Mark recently-used and store.
                template_cache.pop(tmpl_id, None)
                template_cache[tmpl_id] = fields
                # LRU eviction — pop OLDEST first (last=False).
                while len(template_cache) > _MAX_TEMPLATES_PER_SOURCE:
                    template_cache.popitem(last=False)
        elif flowset_id >= 256:
            # Data FlowSet — try to decode using cached template.
            tmpl = template_cache.get(flowset_id)
            if not tmpl:
                continue
            # Touch entry: move to MRU end so it survives eviction.
            template_cache.move_to_end(flowset_id, last=True)
            record_size = sum(f[1] for f in tmpl)
            if record_size == 0:
                continue
            fs_offset = 0
            while fs_offset + record_size <= len(flowset_data):
                record: dict[str, Any] = {}
                for ftype, flen in tmpl:
                    val = flowset_data[fs_offset : fs_offset + flen]
                    # Field types: 8=src_addr, 12=dst_addr, 7=src_port, 11=dst_port, 4=protocol, 1=bytes, 2=pkts
                    if ftype == 8 and flen == 4:
                        record["source_ip"] = socket.inet_ntoa(val)
                    elif ftype == 12 and flen == 4:
                        record["dest_ip"] = socket.inet_ntoa(val)
                    elif ftype == 7 and flen == 2:
                        record["source_port"] = struct.unpack("!H", val)[0]
                    elif ftype == 11 and flen == 2:
                        record["dest_port"] = struct.unpack("!H", val)[0]
                    elif ftype == 4 and flen == 1:
                        record["protocol"] = val[0]
                    elif ftype == 1:
                        record["bytes_in"] = int.from_bytes(val, "big")
                    elif ftype == 2:
                        record["packets"] = int.from_bytes(val, "big")
                    fs_offset += flen
                if "source_ip" in record:
                    record.setdefault("dest_ip", "0.0.0.0")
                    record.setdefault("source_port", None)
                    record.setdefault("dest_port", None)
                    record.setdefault("protocol", 0)
                    record.setdefault("bytes_in", 0)
                    record.setdefault("bytes_out", 0)
                    record.setdefault("packets", 0)
                    flows.append(record)

    return flows


class _NetFlowProtocol(asyncio.DatagramProtocol):
    def __init__(self, receiver: NetFlowReceiver) -> None:
        self._receiver = receiver

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        pass

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if len(self._receiver._pending) < self._receiver._max_pending:
            asyncio.create_task(self._receiver._handle(data, addr[0])).add_done_callback(
                _task_error_handler
            )
        else:
            self._receiver._dropped_packets += 1

    def error_received(self, exc: Exception) -> None:
        logger.warning("NetFlow UDP error: %s", exc)


class _FlowBatch:
    """Wrapper carrying a list of flow dicts plus a retry counter.

    NOTE(H2): The previous implementation called
    ``getattr(batch[0], '_retried', False)`` on a plain dict — which
    always returns False because ``getattr`` doesn't see dict keys.
    Encapsulating the retry count on a dedicated wrapper makes the
    re-queue logic correct (and unit-testable).
    """

    __slots__ = ("flows", "attempts")

    def __init__(self, flows: list[dict[str, Any]], attempts: int = 0) -> None:
        self.flows = flows
        self.attempts = attempts


class NetFlowReceiver:
    """asyncio UDP server for NetFlow v5/v9."""

    # NOTE(H7): max attempts before dropping a batch entirely.
    _MAX_BATCH_ATTEMPTS = 3

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 2055,
        session_factory: Callable[[], AsyncSession] | None = None,
        resolver: Any = None,
        allowlist: list[ipaddress._BaseNetwork] | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self._session_factory = session_factory
        self._resolver = resolver
        self._allowlist = allowlist or []
        self._transport: asyncio.DatagramTransport | None = None
        # NOTE(H6): partition templates per source IP so one chatty
        # exporter cannot evict another exporter's templates.
        self._templates_by_source: dict[str, OrderedDict[int, list[tuple[int, int]]]] = {}
        # Accumulate flows for batch insert: bucket_key -> list of flows
        self._pending: list[dict[str, Any]] = []
        self._pending_retry: list[_FlowBatch] = []
        # NOTE(H3): lock guards mutation of _pending / _pending_retry /
        # counters across concurrent receive coroutines.
        self._pending_lock = asyncio.Lock()
        self._max_pending: int = 100000
        self._dropped_packets: int = 0
        self._rejected_packets: int = 0
        self._dropped_unknown_source: int = 0
        self._flush_task: asyncio.Task[None] | None = None
        self._classifier: Any = None

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _NetFlowProtocol(self),
            local_addr=(self.host, self.port),
            reuse_port=hasattr(socket, "SO_REUSEPORT"),  # seamless rebind on reload
        )
        self._transport = transport
        self._flush_task = asyncio.create_task(self._flush_loop())
        logger.info("NetFlow receiver listening on %s:%s/udp", self.host, self.port)

        # Initialize DPI classifier
        try:
            from app.modules.collector.services.classifier import ApplicationClassifier

            self._classifier = ApplicationClassifier()
            if self._session_factory:
                async with self._session_factory() as db:
                    await self._classifier.load_rules(db)
                logger.info("DPI classifier loaded with %d rules", len(self._classifier._port_map))
        except Exception:
            logger.warning(
                "DPI classifier failed to load — flows will not be classified", exc_info=True
            )

    async def stop(self) -> None:
        if self._transport:
            self._transport.close()
            self._transport = None
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
            except Exception:
                logger.warning("flush task raised on shutdown", exc_info=True)

    def _get_source_templates(self, source_ip: str) -> OrderedDict[int, list[tuple[int, int]]]:
        """Return the per-source template cache, creating it on first use."""
        cache = self._templates_by_source.get(source_ip)
        if cache is None:
            cache = OrderedDict()
            self._templates_by_source[source_ip] = cache
            # Bound the number of distinct sources we track templates
            # for. 1024 sources × 256 templates is a hard upper bound.
            if len(self._templates_by_source) > 1024:
                # Drop the oldest source bucket.
                oldest = next(iter(self._templates_by_source))
                self._templates_by_source.pop(oldest, None)
        return cache

    async def _handle(self, data: bytes, source_ip: str) -> None:
        # NOTE(C3): allowlist guard before any parsing work.
        from app.modules.collector.services.manager import ip_allowed

        if not ip_allowed(source_ip, self._allowlist):
            self._rejected_packets += 1
            logger.info(
                "collector.netflow.rejected source_ip=%s reason=allowlist",
                source_ip,
            )
            return

        version = struct.unpack_from("!H", data, 0)[0] if len(data) >= 2 else 0
        if version == 5:
            flows = _parse_v5(data)
        elif version == 9:
            flows = _parse_v9(data, self._get_source_templates(source_ip))
        else:
            return

        if not flows:
            return

        # NOTE(C2): resolve source IP → (org_id, device_id). Drop the
        # entire packet if unmapped.
        org_id = None
        device_id = None
        if self._resolver is not None:
            resolved = await self._resolver.resolve(source_ip)
            if resolved is None:
                self._dropped_unknown_source += 1
                logger.info(
                    "collector.netflow.dropped source_ip=%s reason=unknown_source",
                    source_ip,
                )
                return
            org_id, device_id = resolved

        bucket = datetime.now(UTC).replace(second=0, microsecond=0)
        for f in flows:
            f["bucket_time"] = bucket
            f.setdefault("bytes_out", 0)
            if org_id is not None:
                f["organization_id"] = org_id
                f["device_id"] = device_id

        if self._classifier:
            for f in flows:
                proto = f.get("protocol", 0)
                dest_port = f.get("dest_port") or 0
                app_name, app_category = self._classifier.classify(proto, dest_port)
                if app_name:
                    f["app_name"] = app_name
                if app_category:
                    f["app_category"] = app_category

        # NOTE(H3): mutate _pending under the lock.
        async with self._pending_lock:
            self._pending.extend(flows)

    async def _flush_loop(self) -> None:
        """Bulk insert pending flows every 60 seconds.

        NOTE(H7): wrapped in try/finally so cancellation does NOT
        silently drop the in-memory batch. We do a final flush on the
        way out.
        """
        try:
            while True:
                await asyncio.sleep(60)
                await self._flush()
        except asyncio.CancelledError:
            # Re-raise after the final flush so the awaiter sees the
            # cancellation.
            await self._flush()
            raise
        finally:
            # Defensive: if we exited the loop for any other reason,
            # still attempt one last flush.
            try:
                await self._flush()
            except Exception:
                logger.warning("final flush failed", exc_info=True)

    async def _flush(self) -> None:
        """One pass of the flush loop — swaps _pending and persists."""
        if not self._session_factory:
            return

        # NOTE(H3): drain under lock so we never race a concurrent
        # ``.extend(...)`` from the receive path.
        async with self._pending_lock:
            if not self._pending and not self._pending_retry:
                return
            new_flows = self._pending[:]
            self._pending.clear()
            retry_batches = self._pending_retry[:]
            self._pending_retry.clear()

        batches: list[_FlowBatch] = list(retry_batches)
        if new_flows:
            batches.append(_FlowBatch(flows=new_flows, attempts=0))

        for batch in batches:
            await self._persist_batch(batch)

    async def _persist_batch(self, batch: _FlowBatch) -> None:
        try:
            from sqlalchemy.dialects.postgresql import insert

            from app.modules.collector.models import FlowRecord

            # Filter out internal keys before insert.
            clean_batch = [
                {k: v for k, v in f.items() if not k.startswith("_")} for f in batch.flows
            ]
            async with self._session_factory() as db:
                await db.execute(insert(FlowRecord).values(clean_batch))
                await db.commit()
            logger.debug("Flushed %d NetFlow records", len(batch.flows))
        except Exception as exc:
            batch.attempts += 1
            # NOTE(H2): retries tracked on the wrapper, not via
            # ``getattr`` on a dict (which always returned False).
            if batch.attempts < self._MAX_BATCH_ATTEMPTS:
                logger.warning(
                    "NetFlow flush failed (attempt %d/%d), re-queueing: %s",
                    batch.attempts,
                    self._MAX_BATCH_ATTEMPTS,
                    exc,
                )
                async with self._pending_lock:
                    self._pending_retry.append(batch)
            else:
                logger.error(
                    "Dropping %d NetFlow records after %d failed attempts: %s",
                    len(batch.flows),
                    batch.attempts,
                    exc,
                )
