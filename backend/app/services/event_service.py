# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Event Service
===========================

Service for managing event history, persistence, and replay.
"""

import asyncio
import logging
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import and_, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.events import Event, EventBus, EventCategory, EventPriority, event_bus
from app.models.events import EventRecord, EventSubscription
from app.schemas.core import PaginatedResponse

logger = logging.getLogger(__name__)


class EventService:
    """
    Service for managing event history and replay.

    Features:
    - Persist events to database
    - Query event history
    - Replay events
    - Manage subscriptions
    """

    def __init__(self, session: AsyncSession, bus: EventBus | None = None):
        self.session = session
        self.bus = bus or event_bus

    # =========================================
    # Event Persistence
    # =========================================

    async def persist_event(
        self,
        event: Event,
        organization_id: UUID | None = None,
        site_id: UUID | None = None,
        user_id: UUID | None = None,
    ) -> EventRecord:
        """
        Persist an event to the database.

        Args:
            event: Event to persist
            organization_id: Organization context
            site_id: Site context
            user_id: Acting user

        Returns:
            Created EventRecord
        """
        record = EventRecord(
            id=UUID(event.id) if isinstance(event.id, str) else event.id,
            event_type=event.event_type,
            category=EventCategory(event.category.value),
            priority=EventPriority(event.priority.value),
            payload=event.payload,
            event_meta=event.metadata,
            source=event.source,
            correlation_id=UUID(event.correlation_id) if event.correlation_id else None,
            causation_id=UUID(event.causation_id) if event.causation_id else None,
            organization_id=organization_id,
            site_id=site_id,
            user_id=user_id,
            timestamp=event.timestamp,
        )

        self.session.add(record)
        await self.session.flush()

        return record

    async def publish_and_persist(
        self,
        event: Event,
        organization_id: UUID | None = None,
        site_id: UUID | None = None,
        user_id: UUID | None = None,
    ) -> EventRecord:
        """
        Publish an event to the bus and persist to database.

        Args:
            event: Event to publish and persist
            organization_id: Organization context
            site_id: Site context
            user_id: Acting user

        Returns:
            Created EventRecord
        """
        # Persist first
        record = await self.persist_event(
            event,
            organization_id=organization_id,
            site_id=site_id,
            user_id=user_id,
        )

        # Then publish
        await self.bus.publish(event)

        return record

    # =========================================
    # Event History Queries
    # =========================================

    async def get_events(
        self,
        organization_id: UUID | None = None,
        site_id: UUID | None = None,
        event_type: str | None = None,
        category: EventCategory | None = None,
        correlation_id: UUID | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        page: int = 1,
        per_page: int = 50,
        accessible_site_ids: set[UUID] | None = None,
    ) -> PaginatedResponse[dict]:
        """
        Query event history with filters.

        Args:
            organization_id: Filter by organization
            site_id: Filter by site
            event_type: Filter by event type (supports wildcards with %)
            category: Filter by category
            correlation_id: Filter by correlation ID
            start_time: Events after this time
            end_time: Events before this time
            page: Page number
            per_page: Items per page
            accessible_site_ids: When the caller is a site-limited user, the set
                of site IDs they were granted. ``None`` = unrestricted (super /
                org admin). A site-limited row with a NULL ``site_id`` is an
                org-level event still visible to any org member.

        Returns:
            Paginated list of events
        """
        query = select(EventRecord).order_by(desc(EventRecord.timestamp))
        count_query = select(func.count(EventRecord.id))

        # Apply filters
        filters = []

        if organization_id:
            filters.append(EventRecord.organization_id == organization_id)
        if site_id:
            filters.append(EventRecord.site_id == site_id)
        # a site-limited caller may only see events for granted
        # sites (or org-level events with NULL site_id). Fail-closed: an empty
        # grant set matches only the NULL-site org-level rows, never all-org.
        if accessible_site_ids is not None:
            filters.append(
                or_(
                    EventRecord.site_id.is_(None),
                    EventRecord.site_id.in_(list(accessible_site_ids)),
                )
            )
        if event_type:
            if "%" in event_type or "*" in event_type:
                pattern = event_type.replace("*", "%")
                filters.append(EventRecord.event_type.like(pattern))
            else:
                filters.append(EventRecord.event_type == event_type)
        if category:
            filters.append(EventRecord.category == category)
        if correlation_id:
            filters.append(EventRecord.correlation_id == correlation_id)
        if start_time:
            filters.append(EventRecord.timestamp >= start_time)
        if end_time:
            filters.append(EventRecord.timestamp <= end_time)

        if filters:
            query = query.where(and_(*filters))
            count_query = count_query.where(and_(*filters))

        # Get total count
        result = await self.session.execute(count_query)
        total = result.scalar() or 0

        # Apply pagination
        offset = (page - 1) * per_page
        query = query.offset(offset).limit(per_page)

        # Execute query
        result = await self.session.execute(query)
        records = result.scalars().all()

        return PaginatedResponse.create(
            items=[r.to_dict() for r in records],
            total=total,
            page=page,
            per_page=per_page,
        )

    async def get_event_by_id(self, event_id: UUID) -> EventRecord | None:
        """Get a single event by ID."""
        result = await self.session.execute(select(EventRecord).where(EventRecord.id == event_id))
        return result.scalar_one_or_none()

    async def get_correlation_chain(
        self,
        correlation_id: UUID,
        organization_id: UUID | None = None,
        accessible_site_ids: set[UUID] | None = None,
    ) -> list[dict]:
        """
        Get all events in a correlation chain.

        Returns events ordered by timestamp.

        Args:
            correlation_id: Correlation chain to fetch.
            organization_id: Filter to organization.
            accessible_site_ids: Site-grant for a site-limited caller.
                ``None`` = unrestricted. Org-level events (NULL site_id) stay
                visible to any org member.
        """
        query = (
            select(EventRecord)
            .where(EventRecord.correlation_id == correlation_id)
            .order_by(EventRecord.timestamp)
        )
        if organization_id:
            query = query.where(EventRecord.organization_id == organization_id)
        if accessible_site_ids is not None:
            query = query.where(
                or_(
                    EventRecord.site_id.is_(None),
                    EventRecord.site_id.in_(list(accessible_site_ids)),
                )
            )
        result = await self.session.execute(query)
        return [r.to_dict() for r in result.scalars().all()]

    async def get_event_stats(
        self,
        organization_id: UUID | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        accessible_site_ids: set[UUID] | None = None,
    ) -> dict:
        """
        Get event statistics.

        Returns counts by category and event type.

        Args:
            organization_id: Filter to organization.
            start_time: Stats window start.
            end_time: Stats window end.
            accessible_site_ids: Site-grant for a site-limited caller.
                ``None`` = unrestricted. Org-level events (NULL site_id) are
                still counted for any org member.
        """
        base_filters = []
        if organization_id:
            base_filters.append(EventRecord.organization_id == organization_id)
        if start_time:
            base_filters.append(EventRecord.timestamp >= start_time)
        if end_time:
            base_filters.append(EventRecord.timestamp <= end_time)
        if accessible_site_ids is not None:
            base_filters.append(
                or_(
                    EventRecord.site_id.is_(None),
                    EventRecord.site_id.in_(list(accessible_site_ids)),
                )
            )

        # Count by category
        category_query = select(
            EventRecord.category, func.count(EventRecord.id).label("count")
        ).group_by(EventRecord.category)
        if base_filters:
            category_query = category_query.where(and_(*base_filters))

        result = await self.session.execute(category_query)
        by_category = {row.category.value: row.count for row in result}

        # Top event types
        type_query = (
            select(EventRecord.event_type, func.count(EventRecord.id).label("count"))
            .group_by(EventRecord.event_type)
            .order_by(desc("count"))
            .limit(20)
        )
        if base_filters:
            type_query = type_query.where(and_(*base_filters))

        result = await self.session.execute(type_query)
        by_type = {row.event_type: row.count for row in result}

        # Total count
        total_query = select(func.count(EventRecord.id))
        if base_filters:
            total_query = total_query.where(and_(*base_filters))
        result = await self.session.execute(total_query)
        total = result.scalar() or 0

        return {
            "total": total,
            "by_category": by_category,
            "by_type": by_type,
        }

    # =========================================
    # Event Replay
    # =========================================

    async def replay_events(
        self,
        start_time: datetime,
        end_time: datetime | None = None,
        event_types: list[str] | None = None,
        organization_id: UUID | None = None,
        batch_size: int = 100,
        delay_ms: int = 0,
        max_events: int | None = None,
        accessible_site_ids: set[UUID] | None = None,
    ) -> AsyncGenerator[Event]:
        """
        Replay events from history.

        Yields events in chronological order for re-processing.

        Args:
            start_time: Start of replay window
            end_time: End of replay window (default: now)
            event_types: Filter to specific event types
            organization_id: Filter to organization
            batch_size: Number of events to fetch per batch
            delay_ms: Delay between events in milliseconds
            accessible_site_ids: Site-grant for a site-limited caller.
                ``None`` = unrestricted. Org-level (NULL site_id) events are
                still replayable by any org member.

        Yields:
            Events in chronological order
        """
        end_time = end_time or datetime.now(UTC)

        query = (
            select(EventRecord)
            .where(EventRecord.timestamp >= start_time)
            .where(EventRecord.timestamp <= end_time)
            .order_by(EventRecord.timestamp)
        )

        if event_types:
            type_filters = []
            for et in event_types:
                if "%" in et or "*" in et:
                    type_filters.append(EventRecord.event_type.like(et.replace("*", "%")))
                else:
                    type_filters.append(EventRecord.event_type == et)
            query = query.where(or_(*type_filters))

        if organization_id:
            query = query.where(EventRecord.organization_id == organization_id)

        if accessible_site_ids is not None:
            query = query.where(
                or_(
                    EventRecord.site_id.is_(None),
                    EventRecord.site_id.in_(list(accessible_site_ids)),
                )
            )

        offset = 0
        emitted = 0
        while True:
            batch_query = query.offset(offset).limit(batch_size)
            result = await self.session.execute(batch_query)
            records = result.scalars().all()

            if not records:
                break

            for record in records:
                # hard ceiling on how many events one replay can
                # re-publish, so a request can't fan the org's entire history
                # into the shared event bus / WS broadcast / Redis pub-sub.
                if max_events is not None and emitted >= max_events:
                    logger.warning("Replay hit max_events cap (%s) — truncating", max_events)
                    return
                event = Event(
                    id=str(record.id),
                    event_type=record.event_type,
                    payload=record.payload,
                    category=record.category,
                    priority=record.priority,
                    source=record.source,
                    correlation_id=str(record.correlation_id) if record.correlation_id else None,
                    causation_id=str(record.causation_id) if record.causation_id else None,
                    metadata={**record.event_meta, "replayed": True},
                    timestamp=record.timestamp,
                )
                yield event
                emitted += 1

                if delay_ms > 0:
                    await asyncio.sleep(delay_ms / 1000)

            offset += batch_size

    async def replay_and_publish(
        self,
        start_time: datetime,
        end_time: datetime | None = None,
        event_types: list[str] | None = None,
        organization_id: UUID | None = None,
        delay_ms: int = 100,
        max_events: int | None = None,
        accessible_site_ids: set[UUID] | None = None,
    ) -> int:
        """
        Replay events and publish to the event bus.

        Returns the number of events replayed.
        """
        count = 0
        async for event in self.replay_events(
            start_time=start_time,
            end_time=end_time,
            event_types=event_types,
            organization_id=organization_id,
            delay_ms=delay_ms,
            max_events=max_events,
            accessible_site_ids=accessible_site_ids,
        ):
            await self.bus.publish(event)
            count += 1

            if count % 100 == 0:
                logger.info("Replayed %s events...", count)

        logger.info("Replay complete: %s events", count)
        return count

    # =========================================
    # Subscription Management
    # =========================================

    @staticmethod
    def _subscription_visible_to_grant(
        sub_site_ids: list[str] | None, accessible_site_ids: set[UUID] | None
    ) -> bool:
        """whether a site-limited caller may see/touch a sub.

        ``accessible_site_ids`` is ``None`` for unrestricted (super / org
        admin) callers — everything is visible. For a site-limited caller a
        subscription is visible ONLY when it targets at least one granted site.

        an org-level subscription (no ``site_ids``) fans out events
        for EVERY site in the org — including sibling sites the caller cannot
        access — so it is NOT visible to a site-limited member (org-level subs
        are admin-only). This fails closed: a site-limited member sees neither
        org-level subs nor sibling-only subs, only subs scoped to a granted site.
        """
        if accessible_site_ids is None:
            return True
        if not sub_site_ids:
            # Org-level subscription — admin-only; hidden from a site-limited
            # member who must never receive org-wide (sibling-site) event fanout.
            return False
        granted = {str(s) for s in accessible_site_ids}
        return any(str(sid) in granted for sid in sub_site_ids)

    async def create_subscription(
        self,
        name: str,
        pattern: str,
        target_type: str,
        target_url: str | None = None,
        target_config: dict | None = None,
        organization_id: UUID | None = None,
        site_ids: list[UUID] | None = None,
    ) -> EventSubscription:
        """Create a new event subscription."""
        subscription = EventSubscription(
            name=name,
            pattern=pattern,
            target_type=target_type,
            target_url=target_url,
            target_config=target_config or {},
            organization_id=organization_id,
            site_ids=[str(s) for s in site_ids] if site_ids else None,
        )

        self.session.add(subscription)
        await self.session.flush()

        return subscription

    async def get_subscriptions(
        self,
        organization_id: UUID | None = None,
        is_active: bool | None = None,
        accessible_site_ids: set[UUID] | None = None,
    ) -> list[EventSubscription]:
        """Get event subscriptions.

        ``accessible_site_ids``: when a site-limited caller's grant set is
        supplied, only org-level subscriptions and subscriptions targeting a
        granted site are returned. ``None`` = unrestricted.
        """
        query = select(EventSubscription)

        if organization_id:
            query = query.where(EventSubscription.organization_id == organization_id)
        if is_active is not None:
            query = query.where(EventSubscription.is_active == is_active)

        result = await self.session.execute(query)
        subscriptions = list(result.scalars().all())

        if accessible_site_ids is not None:
            subscriptions = [
                s
                for s in subscriptions
                if self._subscription_visible_to_grant(s.site_ids, accessible_site_ids)
            ]
        return subscriptions

    async def update_subscription(
        self,
        subscription_id: UUID,
        organization_id: UUID | None = None,
        accessible_site_ids: set[UUID] | None = None,
        **updates,
    ) -> EventSubscription | None:
        """Update an event subscription.

        ``accessible_site_ids``: when supplied (site-limited caller), a
        subscription scoped to ONLY sibling sites is treated as not-found (404
        via the endpoint's None check) — the caller may not retarget or mutate
        another site's subscription.
        """
        query = select(EventSubscription).where(EventSubscription.id == subscription_id)
        if organization_id:
            query = query.where(EventSubscription.organization_id == organization_id)
        result = await self.session.execute(query)
        subscription = result.scalar_one_or_none()

        if subscription and accessible_site_ids is not None:
            if not self._subscription_visible_to_grant(subscription.site_ids, accessible_site_ids):
                return None

        if subscription:
            for key, value in updates.items():
                if hasattr(subscription, key):
                    setattr(subscription, key, value)
            await self.session.flush()

        return subscription

    async def delete_subscription(
        self,
        subscription_id: UUID,
        organization_id: UUID | None = None,
        accessible_site_ids: set[UUID] | None = None,
    ) -> bool:
        """Delete an event subscription.

        ``accessible_site_ids``: a site-limited caller may not delete a
        subscription scoped to ONLY sibling sites — treated as not-found.
        """
        query = select(EventSubscription).where(EventSubscription.id == subscription_id)
        if organization_id:
            query = query.where(EventSubscription.organization_id == organization_id)
        result = await self.session.execute(query)
        subscription = result.scalar_one_or_none()

        if subscription and accessible_site_ids is not None:
            if not self._subscription_visible_to_grant(subscription.site_ids, accessible_site_ids):
                return False

        if subscription:
            await self.session.delete(subscription)
            return True
        return False
