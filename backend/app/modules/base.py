# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Module Base Classes
=================================

Base classes and interfaces for building FreeSDN modules.

A module must:
1. Define a manifest with metadata
2. Implement the BaseModule interface
3. Register its API routes
4. Define its database models (if any)
"""

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import UUID

from fastapi import APIRouter

if TYPE_CHECKING:
    from app.modules.manifest import ModuleManifest

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.core.fabric.operations import EventSpec, Operation
    from app.services.backup_contributors import BackupContributor


# ===========================================
# Device Source Contract
# ===========================================


@dataclass
class DeviceSource:
    """Declarative descriptor: how a module's device model maps to core Device.

    Modules return a list of these from ``get_device_sources()``. The sync
    engine uses the descriptor to batch-upsert shadow rows into the core
    ``devices.devices`` table.
    """

    # Source model (SQLAlchemy declarative class)
    model: type
    # Core device type: "nvr", "voip_phone", "firewall", etc.
    device_type: str
    # Prefix for external_id values: "nvr", "gateway", etc.
    external_id_prefix: str

    # Field mapping: {Device column → source model attribute}
    field_map: dict[str, str] = field(
        default_factory=lambda: {
            "name": "name",
            "manufacturer": "vendor",
            "model": "model",
            "firmware_version": "firmware_version",
            "ip_address": "ip_address",
            "mac_address": "mac_address",
            "serial_number": "serial_number",
            "last_seen": "last_seen",
            "site_id": "site_id",
        }
    )

    # Status resolution
    status_map: dict[str, str] = field(default_factory=dict)
    default_status: str = "unknown"
    status_is_boolean: bool = False
    status_field: str = "status"

    # Defaults
    default_manufacturer: str = "Unknown"

    # Callables for complex field resolution
    name_resolver: Callable[..., Any] | None = None
    site_id_resolver: Callable[..., Any] | None = None

    # Soft-delete filter column (set None to skip)
    soft_delete_column: str | None = "deleted_at"

    # Device count cap per source (plugins enforced at 1,000)
    max_devices: int = 10_000


class ModuleState(StrEnum):
    """Module lifecycle state."""

    UNLOADED = "unloaded"  # Not yet loaded
    LOADING = "loading"  # Currently loading
    LOADED = "loaded"  # Loaded but not started
    STARTING = "starting"  # Currently starting
    RUNNING = "running"  # Fully operational
    STOPPING = "stopping"  # Currently stopping
    STOPPED = "stopped"  # Stopped but loaded
    ERROR = "error"  # Error state
    DISABLED = "disabled"  # Administratively disabled


class ModuleCapability(StrEnum):
    """
    Standard capabilities a module can provide.

    These are used for:
    - Feature detection
    - Permission scoping
    - UI component loading
    """

    # General Capabilities
    DEVICE_MANAGEMENT = "device_management"
    NETWORK_DISCOVERY = "network_discovery"
    TOPOLOGY_MAPPING = "topology_mapping"
    DEVICE_BACKUP = "device_backup"
    BULK_OPERATIONS = "bulk_operations"
    TRAFFIC_ANALYTICS = "traffic_analytics"

    # Network Module Capabilities
    VLAN_MANAGEMENT = "vlan_management"
    WIFI_MANAGEMENT = "wifi_management"
    SWITCH_MANAGEMENT = "switch_management"
    POE_MANAGEMENT = "poe_management"
    POE_CONTROL = "poe_control"
    PORT_MANAGEMENT = "port_management"
    ROUTER_MANAGEMENT = "router_management"
    NAC_802_1X = "nac_802_1x"
    TOPOLOGY_VIEW = "topology_view"

    # Camera Module Capabilities
    CAMERA_LIVE_VIEW = "camera_live_view"
    CAMERA_PLAYBACK = "camera_playback"
    CAMERA_PTZ = "camera_ptz"
    CAMERA_EVENTS = "camera_events"
    NVR_MANAGEMENT = "nvr_management"

    # VoIP Module Capabilities
    PHONE_MANAGEMENT = "phone_management"
    PBX_MANAGEMENT = "pbx_management"
    CALL_LOGS = "call_logs"
    EXTENSIONS = "extensions"
    RING_GROUPS = "ring_groups"

    # Access Control Capabilities
    DOOR_MANAGEMENT = "door_management"
    CARD_MANAGEMENT = "card_management"
    ACCESS_SCHEDULES = "access_schedules"
    ACCESS_EVENTS = "access_events"

    # Firewall Module Capabilities
    FIREWALL_RULES = "firewall_rules"
    NAT_MANAGEMENT = "nat_management"
    VPN_MANAGEMENT = "vpn_management"
    IDS_IPS = "ids_ips"

    # Gateway Orchestration Capabilities
    GATEWAY_ORCHESTRATION = "gateway_orchestration"
    VLAN_DISTRIBUTION = "vlan_distribution"
    SITE_ROLE_MAP = "site_role_map"
    DRIFT_DETECTION = "drift_detection"
    BROWNFIELD_IMPORT = "brownfield_import"

    # Backup Module Capabilities
    BACKUP_CREATE = "backup_create"
    BACKUP_RESTORE = "backup_restore"
    BACKUP_SCHEDULE = "backup_schedule"
    BACKUP_CLOUD = "backup_cloud"

    # Automation Module Capabilities
    AUTOMATION_RULES = "automation_rules"
    AUTOMATION_TRIGGERS = "automation_triggers"
    AUTOMATION_ACTIONS = "automation_actions"
    AUTOMATION_SCHEDULES = "automation_schedules"


class BaseModule(ABC):
    """
    Base class for all FreeSDN modules.

    Modules must implement this interface to be loaded by the module system.

    Lifecycle:
        1. __init__() - Called when module is instantiated
        2. on_load() - Called when module is loaded into registry
        3. on_start() - Called when module is started for an organization
        4. on_stop() - Called when module is stopped for an organization
        5. on_unload() - Called when module is unloaded

    Example:
        class NetworkModule(BaseModule):
            @property
            def manifest(self) -> ModuleManifest:
                return ModuleManifest(
                    id="network",
                    name="Network Management",
                    ...
                )

            def get_router(self) -> APIRouter:
                from app.modules.network.api import router
                return router
    """

    def __init__(self) -> None:
        """Initialize the module."""
        self._state = ModuleState.UNLOADED
        self._error: str | None = None
        self._started_orgs: set[UUID] = set()

    @property
    @abstractmethod
    def manifest(self) -> "ModuleManifest":
        """
        Return the module manifest with metadata.

        Must be implemented by each module.
        """
        ...

    @property
    def id(self) -> str:
        """Module identifier (shortcut to manifest.id)."""
        return str(self.manifest.id)

    @property
    def name(self) -> str:
        """Module name (shortcut to manifest.name)."""
        return str(self.manifest.name)

    @property
    def state(self) -> ModuleState:
        """Current module state."""
        return self._state

    @property
    def error(self) -> str | None:
        """Error message if in error state."""
        return self._error

    @abstractmethod
    def get_router(self) -> APIRouter:
        """
        Return the FastAPI router for this module's API endpoints.

        The router will be mounted at /api/v1/{module_id}/

        Returns:
            FastAPI APIRouter with module endpoints
        """
        ...

    def get_models(self) -> list[type]:
        """
        Return SQLAlchemy models defined by this module.

        These will be used for:
        - Automatic table creation
        - Migration generation
        - Schema introspection

        Returns:
            List of SQLAlchemy model classes
        """
        return []

    def get_tasks(self) -> dict[str, Callable[..., Any]]:
        """
        Return Celery tasks defined by this module.

        Format: {"task_name": task_function}

        Returns:
            Dictionary of task name to task function
        """
        return {}

    async def pre_device_sync(self, session: Any) -> None:  # noqa: B027
        """Optional hook called before reading device sources during sync.

        Override to refresh module-managed tables from external systems
        (e.g., fetching Proxmox nodes from the API) so that
        ``get_device_sources()`` returns up-to-date data.
        """

    def get_device_sources(self) -> list["DeviceSource"]:
        """Return device sources this module manages.

        Override to declare module device models that should be synced
        into the core ``devices.devices`` table by the DeviceSyncService.
        """
        return []

    def get_event_handlers(self) -> dict[str, Callable[..., Any]]:
        """
        Return event handlers for the event bus.

        Format: {"event_type": handler_function}

        Returns:
            Dictionary of event type to handler function
        """
        return {}

    def get_backup_contributor(self) -> "BackupContributor | None":
        """Return this module's backup/restore contributor, or None.

        Override to declare how this module's tables are exported into
        the portable ``.fsdn`` configuration archive and restored from
        it. The contributor is discovered by the BackupService via
        ``BackupContributorRegistry.discover_from_modules()`` — module
        authors don't need any central registration code.

        See ``app/services/backup_contributors/protocol.py`` for the
        ``BackupContributor`` protocol and
        ``app/services/backup_contributors/core.py`` for a reference
        implementation. Returning None (the default) means the module's
        data is NOT included in the configuration backup — appropriate
        for modules whose state is transient (e.g. call logs) or
        instance-tied (e.g. plugin install state).
        """
        return None

    def get_operations(self) -> list["Operation"]:
        """Return the Fabric operations (callable capabilities) this module
        provides.

        Part of the FreeSDN Fabric — the app-agnostic interconnect. Each
        ``Operation`` is the single, normalized representation of "a thing this
        app can do" (modeled on the AI tool shape + the staged-write binding):
        an id, a JSON-Schema input, produced/accepted media-types, the required
        permission, and — for device writes — the staging ``feature`` it routes
        through. The :class:`~app.core.fabric.registry.FabricRegistry` discovers
        these from every module (no central registration, same pattern as
        ``get_backup_contributor()``) and projects them to every consumer (AI
        tools, automation actions, the negotiator).

        Native-module operations are full-trust and use the ``{module}.*``
        namespace. Returning ``[]`` (the default) means this module contributes
        no operations yet — purely additive, nothing breaks.
        """
        return []

    def get_emitted_events(self) -> list["EventSpec"]:
        """Return the Fabric event sources (triggers) this module emits.

        Declares, in catalog form, the events this module publishes on the bus
        so the Fabric negotiator can offer them as wiring sources. Returning
        ``[]`` (the default) means the module declares no event catalog yet.
        """
        return []

    async def on_load(self) -> None:
        """
        Called when the module is loaded into the registry.

        Use this for:
        - Registering event handlers
        - Initializing module-level state
        - Validating configuration

        Raises:
            ModuleLoadError: If loading fails
        """
        self._state = ModuleState.LOADED

    async def on_unload(self) -> None:
        """
        Called when the module is unloaded from the registry.

        Use this for:
        - Cleanup resources
        - Unregistering event handlers
        """
        self._state = ModuleState.UNLOADED

    async def on_start(self, organization_id: UUID, db: "AsyncSession") -> None:
        """
        Called when the module is started for an organization.

        Use this for:
        - Organization-specific initialization
        - Starting background tasks
        - Loading organization settings

        Args:
            organization_id: The organization enabling this module
            db: Database session for initialization queries
        """
        self._started_orgs.add(organization_id)
        if self._state != ModuleState.RUNNING:
            self._state = ModuleState.RUNNING

    async def on_stop(self, organization_id: UUID, db: "AsyncSession") -> None:
        """
        Called when the module is stopped for an organization.

        Use this for:
        - Organization-specific cleanup
        - Stopping background tasks
        - Saving state

        Args:
            organization_id: The organization disabling this module
            db: Database session for cleanup queries
        """
        self._started_orgs.discard(organization_id)
        if not self._started_orgs:
            self._state = ModuleState.STOPPED

    def is_started_for(self, organization_id: UUID) -> bool:
        """Check if module is started for a specific organization."""
        return organization_id in self._started_orgs

    def set_error(self, error: str) -> None:
        """Set module to error state with message."""
        self._state = ModuleState.ERROR
        self._error = error

    def clear_error(self) -> None:
        """Clear error state."""
        self._error = None
        if self._state == ModuleState.ERROR:
            self._state = ModuleState.LOADED

    def get_settings_schema(self) -> dict[str, Any] | None:
        """
        Return JSON Schema for module settings.

        Used to validate module settings when they are saved.

        Returns:
            JSON Schema dict or None if no settings
        """
        return None

    def get_default_settings(self) -> dict[str, Any]:
        """
        Return default settings for this module.

        Returns:
            Dictionary of default setting values
        """
        return {}

    async def validate_settings(
        self,
        settings: dict[str, Any],
        organization_id: UUID,
    ) -> tuple[bool, list[str]]:
        """
        Validate module settings.

        Override for custom validation beyond JSON Schema.

        Args:
            settings: Settings to validate
            organization_id: Organization the settings are for

        Returns:
            Tuple of (is_valid, error_messages)
        """
        return True, []

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}({self.id}, state={self.state})>"


class ModuleLoadError(Exception):
    """Raised when a module fails to load."""

    def __init__(self, module_id: str, message: str):
        self.module_id = module_id
        self.message = message
        super().__init__(f"Failed to load module '{module_id}': {message}")


class ModuleNotFoundError(Exception):
    """Raised when a module is not found."""

    def __init__(self, module_id: str):
        self.module_id = module_id
        super().__init__(f"Module '{module_id}' not found")


class ModuleNotEnabledError(Exception):
    """Raised when trying to use a module that is not enabled."""

    def __init__(self, module_id: str, organization_id: UUID):
        self.module_id = module_id
        self.organization_id = organization_id
        super().__init__(f"Module '{module_id}' is not enabled for organization {organization_id}")
