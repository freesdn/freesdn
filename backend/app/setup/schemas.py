# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Setup Wizard Schemas
==================================

Pydantic schemas for setup wizard API.
All field names align with the ORM models in app.models.core.
"""

from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.core.security import validate_password as _validate_password

# ============================================================================
# Enums
# ============================================================================


class SetupStep(StrEnum):
    """Setup wizard steps."""

    NOT_STARTED = "not_started"
    WELCOME = "welcome"
    DATABASE = "database"
    ADMIN = "admin"
    ORGANIZATION = "organization"
    MODULES = "modules"
    CONTROLLERS = "controllers"
    COMPLETE = "complete"


# ============================================================================
# Status
# ============================================================================


class SetupStatus(BaseModel):
    """Current setup status."""

    is_complete: bool = False
    current_step: SetupStep = SetupStep.NOT_STARTED
    steps_completed: list[SetupStep] = Field(default_factory=list)
    message: str | None = None


# ============================================================================
# Step 1: Welcome
# ============================================================================


class SystemRequirement(BaseModel):
    """System requirement check result."""

    name: str
    required: str
    actual: str
    passed: bool
    message: str | None = None


class StackInfo(BaseModel):
    """Runtime dependency version info."""

    name: str
    version: str
    category: str  # "backend", "database", "infrastructure"


class DockerService(BaseModel):
    """Docker/compose service reachability info."""

    name: str
    host: str
    reachable: bool
    version: str | None = None


class WelcomeResponse(BaseModel):
    """Welcome step response."""

    app_name: str
    app_version: str
    environment: str = "development"
    requirements: list[SystemRequirement]
    all_requirements_met: bool
    can_proceed: bool
    stack_info: list[StackInfo] = Field(default_factory=list)
    docker_services: list[DockerService] = Field(default_factory=list)


# ============================================================================
# Step 2: Database
# ============================================================================


class DatabaseCheckResponse(BaseModel):
    """Database check response."""

    connected: bool
    database_type: str = "postgresql"
    database_version: str | None = None
    timescale_enabled: bool = False
    timescale_version: str | None = None
    timescale_location: str | None = None  # "main" | "logdb"
    logdb_connected: bool = False
    schema_current: bool = False
    migrations_pending: int = 0
    migrations_applied: int = 0
    error: str | None = None


# ============================================================================
# Step 3: Admin User
# ============================================================================


class AdminCreateRequest(BaseModel):
    """Create admin user request.

    Accepts first_name + last_name (concatenated to full_name) to match
    the User ORM model which stores ``full_name``.

    Atomic-org payload: callers MAY include ``organization_name`` (+
    optional slug/timezone/etc.) so the same transaction that creates
    the super_admin user also creates the first organization, default
    site, and the user→org membership link. Without this, the wizard
    would hit the ``require_setup_incomplete`` 403 gate on the
    follow-up ``/setup/organization`` request (the gate closes the
    moment the super_admin is created), and the admin would be left
    with ``organization_id=NULL`` — making every device-add flow
    fail. Fields are optional for backward compat; when present,
    the org is created in the same transaction as the user.
    """

    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=100)
    first_name: str = Field("", max_length=50)
    last_name: str = Field("", max_length=50)
    # Optional org bundle — when set, the admin endpoint creates the
    # org + default site + membership link atomically.
    organization_name: str | None = Field(None, min_length=2, max_length=100)
    organization_slug: str | None = Field(
        None, min_length=2, max_length=50, pattern=r"^[a-z0-9-]+$"
    )
    organization_timezone: str = "UTC"
    organization_locale: str = "en-US"

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _validate_password(v)


class AdminCreateResponse(BaseModel):
    """Admin creation response."""

    success: bool
    user_id: UUID | None = None
    email: str | None = None
    username: str | None = None
    # Populated when the request also created an org atomically.
    organization_id: UUID | None = None
    organization_slug: str | None = None
    default_site_id: UUID | None = None
    error: str | None = None


# ============================================================================
# Step 4: Organization
# ============================================================================


class OrganizationCreateRequest(BaseModel):
    """Create organization request.

    ``admin_id`` is the UUID returned by the admin creation step.
    The backend links the admin user to this organization.
    """

    name: str = Field(..., min_length=2, max_length=100)
    slug: str | None = Field(None, min_length=2, max_length=50, pattern=r"^[a-z0-9-]+$")
    timezone: str = "UTC"
    locale: str = "en-US"
    time_format: str = Field("24h", pattern=r"^(12h|24h)$")
    date_format: str = Field(
        "YYYY-MM-DD", pattern=r"^(YYYY-MM-DD|MM/DD/YYYY|DD/MM/YYYY|DD\.MM\.YYYY)$"
    )
    admin_id: UUID | None = None


class OrganizationCreateResponse(BaseModel):
    """Organization creation response."""

    success: bool
    organization_id: UUID | None = None
    site_id: UUID | None = None
    name: str | None = None
    slug: str | None = None
    error: str | None = None


# ============================================================================
# Step 5: Modules
# ============================================================================


class ModuleOption(BaseModel):
    """Available module for selection."""

    id: str
    name: str
    description: str
    category: str
    recommended: bool = False
    requires: list[str] = Field(default_factory=list)


class ModuleSelectionRequest(BaseModel):
    """Module selection request."""

    enabled_modules: list[str]
    organization_id: UUID


class ModuleSelectionResponse(BaseModel):
    """Module selection response."""

    success: bool
    enabled_modules: list[str] = Field(default_factory=list)
    error: str | None = None


# ============================================================================
# Step 6: Controllers (Optional)
# ============================================================================


class ControllerTypeInfo(BaseModel):
    """Available controller type."""

    adapter_id: str
    name: str
    vendor: str
    description: str
    requires_controller: bool
    icon: str | None = None


class ControllerAddRequest(BaseModel):
    """Add controller request."""

    adapter_id: str
    name: str = Field(..., min_length=1, max_length=100)
    host: str = Field(..., min_length=1, max_length=500)
    port: int = 443
    username: str
    password: str
    verify_ssl: bool = False
    site_id: UUID | None = None
    connection_mode: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    omada_id: str | None = None
    cloud_region: str | None = None
    site_mappings: dict[str, str] | None = None


class ControllerTestResult(BaseModel):
    """Controller connection test result."""

    success: bool
    adapter_id: str
    host: str
    message: str | None = None
    devices_found: int = 0
    error: str | None = None


class ControllerAddResponse(BaseModel):
    """Controller add response."""

    success: bool
    controller_id: UUID | None = None
    test_result: ControllerTestResult | None = None
    error: str | None = None


# ============================================================================
# Step 7: Complete
# ============================================================================


class SetupSummary(BaseModel):
    """Setup summary."""

    admin_email: str
    organization_name: str
    enabled_modules: list[str]
    controllers_added: int
    total_devices: int


class SetupCompleteRequest(BaseModel):
    """Complete setup request."""

    install_sample_data: bool = False
    organization_id: UUID | None = None
    site_id: UUID | None = None
    start_discovery: bool = True
    send_welcome_email: bool = False


class SetupCompleteResponse(BaseModel):
    """Setup complete response."""

    success: bool
    summary: SetupSummary | None = None
    sample_data: "SampleDataResponse | None" = None
    login_url: str | None = None
    error: str | None = None


# ============================================================================
# Sample Data
# ============================================================================


class SampleDataRequest(BaseModel):
    """Install sample data request."""

    organization_id: UUID
    site_id: UUID


class SampleDataResponse(BaseModel):
    """Sample data installation response."""

    success: bool
    devices_created: int = 0
    vlans_created: int = 0
    wifi_networks_created: int = 0
    clients_created: int = 0
    alerts_created: int = 0
    events_created: int = 0
    audit_logs_created: int = 0
    incidents_created: int = 0
    backups_created: int = 0
    firmware_images_created: int = 0
    message: str | None = None
    error: str | None = None
