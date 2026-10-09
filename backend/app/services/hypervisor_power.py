# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Compatibility import for the original power-intent service.

The shared lifecycle service retains the same request namespace and claim rules.
"""

from app.services.hypervisor_operations import HypervisorOperationService

HypervisorPowerService = HypervisorOperationService
