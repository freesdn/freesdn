# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Gateway & Routing Module
========================================

Cross-device orchestration: Site Role Map, VLAN distribution,
DHCP/DNS coordination, drift detection, brownfield import.

The Gateway module enhances the Network module by adding multi-device
coordination.  It does NOT manage firewall rules — it reads them from
the "brain" device for dashboard display and writes only the narrow
set of orchestration items (VLAN interfaces, DHCP scopes, DNS records,
address groups).
"""

from app.modules.gateway.module import GatewayModule

__all__ = ["GatewayModule"]
