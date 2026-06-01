# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN Storage module — TrueNAS as a first-class Fabric participant.

A thin module (no tables, no HTTP routes — live storage reads already live under
``/controllers/{id}/storage``) whose job is to declare the storage **Fabric**
surface: a ``storage.health`` read and a ``storage.store_blob`` staged write, so
an operator can wire "on <event> → store this on TrueNAS" as configuration.
"""
