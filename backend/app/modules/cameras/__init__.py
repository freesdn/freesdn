# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN Cameras Module
======================

Video surveillance functionality including:
- Camera management (IP cameras, NVRs)
- Live streaming
- Recording playback
- PTZ control
- Motion detection events
- Snapshot capture
"""

from app.modules.cameras.module import CamerasModule
from app.modules.cameras.service import (
    CameraError,
    CameraEventService,
    CameraNotFoundError,
    CameraService,
    NVRNotFoundError,
    NVRService,
    PTZService,
    RecordingError,
    RecordingService,
    StreamError,
    StreamService,
)

__all__ = [
    "CamerasModule",
    # Services
    "CameraService",
    "StreamService",
    "RecordingService",
    "NVRService",
    "PTZService",
    "CameraEventService",
    # Exceptions
    "CameraError",
    "StreamError",
    "RecordingError",
    "CameraNotFoundError",
    "NVRNotFoundError",
]
