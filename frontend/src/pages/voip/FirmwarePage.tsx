// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · VoIP Firmware Redirect
 *
 * VoIP firmware is now managed through the unified Firmware page.
 * This component redirects to /firmware?device_type=voip_phone.
 */

import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

export default function FirmwarePage() {
  const navigate = useNavigate();

  useEffect(() => {
    // Guard: only redirect while we are still on the legacy /voip/firmware
    // route. Without this, an exiting page kept alive by
    // <AnimatePresence mode="wait"> can re-trigger the redirect mid-transition.
    if (!window.location.pathname.startsWith('/voip/firmware')) return;
    navigate('/firmware?device_type=voip_phone', { replace: true });
  }, [navigate]);

  return null;
}
