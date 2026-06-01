// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
// Demo mode is baked in at BUILD time. `npm run build:demo` runs
// `vite build --mode demo`, which loads `.env.demo` (VITE_DEMO_MODE=true).
// We also accept MODE === 'demo' directly as a belt-and-suspenders guard so a
// missing/edited .env.demo can't silently produce a non-isolated demo build.
export const isDemoMode =
  import.meta.env.VITE_DEMO_MODE === 'true' || import.meta.env.MODE === 'demo';

export const demoWriteMessage = 'Demo mode: changes are disabled';
