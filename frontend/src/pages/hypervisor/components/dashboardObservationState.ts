// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useEffect, useState } from 'react';
import type { Observation } from './DashboardObservation';

export function observationFreshness(data: Observation | undefined, now: number): { state: 'current' | 'stale' | 'unavailable'; age: number | null } {
  if (!data || data.observation_age_seconds == null || !Number.isFinite(data.observation_age_seconds) || data.observation_age_seconds < 0) return { state: 'unavailable', age: null };
  const started = Date.parse(data.collection_started_at ?? '');
  const observed = Date.parse(data.observed_at ?? '');
  const served = Date.parse(data.served_at ?? '');
  if (![started, observed, served, now].every(Number.isFinite) || started > observed || observed > served || served > now + 5000 || !(data.stale_after_seconds > 0 && data.stale_after_seconds <= 300)) return { state: 'unavailable', age: null };
  const age = Math.max(data.observation_age_seconds + Math.max(0, (now - served) / 1000), (now - started) / 1000);
  return { state: age >= data.stale_after_seconds ? 'stale' : 'current', age };
}

export function useObservationFreshness(data: Observation | undefined) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 5000);
    return () => clearInterval(timer);
  }, []);
  return observationFreshness(data, now);
}

