// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useCallback, useEffect, useRef, useState } from 'react';
import { copyText } from '@/lib/clipboard';

export type CopyState = 'idle' | 'copied' | 'failed';

/**
 * Copy with an honest result. ``state`` is 'copied' only after the clipboard
 * accepted the text and 'failed' when it did not (plain-HTTP origin with no
 * fallback, permission refused); it returns to 'idle' after ``resetMs``.
 *
 *   const { copy, state } = useCopyToClipboard();
 *   <Button onClick={() => copy(apiKey)}>{state === 'copied' ? 'Copied' : 'Copy'}</Button>
 */
export function useCopyToClipboard(resetMs = 2000) {
  const [state, setState] = useState<CopyState>('idle');
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(
    () => () => {
      if (timer.current) clearTimeout(timer.current);
    },
    [],
  );

  const copy = useCallback(
    async (text: string): Promise<boolean> => {
      const ok = await copyText(text);
      setState(ok ? 'copied' : 'failed');
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(() => setState('idle'), ok ? resetMs : resetMs * 2);
      return ok;
    },
    [resetMs],
  );

  return { copy, state };
}
