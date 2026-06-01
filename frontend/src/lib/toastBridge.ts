// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
//
// Tiny non-React bridge so the module-level TanStack MutationCache (which lives
// outside React, in queryClient.ts) can surface a toast through the React
// ToastProvider. A small bridge component rendered under the provider registers
// the handler on mount; the MutationCache's global onError emits raw errors
// here. This keeps queryClient.ts free of React/i18n/axios imports (and the
// import cycle that would otherwise create) while still giving every mutation a
// uniform error-toast safety net.

export type MutationErrorHandler = (error: unknown) => void;

let handler: MutationErrorHandler | null = null;

/** Called by the in-React bridge component to (de)register the toast emitter. */
export function registerMutationErrorHandler(fn: MutationErrorHandler | null): void {
  handler = fn;
}

/** Called by the non-React MutationCache onError. No-op until a handler is registered. */
export function emitMutationError(error: unknown): void {
  handler?.(error);
}
