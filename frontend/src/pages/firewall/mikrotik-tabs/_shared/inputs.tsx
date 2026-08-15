// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTik tab shared validation inputs.
 *
 * Client-side validation for the most common RouterOS field shapes.
 * Each wrapper:
 *   - Sets an HTML `pattern` / `min`/`max` so the browser's native
 *     constraint validation fires on submit.
 *   - Exposes an `isValid` predicate to call sites that want to gate
 *     submit-button disabled state on validity.
 *   - Renders a small red "format" hint below the input when the
 *     current value is non-empty and fails the pattern.
 *
 * The wrappers are *not* a full Form library, they're shadcn `<Input>`
 * with two extra affordances. The submit logic stays in the tab so a
 * tab can decide whether an invalid value should block submission or
 * pass through (e.g. a tab that already wraps the same field in a
 * larger form-state hook).
 *
 * NB: We deliberately don't lowercase MACs on blur via a controlled
 * effect, that surprises a user who already typed uppercase. The
 * `normalizeMac` helper is exported separately if a tab wants to call
 * it explicitly before submit.
 */
import * as React from 'react';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';

// ─── Regex patterns (single source of truth) ───────────────────────────

export const IP_PATTERN = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
export const CIDR_PATTERN = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/(?:3[0-2]|[12]?[0-9])$/;
export const MAC_PATTERN = /^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$/;
// VLAN 1..4094 (0 and 4095 reserved per 802.1Q)
export const VLAN_MIN = 1;
export const VLAN_MAX = 4094;
export const PORT_MIN = 1;
export const PORT_MAX = 65535;

// ─── Predicates (re-usable for submit-time guards) ─────────────────────

export const isValidIp = (v: string): boolean => v === '' || IP_PATTERN.test(v);
export const isValidCidr = (v: string): boolean => v === '' || CIDR_PATTERN.test(v);
export const isValidMac = (v: string): boolean => v === '' || MAC_PATTERN.test(v);
export const isValidVlan = (v: string): boolean => {
  if (v === '') return true;
  const n = Number(v);
  return Number.isInteger(n) && n >= VLAN_MIN && n <= VLAN_MAX;
};
export const isValidPort = (v: string): boolean => {
  if (v === '') return true;
  const n = Number(v);
  return Number.isInteger(n) && n >= PORT_MIN && n <= PORT_MAX;
};

/** Normalise a MAC to lowercase-with-colons. Callers can invoke before submit. */
export function normalizeMac(value: string): string {
  return value.trim().toLowerCase();
}

// ─── Shared rendering primitives ───────────────────────────────────────

interface ValidatedInputProps
  extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'pattern' | 'type'> {
  /** Show the format hint below the input when invalid. */
  formMessage?: string;
}

function FormatHint({ message }: { message: string }) {
  return (
    <p className="text-xs text-destructive mt-1" data-testid="validation-hint">
      {message}
    </p>
  );
}

// ─── IpInput ───────────────────────────────────────────────────────────

export const IpInput = React.forwardRef<HTMLInputElement, ValidatedInputProps>(
  function IpInput({ value, formMessage, className, ...rest }, ref) {
    const v = typeof value === 'string' ? value : '';
    const invalid = v.length > 0 && !isValidIp(v);
    return (
      <>
        <Input
          ref={ref}
          type="text"
          value={value}
          pattern={IP_PATTERN.source}
          inputMode="numeric"
          className={cn(invalid && 'border-destructive', className)}
          aria-invalid={invalid || undefined}
          {...rest}
        />
        {invalid && (
          <FormatHint
            message={formMessage ?? 'Expected dotted-quad IPv4 (e.g. 192.168.1.1).'}
          />
        )}
      </>
    );
  },
);

// ─── CidrInput ─────────────────────────────────────────────────────────

export const CidrInput = React.forwardRef<HTMLInputElement, ValidatedInputProps>(
  function CidrInput({ value, formMessage, className, ...rest }, ref) {
    const v = typeof value === 'string' ? value : '';
    const invalid = v.length > 0 && !isValidCidr(v);
    return (
      <>
        <Input
          ref={ref}
          type="text"
          value={value}
          pattern={CIDR_PATTERN.source}
          inputMode="text"
          className={cn(invalid && 'border-destructive', className)}
          aria-invalid={invalid || undefined}
          {...rest}
        />
        {invalid && (
          <FormatHint
            message={formMessage ?? 'Expected CIDR notation (e.g. 192.168.1.0/24).'}
          />
        )}
      </>
    );
  },
);

// ─── MacInput ──────────────────────────────────────────────────────────

export const MacInput = React.forwardRef<HTMLInputElement, ValidatedInputProps>(
  function MacInput({ value, formMessage, className, ...rest }, ref) {
    const v = typeof value === 'string' ? value : '';
    const invalid = v.length > 0 && !isValidMac(v);
    return (
      <>
        <Input
          ref={ref}
          type="text"
          value={value}
          pattern={MAC_PATTERN.source}
          inputMode="text"
          autoCapitalize="off"
          autoCorrect="off"
          spellCheck={false}
          className={cn('font-mono', invalid && 'border-destructive', className)}
          aria-invalid={invalid || undefined}
          {...rest}
        />
        {invalid && (
          <FormatHint
            message={formMessage ?? 'Expected MAC address (e.g. aa:bb:cc:dd:ee:ff).'}
          />
        )}
      </>
    );
  },
);

// ─── VlanInput ─────────────────────────────────────────────────────────

export const VlanInput = React.forwardRef<HTMLInputElement, ValidatedInputProps>(
  function VlanInput({ value, formMessage, className, ...rest }, ref) {
    const v = typeof value === 'string' ? value : value !== undefined ? String(value) : '';
    const invalid = v.length > 0 && !isValidVlan(v);
    return (
      <>
        <Input
          ref={ref}
          type="number"
          min={VLAN_MIN}
          max={VLAN_MAX}
          value={value}
          inputMode="numeric"
          className={cn(invalid && 'border-destructive', className)}
          aria-invalid={invalid || undefined}
          {...rest}
        />
        {invalid && (
          <FormatHint
            message={formMessage ?? `VLAN ID must be ${VLAN_MIN}-${VLAN_MAX}.`}
          />
        )}
      </>
    );
  },
);

// ─── PortInput ─────────────────────────────────────────────────────────

/**
 * Accepts a single TCP/UDP port number. RouterOS firewall `dst-port`
 * fields often accept comma-separated lists ("80,443"), those should
 * use a plain `<Input>` because this wrapper requires a single integer.
 */
export const PortInput = React.forwardRef<HTMLInputElement, ValidatedInputProps>(
  function PortInput({ value, formMessage, className, ...rest }, ref) {
    const v = typeof value === 'string' ? value : value !== undefined ? String(value) : '';
    const invalid = v.length > 0 && !isValidPort(v);
    return (
      <>
        <Input
          ref={ref}
          type="number"
          min={PORT_MIN}
          max={PORT_MAX}
          value={value}
          inputMode="numeric"
          className={cn(invalid && 'border-destructive', className)}
          aria-invalid={invalid || undefined}
          {...rest}
        />
        {invalid && (
          <FormatHint
            message={formMessage ?? `Port must be ${PORT_MIN}-${PORT_MAX}.`}
          />
        )}
      </>
    );
  },
);
