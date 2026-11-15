// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * One reader for every error shape the FreeSDN backend actually sends.
 *
 * The backend's global handlers (backend/app/core/middleware.py,
 * ``setup_exception_handlers``) wrap almost every failure in an envelope:
 *
 *   { "error": { "code": 404, "message": "Site not found", "request_id": "..." } }
 *   { "error": { "code": 403, "type": "adapter_read_only", "message": "...", "request_id": "..." } }
 *   { "error": { "code": 422, "message": "Validation error",
 *                "details": [{ "field": "body.name", "message": "Field required", "type": "missing" }] } }
 *
 * ``HTTPException(detail=...)`` lands in ``error.message`` verbatim, so the
 * message can also be an object (``{"message": ..., "task_id": ...}``).
 * A few paths still answer with FastAPI's bare shape: the rate limiter and
 * body-size cap (``{"detail": "Rate limit exceeded", "retry_after": 60}``),
 * the vault-confirmation routes, and Starlette's own 404/405 for unmatched
 * routes (``{"detail": "Not Found"}``). A request that never got an answer
 * (server down, TLS failure, timeout) has no body at all.
 *
 * Reading ``error.response.data.detail`` directly misses the envelope, which
 * is why operators saw only a generic fallback for most failures. Use
 * ``getApiErrorMessage`` for display and ``parseApiError`` when you also need
 * the machine-readable type, the HTTP status or per-field messages.
 */
import i18n from 'i18next';

/** One per-field validation failure (from a 422). */
export interface ApiFieldError {
  /** Dotted field path without the request location, e.g. ``name`` or ``ports.0.vlan``. */
  field: string;
  /** Human message for that field. */
  message: string;
  /** Pydantic error type when the backend sent one, e.g. ``missing``. */
  type?: string;
}

/** What went wrong, in a form the UI can show and branch on. */
export type ApiErrorKind =
  /** The server answered with an HTTP error status. */
  | 'http'
  /** The request never reached the server, or no answer came back. */
  | 'network'
  /** The request was aborted after its timeout. */
  | 'timeout'
  /** The caller cancelled the request (AbortController, unmount). */
  | 'cancelled'
  /** Not a request failure: a thrown Error, a string, or something else. */
  | 'client';

export interface ApiErrorInfo {
  /** Human-readable message. Never empty. */
  message: string;
  kind: ApiErrorKind;
  /** HTTP status, or null when there was no response. */
  status: number | null;
  /**
   * Machine-readable error type when the backend sent one (the envelope's
   * ``error.type``), e.g. ``adapter_read_only``, ``confirmation_required``,
   * ``adapter_timeout``, ``invalid_value``. Null otherwise.
   */
  type: string | null;
  /** Per-field validation messages (422). Empty when there are none. */
  fieldErrors: ApiFieldError[];
  /** The backend's request ID, for matching a failure to its server log line. */
  requestId: string | null;
  /** Seconds the server asked the client to wait (``Retry-After``), or null. */
  retryAfter: number | null;
  /**
   * The structured detail object when the backend sent one
   * (``HTTPException(detail={...})``), e.g. ``{ message, task_id }``. Null otherwise.
   */
  detail: Record<string, unknown> | null;
}

type Dict = Record<string, unknown>;

const isDict = (value: unknown): value is Dict =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const nonEmptyString = (value: unknown): string | null =>
  typeof value === 'string' && value.trim() !== '' ? value.trim() : null;

function translate(key: string, defaultValue: string, options: Record<string, unknown> = {}): string {
  // i18next is initialised by src/lib/i18n.ts at app start (and by the test
  // setup). Before that, or if the key is missing, use the English default.
  if (!i18n.isInitialized) {
    return defaultValue.replace(/\{\{\s*(\w+)\s*\}\}/g, (_, name: string) =>
      String(options[name] ?? ''),
    );
  }
  const out = i18n.t(`errors:${key}`, { defaultValue, ...options });
  return typeof out === 'string' && out !== '' ? out : defaultValue;
}

// Request locations FastAPI prefixes onto validation paths. An operator
// thinks "name", not "body.name".
const LOCATION_PREFIX = /^(body|query|path|header|cookie)(\.|$)/;

function cleanField(raw: unknown): string {
  let field: string;
  if (Array.isArray(raw)) field = raw.map((part) => String(part)).join('.');
  else field = typeof raw === 'string' ? raw : raw == null ? '' : String(raw);
  return field.replace(LOCATION_PREFIX, '');
}

// Pydantic v2 prefixes custom validator messages with "Value error, " and
// assertion messages with "Assertion failed, ". The rest is the useful part.
function cleanFieldMessage(raw: unknown): string | null {
  const text = nonEmptyString(raw);
  if (!text) return null;
  return text.replace(/^(Value error|Assertion failed), /, '');
}

function toFieldErrors(items: unknown[]): ApiFieldError[] {
  const out: ApiFieldError[] = [];
  for (const item of items) {
    if (typeof item === 'string') {
      const message = nonEmptyString(item);
      if (message) out.push({ field: '', message });
      continue;
    }
    if (!isDict(item)) continue;
    const type = nonEmptyString(item.type) ?? undefined;
    // Envelope shape: { field, message, type }. FastAPI's bare shape:
    // { loc: [...], msg, type }.
    const message =
      cleanFieldMessage(item.message) ?? cleanFieldMessage(item.msg) ?? type ?? 'invalid';
    const field = cleanField(item.field ?? item.loc);
    out.push(type ? { field, message, type } : { field, message });
  }
  return out;
}

/** Message text from a value that may be a string, a dict or a list. */
function messageFrom(value: unknown): string | null {
  const direct = nonEmptyString(value);
  if (direct) return direct;
  if (isDict(value)) {
    return (
      nonEmptyString(value.message) ??
      nonEmptyString(value.msg) ??
      nonEmptyString(value.detail) ??
      nonEmptyString(value.error) ??
      (isDict(value.error) ? messageFrom(value.error) : null)
    );
  }
  if (Array.isArray(value)) {
    const parts = value.map((item) => messageFrom(item)).filter((part): part is string => !!part);
    return parts.length ? parts.join(', ') : null;
  }
  return null;
}

function parseRetryAfter(headers: unknown, data: Dict | null): number | null {
  const fromBody = data?.retry_after;
  if (typeof fromBody === 'number' && Number.isFinite(fromBody) && fromBody >= 0) return fromBody;
  let header: unknown;
  if (isDict(headers)) {
    const getter = (headers as { get?: unknown }).get;
    header =
      typeof getter === 'function'
        ? (getter as (name: string) => unknown).call(headers, 'retry-after')
        : (headers['retry-after'] ?? headers['Retry-After']);
  }
  const seconds = typeof header === 'string' || typeof header === 'number' ? Number(header) : NaN;
  return Number.isFinite(seconds) && seconds >= 0 ? seconds : null;
}

/**
 * A body that arrived as text: either JSON that axios could not parse (a
 * ``responseType: 'text'`` request) or a proxy's plain-text or HTML page.
 * JSON is decoded; short plain text is kept; HTML is dropped.
 */
function normaliseBody(data: unknown): { dict: Dict | null; text: string | null } {
  if (isDict(data)) return { dict: data, text: null };
  if (typeof data !== 'string') return { dict: null, text: null };
  const trimmed = data.trim();
  if (!trimmed) return { dict: null, text: null };
  if (trimmed.startsWith('{')) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (isDict(parsed)) return { dict: parsed, text: null };
    } catch {
      /* not JSON after all */
    }
  }
  if (trimmed.startsWith('<') || trimmed.length > 300) return { dict: null, text: null };
  return { dict: null, text: trimmed };
}

function statusMessage(status: number, retryAfter: number | null): string {
  switch (status) {
    case 400:
      return translate('badRequest', 'Invalid request');
    case 401:
      return translate('unauthorized', 'Authentication required');
    case 403:
      return translate('forbidden', 'You do not have permission to perform this action');
    case 404:
      return translate('notFound', 'Resource not found');
    case 409:
      return translate('conflict', 'Resource conflict');
    case 413:
      return translate('api.payloadTooLarge', 'The request is too large for the server to accept.');
    case 422:
      return translate('validation', 'Validation error');
    case 429:
      return retryAfter
        ? translate('api.rateLimitedRetry', 'Too many requests. Try again in {{seconds}} s.', {
            seconds: retryAfter,
          })
        : translate('rateLimited', 'Too many requests. Please try again later.');
    case 502:
      return translate(
        'api.badGateway',
        'The FreeSDN API is not answering (HTTP 502). It may be restarting; try again shortly.',
      );
    case 503:
      return translate('serviceUnavailable', 'Service temporarily unavailable');
    case 504:
      return translate('api.gatewayTimeout', 'The FreeSDN API did not answer in time (HTTP 504).');
    default:
      return status >= 500
        ? translate('internalServer', 'An unexpected error occurred')
        : translate('api.status', 'The server returned an error (HTTP {{status}}).', { status });
  }
}

function composeValidationMessage(
  base: string | null,
  fields: ApiFieldError[],
  separator = '; ',
): string | null {
  const parts = fields.map((f) => (f.field ? `${f.field}: ${f.message}` : f.message));
  if (!parts.length) return base;
  const generic = !base || /^validation (error|failed)$/i.test(base);
  return generic ? parts.join(separator) : `${base}, ${parts.join(separator)}`;
}

const defaultFallback = () => translate('api.generic', 'An error occurred');

const looksLikeRequestError = (err: Dict): boolean =>
  err.isAxiosError === true || 'request' in err || 'config' in err;

/**
 * Read any thrown value into an {@link ApiErrorInfo}.
 *
 * ``fallback`` is used only when the error carries no message of its own (an
 * HTTP error whose body is empty or an HTML proxy page, or a bare object).
 * A real backend message, a network failure or a thrown Error's own message
 * always wins over it, because each says more than a generic "failed".
 */
export function parseApiError(error: unknown, fallback?: string): ApiErrorInfo {
  const info: ApiErrorInfo = {
    message: '',
    kind: 'client',
    status: null,
    type: null,
    fieldErrors: [],
    requestId: null,
    retryAfter: null,
    detail: null,
  };
  const fallbackMessage = () => nonEmptyString(fallback) ?? defaultFallback();

  if (typeof error === 'string') {
    info.message = nonEmptyString(error) ?? fallbackMessage();
    return info;
  }
  if (!isDict(error)) {
    info.message = fallbackMessage();
    return info;
  }

  const response = isDict(error.response) ? error.response : null;
  const status = typeof response?.status === 'number' ? response.status : null;

  // A response object means the server answered, even when a hand-built or
  // mocked error leaves out its status.
  if (!response) {
    const code = nonEmptyString(error.code);
    const ownMessage = nonEmptyString(error.message);
    if (code === 'ERR_CANCELED' || error.name === 'CanceledError' || error.name === 'AbortError') {
      info.kind = 'cancelled';
      info.message = translate('api.cancelled', 'The request was cancelled.');
    } else if (
      code === 'ECONNABORTED' ||
      code === 'ETIMEDOUT' ||
      (code !== null && looksLikeRequestError(error) && /timeout/i.test(ownMessage ?? ''))
    ) {
      info.kind = 'timeout';
      info.message = translate('api.timeout', 'The server took too long to respond. Try again.');
    } else if (code === 'ERR_NETWORK' || (error.isAxiosError === true && !ownMessage)) {
      info.kind = 'network';
      const offline = typeof navigator !== 'undefined' && navigator.onLine === false;
      info.message = offline
        ? translate('networkOffline', 'You appear to be offline. Please check your connection.')
        : translate(
            'api.unreachable',
            'Could not reach the FreeSDN server. Check your connection and try again.',
          );
    } else {
      // A thrown Error (or an error-like object): its own message is the best
      // we have.
      info.message = ownMessage ?? fallbackMessage();
    }
    return info;
  }

  info.kind = 'http';
  info.status = status;
  const { dict: data, text } = normaliseBody(response.data);
  info.retryAfter = parseRetryAfter(response.headers, data);

  let message: string | null = null;
  if (data) {
    const envelope = data.error;
    if (isDict(envelope)) {
      info.type = nonEmptyString(envelope.type);
      info.requestId = nonEmptyString(envelope.request_id);
      if (isDict(envelope.message)) info.detail = envelope.message;
      if (Array.isArray(envelope.details)) info.fieldErrors = toFieldErrors(envelope.details);
      message = messageFrom(envelope.message);
      if (info.fieldErrors.length) message = composeValidationMessage(message, info.fieldErrors);
    } else if (nonEmptyString(envelope)) {
      message = nonEmptyString(envelope);
    }

    if (!message) {
      const detail = data.detail;
      if (Array.isArray(detail)) {
        // FastAPI's own 422 shape (a route outside the global handler).
        // Joined with commas, as this reader always has.
        info.fieldErrors = toFieldErrors(detail);
        message = composeValidationMessage(null, info.fieldErrors, ', ');
      } else {
        if (isDict(detail)) {
          info.detail = detail;
          info.type = info.type ?? nonEmptyString(detail.type) ?? nonEmptyString(detail.code);
        }
        message = messageFrom(detail);
      }
    }
    if (!message) message = nonEmptyString(data.message);
    info.requestId = info.requestId ?? nonEmptyString(data.request_id);
  } else if (text) {
    message = text;
  }

  if (!message) {
    message =
      nonEmptyString(fallback) ??
      (status !== null ? statusMessage(status, info.retryAfter) : defaultFallback());
  }

  // A bare "Internal server error" says nothing on its own. The request ID
  // lets an operator find the matching traceback in the server log.
  if (status !== null && status >= 500 && info.requestId && /^internal server error\.?$/i.test(message)) {
    message = translate('api.withRequestId', '{{message}} (request ID {{requestId}})', {
      message,
      requestId: info.requestId,
    });
  }

  info.message = message;
  return info;
}

/**
 * The message to show an operator for any thrown value.
 *
 * Replaces ``err?.response?.data?.detail || fallback``, which misses the
 * backend's ``{ error: { message } }`` envelope and so showed the fallback
 * for nearly every failure.
 */
export function getApiErrorMessage(error: unknown, fallback?: string): string {
  return parseApiError(error, fallback).message;
}

/**
 * Per-field validation messages keyed by field path, for wiring a 422 into a
 * form (``form.setError(field, { message })``). The first message wins when a
 * field has several.
 */
export function getApiFieldErrors(error: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  for (const fieldError of parseApiError(error).fieldErrors) {
    if (fieldError.field && !(fieldError.field in out)) out[fieldError.field] = fieldError.message;
  }
  return out;
}

/** True when the write was refused by the platform's read-only safety. */
export function isReadOnlyRefusal(error: unknown): boolean {
  const info = parseApiError(error);
  if (info.type === 'adapter_read_only') return true;
  return info.status === 403 && /ADAPTER_READ_ONLY|OMADA_READ_ONLY|read[- _]only/i.test(info.message);
}
