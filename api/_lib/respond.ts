// JSON response helpers + centralized error mapping.
// Internal details are never leaked to clients; unexpected errors are logged
// server-side and surfaced as a generic 500.
import type { ApiResponse } from './types.js';
import { ValidationError } from './validate.js';
import { AuthError } from './auth-errors.js';
import { RateLimitError } from './ratelimit.js';

function send(res: ApiResponse, status: number, body: unknown): void {
  res.status(status).setHeader('Content-Type', 'application/json').send(JSON.stringify(body));
}

export const ok = (res: ApiResponse, data: unknown = null) => send(res, 200, { ok: true, data });
export const created = (res: ApiResponse, data: unknown = null) => send(res, 201, { ok: true, data });

export function badRequest(res: ApiResponse, code: string, message: string): void {
  send(res, 400, { ok: false, code, message });
}

export function methodNotAllowed(res: ApiResponse, allow: string[]): void {
  res.setHeader('Allow', allow.join(', '));
  send(res, 405, { ok: false, code: 'method_not_allowed', message: 'Method not allowed' });
}

export function handleApiError(res: ApiResponse, err: unknown): void {
  if (err instanceof ValidationError) {
    send(res, 400, { ok: false, code: err.code, message: err.message });
    return;
  }
  if (err instanceof AuthError) {
    send(res, err.status, { ok: false, code: err.code, message: err.message });
    return;
  }
  if (err instanceof RateLimitError) {
    res.setHeader('Retry-After', String(err.retryAfterSec));
    send(res, 429, { ok: false, code: 'rate_limited', message: 'Too many requests. Please try again later.' });
    return;
  }
  console.error('[api] unexpected error:', err);
  send(res, 500, { ok: false, code: 'internal', message: 'Unexpected server error.' });
}
