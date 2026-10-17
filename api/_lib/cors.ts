// CORS for direct browser calls to the backend API. The primary integration
// path is same-origin proxy routes in each frontend (no CORS needed), but
// these headers allow the documented frontend origins to call directly.
import type { ApiRequest, ApiResponse } from './types.js';
import { header } from './types.js';
import { AuthError } from './auth-errors.js';

function allowedOrigins(): string[] {
  return (process.env.ALLOWED_ORIGINS ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

/** Returns true if this was a preflight request that has been answered. */
export function applyCors(req: ApiRequest, res: ApiResponse): boolean {
  const origin = header(req.headers, 'origin');
  const allowed = allowedOrigins();
  if (origin && allowed.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Max-Age', '600');
  }
  if (req.method === 'OPTIONS') {
    res.status(204).send('');
    return true;
  }
  return false;
}

/** Reject cross-origin state-changing requests not on the allowlist. */
export function assertTrustedOrigin(req: ApiRequest): void {
  const origin = header(req.headers, 'origin');
  if (!origin) return; // same-origin / non-browser callers send no Origin
  const allowed = allowedOrigins();
  // Always allow the backend's own origin (direct same-origin use).
  if (allowed.includes(origin)) return;
  throw new AuthError(403, 'forbidden_origin', 'Origin not allowed.');
}
