// Server-side session management. Session tokens are 256-bit random values;
// only SHA-256 hashes are stored. Sessions expire (remember me = 30 days,
// otherwise 24 hours) and are revoked on sign-out / password reset.
import { q } from './db.js';
import { newToken, hashToken } from './tokens.js';
import type { PublicUser } from './types.js';

export interface SessionInfo {
  token: string;
  expiresAt: Date;
}

const REMEMBER_MS = 30 * 24 * 60 * 60 * 1000;
const DEFAULT_MS = 24 * 60 * 60 * 1000;

export async function createSession(
  userId: string,
  opts: { remember?: boolean; ip?: string; userAgent?: string } = {}
): Promise<SessionInfo> {
  const token = newToken();
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + (opts.remember ? REMEMBER_MS : DEFAULT_MS));
  await q`
    INSERT INTO sessions (user_id, token_hash, expires_at, ip, user_agent)
    VALUES (${userId}, ${tokenHash}, ${expiresAt.toISOString()}, ${opts.ip ?? null}, ${(opts.userAgent ?? '').slice(0, 300)})
  `;
  return { token, expiresAt };
}

export function toPublicUser(row: {
  id: string;
  email: string;
  display_name: string;
  email_verified: boolean;
  role: string;
  created_at: string;
}): PublicUser {
  return {
    id: row.id,
    email: row.email,
    displayName: row.display_name,
    emailVerified: row.email_verified,
    role: row.role === 'admin' ? 'admin' : 'user',
    createdAt: row.created_at,
  };
}

/** Validate a session token → the user, or null. Refreshes last_seen_at. */
export async function getSessionUser(token: string): Promise<PublicUser | null> {
  if (!token || token.length < 20) return null;
  const tokenHash = hashToken(token);
  const rows = await q`
    SELECT u.id, u.email, u.display_name, u.email_verified, u.role, u.created_at,
           u.status, s.expires_at
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ${tokenHash}
    LIMIT 1
  `;
  const row = rows[0] as Record<string, unknown> | undefined;
  if (!row) return null;
  if (new Date(row.expires_at as string).getTime() < Date.now()) {
    await revokeSession(token).catch(() => {});
    return null;
  }
  if (row.status !== 'active') return null;
  await q`UPDATE sessions SET last_seen_at = now() WHERE token_hash = ${tokenHash}`.catch(() => {});
  return toPublicUser(row as never);
}

export async function revokeSession(token: string): Promise<void> {
  await q`DELETE FROM sessions WHERE token_hash = ${hashToken(token)}`;
}

export async function revokeAllSessions(userId: string): Promise<void> {
  await q`DELETE FROM sessions WHERE user_id = ${userId}`;
}

/** Extract a bearer token from Authorization or the mp_session cookie. */
export function extractToken(headers: Record<string, string | string[] | undefined>): string | null {
  const h = headers['authorization'] ?? headers['Authorization'];
  const auth = Array.isArray(h) ? h[0] : h;
  if (auth && auth.toLowerCase().startsWith('bearer ')) {
    const t = auth.slice(7).trim();
    if (t) return t;
  }
  const c = headers['cookie'] ?? headers['Cookie'];
  const cookie = Array.isArray(c) ? c[0] : c;
  if (cookie) {
    for (const part of cookie.split(';')) {
      const [k, ...rest] = part.trim().split('=');
      if (k === 'mp_session' && rest.length > 0) return decodeURIComponent(rest.join('='));
    }
  }
  return null;
}
