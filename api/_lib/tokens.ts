// Opaque token utilities. Tokens are 256-bit random values; only SHA-256
// hashes are stored in the database, so a DB read never yields a live token.
import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';

export function newToken(): string {
  return randomBytes(32).toString('base64url');
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

/** Constant-time comparison for hex hashes. */
export function hashEquals(a: string, b: string): boolean {
  const ba = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}
