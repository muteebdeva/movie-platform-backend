// Password hashing with scrypt (Node built-in crypto — no native deps).
// Format: scrypt$N$r$p$<salt-b64>$<hash-b64>. Verification is constant-time.
import { scrypt as _scrypt, randomBytes, timingSafeEqual } from 'node:crypto';

const N = 16384;
const R = 8;
const P = 1;
const KEYLEN = 64;

function scryptP(password: string, salt: Buffer, keylen: number, n: number, r: number, p: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    _scrypt(password, salt, keylen, { N: n, r, p }, (err, derived) => {
      if (err) reject(err);
      else resolve(derived as Buffer);
    });
  });
}

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const hash = await scryptP(password, salt, KEYLEN, N, R, P);
  return `scrypt$${N}$${R}$${P}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  try {
    const parts = stored.split('$');
    if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
    const n = Number(parts[1]);
    const r = Number(parts[2]);
    const p = Number(parts[3]);
    if (!Number.isInteger(n) || !Number.isInteger(r) || !Number.isInteger(p)) return false;
    const salt = Buffer.from(parts[4], 'base64');
    const expected = Buffer.from(parts[5], 'base64');
    if (salt.length === 0 || expected.length === 0) return false;
    const hash = await scryptP(password, salt, expected.length, n, r, p);
    if (hash.length !== expected.length) return false;
    return timingSafeEqual(hash, expected);
  } catch {
    return false;
  }
}
