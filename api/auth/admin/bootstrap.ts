// POST /api/auth/admin/bootstrap { secret, email } — one-time promotion of a
// user to admin. Guarded by BOOTSTRAP_SECRET (server env only). Call it once
// with curl, verify, then REMOVE the secret from the deployment.
import { q } from '../../_lib/db.js';
import { toPublicUser } from '../../_lib/sessions.js';
import { bodyObject, assertEmail, normalizeEmail } from '../../_lib/validate.js';
import { ok, methodNotAllowed, handleApiError } from '../../_lib/respond.js';
import { AuthError } from '../../_lib/auth-errors.js';
import { checkRateLimit } from '../../_lib/ratelimit.js';
import { audit } from '../../_lib/audit.js';
import { timingSafeEqual } from 'node:crypto';
import { clientIp, type Handler } from '../../_lib/types.js';

function secretsEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ba.length !== bb.length || ba.length === 0) return false;
  return timingSafeEqual(ba, bb);
}

const handler: Handler = async (req, res) => {
  try {
    if (req.method !== 'POST') return methodNotAllowed(res, ['POST']);
    await checkRateLimit(`bootstrap:ip:${clientIp(req)}`, 5, 60 * 60 * 1000);

    const expected = process.env.BOOTSTRAP_SECRET ?? '';
    const body = bodyObject(req.body);
    const secret = typeof body.secret === 'string' ? body.secret : '';
    if (!expected || !secretsEqual(secret, expected)) {
      throw new AuthError(403, 'forbidden', 'Not allowed.');
    }

    const email = assertEmail(body.email);
    const rows = await q`
      UPDATE users SET role = 'admin', updated_at = now()
      WHERE email_normalized = ${normalizeEmail(email)} AND status = 'active'
      RETURNING id, email, display_name, email_verified, role, created_at
    `;
    if (rows.length === 0) {
      throw new AuthError(404, 'not_found', 'No active account with that email.');
    }
    const user = toPublicUser(rows[0] as never);
    await audit('admin-bootstrap', { userId: user.id, ip: clientIp(req) });
    return ok(res, { user });
  } catch (e) {
    handleApiError(res, e);
  }
};

export default handler;
