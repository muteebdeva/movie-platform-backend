// POST /api/auth/verify-email { token } — marks the address verified.
import { q } from '../_lib/db.js';
import { hashToken } from '../_lib/tokens.js';
import { toPublicUser } from '../_lib/sessions.js';
import { bodyObject } from '../_lib/validate.js';
import { ok, methodNotAllowed, handleApiError } from '../_lib/respond.js';
import { invalidToken } from '../_lib/auth-errors.js';
import { checkRateLimit } from '../_lib/ratelimit.js';
import { audit } from '../_lib/audit.js';
import { applyCors, assertTrustedOrigin } from '../_lib/cors.js';
import { clientIp, type Handler } from '../_lib/types.js';

const handler: Handler = async (req, res) => {
  try {
    if (applyCors(req, res)) return;
    if (req.method !== 'POST') return methodNotAllowed(res, ['POST']);
    assertTrustedOrigin(req);
    await checkRateLimit(`verify:ip:${clientIp(req)}`, 10, 10 * 60 * 1000);

    const body = bodyObject(req.body);
    const token = typeof body.token === 'string' ? body.token : '';
    if (!token) throw invalidToken('verification link');

    const rows = await q`
      SELECT t.user_id, t.expires_at, u.email, u.display_name, u.email_verified, u.role, u.created_at, u.id
      FROM email_verification_tokens t
      JOIN users u ON u.id = t.user_id
      WHERE t.token_hash = ${hashToken(token)}
      LIMIT 1
    `;
    const row = rows[0] as Record<string, unknown> | undefined;
    if (!row || new Date(row.expires_at as string).getTime() < Date.now()) {
      throw invalidToken('verification link');
    }

    await q`UPDATE users SET email_verified = TRUE, updated_at = now() WHERE id = ${row.user_id as string}`;
    await q`DELETE FROM email_verification_tokens WHERE user_id = ${row.user_id as string}`;
    await audit('email-verified', { userId: row.user_id as string, ip: clientIp(req) });

    const userRows = await q`
      SELECT id, email, display_name, email_verified, role, created_at
      FROM users WHERE id = ${row.user_id as string} LIMIT 1
    `;
    return ok(res, { user: toPublicUser(userRows[0] as never) });
  } catch (e) {
    handleApiError(res, e);
  }
};

export default handler;
