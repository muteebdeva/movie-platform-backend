// POST /api/auth/reset-password { token, password } — sets a new password
// and revokes every session for the account.
import { q } from '../_lib/db.js';
import { hashPassword } from '../_lib/passwords.js';
import { hashToken } from '../_lib/tokens.js';
import { revokeAllSessions } from '../_lib/sessions.js';
import { bodyObject, assertPassword } from '../_lib/validate.js';
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
    await checkRateLimit(`pwreset-use:ip:${clientIp(req)}`, 10, 10 * 60 * 1000);

    const body = bodyObject(req.body);
    const token = typeof body.token === 'string' ? body.token : '';
    const password = assertPassword(body.password);
    if (!token) throw invalidToken('reset link');

    const rows = await q`
      SELECT user_id, expires_at FROM password_reset_tokens
      WHERE token_hash = ${hashToken(token)} LIMIT 1
    `;
    const row = rows[0] as { user_id: string; expires_at: string } | undefined;
    if (!row || new Date(row.expires_at).getTime() < Date.now()) {
      throw invalidToken('reset link');
    }

    const passwordHash = await hashPassword(password);
    await q`UPDATE users SET password_hash = ${passwordHash}, updated_at = now() WHERE id = ${row.user_id}`;
    await q`DELETE FROM password_reset_tokens WHERE user_id = ${row.user_id}`;
    await revokeAllSessions(row.user_id);
    await audit('password-reset-completed', { userId: row.user_id, ip: clientIp(req) });
    return ok(res, { ok: true });
  } catch (e) {
    handleApiError(res, e);
  }
};

export default handler;
