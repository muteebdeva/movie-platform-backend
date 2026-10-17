// POST /api/auth/request-password-reset { email } — always returns ok,
// never reveals whether the email exists.
import { q } from '../_lib/db.js';
import { newToken, hashToken } from '../_lib/tokens.js';
import { bodyObject, assertEmail, normalizeEmail } from '../_lib/validate.js';
import { ok, methodNotAllowed, handleApiError } from '../_lib/respond.js';
import { checkRateLimit } from '../_lib/ratelimit.js';
import { sendEmail, resetEmail, emailConfigured } from '../_lib/email.js';
import { audit } from '../_lib/audit.js';
import { applyCors, assertTrustedOrigin } from '../_lib/cors.js';
import { clientIp, type Handler } from '../_lib/types.js';

const handler: Handler = async (req, res) => {
  try {
    if (applyCors(req, res)) return;
    if (req.method !== 'POST') return methodNotAllowed(res, ['POST']);
    assertTrustedOrigin(req);
    const ip = clientIp(req);

    const body = bodyObject(req.body);
    const email = assertEmail(body.email);
    const emailNormalized = normalizeEmail(email);
    await checkRateLimit(`pwreset:email:${emailNormalized}`, 3, 60 * 60 * 1000);
    await checkRateLimit(`pwreset:ip:${ip}`, 10, 60 * 60 * 1000);

    const rows = await q`
      SELECT id, email, display_name FROM users
      WHERE email_normalized = ${emailNormalized} AND status = 'active' LIMIT 1
    `;
    const row = rows[0] as { id: string; email: string; display_name: string } | undefined;

    if (row && emailConfigured()) {
      const token = newToken();
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
      await q`DELETE FROM password_reset_tokens WHERE user_id = ${row.id}`;
      await q`
        INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
        VALUES (${row.id}, ${hashToken(token)}, ${expiresAt.toISOString()})
      `;
      const appUrl = (process.env.APP_URL ?? '').replace(/\/$/, '');
      const link = `${appUrl}/#/reset-password?token=${encodeURIComponent(token)}`;
      await sendEmail({ to: row.email, ...resetEmail(row.email, row.display_name, link) });
    }
    await audit('password-reset-requested', { userId: row?.id ?? null, ip });
    // Same response whether or not the account exists.
    return ok(res, {
      ok: true,
      emailConfigured: emailConfigured(),
      message: emailConfigured()
        ? 'If an account exists for this email, a reset link is on its way.'
        : 'Password reset by email is not configured on this deployment.',
    });
  } catch (e) {
    handleApiError(res, e);
  }
};

export default handler;
