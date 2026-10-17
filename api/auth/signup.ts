// POST /api/auth/signup — public registration. ALWAYS creates role='user';
// the request body can never set a role.
import { q } from '../_lib/db.js';
import { hashPassword } from '../_lib/passwords.js';
import { createSession, toPublicUser } from '../_lib/sessions.js';
import { newToken, hashToken } from '../_lib/tokens.js';
import {
  bodyObject, assertDisplayName, assertEmail, assertPassword, assertTerms, normalizeEmail,
} from '../_lib/validate.js';
import { created, methodNotAllowed, handleApiError } from '../_lib/respond.js';
import { emailInUse } from '../_lib/auth-errors.js';
import { checkRateLimit } from '../_lib/ratelimit.js';
import { sendEmail, verificationEmail, emailConfigured } from '../_lib/email.js';
import { audit } from '../_lib/audit.js';
import { applyCors, assertTrustedOrigin } from '../_lib/cors.js';
import { clientIp, type Handler } from '../_lib/types.js';

const handler: Handler = async (req, res) => {
  try {
    if (applyCors(req, res)) return;
    if (req.method !== 'POST') return methodNotAllowed(res, ['POST']);
    assertTrustedOrigin(req);
    const ip = clientIp(req);
    await checkRateLimit(`signup:ip:${ip}`, 5, 60 * 60 * 1000);

    const body = bodyObject(req.body);
    const displayName = assertDisplayName(body.displayName);
    const email = assertEmail(body.email);
    const password = assertPassword(body.password);
    assertTerms(body.terms);
    const emailNormalized = normalizeEmail(email);

    const existing = await q`SELECT id FROM users WHERE email_normalized = ${emailNormalized} LIMIT 1`;
    if (existing.length > 0) throw emailInUse();

    const passwordHash = await hashPassword(password);
    const rows = await q`
      INSERT INTO users (email, email_normalized, display_name, password_hash)
      VALUES (${email}, ${emailNormalized}, ${displayName}, ${passwordHash})
      RETURNING id, email, display_name, email_verified, role, created_at
    `;
    const userRow = rows[0] as never;
    const user = toPublicUser(userRow);

    let verificationSent = false;
    if (emailConfigured()) {
      const token = newToken();
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
      await q`DELETE FROM email_verification_tokens WHERE user_id = ${user.id}`;
      await q`
        INSERT INTO email_verification_tokens (user_id, token_hash, expires_at)
        VALUES (${user.id}, ${hashToken(token)}, ${expiresAt.toISOString()})
      `;
      const appUrl = (process.env.APP_URL ?? '').replace(/\/$/, '');
      const link = `${appUrl}/#/verify-email?token=${encodeURIComponent(token)}`;
      const tpl = verificationEmail(email, displayName, link);
      verificationSent = (await sendEmail({ to: email, ...tpl })).sent;
    }

    const session = await createSession(user.id, { ip });
    await audit('auth-signup', { userId: user.id, ip });
    return created(res, { user, session, verificationSent });
  } catch (e) {
    handleApiError(res, e);
  }
};

export default handler;
