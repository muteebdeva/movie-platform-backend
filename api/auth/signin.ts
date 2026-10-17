// POST /api/auth/signin — email + password. Never reveals whether the email
// exists (wrong email and wrong password produce the same error).
import { q } from '../_lib/db.js';
import { verifyPassword } from '../_lib/passwords.js';
import { createSession, toPublicUser } from '../_lib/sessions.js';
import { bodyObject, assertEmail, normalizeEmail } from '../_lib/validate.js';
import { ok, methodNotAllowed, handleApiError } from '../_lib/respond.js';
import { invalidCredentials, accountSuspended, emailNotVerified } from '../_lib/auth-errors.js';
import { checkRateLimit } from '../_lib/ratelimit.js';
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
    const password = typeof body.password === 'string' ? body.password : '';
    const remember = body.remember === true;
    const emailNormalized = normalizeEmail(email);

    await checkRateLimit(`signin:ip:${ip}`, 10, 10 * 60 * 1000);
    await checkRateLimit(`signin:email:${emailNormalized}`, 10, 10 * 60 * 1000);

    const rows = await q`SELECT * FROM users WHERE email_normalized = ${emailNormalized} LIMIT 1`;
    const row = rows[0] as Record<string, unknown> | undefined;

    let fail: ReturnType<typeof invalidCredentials> | null = null;
    if (!row || row.status === 'deleted') {
      fail = invalidCredentials();
    } else if (row.status === 'suspended') {
      fail = accountSuspended();
    } else if (!(await verifyPassword(password, row.password_hash as string))) {
      fail = invalidCredentials();
    }
    if (fail) {
      await audit('auth-signin-failed', { userId: (row?.id as string) ?? null, ip });
      throw fail;
    }

    const requireVerification =
      process.env.REQUIRE_EMAIL_VERIFICATION === 'true' ||
      (process.env.REQUIRE_EMAIL_VERIFICATION !== 'false' &&
        Boolean(process.env.RESEND_API_KEY));
    if (requireVerification && row!.email_verified !== true) {
      throw emailNotVerified();
    }

    const user = toPublicUser(row as never);
    const session = await createSession(user.id, { remember, ip });
    await audit('auth-signin', { userId: user.id, ip });
    return ok(res, { user, session });
  } catch (e) {
    handleApiError(res, e);
  }
};

export default handler;
