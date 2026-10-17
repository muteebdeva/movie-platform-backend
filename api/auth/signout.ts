// POST /api/auth/signout — revoke the current session. Idempotent.
import { revokeSession, extractToken, getSessionUser } from '../_lib/sessions.js';
import { ok, methodNotAllowed, handleApiError } from '../_lib/respond.js';
import { audit } from '../_lib/audit.js';
import { applyCors, assertTrustedOrigin } from '../_lib/cors.js';
import { clientIp, type Handler } from '../_lib/types.js';

const handler: Handler = async (req, res) => {
  try {
    if (applyCors(req, res)) return;
    if (req.method !== 'POST') return methodNotAllowed(res, ['POST']);
    assertTrustedOrigin(req);
    const token = extractToken(req.headers);
    if (token) {
      const user = await getSessionUser(token).catch(() => null);
      await revokeSession(token);
      await audit('auth-signout', { userId: user?.id ?? null, ip: clientIp(req) });
    }
    return ok(res, { signedOut: true });
  } catch (e) {
    handleApiError(res, e);
  }
};

export default handler;
