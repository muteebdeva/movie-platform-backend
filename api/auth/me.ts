// GET /api/auth/me — current session user (or 401).
import { getSessionUser, extractToken } from '../_lib/sessions.js';
import { ok, methodNotAllowed, handleApiError } from '../_lib/respond.js';
import { unauthorized } from '../_lib/auth-errors.js';
import { checkRateLimit } from '../_lib/ratelimit.js';
import { applyCors } from '../_lib/cors.js';
import { clientIp, type Handler } from '../_lib/types.js';

const handler: Handler = async (req, res) => {
  try {
    if (applyCors(req, res)) return;
    if (req.method !== 'GET') return methodNotAllowed(res, ['GET']);
    await checkRateLimit(`me:ip:${clientIp(req)}`, 240, 60 * 1000);
    const user = await getSessionUser(extractToken(req.headers) ?? '');
    if (!user) throw unauthorized();
    return ok(res, { user });
  } catch (e) {
    handleApiError(res, e);
  }
};

export default handler;
