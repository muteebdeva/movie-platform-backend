// Audit log for security-relevant events. Never records secrets, passwords,
// or tokens — only hashes where needed (never here).
import { q } from './db.js';

export async function audit(
  action: string,
  opts: { userId?: string | null; ip?: string; meta?: Record<string, unknown> } = {}
): Promise<void> {
  try {
    await q`
      INSERT INTO audit_events (user_id, action, ip, meta)
      VALUES (${opts.userId ?? null}, ${action}, ${(opts.ip ?? '').slice(0, 64) || null}, ${opts.meta ? JSON.stringify(opts.meta) : null}::jsonb)
    `;
  } catch (e) {
    // Audit must never break the request path.
    console.error('[audit] write failed:', e);
  }
}
