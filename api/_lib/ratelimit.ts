// Database-backed sliding-window rate limiting (works across serverless
// instances, unlike in-memory counters).
import { q } from './db.js';

export class RateLimitError extends Error {
  retryAfterSec: number;
  constructor(retryAfterSec: number) {
    super('Too many requests.');
    this.name = 'RateLimitError';
    this.retryAfterSec = retryAfterSec;
  }
}

/**
 * Allow up to `max` events per `windowMs` for `key`.
 * Throws RateLimitError when exceeded.
 */
export async function checkRateLimit(key: string, max: number, windowMs: number): Promise<void> {
  const windowSecs = Math.max(1, Math.round(windowMs / 1000));
  const rows = await q`
    INSERT INTO rate_limits (key, window_start, count)
    VALUES (${key}, now(), 1)
    ON CONFLICT (key) DO UPDATE SET
      window_start = CASE
        WHEN rate_limits.window_start < now() - make_interval(secs => ${windowSecs})
        THEN now() ELSE rate_limits.window_start END,
      count = CASE
        WHEN rate_limits.window_start < now() - make_interval(secs => ${windowSecs})
        THEN 1 ELSE rate_limits.count + 1 END
    RETURNING count, EXTRACT(EPOCH FROM (now() - window_start))::int AS elapsed
  `;
  const row = rows[0] as { count: number; elapsed: number };
  if (row.count > max) {
    throw new RateLimitError(Math.max(1, windowSecs - row.elapsed));
  }
}

export async function resetRateLimit(key: string): Promise<void> {
  await q`DELETE FROM rate_limits WHERE key = ${key}`;
}
