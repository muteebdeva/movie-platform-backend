// Postgres access via Neon's serverless driver (HTTP-based: no persistent
// connections, ideal for Vercel serverless functions). All queries go through
// the `q` template tag and are parameterized — never interpolate values.
import { neon } from '@neondatabase/serverless';

export type DbRow = Record<string, any>;
export type DbRows = DbRow[];

let sqlInstance: ReturnType<typeof neon> | null = null;

function getNeon(): ReturnType<typeof neon> {
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error('DATABASE_URL is not configured.');
  if (!sqlInstance) sqlInstance = neon(url);
  return sqlInstance;
}

/** Parameterized query. Usage: await q`SELECT * FROM users WHERE id = ${id}` */
export function q(strings: TemplateStringsArray, ...values: any[]): Promise<DbRows> {
  const fn = getNeon() as unknown as (s: TemplateStringsArray, ...v: any[]) => Promise<DbRows>;
  return fn(strings, ...values);
}

/** Raw driver access (for scripts/migrations needing .unsafe etc). */
export function rawSql(): ReturnType<typeof neon> {
  return getNeon();
}

/** For scripts/tests: driver bound to an explicit URL. */
export function rawSqlWith(url: string): ReturnType<typeof neon> {
  return neon(url);
}
