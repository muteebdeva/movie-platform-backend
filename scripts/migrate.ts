// Applies pending SQL migrations in order, tracking in schema_migrations.
// Usage: DATABASE_URL=... npm run migrate
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { neon } from '@neondatabase/serverless';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const migrationsDir = join(root, 'migrations');

async function main(): Promise<void> {
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error('DATABASE_URL is not set.');
  const sql = neon(url);

  await sql`CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`;
  const applied = new Set(
    (await sql`SELECT version FROM schema_migrations`).map((r) => (r as { version: string }).version)
  );

  const files = readdirSync(migrationsDir)
    .filter((f) => f.endsWith('.sql'))
    .sort();
  let ran = 0;
  for (const file of files) {
    const version = file.replace(/\.sql$/, '');
    if (applied.has(version)) {
      console.log(`skip ${version} (already applied)`);
      continue;
    }
    const body = readFileSync(join(migrationsDir, file), 'utf8');
    console.log(`apply ${version}...`);
    // Split on semicolons at line ends; migrations avoid dollar-quoting tricks.
    const statements = body
      .split(/;\s*\n/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0 && !s.startsWith('--'));
    for (const stmt of statements) {
      await sql(stmt);
    }
    await sql`INSERT INTO schema_migrations (version) VALUES (${version})`;
    console.log(`done ${version}`);
    ran++;
  }
  console.log(ran === 0 ? 'nothing to do' : `applied ${ran} migration(s)`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
