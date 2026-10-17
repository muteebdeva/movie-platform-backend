# movie-platform-backend

Shared Supabase backend for the movie platform (`muteeb-movie`) and the
admin panel (`muteeb-movie-admin`): one Supabase project is the single source
of truth for authentication and user data.

**Supabase Auth** owns credentials (email/password, sessions, email
verification, password reset). This repo holds:

- `supabase/migrations/` — versioned SQL: `profiles` table, Row Level
  Security policies, anti-escalation trigger, auto-profile trigger.
- `docs/` — setup, environment variables, frontend integration, recovery.

There is no custom password system and no second user database. The previous
Neon-based custom auth server was removed when the project moved to Supabase
(see git history); Supabase Auth replaces it entirely.

## Quick start

1. Create a free Supabase project at https://supabase.com.
2. Run `supabase/migrations/001_profiles.sql` in the dashboard SQL Editor.
3. Follow `docs/SETUP.md` (redirect URLs, email settings).
4. Set `VITE_SUPABASE_URL` + `VITE_SUPABASE_PUBLISHABLE_KEY` on both Vercel
   projects (see `docs/ENV.md`).
5. Promote yourself to admin with the SQL in `docs/SETUP.md`.

## Security model

- Passwords never touch this repo — Supabase Auth hashes and stores them.
- `profiles.is_admin` can only be changed via the service-role key or direct
  database access (trigger-enforced); RLS stops users reading or editing
  anyone else's row.
- The service-role key is never placed in frontend code or committed.
