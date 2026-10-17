# Environment variables

## Movie site (`muteeb-movie`) and admin panel (`muteeb-movie-admin`)

Set these on **both** Vercel projects (Production + Preview), then redeploy.

| Variable | Public? | Required | Purpose |
|---|---|---|---|
| `VITE_SUPABASE_URL` | Yes (in frontend bundle) | Yes | Supabase project URL |
| `VITE_SUPABASE_PUBLISHABLE_KEY` | Yes (in frontend bundle) | Yes | Supabase publishable/anon key |

Both values are designed by Supabase to be public — they are protected by
Row Level Security, not by secrecy.

The admin panel keeps its existing GitHub OAuth variables unchanged.

## Admin panel only (`muteeb-movie-admin`, server-side)

Set on the admin Vercel project (Production + Preview), then redeploy.
Server-side only — never use a `VITE_` prefix, never put it in frontend code.

| Variable | Public? | Required | Purpose |
|---|---|---|---|
| `SUPABASE_SERVICE_ROLE_KEY` | **No — secret** | Yes, for user management | Powers the privileged admin API (list/ban/delete users, password resets, session revocation, audit log). All endpoints verify the caller's staff role server-side before using it. |

Find it in the Supabase dashboard: Project Settings → API → `service_role`
key. If it ever leaks, roll it from the same page.

## Never use

- `SUPABASE_SERVICE_ROLE_KEY` must **never** appear in frontend code,
  `VITE_` variables, or git. It is only for trusted server scripts or the
  Supabase dashboard.
