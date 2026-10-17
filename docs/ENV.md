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

## Never use

- `SUPABASE_SERVICE_ROLE_KEY` must **never** appear in frontend code,
  `VITE_` variables, or git. It is only for trusted server scripts or the
  Supabase dashboard.
