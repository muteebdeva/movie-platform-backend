# Environment variables

## Backend Vercel project (`movie-platform-backend`)

| Variable | Public? | Required | Purpose |
|---|---|---|---|
| `DATABASE_URL` | No — server secret | Yes | Pooled Neon Postgres connection string (`?sslmode=require`) |
| `BOOTSTRAP_SECRET` | No — server secret | Once | One-time admin promotion; **remove after use** |
| `APP_URL` | Yes | Yes | Movie site URL, e.g. `https://muteeb-movie.vercel.app` (email links) |
| `ALLOWED_ORIGINS` | Yes | Yes | Comma-separated frontend origins allowed for direct browser calls |
| `RESEND_API_KEY` | No — server secret | No | Enables verification + password-reset emails |
| `EMAIL_FROM` | Yes | No | Sender, e.g. `Movie Platform <no-reply@yourdomain>` |
| `REQUIRE_EMAIL_VERIFICATION` | Yes | No | `true`/`false`; defaults to true when `RESEND_API_KEY` is set |

## Movie site Vercel project (`muteeb-movie`)

| Variable | Public? | Required | Purpose |
|---|---|---|---|
| `AUTH_BACKEND_URL` | Yes | Yes | Backend base URL, e.g. `https://movie-platform-backend.vercel.app` |
| (existing) `VITE_TMDB_API_KEY` | Build-time | Yes | Already configured |

The proxy routes read the session cookie `mp_session` (HttpOnly, Secure,
SameSite=Lax, Path=/). No secrets are ever exposed to the browser.

## Admin panel Vercel project (`muteeb-movie-admin`)

Same as the movie site: `AUTH_BACKEND_URL`. The existing GitHub OAuth
variables stay untouched — both login methods work side by side.
