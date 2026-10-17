# Setup

## 1. Database (Neon, free tier)

1. Sign up at https://neon.tech and create a project (free tier is enough).
2. In the dashboard, copy the **pooled** connection string
   (hostname contains `-pooler`, ends with `?sslmode=require`).

## 2. Backend repo

```bash
git clone https://github.com/muteebdeva/movie-platform-backend.git
cd movie-platform-backend
npm install
cp .env.example .env   # fill in DATABASE_URL etc.
npm run migrate        # creates all tables
npm run smoke          # 28 unit tests (no DB needed)
npm run typecheck
```

## 3. Deploy to Vercel

1. Import the repo in Vercel as a new project.
2. Set the environment variables from `docs/ENV.md`
   (Production + Preview; `DATABASE_URL` and `BOOTSTRAP_SECRET` as Sensitive).
3. Deploy. The API is live at `https://<project>.vercel.app/api/auth/...`.

## 4. First administrator

```bash
# 1. Sign up normally on the movie site with your email.
# 2. Promote (one time):
curl -X POST https://<backend>/api/auth/admin/bootstrap \
  -H 'Content-Type: application/json' \
  -d '{"secret":"<BOOTSTRAP_SECRET>","email":"you@example.com"}'
# 3. Remove BOOTSTRAP_SECRET from Vercel env vars and redeploy.
```

## 5. Wire the frontends

Copy `integrations/vercel-proxy/api/auth/*` into each frontend repo's `api/`
directory, set `AUTH_BACKEND_URL`, redeploy. Full guide: `docs/INTEGRATION.md`.

## 6. Optional: email

Without `RESEND_API_KEY`, accounts activate immediately and password reset
reports "not configured" honestly. To enable real emails:

1. Sign up at https://resend.com (free tier), verify a sending domain.
2. Set `RESEND_API_KEY` + `EMAIL_FROM` on the backend project, redeploy.

## Recovery

- **Lost admin access:** re-add `BOOTSTRAP_SECRET`, redeploy, call bootstrap again.
- **Rotate DB password:** update `DATABASE_URL` in Vercel, redeploy. Sessions
  survive (they live in the DB, not the password).
- **Database backup:** Neon free tier keeps 7 days of point-in-time history;
  for a manual dump: `pg_dump "$DATABASE_URL" > backup.sql`.
