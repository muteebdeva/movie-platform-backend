# Setup

## 1. Create the Supabase project

1. Sign up at https://supabase.com and create a free project.
2. Note the **Project URL** and **publishable (anon) key**:
   Project Settings → API.

## 2. Run the migration

Dashboard → SQL Editor → New query → paste the entire contents of
`supabase/migrations/001_profiles.sql` → Run. It is idempotent (safe to
re-run). This creates:

- `public.profiles` (id, display_name, is_admin, timestamps)
- RLS policies (users see/edit only their own row)
- `prevent_role_escalation` trigger (only service_role / direct DB access
  may change `is_admin`)
- `handle_new_user` trigger (auto-creates a profile on every signup)

Verify: Table Editor → profiles → RLS enabled badge.

## 3. Configure Auth URLs

Authentication → URL Configuration:

- **Site URL:** `https://muteeb-movie.vercel.app`
- **Redirect URLs:** add `https://muteeb-movie.vercel.app/**`
  (covers `#/reset-password` and `#/verify-email`)

Without these, password-reset and verification links will not return to
your site.

## 4. Email

Supabase sends verification and password-reset emails from its built-in
service. On the free tier these are rate-limited — fine for testing, but if
emails arrive late or not at all, configure a custom SMTP provider under
Project Settings → Authentication → SMTP. Do not assume delivery works at
scale without this.

Email confirmation for new sign-ups is ON by default (recommended).

## 5. Promote the first administrator

After signing up on the movie site with your email, run in the SQL Editor:

```sql
update public.profiles set is_admin = true
where id = (select id from auth.users where email = 'you@example.com');
```

Confirm with:

```sql
select u.email, p.display_name, p.is_admin, p.created_at
from auth.users u join public.profiles p on p.id = u.id
order by p.created_at desc;
```

## 6. Frontend environment variables

Set on **both** Vercel projects (`muteeb-movie`, `muteeb-movie-admin`),
Production + Preview:

- `VITE_SUPABASE_URL` = Project URL
- `VITE_SUPABASE_PUBLISHABLE_KEY` = publishable (anon) key

Redeploy both projects after setting them.

## Recovery

- **Lost admin access:** re-run the promote SQL above.
- **Revoke a user:** Dashboard → Authentication → Users → ban the user,
  and/or set `is_admin = false` for their profile row.
- **Backups:** Supabase free tier includes daily backups (7-day retention).
