# Frontend integration guide

Both frontends (movie site, admin panel) talk to the backend through
**same-origin proxy routes**: `your-site.com/api/auth/*` forwards to the
backend. This keeps the session cookie first-party on each domain, so Safari
and Chrome cookie policies can't break sign-in — even though the two sites
live on different Vercel domains.

## 1. Copy the proxy routes

Copy everything under `integrations/vercel-proxy/api/` into your frontend
repo's `api/` directory (same layout). Each file is ~30 lines: it forwards
the method/body to `$AUTH_BACKEND_URL`, passes the session cookie through as
a Bearer token, and on sign-in/sign-up responses sets the frontend's own
`mp_session` HttpOnly cookie (Secure in production, SameSite=Lax, Path=/).

Set `AUTH_BACKEND_URL` in each frontend's Vercel env vars.

## 2. Client helper (movie site example)

```ts
// src/lib/auth.ts
export interface AuthUser { id: string; email: string; displayName: string; emailVerified: boolean; role: string; }

async function req(path: string, init: RequestInit = {}) {
  const res = await fetch(`/api/auth${path}`, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    ...init,
  });
  const data = await res.json().catch(() => null);
  if (!res.ok || !data?.ok) throw new Error(data?.message ?? `Request failed (${res.status})`);
  return data.data;
}

export const auth = {
  me: () => req('/me') as Promise<{ user: AuthUser }>,
  signin: (email: string, password: string, remember: boolean) =>
    req('/signin', { method: 'POST', body: JSON.stringify({ email, password, remember }) }),
  signup: (displayName: string, email: string, password: string, terms: boolean) =>
    req('/signup', { method: 'POST', body: JSON.stringify({ displayName, email, password, terms }) }),
  signout: () => req('/signout', { method: 'POST' }),
  verifyEmail: (token: string) => req('/verify-email', { method: 'POST', body: JSON.stringify({ token }) }),
  requestReset: (email: string) => req('/request-password-reset', { method: 'POST', body: JSON.stringify({ email }) }),
  resetPassword: (token: string, password: string) =>
    req('/reset-password', { method: 'POST', body: JSON.stringify({ token, password }) }),
};
```

## 3. Protecting server routes (example)

```ts
// in a frontend api route:
const meRes = await fetch(`${process.env.AUTH_BACKEND_URL}/api/auth/me`, {
  headers: { cookie: req.headers.cookie ?? '' }, // forward first-party cookie
});
```

## 4. Admin panel

The admin panel keeps its existing GitHub OAuth. Add the email/password
sign-in as a second tab on the login page; after `me()` returns
`role === 'admin'`, treat the session as an admin session server-side
(verify via the backend on every privileged request — never trust a role
sent by the browser).
