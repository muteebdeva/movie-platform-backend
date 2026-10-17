# Frontend integration guide

Both frontends use `@supabase/supabase-js` directly against the shared
Supabase project. No custom backend deployment is needed.

## Client setup

```ts
import { createClient } from '@supabase/supabase-js';

export const supabase = createClient(
  import.meta.env.VITE_SUPABASE_URL,
  import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY,
);
```

## Auth operations

| Task | Call |
|---|---|
| Sign up | `supabase.auth.signUp({ email, password, options: { data: { display_name } } })` |
| Sign in | `supabase.auth.signInWithPassword({ email, password })` |
| Sign out | `supabase.auth.signOut()` |
| Session | `supabase.auth.getSession()` / `onAuthStateChange` |
| Reset request | `supabase.auth.resetPasswordForEmail(email, { redirectTo })` |
| Set new password | `supabase.auth.updateUser({ password })` |
| Own profile | `supabase.from('profiles').select('*').single()` (RLS: own row only) |

## Admin checks (server-side)

The admin panel's API routes accept either the GitHub OAuth session cookie
or a Supabase access token in the `Authorization: Bearer` header. For the
token path, the server queries `profiles` through PostgREST **with the
user's own token** — RLS guarantees the user can only ever read their own
row — and grants access only when `is_admin` is true. Authorization is
re-verified on every request; nothing about roles is trusted from the
client.

## What NOT to do

- Never request or accept `is_admin` from client input.
- Never ship the service-role key in frontend code.
- Never gate admin APIs by hiding UI components alone.
