-- 001_profiles.sql — user profiles linked to Supabase Auth.
--
-- Run once in the Supabase dashboard: SQL Editor -> New query -> paste -> Run.
-- Safe to re-run (all statements are idempotent).
--
-- Design:
--   * Supabase Auth owns credentials (no passwords or hashes here, ever).
--   * public.profiles holds display name + the admin flag.
--   * RLS: users can read/insert/update ONLY their own row.
--   * A trigger blocks is_admin changes except via service_role key or
--     direct database access (dashboard / psql). Ordinary users can never
--     promote themselves, even with a crafted request.

create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  display_name text not null,
  is_admin boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

drop policy if exists "profiles_select_own" on public.profiles;
create policy "profiles_select_own"
  on public.profiles for select
  using (auth.uid() = id);

drop policy if exists "profiles_insert_own" on public.profiles;
create policy "profiles_insert_own"
  on public.profiles for insert
  with check (auth.uid() = id);

drop policy if exists "profiles_update_own" on public.profiles;
create policy "profiles_update_own"
  on public.profiles for update
  using (auth.uid() = id)
  with check (auth.uid() = id);

-- Second layer of defense: no one except service_role / direct DB access
-- may flip is_admin (RLS alone can't express "all columns except this one"
-- cleanly, so the trigger enforces it).
create or replace function public.prevent_role_escalation()
returns trigger
language plpgsql
as $$
begin
  if new.is_admin is distinct from old.is_admin
     and not (auth.role() = 'service_role' or current_user = 'postgres') then
    raise exception 'changing is_admin is not permitted';
  end if;
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists profiles_no_role_escalation on public.profiles;
create trigger profiles_no_role_escalation
  before update on public.profiles
  for each row execute function public.prevent_role_escalation();

-- Auto-create a profile row on every signup (runs as owner, bypasses RLS).
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, display_name)
  values (
    new.id,
    coalesce(nullif(new.raw_user_meta_data ->> 'display_name', ''), split_part(new.email, '@', 1))
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

create index if not exists profiles_created_at_idx on public.profiles (created_at desc);

-- Promote the first administrator (run in the SQL Editor as needed):
--   update public.profiles set is_admin = true
--   where id = (select id from auth.users where email = 'you@example.com');
