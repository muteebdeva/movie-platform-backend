-- 002_admin_system.sql — roles, notifications, audit log, moderation.
--
-- Run once in the Supabase dashboard: SQL Editor -> New query -> paste -> Run.
-- Safe to re-run (all statements are idempotent).
--
-- What this adds:
--   1. profiles.role  — 'owner' | 'admin' | 'moderator' | 'analyst' | 'user'
--      (replaces the is_admin boolean; is_admin is kept in sync by a trigger
--      for backward compatibility and will be dropped in a later cleanup).
--   2. notifications + notification_reads — in-app announcements shown in
--      the movie site's notification center.
--   3. admin_audit_log — append-only record of administrative actions.
--   4. moderation_reports + moderator_notes — abuse handling.
--
-- Security model:
--   * Role changes are blocked for everyone except service_role / postgres
--     (trigger). Ordinary users can never promote themselves.
--   * RLS: users see only their own eligible notifications; audit log and
--     moderation tables are visible only to staff roles via my_role().

-- ---------------------------------------------------------------------------
-- 1. Roles on profiles.
-- ---------------------------------------------------------------------------
alter table public.profiles
  add column if not exists role text not null default 'user'
  check (role in ('owner', 'admin', 'moderator', 'analyst', 'user'));

-- Backfill from the old boolean (idempotent: only touches rows still 'user').
update public.profiles set role = 'admin' where is_admin = true and role = 'user';

-- The project owner. (Change the email if this migration is reused elsewhere.)
update public.profiles set role = 'owner'
where id = (select id from auth.users where email = 'devamuteeb@gmail.com');

-- ---------------------------------------------------------------------------
-- 1b. Staff-role helper (security definer so RLS policies can read the
--     caller's own profile row without recursion). Defined AFTER the role
--     column exists — Postgres validates SQL function bodies at creation.
-- ---------------------------------------------------------------------------
create or replace function public.my_role()
returns text
language sql
security definer
set search_path = public
stable
as $$
  select role from public.profiles where id = auth.uid()
$$;

-- Replace the old escalation trigger: guard `role` now, keep `is_admin`
-- in sync so already-deployed code keeps working until it reads `role`.
create or replace function public.guard_profile_role()
returns trigger
language plpgsql
as $$
begin
  if new.role is distinct from old.role
     and not (auth.role() = 'service_role' or current_user = 'postgres') then
    raise exception 'changing role is not permitted';
  end if;
  -- Backward compatibility for code that still reads is_admin.
  new.is_admin := new.role in ('owner', 'admin');
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists profiles_no_role_escalation on public.profiles;
create trigger profiles_guard_role
  before update on public.profiles
  for each row execute function public.guard_profile_role();

-- ---------------------------------------------------------------------------
-- 2. Notifications.
-- ---------------------------------------------------------------------------
create table if not exists public.notifications (
  id uuid primary key default gen_random_uuid(),
  title text not null check (char_length(title) between 1 and 120),
  message text not null check (char_length(message) between 1 and 2000),
  link text,
  audience text not null default 'all' check (audience in ('all', 'selected')),
  target_user_ids uuid[] not null default '{}',
  publish_at timestamptz not null default now(),
  created_by uuid references public.profiles (id) on delete set null,
  created_at timestamptz not null default now(),
  cancelled_at timestamptz
);

alter table public.notifications enable row level security;

drop policy if exists "notifications_select_eligible" on public.notifications;
create policy "notifications_select_eligible"
  on public.notifications for select
  using (
    cancelled_at is null
    and publish_at <= now()
    and (
      audience = 'all'
      or auth.uid() = any (target_user_ids)
    )
  );
-- Writes go through service_role only (no insert/update/delete policies).

create index if not exists notifications_publish_idx
  on public.notifications (publish_at desc) where cancelled_at is null;

create table if not exists public.notification_reads (
  notification_id uuid not null references public.notifications (id) on delete cascade,
  user_id uuid not null references public.profiles (id) on delete cascade,
  read_at timestamptz not null default now(),
  primary key (notification_id, user_id)
);

alter table public.notification_reads enable row level security;

drop policy if exists "notification_reads_own" on public.notification_reads;
create policy "notification_reads_own"
  on public.notification_reads for select
  using (auth.uid() = user_id);

drop policy if exists "notification_reads_insert_own" on public.notification_reads;
create policy "notification_reads_insert_own"
  on public.notification_reads for insert
  with check (auth.uid() = user_id);

-- ---------------------------------------------------------------------------
-- 3. Admin audit log (append-only; no update/delete policies at all).
-- ---------------------------------------------------------------------------
create table if not exists public.admin_audit_log (
  id bigint generated always as identity primary key,
  admin_id uuid references public.profiles (id) on delete set null,
  admin_label text not null,
  action text not null,
  target_type text,
  target_id text,
  details jsonb not null default '{}',
  outcome text not null default 'success' check (outcome in ('success', 'failure')),
  reason text,
  created_at timestamptz not null default now()
);

alter table public.admin_audit_log enable row level security;

drop policy if exists "audit_log_select_staff" on public.admin_audit_log;
create policy "audit_log_select_staff"
  on public.admin_audit_log for select
  using (public.my_role() in ('owner', 'admin', 'analyst'));
-- Inserts happen via service_role from the admin API only. There is
-- deliberately no update or delete policy: records are immutable.

create index if not exists audit_log_created_idx
  on public.admin_audit_log (created_at desc);
create index if not exists audit_log_action_idx
  on public.admin_audit_log (action);

-- ---------------------------------------------------------------------------
-- 4. Moderation.
-- ---------------------------------------------------------------------------
create table if not exists public.moderation_reports (
  id bigint generated always as identity primary key,
  reporter_id uuid references public.profiles (id) on delete set null,
  target_user_id uuid references public.profiles (id) on delete set null,
  reason text not null check (char_length(reason) between 1 and 200),
  details text,
  status text not null default 'open'
    check (status in ('open', 'reviewing', 'resolved', 'dismissed')),
  handled_by uuid references public.profiles (id) on delete set null,
  created_at timestamptz not null default now(),
  handled_at timestamptz
);

alter table public.moderation_reports enable row level security;

drop policy if exists "reports_insert_any_user" on public.moderation_reports;
create policy "reports_insert_any_user"
  on public.moderation_reports for insert
  with check (auth.uid() = reporter_id);

drop policy if exists "reports_select_staff" on public.moderation_reports;
create policy "reports_select_staff"
  on public.moderation_reports for select
  using (public.my_role() in ('owner', 'admin', 'moderator'));
-- Status changes go through service_role from the admin API.

create index if not exists reports_status_idx
  on public.moderation_reports (status, created_at desc);

create table if not exists public.moderator_notes (
  id bigint generated always as identity primary key,
  user_id uuid not null references public.profiles (id) on delete cascade,
  admin_id uuid references public.profiles (id) on delete set null,
  note text not null check (char_length(note) between 1 and 2000),
  created_at timestamptz not null default now()
);

alter table public.moderator_notes enable row level security;

drop policy if exists "mod_notes_select_staff" on public.moderator_notes;
create policy "mod_notes_select_staff"
  on public.moderator_notes for select
  using (public.my_role() in ('owner', 'admin', 'moderator'));
-- Inserts go through service_role from the admin API (records the acting admin).

create index if not exists mod_notes_user_idx
  on public.moderator_notes (user_id, created_at desc);
