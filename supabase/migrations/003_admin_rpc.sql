-- 003_admin_rpc.sql — privileged admin operations as security-definer functions.
--
-- Why this exists: the admin panel's serverless functions run without the
-- Supabase service-role key (deliberately — the key is never shared). Instead,
-- privileged operations live here as SECURITY DEFINER functions owned by
-- postgres. Each function:
--   1. reads the caller's identity from the request JWT (auth.uid()),
--   2. checks the caller's staff role via public.my_role(),
--   3. raises 'forbidden' for anyone without the required role,
--   4. writes an audit record into public.admin_audit_log.
--
-- The JWT is validated by PostgREST before the function ever runs, so
-- auth.uid() cannot be forged. search_path is locked to prevent hijacking.
-- Only safe columns of auth.users are ever returned (no password hashes,
-- no tokens). Grant is EXECUTE to `authenticated` only — anonymous callers
-- cannot reach these functions at all.
--
-- Run after 002. Safe to re-run (all statements are idempotent).

-- The endpoint role check calls this directly; it must be executable.
grant execute on function public.my_role() to authenticated;

-- Staff need to read all notifications (not just eligible ones) and read
-- receipts for the admin panel. Ordinary users are unaffected.
drop policy if exists "notifications_select_staff" on public.notifications;
create policy "notifications_select_staff"
  on public.notifications for select
  using (public.my_role() in ('owner', 'admin'));

drop policy if exists "notification_reads_select_staff" on public.notification_reads;
create policy "notification_reads_select_staff"
  on public.notification_reads for select
  using (public.my_role() in ('owner', 'admin'));

-- ---------------------------------------------------------------------------
-- Internal: write an audit record for the calling admin.
-- Callable by staff (owner/admin/moderator/analyst) so API endpoints can log
-- actions that don't go through another privileged function (e.g. password
-- reset emails). Ordinary users are rejected.
-- ---------------------------------------------------------------------------
create or replace function public.admin_audit(
  p_action text,
  p_target_type text,
  p_target_id text,
  p_details jsonb,
  p_outcome text,
  p_reason text
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_label text;
  v_role text;
begin
  select display_name, role into v_label, v_role from public.profiles where id = v_uid;
  if coalesce(v_role, '') not in ('owner', 'admin', 'moderator', 'analyst') then
    raise exception 'forbidden';
  end if;
  insert into public.admin_audit_log (admin_id, admin_label, action, target_type, target_id, details, outcome, reason)
  values (v_uid, coalesce(v_label, 'unknown') || ' (' || coalesce(v_role, '?') || ')',
          p_action, p_target_type, p_target_id, coalesce(p_details, '{}'), p_outcome, p_reason);
end;
$$;
grant execute on function public.admin_audit(text, text, text, jsonb, text, text) to authenticated;

-- ---------------------------------------------------------------------------
-- List users (safe columns only). Roles: owner, admin, moderator.
-- ---------------------------------------------------------------------------
create or replace function public.admin_list_users()
returns table (
  id uuid,
  email text,
  display_name text,
  role text,
  created_at timestamptz,
  last_sign_in_at timestamptz,
  email_confirmed_at timestamptz,
  banned_until timestamptz
)
language plpgsql
security definer
set search_path = public
stable
as $$
begin
  if coalesce(public.my_role(), '') not in ('owner', 'admin', 'moderator') then
    raise exception 'forbidden';
  end if;
  return query
    select u.id,
           u.email::text,
           coalesce(p.display_name, split_part(u.email, '@', 1))::text,
           coalesce(p.role, 'user')::text,
           u.created_at,
           u.last_sign_in_at,
           u.email_confirmed_at,
           u.banned_until
    from auth.users u
    left join public.profiles p on p.id = u.id
    order by u.created_at desc
    limit 5000;
end;
$$;
grant execute on function public.admin_list_users() to authenticated;

-- ---------------------------------------------------------------------------
-- Set a user's role. Role: owner only. Cannot change your own role.
-- ---------------------------------------------------------------------------
create or replace function public.admin_set_role(p_target_id uuid, p_new_role text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_old text;
begin
  if coalesce(public.my_role(), '') <> 'owner' then
    raise exception 'forbidden';
  end if;
  if p_new_role not in ('owner', 'admin', 'moderator', 'analyst', 'user') then
    raise exception 'invalid role';
  end if;
  if p_target_id = auth.uid() then
    raise exception 'cannot change your own role';
  end if;
  select role into v_old from public.profiles where id = p_target_id;
  if not found then
    raise exception 'user not found';
  end if;
  -- Runs as postgres, so the guard trigger's service_role/postgres check passes.
  update public.profiles set role = p_new_role where id = p_target_id;
  perform public.admin_audit('users.set_role', 'user', p_target_id::text,
    jsonb_build_object('from', v_old, 'to', p_new_role), 'success', null);
end;
$$;
grant execute on function public.admin_set_role(uuid, text) to authenticated;

-- ---------------------------------------------------------------------------
-- Ban / suspend / unban. Roles: owner, admin, moderator.
-- Staff accounts can only be acted on by the owner; never yourself.
-- ---------------------------------------------------------------------------
create or replace function public.admin_ban_user(p_target_id uuid, p_ban_hours int, p_reason text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_caller_role text := public.my_role();
  v_target_role text;
begin
  if coalesce(v_caller_role, '') not in ('owner', 'admin', 'moderator') then
    raise exception 'forbidden';
  end if;
  if p_target_id = auth.uid() then
    raise exception 'cannot act on your own account';
  end if;
  select role into v_target_role from public.profiles where id = p_target_id;
  if v_target_role is null then
    raise exception 'user not found';
  end if;
  if v_caller_role <> 'owner' and v_target_role in ('owner', 'admin', 'moderator', 'analyst') then
    raise exception 'only the owner can act on staff accounts';
  end if;
  if p_ban_hours is null or p_ban_hours < 1 then
    raise exception 'ban duration must be at least 1 hour';
  end if;
  update auth.users
    set banned_until = now() + (least(p_ban_hours, 876000) || ' hours')::interval
    where id = p_target_id;
  perform public.admin_audit(
    case when p_ban_hours >= 876000 then 'users.ban' else 'users.suspend' end,
    'user', p_target_id::text,
    jsonb_build_object('ban_hours', least(p_ban_hours, 876000)),
    'success', nullif(p_reason, ''));
end;
$$;
grant execute on function public.admin_ban_user(uuid, int, text) to authenticated;

create or replace function public.admin_unban_user(p_target_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_caller_role text := public.my_role();
  v_target_role text;
begin
  if coalesce(v_caller_role, '') not in ('owner', 'admin', 'moderator') then
    raise exception 'forbidden';
  end if;
  select role into v_target_role from public.profiles where id = p_target_id;
  if v_target_role is null then
    raise exception 'user not found';
  end if;
  if v_caller_role <> 'owner' and v_target_role in ('owner', 'admin', 'moderator', 'analyst') then
    raise exception 'only the owner can act on staff accounts';
  end if;
  update auth.users set banned_until = null where id = p_target_id;
  perform public.admin_audit('users.unban', 'user', p_target_id::text, '{}', 'success', null);
end;
$$;
grant execute on function public.admin_unban_user(uuid) to authenticated;

-- ---------------------------------------------------------------------------
-- Delete an account (auth.users; cascades to the profile).
-- Roles: owner (anyone but self), admin (non-staff only, not self).
-- ---------------------------------------------------------------------------
create or replace function public.admin_delete_user(p_target_id uuid, p_reason text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_caller_role text := public.my_role();
  v_target_role text;
begin
  if coalesce(v_caller_role, '') not in ('owner', 'admin') then
    raise exception 'forbidden';
  end if;
  if p_target_id = auth.uid() then
    raise exception 'cannot delete your own account';
  end if;
  select role into v_target_role from public.profiles where id = p_target_id;
  if v_target_role is null then
    raise exception 'user not found';
  end if;
  if v_target_role in ('owner', 'admin', 'moderator', 'analyst') and v_caller_role <> 'owner' then
    raise exception 'only the owner can delete staff accounts';
  end if;
  if v_target_role = 'owner' then
    raise exception 'the owner account cannot be deleted';
  end if;
  delete from auth.users where id = p_target_id;
  perform public.admin_audit('users.delete', 'user', p_target_id::text,
    jsonb_build_object('role', v_target_role), 'success', nullif(p_reason, ''));
end;
$$;
grant execute on function public.admin_delete_user(uuid, text) to authenticated;

-- ---------------------------------------------------------------------------
-- Sign a user out of all sessions. Roles: owner, admin, moderator.
-- ---------------------------------------------------------------------------
create or replace function public.admin_signout_user(p_target_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_caller_role text := public.my_role();
begin
  if coalesce(v_caller_role, '') not in ('owner', 'admin', 'moderator') then
    raise exception 'forbidden';
  end if;
  if p_target_id = auth.uid() then
    raise exception 'cannot act on your own account';
  end if;
  delete from auth.sessions where user_id = p_target_id;
  perform public.admin_audit('users.signout_sessions', 'user', p_target_id::text, '{}', 'success', null);
end;
$$;
grant execute on function public.admin_signout_user(uuid) to authenticated;

-- ---------------------------------------------------------------------------
-- Notifications. Roles: owner, admin.
-- ---------------------------------------------------------------------------
create or replace function public.admin_create_notification(
  p_title text, p_message text, p_link text, p_audience text,
  p_target_ids uuid[], p_publish_at timestamptz
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_id uuid;
begin
  if coalesce(public.my_role(), '') not in ('owner', 'admin') then
    raise exception 'forbidden';
  end if;
  if p_title is null or char_length(p_title) = 0 or char_length(p_title) > 120 then
    raise exception 'title is required (max 120 chars)';
  end if;
  if p_message is null or char_length(p_message) = 0 or char_length(p_message) > 2000 then
    raise exception 'message is required (max 2000 chars)';
  end if;
  if p_audience not in ('all', 'selected') then
    raise exception 'invalid audience';
  end if;
  if p_audience = 'selected' and (p_target_ids is null or array_length(p_target_ids, 1) is null) then
    raise exception 'selected audience needs target user ids';
  end if;
  insert into public.notifications (title, message, link, audience, target_user_ids, publish_at, created_by)
  values (p_title, p_message, nullif(p_link, ''), p_audience,
          coalesce(p_target_ids, '{}'),
          coalesce(p_publish_at, now()), auth.uid())
  returning id into v_id;
  perform public.admin_audit('notifications.create', 'notification', v_id::text,
    jsonb_build_object('title', p_title, 'audience', p_audience), 'success', null);
  return v_id;
end;
$$;
grant execute on function public.admin_create_notification(text, text, text, text, uuid[], timestamptz) to authenticated;

create or replace function public.admin_set_notification_state(p_notif_id uuid, p_op text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if coalesce(public.my_role(), '') not in ('owner', 'admin') then
    raise exception 'forbidden';
  end if;
  if p_op = 'publish' then
    update public.notifications set publish_at = now(), cancelled_at = null where id = p_notif_id;
  elsif p_op = 'cancel' then
    update public.notifications set cancelled_at = now() where id = p_notif_id;
  else
    raise exception 'invalid op';
  end if;
  if not found then
    raise exception 'notification not found';
  end if;
  perform public.admin_audit('notifications.' || p_op, 'notification', p_notif_id::text, '{}', 'success', null);
end;
$$;
grant execute on function public.admin_set_notification_state(uuid, text) to authenticated;

-- ---------------------------------------------------------------------------
-- Moderator note on a user. Roles: owner, admin, moderator.
-- ---------------------------------------------------------------------------
create or replace function public.admin_add_note(p_target_id uuid, p_note text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if coalesce(public.my_role(), '') not in ('owner', 'admin', 'moderator') then
    raise exception 'forbidden';
  end if;
  if p_note is null or char_length(trim(p_note)) = 0 or char_length(p_note) > 2000 then
    raise exception 'note text is required (max 2000 chars)';
  end if;
  insert into public.moderator_notes (user_id, admin_id, note)
  values (p_target_id, auth.uid(), trim(p_note));
  perform public.admin_audit('users.add_note', 'user', p_target_id::text, '{}', 'success', null);
end;
$$;
grant execute on function public.admin_add_note(uuid, text) to authenticated;

-- ---------------------------------------------------------------------------
-- Update a moderation report. Roles: owner, admin, moderator.
-- ---------------------------------------------------------------------------
create or replace function public.admin_update_report(p_report_id bigint, p_status text, p_note text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_login text;
begin
  if coalesce(public.my_role(), '') not in ('owner', 'admin', 'moderator') then
    raise exception 'forbidden';
  end if;
  if p_status not in ('open', 'reviewing', 'resolved', 'dismissed') then
    raise exception 'invalid status';
  end if;
  select display_name into v_login from public.profiles where id = auth.uid();
  update public.moderation_reports
    set status = p_status,
        handled_by = auth.uid(),
        handled_at = now(),
        details = case
          when p_note is not null and char_length(trim(p_note)) > 0
          then coalesce(details, '') || chr(10) || '[' || coalesce(v_login, 'staff') || '] ' || trim(p_note)
          else details
        end
    where id = p_report_id;
  if not found then
    raise exception 'report not found';
  end if;
  perform public.admin_audit('reports.update', 'report', p_report_id::text,
    jsonb_build_object('status', p_status), 'success', null);
end;
$$;
grant execute on function public.admin_update_report(bigint, text, text) to authenticated;
