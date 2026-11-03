-- PK STUDENT cloud schema for Supabase.
-- Run this once in the Supabase SQL Editor. Never place a service_role key in the browser.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.pk_rooms (
  id uuid primary key default gen_random_uuid(),
  room_name text not null,
  room_code_digest text not null unique,
  room_code_hash text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.pk_room_members (
  id uuid primary key default gen_random_uuid(),
  room_id uuid not null references public.pk_rooms(id) on delete cascade,
  profile_id text not null,
  display_name text not null,
  role text not null check (role in ('admin','student')),
  pin_hash text,
  auth_user_id uuid unique references auth.users(id) on delete set null,
  last_pomo_award_at timestamptz,
  created_at timestamptz not null default now(),
  unique (room_id, profile_id)
);
create unique index if not exists pk_room_member_name_unique
  on public.pk_room_members(room_id, lower(display_name));

create table if not exists public.pk_room_state (
  room_id uuid primary key references public.pk_rooms(id) on delete cascade,
  payload jsonb not null default '{"profiles":[],"tasks":[],"announcements":[]}'::jsonb,
  updated_at timestamptz not null default now()
);

alter table public.pk_rooms enable row level security;
alter table public.pk_room_members enable row level security;
alter table public.pk_room_state enable row level security;

create or replace function public.pk_is_room_member(p_room_id uuid)
returns boolean language sql stable security definer set search_path = public, auth, extensions
as $$ select exists(select 1 from public.pk_room_members m where m.room_id=p_room_id and m.auth_user_id=auth.uid()) $$;

create or replace function public.pk_is_room_admin(p_room_id uuid)
returns boolean language sql stable security definer set search_path = public, auth, extensions
as $$ select exists(select 1 from public.pk_room_members m where m.room_id=p_room_id and m.auth_user_id=auth.uid() and m.role='admin') $$;

drop policy if exists pk_rooms_member_read on public.pk_rooms;
create policy pk_rooms_member_read on public.pk_rooms for select to authenticated using (public.pk_is_room_member(id));
drop policy if exists pk_members_read on public.pk_room_members;
create policy pk_members_read on public.pk_room_members for select to authenticated using (auth_user_id=auth.uid() or public.pk_is_room_admin(room_id));
drop policy if exists pk_state_member_read on public.pk_room_state;
create policy pk_state_member_read on public.pk_room_state for select to authenticated using (public.pk_is_room_member(room_id));

revoke all on public.pk_rooms, public.pk_room_members, public.pk_room_state from anon, authenticated;
grant select on public.pk_rooms, public.pk_room_members, public.pk_room_state to authenticated;

create or replace function public.pk_create_room(
  p_room_name text, p_room_code text, p_admin_pin text, p_admin_profile_id text,
  p_admin_name text, p_payload jsonb
) returns uuid language plpgsql security definer set search_path = public, auth, extensions
as $$
declare v_room_id uuid; v_user_id uuid := auth.uid(); v_code text := upper(trim(p_room_code));
begin
  if v_user_id is null then raise exception 'Sign in is required'; end if;
  if length(v_code) < 5 or length(v_code) > 24 then raise exception 'Room code must be 5 to 24 characters'; end if;
  if length(trim(p_admin_pin)) < 6 then raise exception 'Admin PIN must be at least 6 characters'; end if;
  insert into public.pk_rooms(room_name,room_code_digest,room_code_hash)
  values(trim(p_room_name),encode(extensions.digest(v_code,'sha256'),'hex'),extensions.crypt(v_code,extensions.gen_salt('bf')))
  returning id into v_room_id;
  insert into public.pk_room_members(room_id,profile_id,display_name,role,pin_hash,auth_user_id)
  values(v_room_id,p_admin_profile_id,trim(p_admin_name),'admin',extensions.crypt(trim(p_admin_pin),extensions.gen_salt('bf')),v_user_id);
  -- Keep every app feature in the shared JSON state, but never sync local-only credentials.
  insert into public.pk_room_state(room_id,payload)
  values(v_room_id,coalesce(p_payload,'{}'::jsonb)-'adminPass');
  return v_room_id;
end $$;

create or replace function public.pk_join_room(p_room_code text,p_display_name text,p_pin text)
returns jsonb language plpgsql security definer set search_path = public, auth, extensions
as $$
declare v_uid uuid := auth.uid(); v_room public.pk_rooms%rowtype; v_member public.pk_room_members%rowtype;
begin
  if v_uid is null then raise exception 'Sign in is required'; end if;
  select * into v_room from public.pk_rooms r
  where r.room_code_digest=encode(extensions.digest(upper(trim(p_room_code)),'sha256'),'hex')
    and extensions.crypt(upper(trim(p_room_code)),r.room_code_hash)=r.room_code_hash;
  if not found then raise exception 'Room code was not found'; end if;
  select * into v_member from public.pk_room_members m
  where m.room_id=v_room.id and lower(m.display_name)=lower(trim(p_display_name)) and m.role='student'
    and m.pin_hash is not null and extensions.crypt(trim(p_pin),m.pin_hash)=m.pin_hash;
  if not found then raise exception 'Name or member PIN is incorrect'; end if;
  if v_member.auth_user_id is not null and v_member.auth_user_id<>v_uid then
    raise exception 'This profile is linked to another device; ask the admin to reset access';
  end if;
  update public.pk_room_members set auth_user_id=v_uid where id=v_member.id;
  return jsonb_build_object('room_id',v_room.id,'profile_id',v_member.profile_id,'role','student');
end $$;

create or replace function public.pk_admin_login(p_room_code text,p_admin_name text,p_pin text)
returns jsonb language plpgsql security definer set search_path = public, auth, extensions
as $$
declare v_uid uuid := auth.uid(); v_room public.pk_rooms%rowtype; v_member public.pk_room_members%rowtype;
begin
  if v_uid is null then raise exception 'Sign in is required'; end if;
  select * into v_room from public.pk_rooms r
  where r.room_code_digest=encode(extensions.digest(upper(trim(p_room_code)),'sha256'),'hex')
    and extensions.crypt(upper(trim(p_room_code)),r.room_code_hash)=r.room_code_hash;
  if not found then raise exception 'Room code was not found'; end if;
  select * into v_member from public.pk_room_members m
  where m.room_id=v_room.id and lower(m.display_name)=lower(trim(p_admin_name)) and m.role='admin'
    and m.pin_hash is not null and extensions.crypt(trim(p_pin),m.pin_hash)=m.pin_hash;
  if not found then raise exception 'Admin name or PIN is incorrect'; end if;
  update public.pk_room_members set auth_user_id=null where room_id=v_room.id and role='admin' and auth_user_id<>v_uid;
  update public.pk_room_members set auth_user_id=v_uid where id=v_member.id;
  return jsonb_build_object('room_id',v_room.id,'profile_id',v_member.profile_id,'role','admin');
end $$;

create or replace function public.pk_register_member(p_room_id uuid,p_profile_id text,p_display_name text,p_pin text)
returns void language plpgsql security definer set search_path = public, auth, extensions
as $$
begin
  if not public.pk_is_room_admin(p_room_id) then raise exception 'Admin access required'; end if;
  if length(trim(p_pin)) < 4 or length(trim(p_pin)) > 12 then raise exception 'Member PIN must be 4 to 12 characters'; end if;
  insert into public.pk_room_members(room_id,profile_id,display_name,role,pin_hash)
  values(p_room_id,p_profile_id,trim(p_display_name),'student',extensions.crypt(trim(p_pin),extensions.gen_salt('bf')))
  on conflict(room_id,profile_id) do update set display_name=excluded.display_name,pin_hash=excluded.pin_hash,auth_user_id=null;
end $$;

create or replace function public.pk_reset_member_access(p_room_id uuid,p_profile_id text,p_new_pin text)
returns void language plpgsql security definer set search_path = public, auth, extensions
as $$
begin
  if not public.pk_is_room_admin(p_room_id) then raise exception 'Admin access required'; end if;
  if length(trim(p_new_pin)) < 4 or length(trim(p_new_pin)) > 12 then raise exception 'Member PIN must be 4 to 12 characters'; end if;
  update public.pk_room_members set auth_user_id=null,pin_hash=extensions.crypt(trim(p_new_pin),extensions.gen_salt('bf'))
  where room_id=p_room_id and profile_id=p_profile_id and role='student';
  if not found then raise exception 'Member was not found'; end if;
end $$;

create or replace function public.pk_remove_member(p_room_id uuid,p_profile_id text)
returns void language plpgsql security definer set search_path = public, auth, extensions
as $$
begin
  if not public.pk_is_room_admin(p_room_id) then raise exception 'Admin access required'; end if;
  delete from public.pk_room_members where room_id=p_room_id and profile_id=p_profile_id and role='student';
end $$;

create or replace function public.pk_publish_room_state(p_room_id uuid,p_payload jsonb)
returns void language plpgsql security definer set search_path = public, auth, extensions
as $$
declare v_old jsonb; v_profiles jsonb; v_tasks jsonb; v_payload jsonb;
begin
  if not public.pk_is_room_admin(p_room_id) then raise exception 'Admin access required'; end if;
  select payload into v_old from public.pk_room_state where room_id=p_room_id for update;
  select coalesce(jsonb_agg(n.obj || jsonb_build_object(
      'points',coalesce(o.obj->'points',n.obj->'points','0'::jsonb),
      'pomoCount',coalesce(o.obj->'pomoCount',n.obj->'pomoCount','0'::jsonb),
      'rewardedTaskIds',coalesce(o.obj->'rewardedTaskIds',n.obj->'rewardedTaskIds','[]'::jsonb)
    ) order by n.ord),'[]'::jsonb)
    into v_profiles
    from jsonb_array_elements(coalesce(p_payload->'profiles','[]'::jsonb)) with ordinality n(obj,ord)
    left join lateral (select x.obj from jsonb_array_elements(coalesce(v_old->'profiles','[]'::jsonb)) x(obj) where x.obj->>'id'=n.obj->>'id' limit 1) o on true;
  select coalesce(jsonb_agg(n.obj || jsonb_build_object(
      'doneBy',coalesce(o.obj->'doneBy',n.obj->'doneBy','[]'::jsonb),
      'doneAt',coalesce(o.obj->'doneAt',n.obj->'doneAt','{}'::jsonb)
    ) order by n.ord),'[]'::jsonb)
    into v_tasks
    from jsonb_array_elements(coalesce(p_payload->'tasks','[]'::jsonb)) with ordinality n(obj,ord)
    left join lateral (select x.obj from jsonb_array_elements(coalesce(v_old->'tasks','[]'::jsonb)) x(obj) where x.obj->>'id'=n.obj->>'id' limit 1) o on true;
  v_payload:=jsonb_build_object('profiles',v_profiles,'tasks',v_tasks,'announcements',coalesce(p_payload->'announcements','[]'::jsonb));
  update public.pk_room_state set payload=v_payload,updated_at=now() where room_id=p_room_id;
end $$;

create or replace function public.pk_set_task_completion(p_room_id uuid,p_task_id text,p_done boolean)
returns jsonb language plpgsql security definer set search_path = public, auth, extensions
as $$
declare
  v_member public.pk_room_members%rowtype; v_state jsonb; v_tasks jsonb; v_profiles jsonb;
  v_task jsonb; v_doneby jsonb; v_doneat jsonb; v_profile jsonb; v_profile_ix integer;
begin
  select * into v_member from public.pk_room_members
    where room_id=p_room_id and auth_user_id=auth.uid() and role='student';
  if not found then raise exception 'Student room access required'; end if;
  select payload into v_state from public.pk_room_state where room_id=p_room_id for update;
  select obj into v_task from jsonb_array_elements(coalesce(v_state->'tasks','[]'::jsonb)) x(obj) where obj->>'id'=p_task_id;
  if v_task is null then raise exception 'Task was not found'; end if;
  if v_task->>'owner' <> 'all' and v_task->>'owner' <> v_member.profile_id then raise exception 'This task is not assigned to this member'; end if;
  v_doneby:=coalesce(v_task->'doneBy','[]'::jsonb);
  if p_done and not (v_doneby ? v_member.profile_id) then v_doneby:=v_doneby||jsonb_build_array(v_member.profile_id); end if;
  if not p_done and (v_doneby ? v_member.profile_id) then
    select coalesce(jsonb_agg(to_jsonb(value)),'[]'::jsonb) into v_doneby
    from jsonb_array_elements_text(v_doneby) e(value) where value<>v_member.profile_id;
  end if;
  v_doneat:=coalesce(v_task->'doneAt','{}'::jsonb);
  if p_done then v_doneat:=v_doneat||jsonb_build_object(v_member.profile_id,extract(epoch from now())*1000); else v_doneat:=v_doneat-v_member.profile_id; end if;
  select coalesce(jsonb_agg(case when obj->>'id'=p_task_id then jsonb_set(jsonb_set(obj,'{doneBy}',v_doneby,true),'{doneAt}',v_doneat,true) else obj end order by ord),'[]'::jsonb)
    into v_tasks from jsonb_array_elements(coalesce(v_state->'tasks','[]'::jsonb)) with ordinality x(obj,ord);
  v_profiles:=coalesce(v_state->'profiles','[]'::jsonb);
  select ordinality::integer-1 into v_profile_ix from jsonb_array_elements(v_profiles) with ordinality x(obj,ordinality)
    where obj->>'id'=v_member.profile_id limit 1;
  if p_done and v_profile_ix is not null then
    v_profile:=v_profiles->v_profile_ix;
    if not (coalesce(v_profile->'rewardedTaskIds','[]'::jsonb) ? p_task_id) then
      v_profile:=jsonb_set(v_profile,'{points}',to_jsonb(coalesce((v_profile->>'points')::integer,0)+10),true);
      v_profile:=jsonb_set(v_profile,'{rewardedTaskIds}',coalesce(v_profile->'rewardedTaskIds','[]'::jsonb)||jsonb_build_array(p_task_id),true);
      select jsonb_agg(case when ordinality::integer-1=v_profile_ix then v_profile else obj end order by ordinality)
        into v_profiles from jsonb_array_elements(v_profiles) with ordinality x(obj,ordinality);
    end if;
  end if;
  update public.pk_room_state set payload=jsonb_set(jsonb_set(v_state,'{tasks}',v_tasks,true),'{profiles}',v_profiles,true),updated_at=now() where room_id=p_room_id;
  return (select payload from public.pk_room_state where room_id=p_room_id);
end $$;

create or replace function public.pk_award_pomodoro(p_room_id uuid)
returns jsonb language plpgsql security definer set search_path = public, auth, extensions
as $$
declare v_member public.pk_room_members%rowtype; v_state jsonb; v_profiles jsonb; v_profile jsonb; v_ix integer;
begin
  select * into v_member from public.pk_room_members
    where room_id=p_room_id and auth_user_id=auth.uid() and role='student' for update;
  if not found then raise exception 'Student room access required'; end if;
  if v_member.last_pomo_award_at is not null and v_member.last_pomo_award_at>now()-interval '24 minutes'
    then raise exception 'A focus reward was already claimed recently'; end if;
  select payload into v_state from public.pk_room_state where room_id=p_room_id for update;
  select ordinality::integer-1 into v_ix from jsonb_array_elements(coalesce(v_state->'profiles','[]'::jsonb)) with ordinality x(obj,ordinality)
    where obj->>'id'=v_member.profile_id limit 1;
  if v_ix is null then raise exception 'Member profile was not found'; end if;
  v_profiles:=v_state->'profiles'; v_profile:=v_profiles->v_ix;
  v_profile:=jsonb_set(v_profile,'{pomoCount}',to_jsonb(coalesce((v_profile->>'pomoCount')::integer,0)+1),true);
  v_profile:=jsonb_set(v_profile,'{points}',to_jsonb(coalesce((v_profile->>'points')::integer,0)+15),true);
  select jsonb_agg(case when ordinality::integer-1=v_ix then v_profile else obj end order by ordinality)
    into v_profiles from jsonb_array_elements(v_profiles) with ordinality x(obj,ordinality);
  update public.pk_room_members set last_pomo_award_at=now() where id=v_member.id;
  update public.pk_room_state set payload=jsonb_set(v_state,'{profiles}',v_profiles,true),updated_at=now() where room_id=p_room_id;
  return (select payload from public.pk_room_state where room_id=p_room_id);
end $$;

revoke all on function public.pk_create_room(text,text,text,text,text,jsonb) from public, anon;
revoke all on function public.pk_join_room(text,text,text) from public, anon;
revoke all on function public.pk_admin_login(text,text,text) from public, anon;
revoke all on function public.pk_register_member(uuid,text,text,text) from public, anon;
revoke all on function public.pk_reset_member_access(uuid,text,text) from public, anon;
revoke all on function public.pk_remove_member(uuid,text) from public, anon;
revoke all on function public.pk_publish_room_state(uuid,jsonb) from public, anon;
revoke all on function public.pk_set_task_completion(uuid,text,boolean) from public, anon;
revoke all on function public.pk_award_pomodoro(uuid) from public, anon;
grant execute on function public.pk_create_room(text,text,text,text,text,jsonb) to authenticated;
grant execute on function public.pk_join_room(text,text,text) to authenticated;
grant execute on function public.pk_admin_login(text,text,text) to authenticated;
grant execute on function public.pk_register_member(uuid,text,text,text) to authenticated;
grant execute on function public.pk_reset_member_access(uuid,text,text) to authenticated;
grant execute on function public.pk_remove_member(uuid,text) to authenticated;
grant execute on function public.pk_publish_room_state(uuid,jsonb) to authenticated;
grant execute on function public.pk_set_task_completion(uuid,text,boolean) to authenticated;
grant execute on function public.pk_award_pomodoro(uuid) to authenticated;

