-- The Hundred: review hardening (23 Nov 2026). One idempotent, re-runnable file.
-- Assumes: the five earlier migrations have run (init, handicap_matchplay, bookings, board, edit_booking).
-- Assumes: Supabase roles anon/authenticated exist and the supabase_realtime publication exists.
-- Assumes: gen_random_uuid() is available (Postgres 13+); pgcrypto is optional (falls back to uuid bytes).
-- Assumes: no client other than the v4 app calls join_league (it now returns NULL for a bad code, see below).
-- Assumes: nothing relies on owners editing leagues.created_by or leagues.invite_code directly.

-- 1. Invite codes: 10 chars from an unambiguous 32-letter alphabet (50 bits), CSPRNG source.
create or replace function public.gen_invite_code() returns text
language plpgsql volatile set search_path = public, extensions as $$
declare
  alphabet constant text := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  raw bytea; res text := ''; i int;
begin
  begin
    raw := gen_random_bytes(10);
  exception when others then
    raw := decode(substr(replace(gen_random_uuid()::text, '-', ''), 1, 20), 'hex');
  end;
  for i in 0..9 loop
    res := res || substr(alphabet, (get_byte(raw, i) % 32) + 1, 1);
  end loop;
  return res;
end $$;

create or replace function public.create_league(league_name text) returns uuid
language plpgsql security definer set search_path = public as $$
declare lid uuid; code text; nm text := btrim(coalesce(league_name, ''));
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  if char_length(nm) < 1 or char_length(nm) > 60 then raise exception 'invalid league name'; end if;
  loop
    code := public.gen_invite_code();
    exit when not exists (select 1 from public.leagues where invite_code = code);
  end loop;
  insert into public.leagues (name, invite_code, created_by) values (nm, code, auth.uid()) returning id into lid;
  insert into public.league_members (league_id, user_id, role) values (lid, auth.uid(), 'owner');
  return lid;
end $$;

-- 2. Join throttle. Failed attempts are logged; 10 failures per user per hour then 'too many attempts'.
-- An unknown code returns NULL (not an exception) so the failure row is committed and counts.
create table if not exists public.join_attempts (
  id bigint generated always as identity primary key,
  user_id uuid not null,
  at timestamptz not null default now()
);
create index if not exists join_attempts_user_idx on public.join_attempts (user_id, at desc);
alter table public.join_attempts enable row level security;
revoke all on public.join_attempts from public, anon, authenticated;

create or replace function public.join_league(code text) returns uuid
language plpgsql security definer set search_path = public as $$
declare lid uuid; c text; n int;
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  delete from public.join_attempts where at < now() - interval '1 day';
  select count(*) into n from public.join_attempts where user_id = auth.uid() and at > now() - interval '1 hour';
  if n >= 10 then raise exception 'too many attempts'; end if;
  c := upper(regexp_replace(coalesce(code, ''), '[^A-Za-z0-9]', '', 'g'));
  select id into lid from public.leagues where invite_code = c;
  if lid is null then
    insert into public.join_attempts (user_id) values (auth.uid());
    return null;
  end if;
  insert into public.league_members (league_id, user_id) values (lid, auth.uid()) on conflict do nothing;
  return lid;
end $$;

-- 3. Owner can rotate the invite code. Old code stops working immediately.
create or replace function public.regenerate_invite_code(p_league uuid) returns text
language plpgsql security definer set search_path = public as $$
declare code text;
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  if not public.is_league_owner(p_league) then raise exception 'not the owner'; end if;
  loop
    code := public.gen_invite_code();
    exit when not exists (select 1 from public.leagues where invite_code = code);
  end loop;
  update public.leagues set invite_code = code where id = p_league;
  return code;
end $$;

-- 4. Leaving a league. A member may leave; the last owner may not (it would orphan the league).
create or replace function public.league_has_other_owner(lid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.league_members where league_id = lid and role = 'owner' and user_id <> auth.uid());
$$;
drop policy if exists members_leave on public.league_members;
create policy members_leave on public.league_members for delete to authenticated using (
  (user_id = auth.uid() and (role = 'member' or public.league_has_other_owner(league_id)))
  or (public.is_league_owner(league_id) and user_id <> auth.uid())
);

-- 5. Helpers: league_has_all now requires the caller to be a member (was a membership oracle for any two uuids).
create or replace function public.league_has_all(lid uuid, ids uuid[]) returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_league_member(lid) and not exists (
    select u from unnest(ids) as u
    where u not in (select user_id from public.league_members where league_id = lid)
  );
$$;

-- 6. Leagues: owners may only rename (name). Code changes go through regenerate_invite_code.
revoke update on public.leagues from authenticated, anon;
grant update (name) on public.leagues to authenticated;

-- 7. Rounds: author or league owner may correct a round. user_id, league_id, created_by stay immutable.
drop policy if exists rounds_update on public.rounds;
create policy rounds_update on public.rounds for update to authenticated
  using (created_by = auth.uid() or public.is_league_owner(league_id))
  with check (public.is_league_member(league_id) and (created_by = auth.uid() or public.is_league_owner(league_id)));
revoke update on public.rounds from authenticated, anon;
grant update (played_on, course_rank, course_name, gross, points, handicap) on public.rounds to authenticated;

-- 8. Revoke execute from public/anon on helpers. RLS and SECURITY DEFINER callers still work:
-- policies run as the calling role, and authenticated keeps execute.
revoke all on function public.is_league_member(uuid), public.is_league_owner(uuid), public.shares_league(uuid),
  public.league_has_all(uuid, uuid[]), public.league_has_other_owner(uuid), public.board_league(text)
  from public, anon;
grant execute on function public.is_league_member(uuid), public.is_league_owner(uuid), public.shares_league(uuid),
  public.league_has_all(uuid, uuid[]), public.league_has_other_owner(uuid), public.board_league(text) to authenticated;
revoke all on function public.gen_invite_code() from public, anon, authenticated;
revoke all on function public.create_league(text), public.join_league(text), public.regenerate_invite_code(uuid) from public, anon;
grant execute on function public.create_league(text), public.join_league(text), public.regenerate_invite_code(uuid) to authenticated;

-- 9. Realtime: live league board (RLS still applies to change events).
do $$ begin alter publication supabase_realtime add table public.rounds; exception when others then null; end $$;
do $$ begin alter publication supabase_realtime add table public.matches; exception when others then null; end $$;
do $$ begin alter publication supabase_realtime add table public.bookings; exception when others then null; end $$;
do $$ begin alter publication supabase_realtime add table public.booking_players; exception when others then null; end $$;
do $$ begin alter publication supabase_realtime add table public.board_photos; exception when others then null; end $$;
