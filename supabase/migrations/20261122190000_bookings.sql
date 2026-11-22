-- The Hundred: round bookings. Anyone in a league can book a round and share it;
-- other league members can join free spots. Joining is race-safe via RPC.

create table public.bookings (
  id uuid primary key default gen_random_uuid(),
  league_id uuid not null references public.leagues(id) on delete cascade,
  owner_id uuid not null references auth.users(id),
  course_name text not null check (char_length(course_name) between 1 and 120),
  course_rank int check (course_rank between 1 and 100),
  play_on date not null,
  tee_time time not null,
  spots int not null check (spots between 2 and 8),
  is_open boolean not null default true,
  note text check (note is null or char_length(note) <= 140),
  created_at timestamptz not null default now()
);
create index bookings_league_idx on public.bookings (league_id, play_on);

create table public.booking_players (
  booking_id uuid not null references public.bookings(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  joined_at timestamptz not null default now(),
  primary key (booking_id, user_id)
);

create function public.booking_league(bid uuid) returns uuid
language sql stable security definer set search_path = public as $$
  select league_id from public.bookings where id = bid;
$$;
create function public.booking_owner(bid uuid) returns uuid
language sql stable security definer set search_path = public as $$
  select owner_id from public.bookings where id = bid;
$$;

create function public.create_booking(
  p_league uuid, p_course text, p_rank int, p_date date, p_time time,
  p_spots int, p_open boolean, p_note text, p_extras uuid[]
) returns uuid
language plpgsql security definer set search_path = public as $$
declare bid uuid; ex uuid[];
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  if not public.is_league_member(p_league) then raise exception 'not a member'; end if;
  select coalesce(array_agg(distinct e), '{}') into ex from unnest(coalesce(p_extras, '{}')) as e where e <> auth.uid();
  if 1 + cardinality(ex) > p_spots then raise exception 'too many players'; end if;
  if not public.league_has_all(p_league, ex) then raise exception 'not league members'; end if;
  insert into public.bookings (league_id, owner_id, course_name, course_rank, play_on, tee_time, spots, is_open, note)
  values (p_league, auth.uid(), p_course, p_rank, p_date, p_time, p_spots, coalesce(p_open, true), nullif(trim(coalesce(p_note, '')), ''))
  returning id into bid;
  insert into public.booking_players (booking_id, user_id)
  select bid, auth.uid() union select bid, e from unnest(ex) as e;
  return bid;
end $$;

create function public.join_booking(p_booking uuid) returns void
language plpgsql security definer set search_path = public as $$
declare b public.bookings; n int;
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  select * into b from public.bookings where id = p_booking for update;
  if not found then raise exception 'not found'; end if;
  if not public.is_league_member(b.league_id) then raise exception 'not a member'; end if;
  if exists (select 1 from public.booking_players where booking_id = p_booking and user_id = auth.uid()) then return; end if;
  if not b.is_open then raise exception 'closed'; end if;
  if b.play_on < current_date - 1 then raise exception 'past'; end if;
  select count(*) into n from public.booking_players where booking_id = p_booking;
  if n >= b.spots then raise exception 'full'; end if;
  insert into public.booking_players (booking_id, user_id) values (p_booking, auth.uid());
end $$;

revoke all on function public.booking_league(uuid), public.booking_owner(uuid),
  public.create_booking(uuid, text, int, date, time, int, boolean, text, uuid[]), public.join_booking(uuid) from public, anon;
grant execute on function public.booking_league(uuid), public.booking_owner(uuid),
  public.create_booking(uuid, text, int, date, time, int, boolean, text, uuid[]), public.join_booking(uuid) to authenticated;

alter table public.bookings enable row level security;
alter table public.booking_players enable row level security;

create policy bookings_select on public.bookings for select to authenticated using (public.is_league_member(league_id));
create policy bookings_update on public.bookings for update to authenticated using (owner_id = auth.uid()) with check (owner_id = auth.uid());
create policy bookings_delete on public.bookings for delete to authenticated using (owner_id = auth.uid() or public.is_league_owner(league_id));

-- Owners can only change open/closed and the note; everything else is fixed after creation.
revoke update on public.bookings from authenticated, anon;
grant update (is_open, note) on public.bookings to authenticated;

create policy bplayers_select on public.booking_players for select to authenticated
  using (public.is_league_member(public.booking_league(booking_id)));
create policy bplayers_delete on public.booking_players for delete to authenticated
  using ((user_id = auth.uid() and user_id <> public.booking_owner(booking_id))
      or (public.booking_owner(booking_id) = auth.uid() and user_id <> auth.uid()));
