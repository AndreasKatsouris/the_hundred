-- The Hundred: initial schema. Private-by-default via row level security.

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null check (char_length(display_name) between 1 and 40),
  created_at timestamptz not null default now()
);

create table public.leagues (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 60),
  invite_code text not null unique,
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now()
);

create table public.league_members (
  league_id uuid not null references public.leagues(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'member' check (role in ('owner','member')),
  joined_at timestamptz not null default now(),
  primary key (league_id, user_id)
);

create table public.played (
  user_id uuid not null references auth.users(id) on delete cascade,
  course_rank int not null check (course_rank between 1 and 100),
  played_on date,
  created_at timestamptz not null default now(),
  primary key (user_id, course_rank)
);

create table public.wishlist (
  user_id uuid not null references auth.users(id) on delete cascade,
  course_rank int not null check (course_rank between 1 and 100),
  created_at timestamptz not null default now(),
  primary key (user_id, course_rank)
);

create table public.rounds (
  id uuid primary key default gen_random_uuid(),
  league_id uuid not null references public.leagues(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  played_on date not null,
  course_rank int check (course_rank between 1 and 100),
  course_name text not null check (char_length(course_name) between 1 and 120),
  gross int not null check (gross between 30 and 200),
  points int not null check (points between 0 and 80),
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now()
);
create index rounds_league_idx on public.rounds (league_id, played_on desc);
create index league_members_user_idx on public.league_members (user_id);

-- Helpers (security definer so policies do not recurse)
create function public.is_league_member(lid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.league_members where league_id = lid and user_id = auth.uid());
$$;

create function public.is_league_owner(lid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.league_members where league_id = lid and user_id = auth.uid() and role = 'owner');
$$;

create function public.shares_league(other uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.league_members a
    join public.league_members b on a.league_id = b.league_id
    where a.user_id = auth.uid() and b.user_id = other
  );
$$;

create function public.create_league(league_name text) returns uuid
language plpgsql security definer set search_path = public as $$
declare lid uuid; code text;
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  loop
    code := upper(substr(md5(random()::text || clock_timestamp()::text), 1, 6));
    exit when not exists (select 1 from public.leagues where invite_code = code);
  end loop;
  insert into public.leagues (name, invite_code, created_by) values (league_name, code, auth.uid()) returning id into lid;
  insert into public.league_members (league_id, user_id, role) values (lid, auth.uid(), 'owner');
  return lid;
end $$;

create function public.join_league(code text) returns uuid
language plpgsql security definer set search_path = public as $$
declare lid uuid;
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  select id into lid from public.leagues where invite_code = upper(trim(code));
  if lid is null then raise exception 'invalid invite code'; end if;
  insert into public.league_members (league_id, user_id) values (lid, auth.uid()) on conflict do nothing;
  return lid;
end $$;

revoke all on function public.create_league(text), public.join_league(text) from public, anon;
grant execute on function public.create_league(text), public.join_league(text) to authenticated;

-- Row level security
alter table public.profiles enable row level security;
alter table public.leagues enable row level security;
alter table public.league_members enable row level security;
alter table public.played enable row level security;
alter table public.wishlist enable row level security;
alter table public.rounds enable row level security;

create policy profiles_select on public.profiles for select to authenticated using (id = auth.uid() or public.shares_league(id));
create policy profiles_insert on public.profiles for insert to authenticated with check (id = auth.uid());
create policy profiles_update on public.profiles for update to authenticated using (id = auth.uid()) with check (id = auth.uid());

create policy leagues_select on public.leagues for select to authenticated using (public.is_league_member(id));
create policy leagues_update on public.leagues for update to authenticated using (public.is_league_owner(id)) with check (public.is_league_owner(id));

create policy members_select on public.league_members for select to authenticated using (public.is_league_member(league_id));
create policy members_leave on public.league_members for delete to authenticated using (user_id = auth.uid() or public.is_league_owner(league_id));

-- Played is visible to people you share a league with. Wish list is private.
create policy played_select on public.played for select to authenticated using (user_id = auth.uid() or public.shares_league(user_id));
create policy played_insert on public.played for insert to authenticated with check (user_id = auth.uid());
create policy played_update on public.played for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy played_delete on public.played for delete to authenticated using (user_id = auth.uid());

create policy wishlist_all on public.wishlist for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

create policy rounds_select on public.rounds for select to authenticated using (public.is_league_member(league_id));
create policy rounds_insert on public.rounds for insert to authenticated
  with check (created_by = auth.uid() and public.is_league_member(league_id) and (user_id = auth.uid() or public.is_league_owner(league_id)));
create policy rounds_delete on public.rounds for delete to authenticated using (created_by = auth.uid() or public.is_league_owner(league_id));
