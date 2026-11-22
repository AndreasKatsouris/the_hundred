-- The Hundred: handicap (info) + matchplay results. Safe to run once; handicap lines are idempotent.

alter table public.profiles add column if not exists handicap numeric(3,1) check (handicap between -10 and 54);
alter table public.rounds add column if not exists handicap numeric(3,1) check (handicap between -10 and 54);

create table if not exists public.matches (
  id uuid primary key default gen_random_uuid(),
  league_id uuid not null references public.leagues(id) on delete cascade,
  played_on date not null,
  course_name text check (course_name is null or char_length(course_name) between 1 and 120),
  side_a uuid[] not null,
  side_b uuid[] not null,
  result text not null check (result in ('a','b','half')),
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  check (cardinality(side_a) between 1 and 2),
  check (cardinality(side_a) = cardinality(side_b)),
  check (not (side_a && side_b))
);
create index if not exists matches_league_idx on public.matches (league_id, played_on desc);

create or replace function public.league_has_all(lid uuid, ids uuid[]) returns boolean
language sql stable security definer set search_path = public as $$
  select not exists (
    select u from unnest(ids) as u
    where u not in (select user_id from public.league_members where league_id = lid)
  );
$$;

alter table public.matches enable row level security;

create policy matches_select on public.matches for select to authenticated
  using (public.is_league_member(league_id));
create policy matches_insert on public.matches for insert to authenticated
  with check (created_by = auth.uid() and public.is_league_member(league_id)
    and public.league_has_all(league_id, side_a || side_b));
create policy matches_delete on public.matches for delete to authenticated
  using (created_by = auth.uid() or public.is_league_owner(league_id));
