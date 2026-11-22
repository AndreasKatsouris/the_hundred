-- The Hundred: "The 19th Hole" notice board. Photo pins for a league, stored in a private bucket.

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('board', 'board', false, 5242880, array['image/jpeg'])
on conflict (id) do update set public = false, file_size_limit = 5242880, allowed_mime_types = array['image/jpeg'];

-- Object paths are <league_id>/<user_id>/<file>.jpg
create or replace function public.board_league(p text) returns uuid
language plpgsql immutable set search_path = public as $$
begin
  return split_part(p, '/', 1)::uuid;
exception when others then
  return null;
end $$;
grant execute on function public.board_league(text) to authenticated;

create table public.board_photos (
  id uuid primary key default gen_random_uuid(),
  league_id uuid not null references public.leagues(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  course_name text check (course_name is null or char_length(course_name) <= 120),
  caption text check (caption is null or char_length(caption) <= 140),
  play_on date,
  path text not null,
  created_at timestamptz not null default now(),
  check (path like league_id::text || '/' || user_id::text || '/%')
);
create index board_photos_league_idx on public.board_photos (league_id, created_at desc);

alter table public.board_photos enable row level security;

create policy board_photos_select on public.board_photos for select to authenticated
  using (public.is_league_member(league_id));
create policy board_photos_insert on public.board_photos for insert to authenticated
  with check (user_id = auth.uid() and public.is_league_member(league_id));
create policy board_photos_delete on public.board_photos for delete to authenticated
  using (user_id = auth.uid() or public.is_league_owner(league_id));

create policy board_obj_select on storage.objects for select to authenticated
  using (bucket_id = 'board' and public.is_league_member(public.board_league(name)));
create policy board_obj_insert on storage.objects for insert to authenticated
  with check (bucket_id = 'board' and public.is_league_member(public.board_league(name))
    and split_part(name, '/', 2) = auth.uid()::text);
create policy board_obj_delete on storage.objects for delete to authenticated
  using (bucket_id = 'board' and (split_part(name, '/', 2) = auth.uid()::text
    or public.is_league_owner(public.board_league(name))));
