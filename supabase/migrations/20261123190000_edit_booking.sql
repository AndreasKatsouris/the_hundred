-- The Hundred: let the organiser edit a pinned round (course, date, tee time, spots, note).
-- Run once in the Supabase SQL editor. Safe to re-run.

create or replace function public.update_booking(
  p_booking uuid, p_course text, p_rank int, p_date date, p_time time, p_spots int, p_note text
) returns void
language plpgsql security definer set search_path = public as $$
declare b public.bookings; n int;
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  select * into b from public.bookings where id = p_booking for update;
  if not found then raise exception 'not found'; end if;
  if b.owner_id <> auth.uid() then raise exception 'not owner'; end if;
  if p_date <> b.play_on and p_date < current_date then raise exception 'past'; end if;
  select count(*) into n from public.booking_players where booking_id = p_booking;
  if p_spots < n then raise exception 'too few spots'; end if;
  update public.bookings set
    course_name = p_course,
    course_rank = p_rank,
    play_on = p_date,
    tee_time = p_time,
    spots = p_spots,
    note = nullif(trim(coalesce(p_note, '')), '')
  where id = p_booking;
end $$;

revoke all on function public.update_booking(uuid, text, int, date, time, int, text) from public, anon;
grant execute on function public.update_booking(uuid, text, int, date, time, int, text) to authenticated;
