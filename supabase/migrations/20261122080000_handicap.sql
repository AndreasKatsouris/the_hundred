alter table public.profiles add column if not exists handicap numeric(3,1) check (handicap between -10 and 54);
alter table public.rounds add column if not exists handicap numeric(3,1) check (handicap between -10 and 54);
