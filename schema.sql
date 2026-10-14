-- AUTODRIVE — Supabase production schema
-- Project: wuhrxoezcuxykpubldqp
-- Safe to apply through Supabase migrations.

create table if not exists public.profiles(
  id uuid primary key references auth.users(id) on delete cascade,
  name text,
  role text not null default 'contributor' check (role in ('owner','admin','contributor','viewer'))
);

create table if not exists public.docs(
  col text not null,
  id text not null,
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  primary key(col,id)
);

create or replace function public.my_role()
returns text language sql stable security definer set search_path = public
as $$ select role from public.profiles where id = auth.uid() $$;

create or replace function public.is_private(c text)
returns boolean language sql immutable set search_path = public
as $$ select c in ('txns','hold','logx','terms','owners') $$;

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public
as $$ begin
  insert into public.profiles(id,name,role) values(
    new.id,
    coalesce(new.raw_user_meta_data->>'name', new.email),
    case when exists(select 1 from public.profiles) then 'contributor' else 'owner' end
  );
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();

alter table public.profiles enable row level security;
alter table public.docs enable row level security;

drop policy if exists "profiles read" on public.profiles;
drop policy if exists "profiles owner update" on public.profiles;
drop policy if exists "docs read" on public.docs;
drop policy if exists "docs insert" on public.docs;
drop policy if exists "docs update" on public.docs;
drop policy if exists "docs delete" on public.docs;
drop policy if exists "photos read" on storage.objects;
drop policy if exists "photos write" on storage.objects;

grant select, insert, update, delete on public.profiles to authenticated;
grant select, insert, update, delete on public.docs to authenticated;
grant execute on function public.my_role() to authenticated;
grant execute on function public.is_private(text) to authenticated;
revoke execute on function public.handle_new_user() from public, anon, authenticated;
revoke execute on function public.my_role() from public, anon;
revoke execute on function public.is_private(text) from public, anon;
grant execute on function public.my_role() to authenticated;
grant execute on function public.is_private(text) to authenticated;

create policy "profiles read" on public.profiles for select to authenticated
using (id=auth.uid() or public.my_role()='owner');

create policy "profiles owner update" on public.profiles for update to authenticated
using (public.my_role()='owner') with check (public.my_role()='owner');

create policy "docs read" on public.docs for select to authenticated
using (case when public.is_private(col) then public.my_role() in ('owner','admin') else public.my_role() is not null end);

create policy "docs insert" on public.docs for insert to authenticated
with check (case when public.is_private(col) then public.my_role() in ('owner','admin') else public.my_role() in ('owner','admin','contributor') end);

create policy "docs update" on public.docs for update to authenticated
using (case when public.is_private(col) then public.my_role() in ('owner','admin') else public.my_role() in ('owner','admin','contributor') end)
with check (case when public.is_private(col) then public.my_role() in ('owner','admin') else public.my_role() in ('owner','admin','contributor') end);

create policy "docs delete" on public.docs for delete to authenticated
using (case when public.is_private(col) then public.my_role() in ('owner','admin') else public.my_role() in ('owner','admin','contributor') end);

do $$ begin
  if not exists (select 1 from pg_publication p join pg_publication_rel pr on pr.prpubid=p.oid join pg_class c on c.oid=pr.prrelid join pg_namespace n on n.oid=c.relnamespace where p.pubname='supabase_realtime' and n.nspname='public' and c.relname='docs') then
    alter publication supabase_realtime add table public.docs;
  end if;
end $$;

insert into storage.buckets(id,name,public) values('photos','photos',false) on conflict (id) do nothing;
grant select, insert on storage.objects to authenticated;

create policy "photos read" on storage.objects for select to authenticated
using (bucket_id='photos' and public.my_role() is not null);

create policy "photos write" on storage.objects for insert to authenticated
with check (bucket_id='photos' and public.my_role() in ('owner','admin','contributor'));
