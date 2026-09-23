-- DANZZ ID CHECKER - ACCESS KEY SYSTEM
-- Jalankan sekali di Supabase SQL Editor.

alter table public.customer_accounts
  add column if not exists access_key text unique,
  add column if not exists price integer not null default 10000,
  add column if not exists country text not null default 'INDONESIA',
  add column if not exists website_url text default '',
  add column if not exists is_permanent boolean not null default false;

create unique index if not exists customer_accounts_access_key_idx
  on public.customer_accounts(access_key);

create table if not exists public.site_settings (
  id integer primary key,
  website_url text not null default '',
  updated_at timestamptz not null default now()
);

alter table public.site_settings enable row level security;
drop policy if exists "site_settings_public_read" on public.site_settings;
create policy "site_settings_public_read"
on public.site_settings for select to anon, authenticated using (true);

drop policy if exists "site_settings_admin_all" on public.site_settings;
create policy "site_settings_admin_all"
on public.site_settings for all to authenticated using (true) with check (true);

insert into public.site_settings(id, website_url)
values (1, '')
on conflict (id) do nothing;

-- Generate key untuk customer lama yang belum punya key.
update public.customer_accounts
set access_key = 'DANZZGANTENG_KYT_' ||
  upper(substr(encode(gen_random_bytes(8), 'hex'), 1, 8))
where access_key is null;

-- Key login untuk website checker.
drop function if exists public.customer_key_login(text);
create or replace function public.customer_key_login(p_access_key text)
returns table(
  id uuid,
  username text,
  display_name text,
  contact text,
  plan text,
  price integer,
  country text,
  website_url text,
  starts_at timestamptz,
  expires_at timestamptz,
  is_permanent boolean,
  enabled boolean,
  access_key text
)
language sql
security definer
set search_path = public
as $$
  select
    c.id,
    c.username,
    c.display_name,
    c.contact,
    c.plan,
    c.price,
    c.country,
    c.website_url,
    c.starts_at,
    c.expires_at,
    c.is_permanent,
    c.enabled,
    c.access_key
  from public.customer_accounts c
  where upper(c.access_key) = upper(trim(p_access_key))
    and c.enabled = true
    and c.starts_at <= now()
    and (c.is_permanent = true or c.expires_at > now())
  limit 1;
$$;

grant execute on function public.customer_key_login(text) to anon, authenticated;
