create or replace function public.get_server_time()
returns timestamptz
language sql
volatile
set search_path = pg_catalog
as $$
  select clock_timestamp();
$$;

revoke all on function public.get_server_time() from public, anon, authenticated;
grant execute on function public.get_server_time() to anon, authenticated;
