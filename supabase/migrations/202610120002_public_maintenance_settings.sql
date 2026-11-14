drop policy if exists "Anyone can read platform settings" on public.platform_settings;
create policy "Anyone can read platform settings"
  on public.platform_settings
  for select
  to anon, authenticated
  using (id = 1);

grant select on table public.platform_settings to anon, authenticated;

drop function if exists public.save_platform_settings(text, text, text, text, boolean, boolean);

create or replace function public.save_platform_settings(
  requested_platform_name text,
  requested_support_email text,
  requested_whatsapp_number text,
  requested_default_plan text,
  requested_maintenance_mode boolean,
  requested_maintenance_ends_at timestamptz,
  requested_public_registration_enabled boolean
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.is_platform_admin() then
    raise exception 'Platform administrator access required';
  end if;

  insert into public.platform_settings (
    id, platform_name, support_email, whatsapp_number, default_plan,
    maintenance_mode, maintenance_ends_at, public_registration_enabled
  )
  values (
    1, trim(requested_platform_name), trim(requested_support_email),
    regexp_replace(requested_whatsapp_number, '[^0-9]', '', 'g'),
    requested_default_plan, requested_maintenance_mode,
    requested_maintenance_ends_at, requested_public_registration_enabled
  )
  on conflict (id) do update set
    platform_name = excluded.platform_name,
    support_email = excluded.support_email,
    whatsapp_number = excluded.whatsapp_number,
    default_plan = excluded.default_plan,
    maintenance_mode = excluded.maintenance_mode,
    maintenance_ends_at = excluded.maintenance_ends_at,
    public_registration_enabled = excluded.public_registration_enabled;
end;
$$;

revoke all on function public.save_platform_settings(text, text, text, text, boolean, timestamptz, boolean) from public, anon;
grant execute on function public.save_platform_settings(text, text, text, text, boolean, timestamptz, boolean) to authenticated;
