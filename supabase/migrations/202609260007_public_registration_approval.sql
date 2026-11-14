alter table public.platform_settings
  add column if not exists public_registration_enabled boolean not null default false;

drop function if exists public.save_platform_settings(text, text, text, text, boolean);

create or replace function public.save_platform_settings(
  requested_platform_name text,
  requested_support_email text,
  requested_whatsapp_number text,
  requested_default_plan text,
  requested_maintenance_mode boolean,
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
    maintenance_mode, public_registration_enabled
  )
  values (
    1, trim(requested_platform_name), trim(requested_support_email),
    regexp_replace(requested_whatsapp_number, '[^0-9]', '', 'g'),
    requested_default_plan, requested_maintenance_mode,
    requested_public_registration_enabled
  )
  on conflict (id) do update set
    platform_name = excluded.platform_name,
    support_email = excluded.support_email,
    whatsapp_number = excluded.whatsapp_number,
    default_plan = excluded.default_plan,
    maintenance_mode = excluded.maintenance_mode,
    public_registration_enabled = excluded.public_registration_enabled;
end;
$$;

revoke all on function public.save_platform_settings(text, text, text, text, boolean, boolean) from public, anon;
grant execute on function public.save_platform_settings(text, text, text, text, boolean, boolean) to authenticated;

create or replace function public.submit_public_business_registration(
  requested_owner_name text,
  requested_business_name text,
  requested_email text,
  requested_username text,
  requested_password_hash text,
  requested_industry text,
  requested_plan text
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  normalized_username text := lower(trim(requested_username));
  expected_auth_email text;
  registration_enabled boolean;
  selected_package jsonb;
  package_seats integer;
  package_price numeric;
  package_duration integer;
  package_duration_unit text;
  account_status text;
  account_id bigint;
  account_tenant_id text;
begin
  if auth.uid() is null then
    raise exception 'Sign in was not established. Disable email confirmation for username-based accounts and try again.';
  end if;
  if nullif(trim(requested_owner_name), '') is null
    or nullif(trim(requested_business_name), '') is null
    or nullif(trim(requested_industry), '') is null
    or length(normalized_username) < 3
    or coalesce(requested_password_hash, '') !~ '^\$2[aby]\$[0-9]{2}\$' then
    raise exception 'Required business details are missing or invalid';
  end if;

  expected_auth_email := case
    when lower(normalized_username) ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then normalized_username
    else 'u-' || encode(convert_to(normalized_username, 'UTF8'), 'hex') || '@biztrack.app'
  end;
  if lower(coalesce(auth.jwt() ->> 'email', '')) <> expected_auth_email then
    raise exception 'The signed-in account does not match this registration';
  end if;
  if exists (select 1 from public.business_accounts where lower(username) = normalized_username) then
    raise exception 'This username is already in use';
  end if;

  select coalesce(settings.public_registration_enabled, false)
  into registration_enabled
  from public.platform_settings settings
  where settings.id = 1;
  account_status := case when coalesce(registration_enabled, false) then 'Active' else 'Trial' end;

  select package.value into selected_package
  from public.site_admin_snapshots snapshot
  cross join lateral jsonb_array_elements(
    case when jsonb_typeof(snapshot.payload -> 'packages') = 'array' then snapshot.payload -> 'packages' else '[]'::jsonb end
  ) package(value)
  where snapshot.id = 1
    and lower(package.value ->> 'name') = lower(trim(requested_plan))
    and coalesce((package.value ->> 'active')::boolean, true)
  limit 1;

  if selected_package is null then
    if requested_plan not in ('Starter', 'Growth', 'Scale') then
      raise exception 'The selected package is not available';
    end if;
    package_seats := case requested_plan when 'Starter' then 5 when 'Growth' then 12 else 30 end;
    package_price := case requested_plan when 'Starter' then 29 when 'Growth' then 79 else 149 end;
    package_duration := 1;
    package_duration_unit := 'month';
  else
    package_seats := greatest(1, coalesce((selected_package ->> 'seats')::integer, 1));
    package_price := greatest(0, coalesce((selected_package ->> 'price')::numeric, 0));
    package_duration := greatest(1, coalesce((selected_package ->> 'duration')::integer, 1));
    package_duration_unit := coalesce(selected_package ->> 'durationUnit', 'month');
  end if;

  account_id := floor(extract(epoch from clock_timestamp()) * 1000000)::bigint;
  account_tenant_id := 'tenant-' || account_id::text;
  insert into public.business_accounts (
    id, business_name, owner_name, email, username, password, industry,
    plan, status, seats, monthly_price, next_billing, created_at, tenant_id
  ) values (
    account_id, trim(requested_business_name), trim(requested_owner_name),
    trim(requested_email), normalized_username, requested_password_hash,
    trim(requested_industry), trim(requested_plan), account_status,
    package_seats, package_price,
    current_date + case package_duration_unit
      when 'year' then package_duration * 365
      when 'week' then package_duration * 7
      when 'day' then package_duration
      else package_duration * 30
    end,
    current_date, account_tenant_id
  );

  return jsonb_build_object(
    'id', account_id,
    'tenant_id', account_tenant_id,
    'business_name', trim(requested_business_name),
    'owner_name', trim(requested_owner_name),
    'email', trim(requested_email),
    'username', normalized_username,
    'industry', trim(requested_industry),
    'plan', trim(requested_plan),
    'status', account_status,
    'seats', package_seats,
    'monthly_price', package_price,
    'next_billing', current_date + case package_duration_unit
      when 'year' then package_duration * 365
      when 'week' then package_duration * 7
      when 'day' then package_duration
      else package_duration * 30
    end,
    'created_at', current_date
  );
end;
$$;

revoke all on function public.submit_public_business_registration(text, text, text, text, text, text, text) from public;
grant execute on function public.submit_public_business_registration(text, text, text, text, text, text, text) to anon, authenticated;

create or replace function public.claim_owner_account(requested_username text, requested_password text)
returns boolean
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  normalized_username text := lower(trim(requested_username));
  expected_email text;
  matched_account public.business_accounts%rowtype;
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;
  expected_email := case
    when normalized_username ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then normalized_username
    else 'u-' || encode(convert_to(normalized_username, 'UTF8'), 'hex') || '@biztrack.app'
  end;
  if lower(coalesce(auth.jwt() ->> 'email', '')) <> expected_email then
    raise exception 'Owner identity does not match';
  end if;

  select * into matched_account
  from public.business_accounts account
  where lower(account.username) = normalized_username
    and account.status = 'Active'
    and (account.next_billing is null or account.next_billing >= current_date)
    and crypt(requested_password, account.password) = account.password
  limit 1;
  if not found then
    raise exception 'Invalid credentials, account pending activation, or subscription unavailable';
  end if;

  insert into public.tenant_memberships (user_id, tenant_id, role)
  values (auth.uid(), matched_account.tenant_id, 'owner')
  on conflict (user_id, tenant_id) do update set role = 'owner';
  return true;
end;
$$;

revoke all on function public.claim_owner_account(text, text) from public, anon;
grant execute on function public.claim_owner_account(text, text) to authenticated;