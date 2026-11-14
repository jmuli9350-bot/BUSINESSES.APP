update public.business_accounts
set password = crypt(password, gen_salt('bf', 12))
where password !~ '^\$2[aby]\$[0-9]{2}\$';

update public.registration_requests
set password = crypt(password, gen_salt('bf', 12))
where password is not null
  and password !~ '^\$2[aby]\$[0-9]{2}\$';

update public.workspace_sessions
set password_hash = crypt(password_hash, gen_salt('bf', 12))
where password_hash !~ '^\$2[aby]\$[0-9]{2}\$';

update public.workspace_snapshots snapshot
set payload = jsonb_set(
  snapshot.payload,
  '{members}',
  (
    select coalesce(jsonb_agg(
      case
        when coalesce(member ->> 'password', '') !~ '^\$2[aby]\$[0-9]{2}\$'
          and coalesce(member ->> 'password', '') <> ''
        then jsonb_set(member, '{password}', to_jsonb(crypt(member ->> 'password', gen_salt('bf', 12))))
        else member
      end
    ), '[]'::jsonb)
    from jsonb_array_elements(coalesce(snapshot.payload -> 'members', '[]'::jsonb)) member
  ),
  true
)
where jsonb_typeof(snapshot.payload -> 'members') = 'array';

create or replace function public.claim_owner_tenant(requested_tenant_id text)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  requested_username text;
  authenticated_email text := lower(coalesce(auth.jwt() ->> 'email', ''));
  expected_email text;
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;
  select lower(username) into requested_username
  from public.business_accounts
  where tenant_id = requested_tenant_id;
  expected_email := (
    case
      when lower(requested_username) ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then lower(requested_username)
      else 'u-' || encode(convert_to(requested_username, 'UTF8'), 'hex') || '@biztrack.app'
    end
  );
  if requested_username is null
    or authenticated_email <> expected_email
    or not exists (
      select 1 from public.tenant_memberships
      where user_id = auth.uid() and tenant_id = requested_tenant_id and role = 'owner'
    ) then
    raise exception 'Tenant owner identity does not match';
  end if;
  return true;
end;
$$;

create or replace function public.save_workspace_settings(requested_tenant_id text, requested_payload jsonb)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  requested_business_name text;
  requested_username text;
  authenticated_email text := lower(coalesce(auth.jwt() ->> 'email', ''));
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;
  select lower(username) into requested_username
  from public.business_accounts
  where tenant_id = requested_tenant_id;
  if requested_username is null
    or authenticated_email <> (
      case
        when lower(requested_username) ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then lower(requested_username)
        else 'u-' || encode(convert_to(requested_username, 'UTF8'), 'hex') || '@biztrack.app'
      end
    )
    or not exists (
      select 1 from public.tenant_memberships
      where user_id = auth.uid() and tenant_id = requested_tenant_id and role = 'owner'
    ) then
    raise exception 'Workspace owner identity does not match';
  end if;
  requested_business_name := nullif(trim(requested_payload ->> 'workspaceName'), '');
  if requested_business_name is null then
    raise exception 'Business name cannot be empty';
  end if;
  update public.business_accounts
  set business_name = requested_business_name
  where tenant_id = requested_tenant_id;
  insert into public.workspace_snapshots (tenant_id, payload, updated_at)
  values (requested_tenant_id, requested_payload, now())
  on conflict (tenant_id) do update set payload = excluded.payload, updated_at = excluded.updated_at;
  update public.workspace_sessions
  set workspace_name = requested_business_name, updated_at = now()
  where tenant_id = requested_tenant_id;
end;
$$;

revoke all on function public.claim_owner_tenant(text) from public, anon;
grant execute on function public.claim_owner_tenant(text) to authenticated;
revoke all on function public.save_workspace_settings(text, jsonb) from public, anon;
grant execute on function public.save_workspace_settings(text, jsonb) to authenticated;

drop function if exists public.register_owner_biometric_legacy(text, text, text, bigint, text, text, timestamptz);
drop function if exists public.list_owner_biometric_credentials(text, text, text);
drop function if exists public.delete_owner_biometric_credential(text, text, text, bigint);
drop function if exists public.save_platform_settings(text, text, text, text, text, text, boolean);
drop table if exists public.site_admin_accounts;

create or replace function public.save_platform_settings(
  requested_platform_name text,
  requested_support_email text,
  requested_whatsapp_number text,
  requested_default_plan text,
  requested_maintenance_mode boolean
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

  insert into public.platform_settings (id, platform_name, support_email, whatsapp_number, default_plan, maintenance_mode)
  values (1, trim(requested_platform_name), trim(requested_support_email), regexp_replace(requested_whatsapp_number, '[^0-9]', '', 'g'), requested_default_plan, requested_maintenance_mode)
  on conflict (id) do update set
    platform_name = excluded.platform_name,
    support_email = excluded.support_email,
    whatsapp_number = excluded.whatsapp_number,
    default_plan = excluded.default_plan,
    maintenance_mode = excluded.maintenance_mode;
end;
$$;

revoke all on function public.save_platform_settings(text, text, text, text, boolean) from public, anon;
grant execute on function public.save_platform_settings(text, text, text, text, boolean) to authenticated;

create or replace function public.register_biometric_credential(requested_tenant_id text, requested_member_id bigint, requested_member_name text, requested_credential_id text, requested_registered_at timestamptz)
returns void
language plpgsql
security definer
set search_path = public, private_biometrics
as $$
begin
  if not exists (
    select 1 from public.tenant_memberships
    where user_id = auth.uid() and tenant_id = requested_tenant_id and role = 'owner'
  ) then
    raise exception 'Workspace owner access required';
  end if;
  if exists (select 1 from private_biometrics.credentials where tenant_id = requested_tenant_id and member_id = requested_member_id) then
    raise exception 'This worker already has a biometric in this business';
  end if;
  insert into private_biometrics.credentials (tenant_id, member_id, member_name, credential_id, subject_identifier, registered_at)
  values (requested_tenant_id, requested_member_id, requested_member_name, requested_credential_id, requested_credential_id, requested_registered_at);
exception when unique_violation then
  raise exception 'This biometric is already registered in this business';
end;
$$;

create or replace function public.list_biometric_credentials(requested_tenant_id text)
returns table (member_id bigint, credential_id text)
language plpgsql
security definer
set search_path = public, private_biometrics
as $$
begin
  if not exists (
    select 1 from public.tenant_memberships
    where user_id = auth.uid() and tenant_id = requested_tenant_id and role = 'owner'
  ) then
    raise exception 'Workspace owner access required';
  end if;
  return query
    select credentials.member_id, credentials.credential_id
    from private_biometrics.credentials credentials
    where credentials.tenant_id = requested_tenant_id;
end;
$$;

create or replace function public.delete_biometric_credential(requested_tenant_id text, requested_member_id bigint, requested_credential_id text)
returns void
language plpgsql
security definer
set search_path = public, private_biometrics
as $$
begin
  if not exists (
    select 1 from public.tenant_memberships
    where user_id = auth.uid() and tenant_id = requested_tenant_id and role = 'owner'
  ) then
    raise exception 'Workspace owner access required';
  end if;
  delete from private_biometrics.credentials
  where tenant_id = requested_tenant_id
    and member_id = requested_member_id
    and (requested_credential_id = '' or credential_id = requested_credential_id);
end;
$$;

revoke all on function public.register_biometric_credential(text, bigint, text, text, timestamptz) from public, anon;
revoke all on function public.list_biometric_credentials(text) from public, anon;
revoke all on function public.delete_biometric_credential(text, bigint, text) from public, anon;
grant execute on function public.register_biometric_credential(text, bigint, text, text, timestamptz) to authenticated;
grant execute on function public.list_biometric_credentials(text) to authenticated;
grant execute on function public.delete_biometric_credential(text, bigint, text) to authenticated;

drop policy if exists "Anyone can submit a registration request" on public.registration_requests;
create policy "Anyone can submit a registration request"
  on public.registration_requests for insert to anon, authenticated
  with check (password is null or password ~ '^\$2[aby]\$[0-9]{2}\$');

drop policy if exists "Members access their biometric devices" on public.biometric_devices;
drop policy if exists "Members can read their biometric devices" on public.biometric_devices;
drop policy if exists "Owners manage their biometric devices" on public.biometric_devices;
create policy "Members can read their biometric devices"
  on public.biometric_devices for select to authenticated
  using (public.has_tenant_access(tenant_id));
create policy "Owners manage their biometric devices"
  on public.biometric_devices for all to authenticated
  using (exists (
    select 1 from public.tenant_memberships
    where user_id = auth.uid() and tenant_id = biometric_devices.tenant_id and role = 'owner'
  ))
  with check (exists (
    select 1 from public.tenant_memberships
    where user_id = auth.uid() and tenant_id = biometric_devices.tenant_id and role = 'owner'
  ));