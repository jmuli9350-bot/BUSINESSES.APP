create or replace function public.save_workspace_settings(requested_tenant_id text, requested_payload jsonb)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  requested_business_name text;
  requested_username text;
  expected_owner_email text;
  authenticated_email text := lower(coalesce(auth.jwt() ->> 'email', ''));
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  select lower(username) into requested_username
  from public.business_accounts
  where tenant_id = requested_tenant_id;

  expected_owner_email := case
    when lower(requested_username) ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then lower(requested_username)
    else 'u-' || encode(convert_to(requested_username, 'UTF8'), 'hex') || '@biztrack.app'
  end;

  if requested_username is null or authenticated_email <> expected_owner_email then
    raise exception 'Workspace owner identity does not match';
  end if;

  insert into public.tenant_memberships (user_id, tenant_id, role)
  values (auth.uid(), requested_tenant_id, 'owner')
  on conflict (user_id, tenant_id) do update set role = 'owner';

  requested_business_name := nullif(trim(requested_payload ->> 'workspaceName'), '');
  if requested_business_name is null then
    raise exception 'Business name cannot be empty';
  end if;

  update public.business_accounts
  set business_name = requested_business_name
  where tenant_id = requested_tenant_id;

  insert into public.workspace_snapshots (tenant_id, payload, updated_at)
  values (requested_tenant_id, requested_payload, now())
  on conflict (tenant_id) do update set
    payload = excluded.payload,
    updated_at = excluded.updated_at;

  update public.workspace_sessions
  set workspace_name = requested_business_name, updated_at = now()
  where tenant_id = requested_tenant_id;
end;
$$;

revoke all on function public.save_workspace_settings(text, jsonb) from public, anon;
grant execute on function public.save_workspace_settings(text, jsonb) to authenticated;
