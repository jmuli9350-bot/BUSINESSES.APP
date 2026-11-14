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

  expected_email := case
    when lower(requested_username) ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then lower(requested_username)
    else 'u-' || encode(convert_to(requested_username, 'UTF8'), 'hex') || '@biztrack.app'
  end;

  if requested_username is null or authenticated_email <> expected_email then
    raise exception 'Tenant owner identity does not match';
  end if;

  insert into public.tenant_memberships (user_id, tenant_id, role)
  values (auth.uid(), requested_tenant_id, 'owner')
  on conflict (user_id, tenant_id) do update set role = 'owner';

  return true;
end;
$$;

revoke all on function public.claim_owner_tenant(text) from public, anon;
grant execute on function public.claim_owner_tenant(text) to authenticated;
