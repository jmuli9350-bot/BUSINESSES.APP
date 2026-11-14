create or replace function public.claim_owner_tenant_by_credentials(requested_username text, requested_password text)
returns table (
  id bigint,
  business_name text,
  owner_name text,
  email text,
  username text,
  industry text,
  plan text,
  status text,
  seats integer,
  monthly_price numeric,
  next_billing date,
  created_at date,
  tenant_id text
)
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  authenticated_email text := lower(coalesce(auth.jwt() ->> 'email', ''));
  normalized_username text;
  expected_email text;
  matching_accounts integer;
  owner_record public.business_accounts%rowtype;
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  normalized_username := lower(trim(requested_username));
  if normalized_username = '' then
    raise exception 'Username is required';
  end if;

  if normalized_username ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then
    expected_email := normalized_username;
  else
    expected_email := 'u-' || encode(convert_to(normalized_username, 'UTF8'), 'hex') || '@biztrack.app';
  end if;

  if authenticated_email <> expected_email then
    raise exception 'Auth identity does not match the owner username';
  end if;

  select count(*) into matching_accounts
  from public.business_accounts as account
  where lower(trim(account.username)) = normalized_username
    and coalesce(account.password, '') like '$2%'
    and crypt(requested_password, account.password) = account.password;

  if matching_accounts <> 1 then
    raise exception 'Owner credentials do not match exactly one business account';
  end if;

  select account.* into owner_record
  from public.business_accounts as account
  where lower(trim(account.username)) = normalized_username
    and coalesce(account.password, '') like '$2%'
    and crypt(requested_password, account.password) = account.password
  limit 1;

  insert into public.tenant_memberships (user_id, tenant_id, role)
  values (auth.uid(), owner_record.tenant_id, 'owner')
  on conflict (user_id, tenant_id) do update set role = 'owner';

  return query
  select
    owner_record.id,
    owner_record.business_name,
    owner_record.owner_name,
    owner_record.email,
    owner_record.username,
    owner_record.industry,
    owner_record.plan,
    owner_record.status,
    owner_record.seats,
    owner_record.monthly_price,
    owner_record.next_billing,
    owner_record.created_at,
    owner_record.tenant_id;
end;
$$;

revoke all on function public.claim_owner_tenant_by_credentials(text, text) from public, anon;
grant execute on function public.claim_owner_tenant_by_credentials(text, text) to authenticated;