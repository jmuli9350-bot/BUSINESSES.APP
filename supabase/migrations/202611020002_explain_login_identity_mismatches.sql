create or replace function public.resolve_login_identity(requested_username text, requested_password text)
returns table (tenant_id text, account_type text, member_id bigint, auth_email text)
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  normalized_username text := lower(trim(requested_username));
  matched_tenant_id text;
  matched_account_type text;
  matched_member_id bigint;
  matching_accounts integer;
begin
  if normalized_username is null or normalized_username = '' or coalesce(requested_password, '') = '' then
    raise exception 'Invalid username or password';
  end if;

  with login_matches as (
    select account.tenant_id, 'owner'::text as account_type, null::bigint as member_id
    from public.business_accounts as account
    where lower(trim(account.username)) = normalized_username
      and coalesce(account.password, '') like '$2%'
      and crypt(requested_password, account.password) = account.password
    union all
    select snapshot.tenant_id, 'member'::text as account_type, (member.value ->> 'id')::bigint as member_id
    from public.workspace_snapshots as snapshot
    cross join lateral jsonb_array_elements(
      case
        when jsonb_typeof(snapshot.payload -> 'members') = 'array' then snapshot.payload -> 'members'
        else '[]'::jsonb
      end
    ) as member(value)
    where lower(coalesce(member.value ->> 'username', '')) = normalized_username
      and member.value ->> 'hasAccount' = 'true'
      and coalesce(member.value ->> 'password', '') like '$2%'
      and crypt(requested_password, member.value ->> 'password') = member.value ->> 'password'
  )
  select count(*) into matching_accounts from login_matches;

  if matching_accounts > 1 then
    raise exception 'Duplicate username and password match multiple accounts; each account must use a different password';
  elsif matching_accounts = 0 then
    raise exception 'Invalid username or password';
  end if;

  with login_matches as (
    select account.tenant_id, 'owner'::text as account_type, null::bigint as member_id
    from public.business_accounts as account
    where lower(trim(account.username)) = normalized_username
      and coalesce(account.password, '') like '$2%'
      and crypt(requested_password, account.password) = account.password
    union all
    select snapshot.tenant_id, 'member'::text as account_type, (member.value ->> 'id')::bigint as member_id
    from public.workspace_snapshots as snapshot
    cross join lateral jsonb_array_elements(
      case
        when jsonb_typeof(snapshot.payload -> 'members') = 'array' then snapshot.payload -> 'members'
        else '[]'::jsonb
      end
    ) as member(value)
    where lower(coalesce(member.value ->> 'username', '')) = normalized_username
      and member.value ->> 'hasAccount' = 'true'
      and coalesce(member.value ->> 'password', '') like '$2%'
      and crypt(requested_password, member.value ->> 'password') = member.value ->> 'password'
  )
  select matches.tenant_id, matches.account_type, matches.member_id
  into matched_tenant_id, matched_account_type, matched_member_id
  from login_matches as matches
  limit 1;

  return query
  select
    matched_tenant_id,
    matched_account_type,
    matched_member_id,
    public.account_login_email(matched_tenant_id, matched_account_type, normalized_username);
end;
$$;

revoke all on function public.resolve_login_identity(text, text) from public;
grant execute on function public.resolve_login_identity(text, text) to anon, authenticated;
