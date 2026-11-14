create or replace function public.claim_member_tenant(requested_username text, requested_password text)
returns table (tenant_id text, member_id bigint, granted_pages jsonb)
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  expected_email text;
  authenticated_email text := lower(coalesce(auth.jwt() ->> 'email', ''));
  matching_accounts integer;
  claimed_tenant_id text;
  claimed_member_id bigint;
  claimed_pages jsonb;
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  expected_email := case
    when lower(trim(requested_username)) ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then lower(trim(requested_username))
    else 'u-' || encode(convert_to(lower(trim(requested_username)), 'UTF8'), 'hex') || '@biztrack.app'
  end;
  if nullif(trim(requested_username), '') is null or authenticated_email <> expected_email then
    raise exception 'Invalid username or password';
  end if;

  select count(*) into matching_accounts
  from public.workspace_snapshots snapshot
  cross join lateral jsonb_array_elements(
    case when jsonb_typeof(snapshot.payload -> 'members') = 'array' then snapshot.payload -> 'members' else '[]'::jsonb end
  ) member
  where lower(coalesce(member ->> 'username', '')) = lower(trim(requested_username))
    and member ->> 'hasAccount' = 'true'
    and coalesce(member ->> 'password', '') like '$2%'
    and crypt(requested_password, member ->> 'password') = member ->> 'password'
    and jsonb_array_length(case
      when jsonb_typeof(snapshot.payload -> 'accessByMember' -> (member ->> 'id')) = 'array' then snapshot.payload -> 'accessByMember' -> (member ->> 'id')
      else '[]'::jsonb
    end) > 0;

  if matching_accounts <> 1 then
    raise exception 'Invalid credentials, no assigned pages, or duplicate workspace usernames';
  end if;

  select snapshot.tenant_id, (member ->> 'id')::bigint, snapshot.payload -> 'accessByMember' -> (member ->> 'id')
  into claimed_tenant_id, claimed_member_id, claimed_pages
  from public.workspace_snapshots snapshot
  cross join lateral jsonb_array_elements(
    case when jsonb_typeof(snapshot.payload -> 'members') = 'array' then snapshot.payload -> 'members' else '[]'::jsonb end
  ) member
  where lower(coalesce(member ->> 'username', '')) = lower(trim(requested_username))
    and member ->> 'hasAccount' = 'true'
    and coalesce(member ->> 'password', '') like '$2%'
    and crypt(requested_password, member ->> 'password') = member ->> 'password'
    and jsonb_array_length(case
      when jsonb_typeof(snapshot.payload -> 'accessByMember' -> (member ->> 'id')) = 'array' then snapshot.payload -> 'accessByMember' -> (member ->> 'id')
      else '[]'::jsonb
    end) > 0;

  insert into public.tenant_memberships (user_id, tenant_id, role)
  values (auth.uid(), claimed_tenant_id, 'member')
  on conflict (user_id, tenant_id) do nothing;

  return query select claimed_tenant_id, claimed_member_id, claimed_pages;
end;
$$;

revoke all on function public.claim_member_tenant(text, text) from public, anon;
grant execute on function public.claim_member_tenant(text, text) to authenticated;
