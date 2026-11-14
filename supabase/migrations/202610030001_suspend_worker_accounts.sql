create or replace function public.claim_member_tenant(requested_username text, requested_password text)
returns table (tenant_id text, member_id bigint, granted_pages jsonb)
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  normalized_username text := lower(trim(requested_username));
  authenticated_email text := lower(coalesce(auth.jwt() ->> 'email', ''));
  expected_email text;
  suspended_accounts integer;
  matching_accounts integer;
  claimed_tenant_id text;
  claimed_member_id bigint;
  claimed_pages jsonb;
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  if normalized_username is null or normalized_username = '' then
    raise exception 'Invalid username or password';
  end if;

  if normalized_username ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then
    expected_email := normalized_username;
  else
    expected_email := 'u-' || encode(convert_to(normalized_username, 'UTF8'), 'hex') || '@biztrack.app';
  end if;

  if authenticated_email <> expected_email then
    raise exception 'Invalid username or password';
  end if;

  select count(*) into suspended_accounts
  from public.workspace_snapshots as snapshot
  cross join lateral jsonb_array_elements(
    case
      when jsonb_typeof(snapshot.payload -> 'members') = 'array' then snapshot.payload -> 'members'
      else '[]'::jsonb
    end
  ) as member(value)
  where lower(coalesce(member.value ->> 'username', '')) = normalized_username
    and member.value ->> 'hasAccount' = 'true'
    and coalesce(member.value ->> 'suspended', 'false') = 'true'
    and coalesce(member.value ->> 'password', '') like '$2%'
    and crypt(requested_password, member.value ->> 'password') = member.value ->> 'password';

  if suspended_accounts > 0 then
    raise exception 'Worker account is suspended';
  end if;

  select count(*) into matching_accounts
  from public.workspace_snapshots as snapshot
  cross join lateral jsonb_array_elements(
    case
      when jsonb_typeof(snapshot.payload -> 'members') = 'array' then snapshot.payload -> 'members'
      else '[]'::jsonb
    end
  ) as member(value)
  where lower(coalesce(member.value ->> 'username', '')) = normalized_username
    and member.value ->> 'hasAccount' = 'true'
    and coalesce(member.value ->> 'suspended', 'false') <> 'true'
    and coalesce(member.value ->> 'password', '') like '$2%'
    and crypt(requested_password, member.value ->> 'password') = member.value ->> 'password';

  if matching_accounts <> 1 then
    raise exception 'Invalid credentials or duplicate worker usernames';
  end if;

  select
    snapshot.tenant_id,
    (member.value ->> 'id')::bigint,
    case
      when jsonb_typeof(snapshot.payload -> 'accessByMember' -> (member.value ->> 'id')) = 'array'
        then snapshot.payload -> 'accessByMember' -> (member.value ->> 'id')
      else '[]'::jsonb
    end
  into claimed_tenant_id, claimed_member_id, claimed_pages
  from public.workspace_snapshots as snapshot
  cross join lateral jsonb_array_elements(
    case
      when jsonb_typeof(snapshot.payload -> 'members') = 'array' then snapshot.payload -> 'members'
      else '[]'::jsonb
    end
  ) as member(value)
  where lower(coalesce(member.value ->> 'username', '')) = normalized_username
    and member.value ->> 'hasAccount' = 'true'
    and coalesce(member.value ->> 'suspended', 'false') <> 'true'
    and coalesce(member.value ->> 'password', '') like '$2%'
    and crypt(requested_password, member.value ->> 'password') = member.value ->> 'password'
  limit 1;

  insert into public.tenant_memberships (user_id, tenant_id, role)
  values (auth.uid(), claimed_tenant_id, 'member')
  on conflict on constraint tenant_memberships_pkey do nothing;

  return query select claimed_tenant_id, claimed_member_id, coalesce(claimed_pages, '[]'::jsonb);
end;
$$;

revoke all on function public.claim_member_tenant(text, text) from public, anon;
grant execute on function public.claim_member_tenant(text, text) to authenticated;

create or replace function public.has_tenant_access(requested_tenant_id text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.tenant_memberships membership
    join public.business_accounts account on account.tenant_id = membership.tenant_id
    where membership.user_id = auth.uid()
      and membership.tenant_id = requested_tenant_id
      and account.status = 'Active'
      and (account.next_billing is null or account.next_billing >= current_date)
      and (
        membership.role = 'owner'
        or (
          membership.role = 'member'
          and exists (
            select 1
            from public.workspace_snapshots snapshot
            cross join lateral jsonb_array_elements(
              case
                when jsonb_typeof(snapshot.payload -> 'members') = 'array' then snapshot.payload -> 'members'
                else '[]'::jsonb
              end
            ) as member(value)
            where snapshot.tenant_id = membership.tenant_id
              and member.value ->> 'hasAccount' = 'true'
              and coalesce(member.value ->> 'suspended', 'false') <> 'true'
              and (
                case
                  when lower(coalesce(member.value ->> 'username', '')) ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$'
                    then lower(member.value ->> 'username')
                  else 'u-' || encode(convert_to(lower(coalesce(member.value ->> 'username', '')), 'UTF8'), 'hex') || '@biztrack.app'
                end
              ) = lower(coalesce(auth.jwt() ->> 'email', ''))
          )
        )
      )
  );
$$;