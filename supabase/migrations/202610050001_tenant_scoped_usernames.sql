create or replace function public.account_login_email(requested_tenant_id text, requested_role text, requested_username text)
returns text
language sql
immutable
set search_path = public
as $$
  select 'u-' || md5(
    coalesce(requested_tenant_id, '') || ':' ||
    coalesce(requested_role, '') || ':' ||
    lower(trim(coalesce(requested_username, '')))
  ) || '@biztrack.app';
$$;

revoke all on function public.account_login_email(text, text, text) from public;
grant execute on function public.account_login_email(text, text, text) to anon, authenticated;

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

  if matching_accounts <> 1 then
    raise exception 'Invalid credentials or duplicate username and password';
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

create or replace function public.account_credentials_available(requested_username text, requested_password text)
returns boolean
language sql
security definer
set search_path = public, extensions
as $$
  select not (
    exists (
      select 1 from public.business_accounts as account
      where lower(trim(account.username)) = lower(trim(requested_username))
        and coalesce(account.password, '') like '$2%'
        and crypt(requested_password, account.password) = account.password
    ) or exists (
      select 1
      from public.workspace_snapshots as snapshot
      cross join lateral jsonb_array_elements(
        case when jsonb_typeof(snapshot.payload -> 'members') = 'array' then snapshot.payload -> 'members' else '[]'::jsonb end
      ) as member(value)
      where lower(coalesce(member.value ->> 'username', '')) = lower(trim(requested_username))
        and member.value ->> 'hasAccount' = 'true'
        and coalesce(member.value ->> 'password', '') like '$2%'
        and crypt(requested_password, member.value ->> 'password') = member.value ->> 'password'
    ) or exists (
      select 1 from auth.users as auth_user
      where coalesce(auth_user.raw_app_meta_data ->> 'role', '') = 'platform_admin'
        and lower(auth_user.email) = case
          when lower(trim(requested_username)) ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then lower(trim(requested_username))
          else 'u-' || encode(convert_to(lower(trim(requested_username)), 'UTF8'), 'hex') || '@biztrack.app'
        end
        and coalesce(auth_user.encrypted_password, '') like '$2%'
        and crypt(requested_password, auth_user.encrypted_password) = auth_user.encrypted_password
    )
  );
$$;

revoke all on function public.account_credentials_available(text, text) from public;
grant execute on function public.account_credentials_available(text, text) to anon, authenticated;

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
  normalized_username text := lower(trim(requested_username));
  matching_accounts integer;
  owner_record public.business_accounts%rowtype;
begin
  if auth.uid() is null or normalized_username is null or normalized_username = '' then
    raise exception 'Authentication required';
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

  if authenticated_email <> public.account_login_email(owner_record.tenant_id, 'owner', normalized_username) then
    raise exception 'Auth identity does not match the owner account';
  end if;

  insert into public.tenant_memberships (user_id, tenant_id, role)
  values (auth.uid(), owner_record.tenant_id, 'owner')
  on conflict on constraint tenant_memberships_pkey do update set role = 'owner';

  return query
  select owner_record.id, owner_record.business_name, owner_record.owner_name, owner_record.email,
    owner_record.username, owner_record.industry, owner_record.plan, owner_record.status,
    owner_record.seats, owner_record.monthly_price, owner_record.next_billing,
    owner_record.created_at, owner_record.tenant_id;
end;
$$;

revoke all on function public.claim_owner_tenant_by_credentials(text, text) from public, anon;
grant execute on function public.claim_owner_tenant_by_credentials(text, text) to authenticated;

create or replace function public.save_workspace_settings(requested_tenant_id text, requested_payload jsonb)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  requested_username text;
  requested_business_name text;
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  select lower(trim(username)) into requested_username
  from public.business_accounts
  where tenant_id = requested_tenant_id;

  if requested_username is null
    or lower(coalesce(auth.jwt() ->> 'email', '')) not in (
      public.account_login_email(requested_tenant_id, 'owner', requested_username),
      case
        when requested_username ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then requested_username
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

revoke all on function public.save_workspace_settings(text, jsonb) from public, anon;
grant execute on function public.save_workspace_settings(text, jsonb) to authenticated;

create or replace function public.claim_member_tenant(requested_username text, requested_password text)
returns table (tenant_id text, member_id bigint, granted_pages jsonb)
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  normalized_username text := lower(trim(requested_username));
  authenticated_email text := lower(coalesce(auth.jwt() ->> 'email', ''));
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

  select count(*) into suspended_accounts
  from public.workspace_snapshots as snapshot
  cross join lateral jsonb_array_elements(
    case when jsonb_typeof(snapshot.payload -> 'members') = 'array' then snapshot.payload -> 'members' else '[]'::jsonb end
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
    case when jsonb_typeof(snapshot.payload -> 'members') = 'array' then snapshot.payload -> 'members' else '[]'::jsonb end
  ) as member(value)
  where lower(coalesce(member.value ->> 'username', '')) = normalized_username
    and member.value ->> 'hasAccount' = 'true'
    and coalesce(member.value ->> 'suspended', 'false') <> 'true'
    and coalesce(member.value ->> 'password', '') like '$2%'
    and crypt(requested_password, member.value ->> 'password') = member.value ->> 'password';

  if matching_accounts <> 1 then
    raise exception 'Invalid credentials or duplicate username and password';
  end if;

  select snapshot.tenant_id, (member.value ->> 'id')::bigint,
    case
      when jsonb_typeof(snapshot.payload -> 'accessByMember' -> (member.value ->> 'id')) = 'array'
        then snapshot.payload -> 'accessByMember' -> (member.value ->> 'id')
      else '[]'::jsonb
    end
  into claimed_tenant_id, claimed_member_id, claimed_pages
  from public.workspace_snapshots as snapshot
  cross join lateral jsonb_array_elements(
    case when jsonb_typeof(snapshot.payload -> 'members') = 'array' then snapshot.payload -> 'members' else '[]'::jsonb end
  ) as member(value)
  where lower(coalesce(member.value ->> 'username', '')) = normalized_username
    and member.value ->> 'hasAccount' = 'true'
    and coalesce(member.value ->> 'suspended', 'false') <> 'true'
    and coalesce(member.value ->> 'password', '') like '$2%'
    and crypt(requested_password, member.value ->> 'password') = member.value ->> 'password'
  limit 1;

  if authenticated_email <> public.account_login_email(claimed_tenant_id, 'member', normalized_username) then
    raise exception 'Invalid username or password';
  end if;

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
    from public.tenant_memberships as membership
    join public.business_accounts as account on account.tenant_id = membership.tenant_id
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
            from public.workspace_snapshots as snapshot
            cross join lateral jsonb_array_elements(
              case when jsonb_typeof(snapshot.payload -> 'members') = 'array' then snapshot.payload -> 'members' else '[]'::jsonb end
            ) as member(value)
            where snapshot.tenant_id = membership.tenant_id
              and member.value ->> 'hasAccount' = 'true'
              and coalesce(member.value ->> 'suspended', 'false') <> 'true'
              and (
                public.account_login_email(membership.tenant_id, 'member', member.value ->> 'username')
                  = lower(coalesce(auth.jwt() ->> 'email', ''))
                or case
                  when lower(coalesce(member.value ->> 'username', '')) ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$'
                    then lower(member.value ->> 'username')
                  else 'u-' || encode(convert_to(lower(coalesce(member.value ->> 'username', '')), 'UTF8'), 'hex') || '@biztrack.app'
                end = lower(coalesce(auth.jwt() ->> 'email', ''))
                )
          )
        )
      )
  );
$$;

create or replace function public.update_worker_auth_credentials(
  requested_tenant_id text,
  requested_member_id bigint,
  requested_username text,
  requested_password text
)
returns boolean
language plpgsql
security definer
set search_path = public, auth, extensions
as $$
declare
  normalized_username text := lower(trim(requested_username));
  worker_record jsonb;
  current_username text;
  legacy_email text;
  current_scoped_email text;
  requested_email text;
  worker_auth_id uuid;
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  if not exists (
    select 1 from public.tenant_memberships
    where user_id = auth.uid() and tenant_id = requested_tenant_id and role = 'owner'
  ) then
    raise exception 'Tenant owner access required';
  end if;

  if normalized_username is null or length(normalized_username) < 3 then
    raise exception 'Username must be at least 3 characters';
  end if;

  if coalesce(requested_password, '') <> '' and length(requested_password) < 6 then
    raise exception 'Password must be at least 6 characters';
  end if;

  select member.value into worker_record
  from public.workspace_snapshots as snapshot
  cross join lateral jsonb_array_elements(
    case when jsonb_typeof(snapshot.payload -> 'members') = 'array' then snapshot.payload -> 'members' else '[]'::jsonb end
  ) as member(value)
  where snapshot.tenant_id = requested_tenant_id
    and member.value ->> 'id' = requested_member_id::text
  limit 1;

  if worker_record is null or coalesce(worker_record ->> 'hasAccount', 'false') <> 'true' then
    raise exception 'Worker account was not found';
  end if;

  if exists (
    select 1
    from public.workspace_snapshots as snapshot
    cross join lateral jsonb_array_elements(
      case when jsonb_typeof(snapshot.payload -> 'members') = 'array' then snapshot.payload -> 'members' else '[]'::jsonb end
    ) as member(value)
    where snapshot.tenant_id = requested_tenant_id
      and member.value ->> 'hasAccount' = 'true'
      and lower(coalesce(member.value ->> 'username', '')) = normalized_username
      and member.value ->> 'id' <> requested_member_id::text
  ) then
    raise exception 'That username is already assigned to another worker in this business';
  end if;

  if coalesce(requested_password, '') <> '' and (
    exists (
      select 1 from public.business_accounts as account
      where lower(trim(account.username)) = normalized_username
        and coalesce(account.password, '') like '$2%'
        and crypt(requested_password, account.password) = account.password
    ) or exists (
      select 1
      from public.workspace_snapshots as snapshot
      cross join lateral jsonb_array_elements(
        case when jsonb_typeof(snapshot.payload -> 'members') = 'array' then snapshot.payload -> 'members' else '[]'::jsonb end
      ) as member(value)
      where not (snapshot.tenant_id = requested_tenant_id and member.value ->> 'id' = requested_member_id::text)
        and lower(coalesce(member.value ->> 'username', '')) = normalized_username
        and member.value ->> 'hasAccount' = 'true'
        and coalesce(member.value ->> 'password', '') like '$2%'
        and crypt(requested_password, member.value ->> 'password') = member.value ->> 'password'
    )
  ) then
    raise exception 'That username and password are already used by another account';
  end if;

  current_username := lower(trim(coalesce(worker_record ->> 'username', '')));
  if normalized_username <> current_username and coalesce(requested_password, '') = '' then
    raise exception 'A password is required when changing a worker username';
  end if;
  legacy_email := case
    when current_username ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then current_username
    else 'u-' || encode(convert_to(current_username, 'UTF8'), 'hex') || '@biztrack.app'
  end;
  current_scoped_email := public.account_login_email(requested_tenant_id, 'member', current_username);
  requested_email := public.account_login_email(requested_tenant_id, 'member', normalized_username);

  select id into worker_auth_id
  from auth.users
  where lower(email) = current_scoped_email
  limit 1;
  if worker_auth_id is null then
    select id into worker_auth_id
    from auth.users
    where lower(email) = legacy_email
    limit 1;
  end if;

  if worker_auth_id is null then
    return true;
  end if;

  if exists (select 1 from auth.users where lower(email) = requested_email and id <> worker_auth_id) then
    raise exception 'This worker already has a different authentication identity';
  end if;

  update auth.users
  set email = requested_email,
      encrypted_password = case
        when coalesce(requested_password, '') = '' then encrypted_password
        else crypt(requested_password, gen_salt('bf', 12))
      end,
      updated_at = now()
  where id = worker_auth_id;

  update auth.identities
  set identity_data = jsonb_set(coalesce(identity_data, '{}'::jsonb), '{email}', to_jsonb(requested_email), true),
      updated_at = now()
  where user_id = worker_auth_id and provider = 'email';

  return true;
end;
$$;

revoke all on function public.update_worker_auth_credentials(text, bigint, text, text) from public, anon;
grant execute on function public.update_worker_auth_credentials(text, bigint, text, text) to authenticated;