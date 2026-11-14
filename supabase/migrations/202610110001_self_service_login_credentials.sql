create or replace function public.update_my_login_credentials(
  requested_tenant_id text,
  requested_username text,
  requested_current_password text,
  requested_new_password text default ''
)
returns boolean
language plpgsql
security definer
set search_path = public, auth, extensions
as $$
declare
  authenticated_user_id uuid := auth.uid();
  authenticated_email text := lower(coalesce(auth.jwt() ->> 'email', ''));
  membership_role text;
  normalized_username text := lower(trim(requested_username));
  current_username text;
  current_password_hash text;
  next_password_hash text;
  requested_email text;
  account_record public.business_accounts%rowtype;
  member_record jsonb;
  member_id text;
begin
  if authenticated_user_id is null then
    raise exception 'Authentication required';
  end if;

  if normalized_username is null or length(normalized_username) < 3 then
    raise exception 'Username must be at least 3 characters';
  end if;

  if coalesce(requested_current_password, '') = '' then
    raise exception 'Enter your current password to verify this change';
  end if;

  if coalesce(requested_new_password, '') <> '' and length(requested_new_password) < 6 then
    raise exception 'New password must be at least 6 characters';
  end if;

  select membership.role into membership_role
  from public.tenant_memberships as membership
  where membership.user_id = authenticated_user_id
    and membership.tenant_id = requested_tenant_id
    and membership.role in ('owner', 'member');

  if membership_role is null then
    raise exception 'Workspace access required';
  end if;

  if membership_role = 'owner' then
    select account.* into account_record
    from public.business_accounts as account
    where account.tenant_id = requested_tenant_id;

    if account_record.id is null then
      raise exception 'Owner account was not found';
    end if;

    current_username := lower(trim(account_record.username));
    current_password_hash := coalesce(account_record.password, '');
    if authenticated_email <> public.account_login_email(requested_tenant_id, 'owner', current_username) then
      raise exception 'Signed-in account does not match this owner account';
    end if;
  else
    select member.value, member.value ->> 'id'
      into member_record, member_id
    from public.workspace_snapshots as snapshot
    cross join lateral jsonb_array_elements(
      case when jsonb_typeof(snapshot.payload -> 'members') = 'array' then snapshot.payload -> 'members' else '[]'::jsonb end
    ) as member(value)
    where snapshot.tenant_id = requested_tenant_id
      and member.value ->> 'hasAccount' = 'true'
      and coalesce(member.value ->> 'suspended', 'false') <> 'true'
      and (
        authenticated_email = public.account_login_email(requested_tenant_id, 'member', member.value ->> 'username')
        or authenticated_email = case
          when lower(coalesce(member.value ->> 'username', '')) ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then lower(member.value ->> 'username')
          else 'u-' || encode(convert_to(lower(coalesce(member.value ->> 'username', '')), 'UTF8'), 'hex') || '@biztrack.app'
        end
      );

    if member_id is null then
      raise exception 'Signed-in account does not match a worker in this workspace';
    end if;

    current_username := lower(trim(coalesce(member_record ->> 'username', '')));
    current_password_hash := coalesce(member_record ->> 'password', '');
  end if;

  if current_password_hash like '$2%'
    then
      if coalesce(crypt(requested_current_password, current_password_hash), '') <> current_password_hash then
        raise exception 'Current password is incorrect';
      end if;
    elsif current_password_hash <> requested_current_password then
      raise exception 'Current password is incorrect';
  end if;

  if exists (
    select 1
    from public.business_accounts as account
    where account.tenant_id = requested_tenant_id
      and lower(trim(account.username)) = normalized_username
      and membership_role <> 'owner'
  ) or exists (
    select 1
    from public.workspace_snapshots as snapshot
    cross join lateral jsonb_array_elements(
      case when jsonb_typeof(snapshot.payload -> 'members') = 'array' then snapshot.payload -> 'members' else '[]'::jsonb end
    ) as member(value)
    where snapshot.tenant_id = requested_tenant_id
      and member.value ->> 'hasAccount' = 'true'
      and lower(trim(coalesce(member.value ->> 'username', ''))) = normalized_username
      and (membership_role = 'owner' or member.value ->> 'id' <> member_id)
  ) then
    raise exception 'That username is already used in this workspace';
  end if;

  requested_email := public.account_login_email(requested_tenant_id, membership_role, normalized_username);
  if exists (select 1 from auth.users where lower(email) = requested_email and id <> authenticated_user_id) then
    raise exception 'That username is already connected to another login';
  end if;

  if exists (
    select 1 from public.business_accounts as account
    where lower(trim(account.username)) = normalized_username
      and not (membership_role = 'owner' and account.tenant_id = requested_tenant_id)
      and coalesce(account.password, '') like '$2%'
      and crypt(coalesce(nullif(requested_new_password, ''), requested_current_password), account.password) = account.password
  ) or exists (
    select 1
    from public.workspace_snapshots as snapshot
    cross join lateral jsonb_array_elements(
      case when jsonb_typeof(snapshot.payload -> 'members') = 'array' then snapshot.payload -> 'members' else '[]'::jsonb end
    ) as member(value)
    where lower(coalesce(member.value ->> 'username', '')) = normalized_username
      and member.value ->> 'hasAccount' = 'true'
      and not (membership_role = 'member' and snapshot.tenant_id = requested_tenant_id and member.value ->> 'id' = member_id)
      and coalesce(member.value ->> 'password', '') like '$2%'
      and crypt(coalesce(nullif(requested_new_password, ''), requested_current_password), member.value ->> 'password') = member.value ->> 'password'
  ) then
    raise exception 'That username and password are already used by another account';
  end if;

  next_password_hash := case
    when coalesce(requested_new_password, '') <> '' then crypt(requested_new_password, gen_salt('bf', 12))
    when current_password_hash like '$2%' then current_password_hash
    else crypt(requested_current_password, gen_salt('bf', 12))
  end;

  if membership_role = 'owner' then
    update public.business_accounts
    set username = normalized_username,
        password = next_password_hash
    where tenant_id = requested_tenant_id;

    update public.workspace_sessions
    set username = normalized_username,
      password_hash = next_password_hash,
      updated_at = now()
    where tenant_id = requested_tenant_id;
  else
    update public.workspace_snapshots as snapshot
    set payload = jsonb_set(
      snapshot.payload,
      '{members}',
      (
        select coalesce(jsonb_agg(
          case when member.value ->> 'id' = member_id then
            jsonb_set(
              jsonb_set(member.value, '{username}', to_jsonb(normalized_username), true),
              '{password}', to_jsonb(next_password_hash), true
            )
          else member.value end
          order by member.ordinality
        ), '[]'::jsonb)
        from jsonb_array_elements(snapshot.payload -> 'members') with ordinality as member(value, ordinality)
      ),
      true
    )
    where snapshot.tenant_id = requested_tenant_id;
  end if;

  update auth.users
  set email = requested_email,
      encrypted_password = case
        when coalesce(requested_new_password, '') = '' then encrypted_password
        else crypt(requested_new_password, gen_salt('bf', 12))
      end,
      updated_at = now()
  where id = authenticated_user_id;

  update auth.identities
  set identity_data = jsonb_set(coalesce(identity_data, '{}'::jsonb), '{email}', to_jsonb(requested_email), true),
      updated_at = now()
  where user_id = authenticated_user_id
    and provider = 'email';

  return true;
end;
$$;

revoke all on function public.update_my_login_credentials(text, text, text, text) from public, anon;
grant execute on function public.update_my_login_credentials(text, text, text, text) to authenticated;