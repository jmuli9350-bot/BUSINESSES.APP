create or replace function public.admin_reset_account_password(
  requested_tenant_id text,
  requested_member_id bigint,
  requested_is_owner boolean,
  requested_new_password text
)
returns boolean
language plpgsql
security definer
set search_path = public, auth, extensions
as $$
declare
  account_username text;
  auth_email text;
  legacy_email text;
  target_auth_id uuid;
  member_record jsonb;
  password_hash text;
begin
  if not public.is_platform_admin() then
    raise exception 'Platform administrator access required';
  end if;

  if coalesce(requested_new_password, '') = '' or length(requested_new_password) < 6 then
    raise exception 'New password must be at least 6 characters';
  end if;

  if requested_is_owner then
    select lower(trim(account.username)) into account_username
    from public.business_accounts as account
    where account.tenant_id = requested_tenant_id;

    if account_username is null then
      raise exception 'Business owner account was not found';
    end if;

    auth_email := public.account_login_email(requested_tenant_id, 'owner', account_username);
  else
    select member.value, lower(trim(coalesce(member.value ->> 'username', '')))
      into member_record, account_username
    from public.workspace_snapshots as snapshot
    cross join lateral jsonb_array_elements(
      case when jsonb_typeof(snapshot.payload -> 'members') = 'array' then snapshot.payload -> 'members' else '[]'::jsonb end
    ) as member(value)
    where snapshot.tenant_id = requested_tenant_id
      and member.value ->> 'id' = requested_member_id::text
      and member.value ->> 'hasAccount' = 'true';

    if member_record is null or account_username is null or account_username = '' then
      raise exception 'Worker account was not found';
    end if;

    auth_email := public.account_login_email(requested_tenant_id, 'member', account_username);
  end if;

  password_hash := crypt(requested_new_password, gen_salt('bf', 12));

  if requested_is_owner then
    update public.business_accounts
    set password = password_hash
    where tenant_id = requested_tenant_id;
  else
    update public.workspace_snapshots as snapshot
    set payload = jsonb_set(
      snapshot.payload,
      '{members}',
      (
        select coalesce(jsonb_agg(
          case when member.value ->> 'id' = requested_member_id::text then
            jsonb_set(member.value, '{password}', to_jsonb(password_hash), true)
          else member.value end
          order by member.ordinality
        ), '[]'::jsonb)
        from jsonb_array_elements(snapshot.payload -> 'members') with ordinality as member(value, ordinality)
      ),
      true
    ),
    updated_at = now()
    where snapshot.tenant_id = requested_tenant_id;
  end if;

  legacy_email := case
    when account_username ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then account_username
    else 'u-' || encode(convert_to(account_username, 'UTF8'), 'hex') || '@biztrack.app'
  end;

  select auth_user.id into target_auth_id
  from auth.users as auth_user
  where lower(auth_user.email) = auth_email
     or lower(auth_user.email) = legacy_email
  order by case when lower(auth_user.email) = auth_email then 0 else 1 end
  limit 1;

  if target_auth_id is not null then
    update auth.users
    set email = auth_email,
        encrypted_password = password_hash,
        updated_at = now()
    where id = target_auth_id;

    update auth.identities
    set identity_data = jsonb_set(coalesce(identity_data, '{}'::jsonb), '{email}', to_jsonb(auth_email), true),
        updated_at = now()
    where user_id = target_auth_id
      and provider = 'email';
  end if;

  return true;
end;
$$;

revoke all on function public.admin_reset_account_password(text, bigint, boolean, text) from public, anon;
grant execute on function public.admin_reset_account_password(text, bigint, boolean, text) to authenticated;
