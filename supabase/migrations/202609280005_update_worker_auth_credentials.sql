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
  current_email text;
  requested_email text;
  worker_auth_id uuid;
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  if not exists (
    select 1
    from public.tenant_memberships
    where user_id = auth.uid()
      and tenant_id = requested_tenant_id
      and role = 'owner'
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
    case
      when jsonb_typeof(snapshot.payload -> 'members') = 'array' then snapshot.payload -> 'members'
      else '[]'::jsonb
    end
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
      case
        when jsonb_typeof(snapshot.payload -> 'members') = 'array' then snapshot.payload -> 'members'
        else '[]'::jsonb
      end
    ) as member(value)
    where member.value ->> 'hasAccount' = 'true'
      and lower(coalesce(member.value ->> 'username', '')) = normalized_username
      and not (
        snapshot.tenant_id = requested_tenant_id
        and member.value ->> 'id' = requested_member_id::text
      )
  ) then
    raise exception 'That username is already assigned to another worker';
  end if;

  current_username := lower(trim(coalesce(worker_record ->> 'username', '')));
  current_email := case
    when current_username ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then current_username
    else 'u-' || encode(convert_to(current_username, 'UTF8'), 'hex') || '@biztrack.app'
  end;
  requested_email := case
    when normalized_username ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then normalized_username
    else 'u-' || encode(convert_to(normalized_username, 'UTF8'), 'hex') || '@biztrack.app'
  end;

  select id into worker_auth_id
  from auth.users
  where lower(email) = current_email
  limit 1;

  if worker_auth_id is null then
    return true;
  end if;

  if exists (
    select 1 from auth.users
    where lower(email) = requested_email
      and id <> worker_auth_id
  ) then
    raise exception 'That username is already used by an authentication account';
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
  set identity_data = jsonb_set(
        coalesce(identity_data, '{}'::jsonb),
        '{email}',
        to_jsonb(requested_email),
        true
      ),
      updated_at = now()
  where user_id = worker_auth_id
    and provider = 'email';

  return true;
end;
$$;

revoke all on function public.update_worker_auth_credentials(text, bigint, text, text) from public, anon;
grant execute on function public.update_worker_auth_credentials(text, bigint, text, text) to authenticated;