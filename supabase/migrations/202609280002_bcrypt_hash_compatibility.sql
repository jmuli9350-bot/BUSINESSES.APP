update public.business_accounts
set password = '$2a$' || substring(password from 5)
where password ~ '^\$2b\$[0-9]{2}\$';

update public.registration_requests
set password = '$2a$' || substring(password from 5)
where password ~ '^\$2b\$[0-9]{2}\$';

update public.workspace_sessions
set password_hash = '$2a$' || substring(password_hash from 5)
where password_hash ~ '^\$2b\$[0-9]{2}\$';

update public.workspace_snapshots snapshot
set payload = jsonb_set(
  snapshot.payload,
  '{members}',
  (
    select coalesce(jsonb_agg(
      case
        when coalesce(member ->> 'password', '') ~ '^\$2b\$[0-9]{2}\$'
        then jsonb_set(member, '{password}', to_jsonb('$2a$' || substring(member ->> 'password' from 5)))
        else member
      end
    ), '[]'::jsonb)
    from jsonb_array_elements(snapshot.payload -> 'members') member
  ),
  true
)
where jsonb_typeof(snapshot.payload -> 'members') = 'array'
  and exists (
    select 1
    from jsonb_array_elements(snapshot.payload -> 'members') member
    where coalesce(member ->> 'password', '') ~ '^\$2b\$[0-9]{2}\$'
  );