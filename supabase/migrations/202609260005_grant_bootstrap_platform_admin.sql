update auth.users
set raw_app_meta_data = coalesce(raw_app_meta_data, '{}'::jsonb)
  || jsonb_build_object('role', 'platform_admin')
where lower(email) = 'u-61646d696e4031323334@biztrack.app';