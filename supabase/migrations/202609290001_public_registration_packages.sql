create or replace function public.get_public_registration_packages()
returns jsonb
language sql
stable
security definer
set search_path = public
as $$
  with package_source as (
    select coalesce(
      (select payload -> 'packages' from public.site_admin_snapshots where id = 1),
      '[
        {"name":"Starter","price":29,"seats":5,"duration":1,"durationUnit":"month","description":"For a small team getting started.","features":["Sales and revenue tracking","Team and permissions"],"active":true},
        {"name":"Growth","price":79,"seats":12,"duration":1,"durationUnit":"month","description":"For growing businesses and teams.","features":["Sales and revenue tracking","Team and permissions","Attendance and payroll","Inventory and stock"],"active":true},
        {"name":"Scale","price":149,"seats":30,"duration":1,"durationUnit":"month","description":"For larger operations with more seats.","features":["Sales and revenue tracking","Team and permissions","Attendance and payroll","Inventory and stock","Reports and printing","Departments and roles"],"active":true}
      ]'::jsonb
    ) as packages
  )
  select coalesce(jsonb_agg(jsonb_build_object(
    'name', package.value ->> 'name',
    'price', coalesce(package.value -> 'price', '0'::jsonb),
    'seats', coalesce(package.value -> 'seats', '1'::jsonb),
    'duration', coalesce(package.value -> 'duration', '1'::jsonb),
    'durationUnit', coalesce(package.value ->> 'durationUnit', 'month'),
    'description', coalesce(package.value ->> 'description', ''),
    'features', case when jsonb_typeof(package.value -> 'features') = 'array' then package.value -> 'features' else '[]'::jsonb end,
    'active', true
  ) order by package.ordinality), '[]'::jsonb)
  from package_source
  cross join lateral jsonb_array_elements(
    case when jsonb_typeof(package_source.packages) = 'array' then package_source.packages else '[]'::jsonb end
  ) with ordinality as package(value, ordinality)
  where nullif(trim(package.value ->> 'name'), '') is not null
    and package.value ->> 'active' is distinct from 'false';
$$;

revoke all on function public.get_public_registration_packages() from public, anon, authenticated;
grant execute on function public.get_public_registration_packages() to anon, authenticated;