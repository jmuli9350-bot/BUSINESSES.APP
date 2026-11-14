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
  );
$$;