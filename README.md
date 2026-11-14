# Biz Track

Fielddesk is a React dashboard backed by Supabase for running a small business from one workspace.

## Included workflows

- Role-aware views for Owner, Manager, Stock Keeper, Cashier, and Worker
- Daily attendance check-in and check-out
- Payroll summary and monthly budget tracking
- Department and team performance surface
- Inventory watchlist with stock severity
- Sales performance and daily sales summary
- Supabase persistence for workspace data, business registrations, and platform settings
- Online/offline connection status and cached workspace viewing when a connection drops

## Run locally

```bash
npm install

npm run dev
```

## Supabase setup

1. Create a Supabase project.
2. Open the Supabase SQL editor and run [`supabase.sql`](supabase.sql).
3. Copy [`.env.example`](.env.example) to `.env.local` and fill in the project URL and anon key. These variables are required. Supabase remains the source of truth; the app can show a previously loaded workspace from this device during a connection outage, but sign-in and saving changes still require a connection.
4. Restart Vite with `npm run dev`.

The SQL enables tenant RLS and requires an authenticated Supabase user with a row in `public.tenant_memberships`. Business owners and workers sign in with their username and password; the app resolves each valid pair to a tenant-specific Auth identity and claims membership for that tenant. If Supabase email confirmation is enabled, username-based accounts cannot complete their first sign-in because generated `@biztrack.app` addresses cannot receive confirmation mail. Do not grant clients insert or update access to `public.tenant_memberships`.

Platform administrators must be provisioned as Supabase Auth users by a trusted operator, with `app_metadata.role` set to `platform_admin`. The app intentionally has no default admin credentials or public admin-registration flow; `user_metadata` is not an authorization source. Create and confirm the Auth user first. For a username that is not an email, use the app's generated email convention; for example, `muli@track12` maps to `u-6d756c6940747261636b3132@biztrack.app`. In the Supabase SQL editor, set the trusted claim for that exact Auth user:

```sql
update auth.users
set raw_app_meta_data = coalesce(raw_app_meta_data, '{}'::jsonb) || '{"role":"platform_admin"}'::jsonb
where email = 'u-6d756c6940747261636b3132@biztrack.app';
```

Verify one row was updated, then sign out and sign in again so the new claim is present in the Auth token. For an existing project, apply [`202609260002_secure_auth_boundaries.sql`](supabase/migrations/202609260002_secure_auth_boundaries.sql) before deploying this frontend. It hashes legacy plaintext account passwords, removes the obsolete site-admin password table and public password-based biometric RPCs, and restricts platform settings to platform-admin Auth claims. Then apply [`202610050001_tenant_scoped_usernames.sql`](supabase/migrations/202610050001_tenant_scoped_usernames.sql) before deploying the matching frontend. It allows the same username across businesses while requiring a different password for each account using that username. Tenant-specific Auth identities are created on first login. Fresh projects should run `supabase.sql` and then this migration.

After applying the SQL migration, the app uses the public anon key and direct Supabase auth + database access only. No Edge Functions are required for workspace login or worker provisioning. Workspace settings are saved through an owner-only RPC; payment-method settings are applied to the sales form immediately.

For existing projects, also apply [`202611020001_allow_password_reset_before_first_auth_login.sql`](supabase/migrations/202611020001_allow_password_reset_before_first_auth_login.sql). It lets site admins reset a business owner or worker password before that account has created its first Supabase Auth login, and synchronizes the Auth password when one already exists.

Then apply [`202611020003_confirm_auth_login_on_admin_reset.sql`](supabase/migrations/202611020003_confirm_auth_login_on_admin_reset.sql). A site-admin reset now confirms an existing generated BizTrack Auth login as well as synchronizing its password, so a pending email-confirmation state cannot block that reset account from signing in.

Apply [`202611020002_explain_login_identity_mismatches.sql`](supabase/migrations/202611020002_explain_login_identity_mismatches.sql) to distinguish a wrong username/password from a username/password pair shared by multiple accounts. The sign-in page now reports lookup failures separately instead of disguising them as invalid credentials.

Apply [`202611020004_login_resolution_performance.sql`](supabase/migrations/202611020004_login_resolution_performance.sql) to index account usernames and account-bearing workspace members and avoid repeating bcrypt comparisons during sign-in. The app also avoids unnecessary local password hashing and only attempts first-login account creation when Supabase reports invalid credentials, not on network or service errors.

The browser uses the public anon key only. Do not put a Supabase service-role key in this app. Biometric data is WebAuthn credential metadata only: credential IDs and verification proofs are stored in the non-exposed `private_biometrics` schema and accessed through tenant-checked RPCs. Raw biometric templates or fingerprint/face images are never stored.

Fingerprint readers are tenant-configurable through `public.biometric_devices`: each business stores its own provider, model, device identifier, and local bridge URL. The private credential registry stores only the reader's opaque subject identifier and enforces one subject per worker/business. A worker can register in multiple businesses, but cannot receive a second biometric in the same business. Raw fingerprint images/templates are never stored by Biz Track.

Hardware integration requires a small local bridge supplied by the reader manufacturer or SDK. The bridge should expose a provider-neutral contract: `POST /enroll` returns `{ "subjectIdentifier": "..." }`, and `POST /verify` accepts `{ "subjectIdentifier": "..." }` and returns `{ "verified": true }`. Different tenants can point `bridge_url` and `provider/model` at different reader integrations.

When an enabled row exists in `public.biometric_devices` with a `bridge_url`, the app uses that scanner bridge for worker enrollment and verification. Configure one row per tenant, for example:

```sql
insert into public.biometric_devices (tenant_id, provider, model, device_identifier, bridge_url)
values ('your-tenant-id', 'vendor-name', 'reader-model', 'reader-01', 'https://scanner-bridge.example.com');
```

The bridge must be reachable from the browser, allow CORS from the deployed app, and use HTTPS when Biz Track is served over HTTPS. A USB reader by itself cannot be called directly by a normal web page; it needs the manufacturer's local bridge or SDK service. If no enabled bridge is found, Biz Track falls back to the browser's WebAuthn/passkey prompt.

## Deploy to Vercel

From the project folder, run:

```bash
npx vercel --prod
npx vercel alias <deployment-url> Biztrack1.vercel.app
```

Add `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY` to the Vercel project environment variables for Production, then redeploy. The existing [`vercel.json`](vercel.json) keeps client-side routes working on refresh.

To enable the owner AI assistant, add `GEMINI_API_KEY` (recommended) or `OPENAI_API_KEY` as a server-side Production environment variable in Vercel, then redeploy. Create a Gemini API key in [Google AI Studio](https://aistudio.google.com/apikey). Enter only the key value; do not use a `VITE_` prefix or include the variable name in the value. The key must not be added to client-side code.
