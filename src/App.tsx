// @ts-nocheck
import { DEFAULT_SESSION_IDLE_TIMEOUT_MS, runBulkAttendanceAction } from './bulkAttendance.js'

function CrossDeviceSignInPage({ ownerAccount, members, businessAccounts, siteAdminAccount, onLogin, onBusinessLogin, onAdminLogin, onNavigate, adminOnly = false }: { ownerAccount: OwnerAccount | null; members: Member[]; businessAccounts: BusinessAccount[]; siteAdminAccount?: OwnerAccount | null; onLogin: (memberId: number, password?: string) => void | boolean | Promise<void | boolean>; onBusinessLogin: (account: BusinessAccount, memberId?: number, access?: AccessArea[], ownerPassword?: string, ownerVerified?: boolean, initialSnapshot?: Partial<WorkspaceSnapshot>) => void | boolean | Promise<void | boolean>; onAdminLogin?: (success: boolean) => void; onNavigate?: (page: string) => void; adminOnly?: boolean }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const matchesLoginName = (storedUser: string, inputUser: string) => {
    const normalizedStored = (storedUser || '').trim().toLowerCase()
    const normalizedInput = (inputUser || '').trim().toLowerCase()
    if (!normalizedStored || !normalizedInput) return false
    const storedVariants = [normalizedStored, normalizedStored.replace(/@biztrack\.app$/i, '')]
    const inputVariants = [normalizedInput, normalizedInput.replace(/@biztrack\.app$/i, '')]
    return storedVariants.some((variant) => inputVariants.includes(variant))
  }
  const submit = async () => {
    setBusy(true)
    setError('')
    try {
    const normalizedUser = username.trim().toLowerCase()
    const loginVariants = new Set([normalizedUser, normalizedUser.replace(/@biztrack\.app$/i, '')])
    const ownerMatch = !isSupabaseConfigured && ownerAccount && matchesLoginName(ownerAccount.username, normalizedUser) && await verifyPassword(ownerAccount.password, password)
    const localBusinessAccount = businessAccounts.find((account) => matchesLoginName(account.username, normalizedUser))
    const member = members.find((item) => matchesLoginName(item.username, normalizedUser))
    const memberMatch = !isSupabaseConfigured && member ? await verifyPassword(member.password, password) : false
    const localBusinessMatch = !isSupabaseConfigured && localBusinessAccount ? await verifyPassword(localBusinessAccount.password, password) : false
    if (ownerMatch) {
      if (localBusinessAccount && businessRequiresActivation(localBusinessAccount)) { setError('This business package has expired or is suspended. Contact the site admin to reactivate it.'); return }
      const accepted = localBusinessAccount
        ? await onBusinessLogin(localBusinessAccount, -1, undefined, password)
        : await onLogin(-1, password)
      if (accepted === false) { setError('Supabase could not open this owner workspace. Apply migration 202609280001_owner_login_lookup.sql and disable email confirmation for username-based accounts.'); setBusy(false); return }
      setError(''); return
    }
    if (!isSupabaseConfigured && member?.suspended && memberMatch) {
      setBusy(false)
      setError(`${member.name}, your account has been suspended by the business owner. You cannot sign in until it is reactivated. Contact the owner and ask them to activate your account.`)
      return
    }
    if (member && memberMatch && !isSupabaseConfigured) {
      const memberBusiness = businessAccounts.find((account) => account.tenantId === member.tenantId)
      if (memberBusiness && businessRequiresActivation(memberBusiness)) { setError('This business package has expired or is suspended.'); return }
      const accepted = await onLogin(member.id)
      if (accepted === false) { setError('This worker has no assigned pages. Ask the owner to assign access.'); setBusy(false); return }
      setError(''); return
    }
    const businessAccount = localBusinessAccount
    if (!isSupabaseConfigured && businessAccount && localBusinessMatch) {
      if (businessRequiresActivation(businessAccount)) { setError('This business package has expired. Contact the site admin to reactivate it.'); return }
      const accepted = await onBusinessLogin(businessAccount, -1, undefined, password)
      if (accepted === false) { setError('Could not verify this business with Supabase. Check Auth settings and apply the latest owner-access migration.'); setBusy(false); return }
      setError(''); return
    }
    if (isSupabaseConfigured && supabase) {
      const identity = adminOnly ? null : await resolveAccountLoginIdentity(normalizedUser, password)
      if (!identity?.auth_email) {
        const adminAuthResult = await supabase.auth.signInWithPassword({ email: supabaseAuthEmailForUsername(normalizedUser), password })
        if (adminAuthResult.data.session && adminAuthResult.data.user?.app_metadata?.role === 'platform_admin') {
          onAdminLogin?.(true)
          return
        }
        if (adminAuthResult.data.session) await supabase.auth.signOut()
        setBusy(false)
        setError(isNetworkFailure(adminAuthResult.error)
          ? 'Network issue. Check your internet connection and try signing in again.'
          : adminOnly
          ? 'Only a site administrator can sign in while maintenance mode is active.'
          : siteAdminAccount && matchesLoginName(siteAdminAccount.username, normalizedUser)
            ? 'Invalid username or password. Confirm the platform admin Auth account is provisioned with the platform_admin role.'
            : 'Invalid username or password. Check the username and password, then try again.')
        return
      }
      const email = String(identity.auth_email).toLowerCase()
      let authResult = await supabase.auth.signInWithPassword({ email, password })
      if (authResult.data.session && authResult.data.user?.app_metadata?.role === 'platform_admin') {
        onAdminLogin?.(true)
        return
      }
      if (authResult.error) {
        const signInError = authResult.error
        if (isNetworkFailure(signInError)) {
          setBusy(false)
          setError('Network issue while connecting to the sign-in service. Check your connection and try again.')
          return
        }
        if (signInError.code !== 'invalid_credentials' && signInError.code !== 'user_not_found') {
          setBusy(false)
          setError('The sign-in service could not complete your request. Please try again. If it continues, contact the site administrator.')
          return
        }
        authResult = await supabase.auth.signUp({ email, password })
        if (authResult.error && /already registered|already exists/i.test(authResult.error.message)) {
          setBusy(false)
          setError('The saved account password and its sign-in password do not match. Ask the site admin to reset this account password, then try again.')
          return
        }
      }
      if (authResult.data.session) {
        const claimResult = identity.account_type === 'owner'
          ? { data: null, error: { message: 'Owner account identified.' } }
          : await supabase.rpc('claim_member_tenant', { requested_username: normalizedUser, requested_password: password })
        const { data: claimRows, error: claimError } = claimResult
        const claim = Array.isArray(claimRows) ? claimRows[0] : claimRows
        if (!claimError && claim?.tenant_id && claim?.member_id) {
          const [businessResult, snapshotResult] = await Promise.all([
            supabase.from('business_accounts').select('id,business_name,owner_name,email,username,industry,plan,status,seats,monthly_price,next_billing,created_at,tenant_id').eq('tenant_id', claim.tenant_id).maybeSingle(),
            supabase.from('workspace_snapshots').select('payload').eq('tenant_id', claim.tenant_id).maybeSingle(),
          ])
          const { data: businessData, error: businessError } = businessResult
          const business = businessError ? null : normalizeBusinessAccount(businessData)
          const initialSnapshot = snapshotResult.error ? undefined : snapshotResult.data?.payload as Partial<WorkspaceSnapshot> | undefined
          if (business && !businessRequiresActivation(business)) {
            setError('')
            await onBusinessLogin(business, Number(claim.member_id), normalizeAccessAreas(claim.granted_pages), undefined, false, initialSnapshot)
            return
          }
          setError(business ? 'This business package has expired or is suspended.' : 'Could not load this worker account. Ask the business owner to try again.')
        } else if (claimError) {
          const { data: ownerRows, error: ownerClaimError } = await supabase.rpc('claim_owner_tenant_by_credentials', { requested_username: normalizedUser, requested_password: password })
          const ownerRecord = Array.isArray(ownerRows) ? ownerRows[0] : ownerRows
          const ownerBusiness = ownerRecord ? normalizeBusinessAccount({ ...ownerRecord, password: await hashPassword(password) }) : null
          if (!ownerClaimError && ownerBusiness && !businessRequiresActivation(ownerBusiness)) {
            const accepted = await onBusinessLogin(ownerBusiness, -1, undefined, password, true)
            if (accepted !== false) { setError(''); return }
            setError('Owner account was verified, but the workspace could not be opened. Check Supabase tenant access and try again.')
          } else if (ownerBusiness && businessRequiresActivation(ownerBusiness)) {
            setError('This business package has expired or is suspended.')
          } else {
            const ownerError = ownerClaimError?.message || claimError.message
            if (ownerError.includes('tenant_id') && ownerError.includes('ambiguous')) {
              const fallbackBusiness = localBusinessAccount || ownerBusiness || businessAccounts.find((account) => matchesLoginName(account.username, normalizedUser))
              if (fallbackBusiness && !businessRequiresActivation(fallbackBusiness)) {
                const accepted = await onBusinessLogin(fallbackBusiness, -1, undefined, password)
                if (accepted !== false) { setError(''); return }
              }
              setError('This business owner account was matched locally, but the tenant lookup is ambiguous in Supabase. The app is still allowing the workspace to open using the local account record.')
            } else if (ownerError.includes('Owner credentials do not match exactly one business account')) {
              const workerError = claimError?.message || ''
              if (/worker account is suspended/i.test(workerError)) {
                const workerName = member?.name || normalizedUser
                setError(`${workerName}, your account has been suspended by the business owner. You cannot sign in until it is reactivated. Contact the owner and ask them to activate your account.`)
              } else if (workerError.includes('claim_member_tenant')) {
                setError('Worker sign-in database function is missing or unavailable. Run the latest worker-login migration in Supabase, then try again.')
              } else if (workerError.includes('tenant_id') && workerError.includes('ambiguous')) {
                setError('The worker login database function has an ambiguous tenant membership conflict. Run migration 202609280004_fix_tenant_membership_claim_conflicts.sql in Supabase, then try again.')
              } else if (/no assigned pages/i.test(workerError)) {
                setError('Supabase still has the old worker-login function, which blocks workers without page grants. Run migration 202609280003_worker_login_without_page_grants.sql.')
              } else if (/duplicate worker usernames/i.test(workerError)) {
                setError('More than one worker account uses this username. Ask the owner to give each worker a unique username.')
              } else if (/invalid credentials/i.test(workerError)) {
                setError('Worker credentials were not matched in the shared workspace. Check the exact worker username and password, then have the owner save the worker account and page access again.')
              } else {
                setError('These credentials did not match a business owner or worker account. Use the exact username and password created for the account.')
              }
            } else if (ownerError.includes('claim_owner_tenant_by_credentials')) {
              setError('The owner sign-in database function is missing. Apply migration 202609280001_owner_login_lookup.sql, then try again.')
            } else {
              setError(`Owner sign-in failed: ${ownerError}. Check the registered username and business password.`)
            }
          }
        } else {
          setError('These credentials have no saved page grants. Ask the business owner to assign access and press OK again.')
        }
        await supabase.auth.signOut()
        setBusy(false)
        return
      }
      setBusy(false)
      if (authResult.data.user && !authResult.data.session) {
        setError('Supabase created this login but is waiting for email confirmation. Disable email confirmation in Supabase Authentication settings, then try again.')
      } else if (authResult.error) {
        setError(`Supabase sign-in failed: ${authResult.error.message}`)
      } else {
        setError('Supabase did not create a sign-in session. Check the project Auth settings and try again.')
      }
      return
    }
    setBusy(false)
    setError('Invalid username or password.')
    } catch (signInError) {
      setError(isNetworkFailure(signInError)
        ? 'Network issue. Check your internet connection and try signing in again.'
        : signInError instanceof Error ? signInError.message : 'Sign-in failed. Check your connection and try again.')
    } finally {
      setBusy(false)
    }
  }
  return <main className="auth-page client-signin-page"><section className="signin-story"><div className="signin-story-brand"><span className="auth-brand-mark">b</span><strong>BizTrack</strong></div><div className="signin-story-copy"><p className="signin-kicker">YOUR BUSINESS, IN CLEAR VIEW</p><h2>Make room for what matters.</h2><span>Keep your people, sales, and stock moving together, wherever work happens.</span></div><div className="signin-story-footer"><span>ONE WORKSPACE</span><span>BUILT FOR EVERYDAY WORK</span></div></section><section className="signin-panel"><form className="login-card minimal-login" onSubmit={(event) => { event.preventDefault(); if (!busy) void submit() }}><p className="signin-kicker">WORKSPACE ACCESS</p><h1>Welcome back</h1><p className="auth-copy">Sign in to continue to your workspace.</p><label className="login-field"><span>Username</span><input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" placeholder="Username" required /></label><label className="login-field"><span>Password</span><input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" placeholder="Password" required /></label>{error && <p className="login-error" role="alert">{error}</p>}<button className="primary-button login-button" type="submit" disabled={busy}>{busy ? 'Checking account...' : 'Sign in'} <span>→</span></button><p className="signin-register">New to Biz Track? <button type="button" onClick={() => onNavigate ? onNavigate('Register') : window.history.pushState({}, '', '/register/')}>Create account</button></p></form></section></main>
}

// @ts-nocheck
function MyLoginCredentialsDialog({ username, onSave, onClose }: { username: string; onSave: (username: string, currentPassword: string, newPassword: string) => Promise<void>; onClose: () => void }) {
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (saving) return
    const formElement = event.currentTarget
    const form = new FormData(formElement)
    const currentPassword = String(form.get('currentPassword') || '')
    const nextUsername = username.trim()
    const newPassword = String(form.get('newPassword') || '')
    const confirmation = String(form.get('confirmPassword') || '')
    if (newPassword && newPassword !== confirmation) { setError('The new passwords do not match.'); return }
    setSaving(true)
    setError('')
    setMessage('')
    try {
      await onSave(nextUsername, currentPassword, newPassword)
      ;(formElement.elements.namedItem('currentPassword') as HTMLInputElement).value = ''
      ;(formElement.elements.namedItem('newPassword') as HTMLInputElement).value = ''
      ;(formElement.elements.namedItem('confirmPassword') as HTMLInputElement).value = ''
      setMessage('Password updated. Username unchanged.')
    } catch (saveError) {
      setError(saveError instanceof Error ? saveError.message : 'Could not save changes.')
    } finally { setSaving(false) }
  }
  return <div className="admin-modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !saving) onClose() }}><section className="admin-modal credentials-modal" role="dialog" aria-modal="true" aria-labelledby="credentials-title"><button className="admin-modal-close" type="button" aria-label="Close" onClick={onClose} disabled={saving}>×</button><h2 id="credentials-title">Account</h2><form onSubmit={(event) => void submit(event)}><div className="form-grid"><label><span>Current password</span><input name="currentPassword" type="password" autoComplete="current-password" required disabled={saving} /></label><label><span>Username</span><input name="loginUsername" type="text" autoComplete="username" value={username} readOnly disabled={saving} /></label><label><span>New password</span><input name="newPassword" type="password" autoComplete="new-password" minLength={6} placeholder="Leave blank to keep current password" disabled={saving} /></label><label><span>Confirm new password</span><input name="confirmPassword" type="password" autoComplete="new-password" minLength={6} placeholder="Repeat new password" disabled={saving} /></label></div>{error && <p className="login-error" role="alert">{error}</p>}{message && <p className="settings-success" role="status">{message}</p>}<div className="form-actions"><button type="button" className="secondary-button" disabled={saving} onClick={onClose}>Cancel</button><button type="submit" className="primary-button" disabled={saving}>{saving ? 'Saving...' : 'Save'}</button></div></form></section></div>
}

function WorkspaceSettingsPage({ businessName, currency, paymentMethods, defaultSignIn, defaultSignOut, strictSignIn, allowMultipleDailyShifts, categories, setCategories, deletedCategories, setDeletedCategories, categoryUnits, setCategoryUnits, categoryThresholds, setCategoryThresholds, inventory, setInventory, onSaveIdentity, onSavePaymentMethods, onSaveAttendanceRules }: any) {
  const [identityDraft, setIdentityDraft] = useState({ businessName, currency })
  const [paymentMethodsDraft, setPaymentMethodsDraft] = useState<string[]>(paymentMethods)
  const [attendanceDraft, setAttendanceDraft] = useState({ defaultSignIn, defaultSignOut, strictSignIn, allowMultipleDailyShifts })
  const [identitySaving, setIdentitySaving] = useState(false)
  const [paymentMethodsSaving, setPaymentMethodsSaving] = useState(false)
  const [attendanceSaving, setAttendanceSaving] = useState(false)
  useEffect(() => setIdentityDraft({ businessName, currency }), [businessName, currency])
  useEffect(() => setPaymentMethodsDraft(paymentMethods), [paymentMethods])
  useEffect(() => setAttendanceDraft({ defaultSignIn, defaultSignOut, strictSignIn, allowMultipleDailyShifts }), [defaultSignIn, defaultSignOut, strictSignIn, allowMultipleDailyShifts])
  const saveIdentity = async () => {
    setIdentitySaving(true)
    try {
      const saved = await onSaveIdentity(identityDraft.businessName.trim(), identityDraft.currency)
      if (saved) setIdentityDraft({ businessName: identityDraft.businessName.trim(), currency: identityDraft.currency })
    } finally { setIdentitySaving(false) }
  }
  const savePaymentMethods = async () => {
    setPaymentMethodsSaving(true)
    try {
      const saved = await onSavePaymentMethods(paymentMethodsDraft)
      if (saved) setPaymentMethodsDraft(paymentMethodsDraft)
    } finally { setPaymentMethodsSaving(false) }
  }
  const saveAttendanceRules = async () => {
    setAttendanceSaving(true)
    try { await onSaveAttendanceRules(attendanceDraft) } finally { setAttendanceSaving(false) }
  }
  return <>
    <PageHeading eyebrow="BUSINESS WORKSPACE / SETTINGS" title="Workspace settings" subtitle="These settings apply to this business workspace only." />
    <section className="settings-stack">
      <article className="panel member-form">
        <PanelHeading title="Business identity and money" subtitle="These choices are used across the workspace and sales records." />
        <div className="form-grid">
          <label><span>Business name</span><input value={identityDraft.businessName} disabled={identitySaving} onChange={(event) => setIdentityDraft((current) => ({ ...current, businessName: event.target.value }))} /></label>
          <label><span>Display currency</span><select value={identityDraft.currency} disabled={identitySaving} onChange={(event) => setIdentityDraft((current) => ({ ...current, currency: event.target.value }))}><option>KES</option><option>USD</option><option>EUR</option></select></label>
        </div>
        <div className="form-actions settings-section-actions"><button type="button" className="primary-button" disabled={identitySaving || !identityDraft.businessName.trim() || (identityDraft.businessName.trim() === businessName && identityDraft.currency === currency)} onClick={() => void saveIdentity()}>{identitySaving ? 'Saving...' : 'Save identity and currency'}</button></div>
        <div className="settings-choice-group"><strong>Sales payment methods</strong><small>Choose methods available to cashiers.</small><div className="settings-choice-grid">{['Cash', 'Credit', 'Mobile money'].map((method) => <label key={method} className={paymentMethodsDraft.includes(method) ? 'settings-choice enabled' : 'settings-choice'}><input type="checkbox" disabled={paymentMethodsSaving} checked={paymentMethodsDraft.includes(method)} onChange={() => setPaymentMethodsDraft((current) => current.includes(method) ? current.filter((item) => item !== method) : [...current, method])} /><span>{method}</span></label>)}</div><div className="form-actions settings-section-actions"><button type="button" className="primary-button" disabled={paymentMethodsSaving || (paymentMethodsDraft.length === paymentMethods.length && paymentMethodsDraft.every((method: string) => paymentMethods.includes(method)))} onClick={() => void savePaymentMethods()}>{paymentMethodsSaving ? 'Saving...' : 'Save payment methods'}</button></div></div>
      </article>
      <article className="panel member-form">
        <PanelHeading title="Attendance rules" subtitle="Control daily sign-in behavior and new worker schedules." />
        <div className="form-grid settings-times">
          <label><span>Default sign-in time</span><input type="time" value={attendanceDraft.defaultSignIn} disabled={attendanceSaving} onChange={(event) => setAttendanceDraft((current: typeof attendanceDraft) => ({ ...current, defaultSignIn: event.target.value }))} /></label>
          <label><span>Default sign-out time</span><input type="time" value={attendanceDraft.defaultSignOut} disabled={attendanceSaving} onChange={(event) => setAttendanceDraft((current: typeof attendanceDraft) => ({ ...current, defaultSignOut: event.target.value }))} /></label>
          <label className="settings-checkbox"><input type="checkbox" checked={!attendanceDraft.allowMultipleDailyShifts} disabled={attendanceSaving} onChange={(event) => setAttendanceDraft((current: typeof attendanceDraft) => ({ ...current, allowMultipleDailyShifts: !event.target.checked }))} /><span><strong>One sign-in per day</strong><small>Prevent a second shift on the same day.</small></span></label>
          <label className="settings-checkbox"><input type="checkbox" checked={attendanceDraft.strictSignIn} disabled={attendanceSaving} onChange={(event) => setAttendanceDraft((current: typeof attendanceDraft) => ({ ...current, strictSignIn: event.target.checked }))} /><span><strong>Strict sign-in checks</strong><small>Block sign-in after schedule and sign-out before schedule.</small></span></label>
        </div>
        <div className="form-actions settings-section-actions"><button type="button" className="primary-button" disabled={attendanceSaving || (attendanceDraft.defaultSignIn === defaultSignIn && attendanceDraft.defaultSignOut === defaultSignOut && attendanceDraft.strictSignIn === strictSignIn && attendanceDraft.allowMultipleDailyShifts === allowMultipleDailyShifts)} onClick={() => void saveAttendanceRules()}>{attendanceSaving ? 'Saving...' : 'Save attendance rules'}</button></div>
      </article>
      <InventoryCategorySettings categories={categories} setCategories={setCategories} deletedCategories={deletedCategories} setDeletedCategories={setDeletedCategories} categoryUnits={categoryUnits} setCategoryUnits={setCategoryUnits} categoryThresholds={categoryThresholds} setCategoryThresholds={setCategoryThresholds} inventory={inventory} setInventory={setInventory} />
      <article className="panel member-form"><PanelHeading title="Account and access policy" subtitle="Only workers with login accounts appear in Permissions and can sign in." /><div className="settings-policy"><span className="settings-policy-icon">✓</span><div><strong>Owner-controlled access</strong><small>Enable accounts from Add worker, then assign pages in Permissions.</small></div></div></article>
    </section>
  </>
}

type CategoryDraft = { key: string; originalCategory: string | null; name: string; unit: string; threshold: number }
function InventoryCategorySettings({ categories, setCategories, deletedCategories, setDeletedCategories, categoryUnits, setCategoryUnits, categoryThresholds, setCategoryThresholds, inventory, setInventory }: { categories: string[]; setCategories: (categories: string[]) => void; deletedCategories: string[]; setDeletedCategories: (categories: string[]) => void; categoryUnits: Record<string, string>; setCategoryUnits: (units: Record<string, string>) => void; categoryThresholds: Record<string, number>; setCategoryThresholds: (thresholds: Record<string, number>) => void; inventory: InventoryItem[]; setInventory: React.Dispatch<React.SetStateAction<InventoryItem[]>> }) {
  const hiddenCategories = new Set(deletedCategories.map((category) => category.toLowerCase()))
  const buildDrafts = (): CategoryDraft[] => Array.from(new Set([...categories, ...inventory.map((item) => item.category).filter((category) => category && !hiddenCategories.has(category.toLowerCase()))])).map((category, index) => ({ key: `${category}-${index}`, originalCategory: category, name: category, unit: categoryUnits[category] || 'pieces', threshold: categoryThresholds[category] ?? 5 }))
  const [drafts, setDrafts] = useState<CategoryDraft[]>(buildDrafts)
  const [error, setError] = useState('')
  const [confirmedDeletions, setConfirmedDeletions] = useState<string[]>([])
  const [pendingDelete, setPendingDelete] = useState<CategoryDraft | null>(null)
  const [firstConfirmation, setFirstConfirmation] = useState('')
  const [secondConfirmation, setSecondConfirmation] = useState('')
  const normalizedDrafts = (items: CategoryDraft[]) => items.map((draft) => ({ name: draft.name.trim(), unit: (draft.unit || 'pieces').trim() || 'pieces', threshold: Number.isFinite(draft.threshold) ? Math.max(0, Number(draft.threshold)) : 0 }))
  const hasChanges = JSON.stringify(normalizedDrafts(drafts)) !== JSON.stringify(normalizedDrafts(buildDrafts()))
  useEffect(() => { setDrafts(buildDrafts()); setError('') }, [categories, deletedCategories, categoryUnits, categoryThresholds])
  const updateDraft = (key: string, changes: Partial<CategoryDraft>) => setDrafts((current) => current.map((draft) => draft.key === key ? { ...draft, ...changes } : draft))
  const saveCategories = () => {
    const nextCategories = drafts.map((draft) => draft.name.trim())
    if (nextCategories.some((name) => !name)) { setError('Enter a name for each category.'); return }
    if (new Set(nextCategories.map((name) => name.toLowerCase())).size !== nextCategories.length) { setError('Category names must be unique.'); return }
    const nextUnits: Record<string, string> = { ...categoryUnits }
    const nextThresholds: Record<string, number> = { ...categoryThresholds }
    const renamedCategories: Record<string, string> = {}
    drafts.forEach((draft, index) => {
      const name = nextCategories[index]
      nextUnits[name] = draft.unit.trim() || 'pieces'
      nextThresholds[name] = Math.max(0, Number.isFinite(draft.threshold) ? draft.threshold : 0)
      if (draft.originalCategory) renamedCategories[draft.originalCategory] = name
    })
    setInventory((current) => current.map((item) => {
      const category = renamedCategories[item.category] || item.category
      return nextCategories.includes(category) ? { ...item, category, unit: nextUnits[category] || item.unit, reorderAt: nextThresholds[category] ?? item.reorderAt } : item
    }))
    setCategories(nextCategories)
    const nextDeletedCategories = new Map([...deletedCategories, ...confirmedDeletions].map((category) => [category.toLowerCase(), category]))
    nextCategories.forEach((category) => nextDeletedCategories.delete(category.toLowerCase()))
    setDeletedCategories(Array.from(nextDeletedCategories.values()))
    setCategoryUnits(nextUnits)
    setCategoryThresholds(nextThresholds)
    setConfirmedDeletions([])
    setError('')
  }
  const confirmCategoryDeletion = () => {
    if (!pendingDelete) return
    setDrafts((current) => current.filter((draft) => draft.key !== pendingDelete.key))
    if (pendingDelete.originalCategory) setConfirmedDeletions((current) => [...current, pendingDelete.originalCategory!])
    setPendingDelete(null)
    setFirstConfirmation('')
    setSecondConfirmation('')
  }
  const pendingName = pendingDelete?.name.trim() || pendingDelete?.originalCategory || ''
  const deletionConfirmed = Boolean(pendingName && firstConfirmation.trim() === pendingName && secondConfirmation.trim() === pendingName)
  return <article className="panel member-form">
    <PanelHeading title="Inventory categories" subtitle="Category removal keeps inventory and printed history intact. Save changes to apply catalog edits." />
    <div className="category-unit-list">
      <div className="category-unit-heading"><span>Category</span><span>Unit</span><span>Low-stock threshold</span><span></span></div>
      {drafts.map((draft) => {
        return <div className="category-unit-row" key={draft.key}>
          <input aria-label="Category name" value={draft.name} onChange={(event) => updateDraft(draft.key, { name: event.target.value })} />
          <input aria-label="Unit" value={draft.unit} onChange={(event) => updateDraft(draft.key, { unit: event.target.value })} />
          <input aria-label="Low-stock threshold" type="number" min="0" value={draft.threshold} onChange={(event) => updateDraft(draft.key, { threshold: Number(event.target.value) })} />
          <button type="button" className="category-delete-button" title="Remove category" aria-label={`Remove ${draft.name || 'category'}`} onClick={() => {
            if (!draft.name.trim() && !draft.originalCategory) setDrafts((current) => current.filter((item) => item.key !== draft.key))
            else { setPendingDelete(draft); setFirstConfirmation(''); setSecondConfirmation('') }
          }}>Delete</button>
        </div>
      })}
    </div>
    {error && <p className="login-error" role="alert">{error}</p>}
    <div className="category-settings-actions"><button type="button" className="secondary-button" onClick={() => setDrafts((current) => [...current, { key: `new-${Date.now()}`, originalCategory: null, name: '', unit: 'pieces', threshold: 5 }])}>+ Add category</button><button type="button" className="primary-button" disabled={!hasChanges} onClick={saveCategories}>Save changes</button></div>
    {pendingDelete && <div className="business-confirm-backdrop" role="presentation"><section className="business-confirm-dialog category-delete-dialog" role="alertdialog" aria-modal="true" aria-labelledby="category-delete-title"><p className="eyebrow">Inventory categories</p><h2 id="category-delete-title">Confirm category removal</h2><p>Type <strong>{pendingName}</strong> in both fields to remove it from settings. Inventory items and existing print records will be kept.</p><label><span>Category name</span><input autoFocus value={firstConfirmation} onChange={(event) => setFirstConfirmation(event.target.value)} autoComplete="off" /></label><label><span>Type the name again</span><input value={secondConfirmation} onChange={(event) => setSecondConfirmation(event.target.value)} autoComplete="off" /></label><div className="business-confirm-actions"><button type="button" data-confirm="cancel" className="secondary-button" onClick={() => setPendingDelete(null)}>Cancel</button><button type="button" className="primary-button" disabled={!deletionConfirmed} onClick={confirmCategoryDeletion}>Confirm delete</button></div></section></div>}
  </article>
}

function PayrollReportOrderSettings({ value, onSave }: { value: PayrollReportOrder; onSave: (value: PayrollReportOrder) => Promise<boolean> }) {
  const [draft, setDraft] = useState(value)
  const [saving, setSaving] = useState(false)
  useEffect(() => setDraft(value), [value])
  const saveChanges = async () => {
    setSaving(true)
    try { await onSave(draft) } finally { setSaving(false) }
  }
  return <article className="panel member-form"><PanelHeading title="Payroll report order" subtitle="Choose how earnings and deductions are arranged in payroll reports." /><div className="form-grid settings-times"><label><span>Entry arrangement</span><select value={draft} onChange={(event) => setDraft(event.target.value as PayrollReportOrder)}><option value="chronological">By date, earnings and deductions together</option><option value="deductions-bottom">Deductions at the bottom</option><option value="deductions-top">Deductions at the top</option></select></label></div><div className="form-actions"><button type="button" className="primary-button" disabled={saving || draft === value} onClick={() => void saveChanges()}>{saving ? 'Saving...' : 'Save changes'}</button></div></article>
}


import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import './App.css'
import { isSupabaseConfigured, supabase } from './lib/supabase'
import { cacheWorkspaceSnapshot, readCachedWorkspaceSnapshot } from './lib/workspace-cache'

const remoteAdminFeaturesEnabled = true
const remoteBiometricRegistryEnabled = false
const isBcryptHash = (value: string) => /^\$2[aby]\$\d{2}\$/.test(value)
const verifyPassword = async (storedPassword: string, enteredPassword: string) => isBcryptHash(storedPassword)
  ? (await import('bcryptjs')).compare(enteredPassword, storedPassword)
  : storedPassword === enteredPassword
const postgresCompatibleHash = (value: string) => value.startsWith('$2b$') ? `$2a$${value.slice(4)}` : value
const isNetworkFailure = (error: unknown) => {
  if (typeof navigator !== 'undefined' && !navigator.onLine) return true
  const message = error instanceof Error ? `${error.name}: ${error.message}` : String(error || '')
  return /failed to fetch|network(error| request failed)?|load failed|timed? ?out|connection (?:reset|refused|closed|lost)/i.test(message)
}
const hashPassword = (password: string) => isBcryptHash(password)
  ? Promise.resolve(postgresCompatibleHash(password))
  : import('bcryptjs').then(({ hash }) => hash(password, 12)).then(postgresCompatibleHash)
const supabaseAuthEmailForUsername = (username: string) => {
  const normalized = username.trim().toLowerCase()
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(normalized)) return normalized
  const encoded = Array.from(new TextEncoder().encode(normalized), (byte) => byte.toString(16).padStart(2, '0')).join('')
  return `u-${encoded}@biztrack.app`
}
const resolveAccountLoginIdentity = async (username: string, password: string) => {
  if (!supabase) return null
  const { data, error } = await supabase.rpc('resolve_login_identity', {
    requested_username: username,
    requested_password: password,
  })
  if (error) {
    const lookupError = `${error.code || ''} ${error.message || ''} ${error.details || ''}`
    if (/duplicate username and password/i.test(lookupError)) {
      throw new Error('This username and password match more than one account. Keep the username, but set a different password for each account that shares it.')
    }
    if (/invalid credentials|invalid username or password/i.test(lookupError)) return null
    if (/PGRST202|42883|schema cache|function .*resolve_login_identity.*does not exist/i.test(lookupError)) {
      throw new Error('The sign-in database update is missing. Apply migrations 202610050001_tenant_scoped_usernames.sql and 202611020002_explain_login_identity_mismatches.sql in Supabase, then try again.')
    }
    if (/42501|permission denied/i.test(lookupError)) {
      throw new Error('Supabase denied access to the sign-in lookup. Apply the latest tenant-scoped username migrations and verify the function grants in Supabase.')
    }
    throw new Error(`Account lookup failed${error.code ? ` (${error.code})` : ''}: ${error.message || 'Unknown Supabase error'}`)
  }
  return Array.isArray(data) ? data[0] || null : data
}
const accountCredentialsAvailable = async (username: string, password: string) => {
  if (!supabase) return true
  const { data, error } = await supabase.rpc('account_credentials_available', {
    requested_username: username,
    requested_password: password,
  })
  if (error) throw new Error(`Could not check account credentials. Apply migration 202610050001_tenant_scoped_usernames.sql, then try again. ${error.message}`)
  return data === true
}
const toBase64Url = (value: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
const fromBase64Url = (value: string) => { const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((value.length + 3) % 4); return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0)) }
const biometricSupported = () => Boolean(window.isSecureContext && navigator.credentials && window.PublicKeyCredential)
type BiometricBridge = { bridge_url: string; provider: string; model: string; device_identifier: string }
const readBiometricBridge = async (tenantId: string): Promise<BiometricBridge | null> => {
  if (!supabase || !tenantId || tenantId === 'workspace' || !remoteBiometricRegistryEnabled) return null
  const { data, error } = await supabase.from('biometric_devices').select('bridge_url,provider,model,device_identifier').eq('tenant_id', tenantId).eq('enabled', true).not('bridge_url', 'is', null).limit(1).maybeSingle()
  if (error || !data?.bridge_url) return null
  return data as BiometricBridge
}
const callBiometricBridge = async (bridge: BiometricBridge, path: '/enroll' | '/verify', body: Record<string, string>) => {
  const response = await fetch(`${bridge.bridge_url.replace(/\/$/, '')}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  if (!response.ok) throw new Error(`The ${bridge.provider} scanner bridge returned an error.`)
  return response.json() as Promise<{ subjectIdentifier?: string; verified?: boolean }>
}
const ensureOwnerTenantSession = async (username: string, password: string, tenantId?: string) => {
  if (!supabase || !tenantId) return true
  const identity = await resolveAccountLoginIdentity(username, password)
  if (!identity || identity.account_type !== 'owner' || identity.tenant_id !== tenantId || !identity.auth_email) return false
  const email = String(identity.auth_email).toLowerCase()
  let { data } = await supabase.auth.getSession()
  if (data.session?.user.email?.toLowerCase() !== email) {
    await supabase.auth.signOut()
    data = { session: null } as typeof data
  }
  if (!data.session) {
    const signedIn = await supabase.auth.signInWithPassword({ email, password })
    data = signedIn.data
    if (!data.session) {
      const signedUp = await supabase.auth.signUp({ email, password })
      data = signedUp.data
    }
  }
  if (!data.session) return false
  try {
    const { data: claimRows, error } = await supabase.rpc('claim_owner_tenant_by_credentials', {
      requested_username: username,
      requested_password: password,
    })
    const claim = Array.isArray(claimRows) ? claimRows[0] : claimRows
    if (error) return false
    return Boolean(claim?.tenant_id) && claim.tenant_id === tenantId
  } catch {
    return false
  }
}
const showBusinessConfirm = (businessName: string, message: string, title = 'Confirm action') => new Promise<boolean>((resolve) => {
  const overlay = document.createElement('div')
  overlay.className = 'business-confirm-backdrop'
  const dialog = document.createElement('section')
  dialog.className = 'business-confirm-dialog'
  dialog.setAttribute('role', 'dialog')
  dialog.setAttribute('aria-modal', 'true')
  const businessLabel = document.createElement('p')
  businessLabel.className = 'eyebrow'
  businessLabel.textContent = businessName
  const heading = document.createElement('h2')
  heading.textContent = title
  const detail = document.createElement('p')
  detail.textContent = message
  const actions = document.createElement('div')
  actions.className = 'business-confirm-actions'
  const cancelButton = document.createElement('button')
  cancelButton.type = 'button'
  cancelButton.className = 'secondary-button'
  cancelButton.textContent = 'Cancel'
  const continueButton = document.createElement('button')
  continueButton.type = 'button'
  continueButton.className = 'primary-button'
  continueButton.textContent = 'Continue'
  const finish = (value: boolean) => { document.removeEventListener('keydown', handleEscape); overlay.remove(); resolve(value) }
  const handleEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') finish(false) }
  cancelButton.addEventListener('click', () => finish(false))
  continueButton.addEventListener('click', () => finish(true))
  overlay.addEventListener('click', (event) => { if (event.target === overlay) finish(false) })
  document.addEventListener('keydown', handleEscape)
  actions.append(cancelButton, continueButton)
  dialog.append(businessLabel, heading, detail, actions)
  overlay.appendChild(dialog)
  document.body.appendChild(overlay)
  cancelButton.focus()
})
let businessAlertSequence = 0
const showBusinessAlert = (businessName: string, message: string, title = 'Notice') => {
  const overlay = document.createElement('div')
  overlay.className = 'business-confirm-backdrop'
  const dialog = document.createElement('section')
  dialog.className = 'business-confirm-dialog business-alert-dialog'
  dialog.setAttribute('role', 'alertdialog')
  dialog.setAttribute('aria-modal', 'true')
  const businessLabel = document.createElement('p')
  businessLabel.className = 'eyebrow'
  businessLabel.textContent = businessName
  const warningIcon = document.createElement('span')
  warningIcon.className = 'business-alert-icon'
  warningIcon.setAttribute('aria-hidden', 'true')
  warningIcon.textContent = '!'
  const heading = document.createElement('h2')
  heading.id = `business-alert-title-${++businessAlertSequence}`
  heading.textContent = title
  dialog.setAttribute('aria-labelledby', heading.id)
  const detail = document.createElement('p')
  detail.textContent = message
  const actions = document.createElement('div')
  actions.className = 'business-confirm-actions'
  const closeButton = document.createElement('button')
  closeButton.type = 'button'
  closeButton.className = 'primary-button'
  closeButton.textContent = 'OK'
  const close = () => { document.removeEventListener('keydown', handleEscape); overlay.remove() }
  const handleEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') close() }
  closeButton.addEventListener('click', close)
  overlay.addEventListener('click', (event) => { if (event.target === overlay) close() })
  document.addEventListener('keydown', handleEscape)
  actions.appendChild(closeButton)
  dialog.append(businessLabel, warningIcon, heading, detail, actions)
  overlay.appendChild(dialog)
  document.body.appendChild(overlay)
  closeButton.focus()
}
const showBiometricPrompt = (title: string, detail: string) => {
  const overlay = document.createElement('div')
  overlay.className = 'biometric-dialog-backdrop'
  overlay.innerHTML = `<section class="biometric-dialog" role="dialog" aria-modal="true"><button type="button" class="biometric-dialog-close" aria-label="Close">×</button><div class="biometric-dialog-icon">⌁</div><p class="eyebrow">SECURE ACTION PROOF</p><h2>${title}</h2><p>${detail}</p><div class="biometric-dialog-status">Waiting for device verification...</div></section>`
  const close = () => overlay.remove()
  overlay.addEventListener('click', (event) => { if (event.target === overlay || (event.target as HTMLElement).closest('.biometric-dialog-close')) close() })
  document.addEventListener('keydown', (event) => { if (event.key === 'Escape') close() }, { once: true })
  document.body.appendChild(overlay)
  return { overlay, status: overlay.querySelector('.biometric-dialog-status') as HTMLElement }
}
async function runBiometricPrompt<T>(title: string, detail: string, operation: () => Promise<T>) {
  const prompt = showBiometricPrompt(title, detail)
  try { const result = await operation(); prompt.overlay.remove(); return result } catch (error) { prompt.status.textContent = error instanceof Error ? error.message : 'Verification was cancelled.'; window.setTimeout(() => prompt.overlay.remove(), 1500); throw error }
}
async function registerBiometric(memberId: number, memberName: string, businessName: string, tenantId: string, owner?: { username: string; password: string }) {
  return runBiometricPrompt('Register worker biometric', `Verify ${memberName} for ${businessName}. This will be used as proof for this worker's attendance actions.`, async () => {
    const bridge = await readBiometricBridge(tenantId)
    if (bridge) {
      const result = await callBiometricBridge(bridge, '/enroll', { memberId: String(memberId), memberName, deviceIdentifier: bridge.device_identifier })
      if (!result.subjectIdentifier) throw new Error('The scanner did not return a worker subject identifier.')
      return result.subjectIdentifier
    }
    if (!biometricSupported()) throw new Error('No scanner bridge is configured, and this browser or device does not support biometric verification. Configure a scanner bridge or use HTTPS with WebAuthn.')
    if (supabase && tenantId && owner) {
      const { data: existingCredentials, error } = await supabase.rpc('list_owner_biometric_credentials', { requested_tenant_id: tenantId, requested_username: owner.username, requested_password: owner.password })
      if (error) throw new Error('Could not check this business biometric registry. Run the latest Supabase SQL migration and try again.')
      const existingCredentialIds = (existingCredentials || []).map((item: { credential_id: string }) => item.credential_id).filter(Boolean)
      if (existingCredentialIds.length) {
        try {
          await navigator.credentials.get({ publicKey: { challenge: crypto.getRandomValues(new Uint8Array(32)), allowCredentials: existingCredentialIds.map((credentialId) => ({ id: fromBase64Url(credentialId), type: 'public-key' as const })), userVerification: 'required', timeout: 60000 } })
          throw new Error('This biometric is already registered in this business. Delete the previous worker before registering it again.')
        } catch (error) {
          if (error instanceof Error && error.message.includes('already registered')) throw error
        }
      }
    }
    const credential = await navigator.credentials.create({ publicKey: { challenge: crypto.getRandomValues(new Uint8Array(32)), rp: { name: businessName }, user: { id: new TextEncoder().encode(String(memberId)), name: memberName, displayName: memberName }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }], authenticatorSelection: { userVerification: 'required' }, timeout: 60000 } }) as PublicKeyCredential | null
    if (!credential) throw new Error('Biometric registration was cancelled.')
    return toBase64Url(credential.rawId)
  })
}
async function verifyBiometric(credentialId: string, tenantId: string, action = 'attendance action', businessName = 'your business') {
  return runBiometricPrompt(`Confirm ${action}`, `Verify the registered worker biometric for ${businessName} before this action can be completed.`, async () => {
    const bridge = await readBiometricBridge(tenantId)
    if (bridge) {
      const result = await callBiometricBridge(bridge, '/verify', { subjectIdentifier: credentialId, deviceIdentifier: bridge.device_identifier })
      if (!result.verified) throw new Error('The scanner could not verify this worker.')
      return true
    }
    if (!biometricSupported()) throw new Error('This browser or device does not support biometric verification. Use HTTPS or localhost and try again.')
    const credential = await navigator.credentials.get({ publicKey: { challenge: crypto.getRandomValues(new Uint8Array(32)), allowCredentials: [{ id: fromBase64Url(credentialId), type: 'public-key' }], userVerification: 'required', timeout: 60000 } })
    if (!credential) throw new Error('Biometric verification was cancelled.')
    return true
  })
}
async function saveBiometricRecord(table: 'biometric_credentials' | 'biometric_proofs', values: Record<string, unknown>, owner?: { username: string; password: string }) {
  if (!isSupabaseConfigured || !supabase || !remoteBiometricRegistryEnabled) return true
  if (table === 'biometric_credentials' && owner) {
    const { error: legacyError } = await supabase.rpc('register_owner_biometric_legacy', {
      requested_tenant_id: values.tenant_id,
      requested_username: owner.username,
      requested_password: owner.password,
      requested_member_id: values.member_id,
      requested_member_name: values.member_name,
      requested_credential_id: values.credential_id,
      requested_registered_at: values.registered_at,
    })
    if (!legacyError) return true
    if (legacyError.message.toLowerCase().includes('already registered') || legacyError.message.toLowerCase().includes('already has a biometric')) throw new Error('This worker already has a biometric in this business. The same biometric can be used in another business.')
  }
  const functionName = table === 'biometric_credentials' ? 'register_biometric_credential' : 'record_biometric_proof'
  const args = table === 'biometric_credentials' ? { requested_tenant_id: values.tenant_id, requested_member_id: values.member_id, requested_member_name: values.member_name, requested_credential_id: values.credential_id, requested_registered_at: values.registered_at } : { requested_tenant_id: values.tenant_id, requested_member_id: values.member_id, requested_action: values.action, requested_credential_id: values.credential_id, requested_verified_at: values.verified_at, requested_attendance_date: values.attendance_date }
  const { error } = await supabase.rpc(functionName, args)
  if (error) {
    if (table === 'biometric_credentials' && (error.code === '23505' || error.message.toLowerCase().includes('already registered') || error.message.toLowerCase().includes('already has a biometric'))) throw new Error('This worker already has a biometric in this business. The same biometric can be used in another business.')
    if (error.message.toLowerCase().includes('tenant access denied')) throw new Error('This business is not yet provisioned for secure storage. Add the owner Auth membership for this tenant, then try again.')
    throw new Error(`Could not save ${table}. Try again.`)
  }
  return true
}
const canTransitionPaymentStatus = (currentStatus: PaymentStatus | undefined, nextStatus: PaymentStatus): boolean => {
  if (!currentStatus) return true
  if (currentStatus === 'Paid') return nextStatus === 'Paid'
  if (currentStatus === 'Pending') return nextStatus === 'Pending' || nextStatus === 'Paid' || nextStatus === 'Partially paid' || nextStatus === 'On hold'
  if (currentStatus === 'On hold') return nextStatus === 'Pending' || nextStatus === 'Paid' || nextStatus === 'Partially paid' || nextStatus === 'On hold'
  if (currentStatus === 'Partially paid') return nextStatus === 'Paid' || nextStatus === 'Partially paid'
  return true
}

type Role = 'Owner' | 'Manager' | 'Stock Keeper' | 'Cashier' | 'Worker'
type AttendanceStatus = 'Present' | 'Late' | 'Early' | 'Absent' | 'Off'
type PaymentStatus = 'Pending' | 'Paid' | 'Partially paid' | 'On hold'
type PayTerms = 'Casual' | 'Per shift'
type PayrollPaymentRecord = { id: string; date: string; amount: number; reason: string; status: 'Paid' | 'Partially paid'; balanceRemaining?: number; balanceSourceTerms?: PayTerms | 'Mixed'; paymentBatchId?: string }
type Member = { id: number; tenantId?: string; name: string; username: string; password: string; hasAccount?: boolean; suspended?: boolean; archived?: boolean; joinedAt?: string; scheduledUpdate?: { effectiveAt: string; changes: Partial<Member>; includeTodayShift?: boolean }; payrollCarryBalance?: number; payrollCarryPayTerms?: PayTerms | 'Mixed'; payrollPaymentHistory?: PayrollPaymentRecord[]; payTermsSince?: string; biometricCredentialId?: string; phone: string; email: string; department: string; role: Role; initials: string; color: string; payRate: number; payTerms?: PayTerms; payFrequency: PayFrequency; signInTime: string; signOutTime: string }
type OwnerAccount = { name: string; username: string; password: string; business?: string; tenantId?: string; phone?: string; industry?: string; plan?: SubscriptionPlan }
type AttendanceEntry = { memberId: number; date: string; status: AttendanceStatus; checkIn: string; checkOut: string; workerName?: string; workerDepartment?: string; workerRole?: Role; workerPayTerms?: PayTerms; workerPayFrequency?: PayFrequency; payRate?: number; earningType?: 'casual' | 'shift'; earningId?: number; reason?: string; paymentStatus?: PaymentStatus; paymentReceived?: number; paymentHistory?: PayrollPaymentRecord[]; paidAt?: string; paymentBatchId?: string; biometricProof?: { action: string; verifiedAt: string; credentialId: string } }
type CasualEarning = { id: number; memberId: number; date: string; amount: number; paymentStatus: PaymentStatus; paymentReceived: number; workerName?: string; workerDepartment?: string; workerRole?: Role; workerPayTerms?: PayTerms; workerPayFrequency?: PayFrequency; earningReason?: string; reason?: string; paymentHistory?: PayrollPaymentRecord[]; paidAt?: string; paymentBatchId?: string }
type PaymentMethod = 'Cash' | 'Credit' | 'Mobile money'
type Sale = { id: number; amount: number; paymentMethod: PaymentMethod; date: string; time: string; cashier: string; archived?: boolean }
type InventoryItem = { id: number; name: string; category: string; quantity: number; initialQuantity?: number; unit: string; reorderAt: number }
type Expense = { id: number; inventoryItemId: number; itemName: string; category: string; quantity: number; unit: string; reason: string; date: string; time: string }
type StockMovement = { id: number; type: 'Stocked' | 'Used'; inventoryItemId: number; itemName: string; category: string; quantity: number; unit: string; reason: string; date: string; time: string }
type Deduction = { id: number; memberId: number; amount: number; reason: string; date: string; archived?: boolean }
type AccessArea = 'Overview' | 'Attendance' | 'Payroll' | 'Deductions' | 'Departments' | 'Inventory' | 'Sales' | 'Team' | 'OFF MARK' | 'Print' | 'ROLL' | 'Settings'
type SubscriptionPlan = string
type SubscriptionStatus = 'Trial' | 'Active' | 'Paused' | 'Canceled'
type BusinessAccount = {
  id: number
  businessName: string
  ownerName: string
  email: string
  username: string
  password: string
  industry: string
  plan: SubscriptionPlan
  status: SubscriptionStatus
  seats: number
  monthlyPrice: number
  nextBilling: string
  createdAt: string
  tenantId: string
}
type RegistrationRequest = { id: number; applicantName: string; businessName: string; issue: string; submittedAt: string; phone?: string; email?: string; username?: string; password?: string; industry?: string; plan?: SubscriptionPlan; reviewStatus?: 'Pending' | 'Activated' | 'Declined' }
type ActivationCode = { id: number; code: string; packageName: SubscriptionPlan; status: 'Available' | 'Used'; createdAt: string; usedBy?: string }
type PackageConfig = { name: SubscriptionPlan; price: number; seats: number; duration: number; durationUnit: 'day' | 'week' | 'month' | 'year'; description: string; features: string[]; active: boolean }
type WorkspaceSession = { username: string; tenant_id: string; workspace_name: string; owner_name: string; password_hash: string; updated_at: string }

const roles: Role[] = ['Owner', 'Manager', 'Stock Keeper', 'Cashier', 'Worker']
const uniqueAccessAreas: AccessArea[] = ['Overview', 'Attendance', 'Payroll', 'Deductions', 'Departments', 'Inventory', 'Sales', 'Team', 'OFF MARK', 'Print', 'ROLL', 'Settings']
const accessAreas: AccessArea[] = Array.from(new Set(uniqueAccessAreas)) as AccessArea[]
const navItems = [{ label: 'Overview', icon: '◈' }, { label: 'Sales', icon: '↗' }, { label: 'Attendance', icon: '◷' }, { label: 'Payroll', icon: 'KES' }, { label: 'Deductions', icon: '−' }, { label: 'Inventory', icon: '□' }, { label: 'Departments', icon: '▦' }, { label: 'OFF MARK', icon: '◉' }, { label: 'Print', icon: '▤' }]
const dedupeLinks = (links: string[]) => Array.from(new Set(links.filter(Boolean)))
const sidebarGroups = [
  { label: '', links: dedupeLinks(['Overview', 'Sales', 'Attendance', 'Payroll', 'Deductions', 'Inventory', 'Team', 'Permissions', 'Departments', 'OFF MARK', 'Print', 'ROLL', 'Settings']) },
]
const localDateKey = (date: Date) => `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`
export function SiteCalendarPopups() {
  const [activeInput, setActiveInput] = useState<HTMLInputElement | null>(null)
  const [visibleMonth, setVisibleMonth] = useState(() => new Date(new Date().getFullYear(), new Date().getMonth(), 1))
  const [position, setPosition] = useState({ left: 0, top: 0 })
  const todayKey = localDateKey(new Date())
  const selectedValue = activeInput?.value.slice(0, 10) || ''
  const selectedDate = /^\d{4}-\d{2}-\d{2}$/.test(selectedValue) ? new Date(`${selectedValue}T00:00:00`) : null
  const monthName = visibleMonth.toLocaleDateString(undefined, { month: 'long', year: 'numeric' })
  const monthStart = new Date(visibleMonth.getFullYear(), visibleMonth.getMonth(), 1)
  const dayOffset = (monthStart.getDay() + 6) % 7
  const daysInMonth = new Date(visibleMonth.getFullYear(), visibleMonth.getMonth() + 1, 0).getDate()
  const placePopup = (input: HTMLInputElement) => {
    const rect = input.getBoundingClientRect()
    const width = Math.min(288, window.innerWidth - 24)
    const left = Math.max(12, Math.min(rect.left, window.innerWidth - width - 12))
    const top = rect.bottom + 6 + 360 > window.innerHeight ? Math.max(12, rect.top - 366) : rect.bottom + 6
    setPosition({ left, top })
  }
  useEffect(() => {
    const openCalendar = (event: MouseEvent) => {
      const input = (event.target as HTMLElement).closest<HTMLInputElement>('input[type="date"], input[type="datetime-local"]')
      if (!input || input.disabled || input.readOnly) return
      event.preventDefault()
      event.stopPropagation()
      input.focus({ preventScroll: true })
      const inputDate = /^\d{4}-\d{2}-\d{2}$/.test(input.value.slice(0, 10)) ? new Date(`${input.value.slice(0, 10)}T00:00:00`) : new Date()
      setVisibleMonth(new Date(inputDate.getFullYear(), inputDate.getMonth(), 1))
      placePopup(input)
      setActiveInput(input)
    }
    const closeOutside = (event: MouseEvent) => {
      const target = event.target as HTMLElement
      if (target.closest('.site-calendar-popup') || target.closest('input[type="date"], input[type="datetime-local"]')) return
      setActiveInput(null)
    }
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') setActiveInput(null) }
    const reposition = () => { if (activeInput?.isConnected) placePopup(activeInput); else setActiveInput(null) }
    document.addEventListener('click', openCalendar, true)
    document.addEventListener('mousedown', closeOutside, true)
    document.addEventListener('keydown', closeOnEscape, true)
    window.addEventListener('resize', reposition)
    window.addEventListener('scroll', reposition, true)
    return () => {
      document.removeEventListener('click', openCalendar, true)
      document.removeEventListener('mousedown', closeOutside, true)
      document.removeEventListener('keydown', closeOnEscape, true)
      window.removeEventListener('resize', reposition)
      window.removeEventListener('scroll', reposition, true)
    }
  }, [activeInput])
  if (!activeInput) return null
  const minimumDate = activeInput.min.slice(0, 10)
  const maximumDate = activeInput.max.slice(0, 10)
  const chooseDate = (date: string) => {
    const nextValue = activeInput.type === 'datetime-local' ? `${date}T${activeInput.value.split('T')[1] || '00:00'}` : date
    const valueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set
    valueSetter?.call(activeInput, nextValue)
    activeInput.dispatchEvent(new Event('input', { bubbles: true }))
    activeInput.dispatchEvent(new Event('change', { bubbles: true }))
    setActiveInput(null)
  }
  return <div className="site-calendar-popup" role="dialog" aria-modal="false" aria-label="Choose date" style={{ left: position.left, top: position.top }}>
    <header className="site-calendar-header"><button type="button" aria-label="Previous month" onClick={() => setVisibleMonth((current) => new Date(current.getFullYear(), current.getMonth() - 1, 1))}>‹</button><strong>{monthName}</strong><button type="button" aria-label="Next month" onClick={() => setVisibleMonth((current) => new Date(current.getFullYear(), current.getMonth() + 1, 1))}>›</button></header>
    <div className="site-calendar-weekdays" aria-hidden="true">{['Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa', 'Su'].map((day) => <span key={day}>{day}</span>)}</div>
    <div className="site-calendar-days">{Array.from({ length: 42 }, (_, index) => {
      const day = index - dayOffset + 1
      if (day < 1 || day > daysInMonth) return <span className="site-calendar-empty" key={index} />
      const dateKey = localDateKey(new Date(visibleMonth.getFullYear(), visibleMonth.getMonth(), day))
      const isDisabled = Boolean((minimumDate && dateKey < minimumDate) || (maximumDate && dateKey > maximumDate))
      return <button type="button" key={dateKey} disabled={isDisabled} aria-pressed={dateKey === selectedValue} className={`${dateKey === selectedValue ? 'is-selected ' : ''}${dateKey === todayKey ? 'is-today' : ''}`} onClick={() => chooseDate(dateKey)}>{day}</button>
    })}</div>
    <footer className="site-calendar-footer"><button type="button" onClick={() => chooseDate(todayKey)} disabled={Boolean((minimumDate && todayKey < minimumDate) || (maximumDate && todayKey > maximumDate))}>Today</button></footer>
  </div>
}
const today = localDateKey(new Date())
const formatDate = (value: string) => {
  const parts = value.slice(0, 10).split('-')
  if (parts.length !== 3) return value
  const [year, month, day] = parts.map(Number)
  if (!year || !month || !day) return value
  const date = new Date(year, month - 1, day)
  return `${date.toLocaleDateString(undefined, { weekday: 'short' })} ${String(day).padStart(2, '0')}/${String(month).padStart(2, '0')}/${year}`
}
const formatReportPeriod = (period: string, start: string, end: string) => period === 'today' || period === 'day' ? formatDate(start) : `From ${formatDate(start)} to ${formatDate(end)}`
const formatPayrollReportDate = formatDate
const formatPayrollReportPeriod = (period: string, start: string, end: string) => period === 'today' || period === 'day' ? formatPayrollReportDate(start) : `From ${formatPayrollReportDate(start)} to ${formatPayrollReportDate(end)}`
type PayrollPrintRow = { type: 'earning'; entry: AttendanceEntry; paymentEvents: PayrollPaymentRecord[]; previousBalanceEvents: PayrollPaymentRecord[] } | { type: 'payment'; payment: PayrollPaymentRecord } | { type: 'deduction'; deduction: Deduction }
const payrollPrintRows = (earnings: AttendanceEntry[], payments: PayrollPaymentRecord[], deductions: Deduction[], defaultPayRate = 0): PayrollPrintRow[] => {
  const attachedPaymentIds = new Set<string>()
  const attachedCarryIds = new Set<string>()
  const carryPayments = payments.filter((payment) => Boolean(payment.balanceSourceTerms))
  const earningRows: PayrollPrintRow[] = earnings.map((entry) => {
    const paymentEvents = payrollPaymentEventsForEntry(entry, entry.payRate ?? defaultPayRate)
    paymentEvents.forEach((payment) => attachedPaymentIds.add(payment.id))
    const batchIds = new Set(paymentEvents.map((payment) => payment.paymentBatchId).filter((batchId): batchId is string => Boolean(batchId)))
    const previousBalanceEvents = carryPayments.filter((payment) => Boolean(payment.paymentBatchId && batchIds.has(payment.paymentBatchId)) && !attachedCarryIds.has(payment.id))
    previousBalanceEvents.forEach((payment) => { attachedCarryIds.add(payment.id); attachedPaymentIds.add(payment.id) })
    return { type: 'earning', entry, paymentEvents, previousBalanceEvents }
  })
  const standalonePayments: PayrollPrintRow[] = payments.filter((payment) => !attachedPaymentIds.has(payment.id)).map((payment) => ({ type: 'payment', payment }))
  const deductionRows: PayrollPrintRow[] = deductions.map((deduction) => ({ type: 'deduction', deduction }))
  return [...earningRows, ...standalonePayments, ...deductionRows].sort((first, second) => {
    const firstDate = first.type === 'earning' ? first.entry.date : first.type === 'payment' ? first.payment.date : first.deduction.date
    const secondDate = second.type === 'earning' ? second.entry.date : second.type === 'payment' ? second.payment.date : second.deduction.date
    const firstOrder = first.type === 'earning' ? 0 : first.type === 'payment' ? 1 : 2
    const secondOrder = second.type === 'earning' ? 0 : second.type === 'payment' ? 1 : 2
    return firstDate.localeCompare(secondDate) || firstOrder - secondOrder
  })
}
const isWithinDateRange = (date: string, start: string, end: string) => date >= start && date <= end
const formatShortDate = (value?: string) => {
  const date = value?.slice(0, 10) || ''
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return '—'
  return formatDate(date)
}
function datesBetween(start: string, end: string) {
  const dates: string[] = []
  const cursor = new Date(`${start}T00:00:00`)
  const last = new Date(`${end}T00:00:00`)
  while (cursor <= last) {
    dates.push(localDateKey(cursor))
    cursor.setDate(cursor.getDate() + 1)
  }
  return dates
}
const currentMonthStart = `${today.slice(0, 7)}-01`
const currentWeekStartDate = new Date(`${today}T00:00:00`)
const currentWeekDay = currentWeekStartDate.getDay()
currentWeekStartDate.setDate(currentWeekStartDate.getDate() - (currentWeekDay === 0 ? 6 : currentWeekDay - 1))
const currentWeekStart = localDateKey(currentWeekStartDate)
const currentWeekEndDate = new Date(currentWeekStartDate)
currentWeekEndDate.setDate(currentWeekEndDate.getDate() + 6)
const currentWeekEnd = localDateKey(currentWeekEndDate)
const paymentReceivedForEntry = (entry: AttendanceEntry, member: Member) => {
  const earned = entry.payRate ?? member.payRate
  const received = entry.paymentReceived ?? (entry.paymentStatus === 'Paid' ? earned : 0)
  return Math.min(earned, Math.max(0, received))
}
const payrollPaymentEventsForEntry = (entry: AttendanceEntry, earned: number): PayrollPaymentRecord[] => {
  if (entry.paymentHistory?.length) {
    let remaining = earned
    return [...entry.paymentHistory].sort((first, second) => first.date.localeCompare(second.date)).filter((payment) => payment.amount > 0).map((payment) => {
      remaining = payment.balanceRemaining ?? Math.max(0, remaining - payment.amount)
      return { ...payment, balanceRemaining: remaining }
    })
  }
  const amount = Math.min(earned, Math.max(0, entry.paymentReceived ?? (entry.paymentStatus === 'Paid' ? earned : 0)))
  if (amount <= 0) return []
  return [{ id: `${entry.paymentBatchId || 'legacy'}-${entry.memberId}-${entry.earningId ?? entry.date}-${entry.checkIn}`, date: entry.paidAt || entry.date, amount, reason: entry.reason || 'Payment recorded', status: entry.paymentStatus === 'Partially paid' ? 'Partially paid' : 'Paid', balanceRemaining: Math.max(0, earned - amount), paymentBatchId: entry.paymentBatchId }]
}
function paymentAmountsForPeriod(member: Member, entries: AttendanceEntry[], deductions: Deduction[]) {
  const amountEarned = entries.reduce((sum, entry) => sum + (entry.payRate ?? member.payRate), 0)
  const amountDeducted = deductions.reduce((sum, deduction) => sum + deduction.amount, 0)
  const netEarned = Math.max(0, amountEarned - amountDeducted)
  const recordedPayments = entries.reduce((sum, entry) => sum + paymentReceivedForEntry(entry, member), 0)
  const fullyPaid = entries.length > 0 && entries.every((entry) => paymentReceivedForEntry(entry, member) >= (entry.payRate ?? member.payRate))
  const amountOwed = Math.max(0, netEarned - recordedPayments)
  const amountReceived = fullyPaid ? netEarned : recordedPayments
  return { netEarned, amountOwed, amountReceived, recordedPayments }
}
function outstandingPayrollBalance(member: Member, attendance: AttendanceEntry[], casualEarnings: CasualEarning[], deductions: Deduction[], endDate: string) {
  const startDate = member.payTermsSince || ''
  const earnings = member.payTerms === 'Casual'
    ? casualEarnings.filter((earning) => earning.memberId === member.id && earning.date >= startDate && earning.date <= endDate).map((earning) => ({ memberId: earning.memberId, date: earning.date, status: 'Present' as AttendanceStatus, checkIn: '—', checkOut: '—', payRate: earning.amount, paymentStatus: earning.paymentStatus, paymentReceived: earning.paymentReceived }))
    : attendance.filter((entry) => entry.memberId === member.id && entry.checkOut !== '—' && entry.date >= startDate && entry.date <= endDate)
  const eligibleDeductions = deductions.filter((deduction) => !deduction.archived && deduction.memberId === member.id && deduction.date >= startDate && deduction.date <= endDate)
  return paymentAmountsForPeriod(member, earnings, eligibleDeductions).amountOwed
}
function payrollAmountOwedForPeriod(member: Member, attendance: AttendanceEntry[], casualEarnings: CasualEarning[], deductions: Deduction[], startDate: string, endDate: string) {
  const payTermsSince = member.payTermsSince || ''
  const signedInDates = new Set(attendance.filter((entry) => entry.memberId === member.id && entry.date >= payTermsSince && entry.date >= startDate && entry.date <= endDate && Boolean(entry.checkIn && entry.checkIn !== '—')).map((entry) => entry.date))
  const earnings = member.payTerms === 'Casual'
    ? casualEarnings.filter((earning) => earning.memberId === member.id && earning.date >= payTermsSince && earning.date >= startDate && earning.date <= endDate && earning.amount > 0 && signedInDates.has(earning.date)).map((earning) => ({ memberId: earning.memberId, date: earning.date, status: 'Present' as AttendanceStatus, checkIn: '—', checkOut: '—', payRate: earning.amount, paymentStatus: earning.paymentStatus, paymentReceived: earning.paymentReceived }))
    : attendance.filter((entry) => entry.memberId === member.id && entry.checkOut !== '—' && entry.date >= payTermsSince && entry.date >= startDate && entry.date <= endDate)
  const periodDeductions = deductions.filter((deduction) => !deduction.archived && deduction.memberId === member.id && deduction.date >= payTermsSince && deduction.date >= startDate && deduction.date <= endDate)
  return Math.max(0, member.payrollCarryBalance || 0) + paymentAmountsForPeriod(member, earnings, periodDeductions).amountOwed
}
function nextPayTermsStart(effectiveAt: string) {
  return localDateKey(new Date(effectiveAt))
}
function applyMemberUpdate(member: Member, changes: Partial<Member>, effectiveAt: string, attendance: AttendanceEntry[], casualEarnings: CasualEarning[], deductions: Deduction[], includeTodayShift = true) {
  if (!changes.payTerms || changes.payTerms === member.payTerms) return { ...member, ...changes, id: member.id, scheduledUpdate: undefined }
  const transitionDate = nextPayTermsStart(effectiveAt)
  const nextDate = new Date(`${transitionDate}T00:00:00`)
  nextDate.setDate(nextDate.getDate() + 1)
  const payTermsSince = includeTodayShift ? transitionDate : localDateKey(nextDate)
  const existingCarryBalance = Math.max(0, member.payrollCarryBalance || 0)
  const newlyCarriedBalance = outstandingPayrollBalance(member, attendance, casualEarnings, deductions, transitionDate)
  const carryBalance = existingCarryBalance + newlyCarriedBalance
  const previousCarryTerms = member.payrollCarryPayTerms || (existingCarryBalance > 0 ? member.payTerms === 'Casual' ? 'Per shift' : 'Casual' : undefined)
  const payrollCarryPayTerms = carryBalance > 0
    ? newlyCarriedBalance > 0 && previousCarryTerms && previousCarryTerms !== member.payTerms ? 'Mixed' : newlyCarriedBalance > 0 ? member.payTerms : previousCarryTerms
    : undefined
  return { ...member, ...changes, id: member.id, payrollCarryBalance: carryBalance, payrollCarryPayTerms, payTermsSince, scheduledUpdate: undefined }
}
function paymentRegisterRows(members: Member[], attendance: AttendanceEntry[], deductions: Deduction[], start: string, end: string, includeArchived = false, casualEarnings: CasualEarning[] = []) {
  return members.map((member) => {
    const shiftEntries = attendance.filter((entry) => entry.memberId === member.id && entry.checkOut !== '—' && isWithinDateRange(entry.date, start, end))
    const paidCasualEntries = member.payTerms === 'Casual' ? casualEarnings.filter((earning) => earning.memberId === member.id && earning.paymentStatus === 'Paid' && isWithinDateRange(earning.date, start, end)).map((earning) => ({ memberId: earning.memberId, date: earning.date, status: 'Present' as AttendanceStatus, checkIn: '—', checkOut: '—', payRate: earning.amount, earningType: 'casual' as const, earningId: earning.id, reason: earning.reason, paymentStatus: earning.paymentStatus, paymentReceived: earning.paymentReceived, paidAt: earning.paidAt, paymentBatchId: earning.paymentBatchId })) : []
    const periodEntries = member.payTerms === 'Casual' ? paidCasualEntries : shiftEntries
    const periodDeductions = deductions.filter((deduction) => deduction.memberId === member.id && (includeArchived || !deduction.archived) && isWithinDateRange(deduction.date, start, end))
    return { member, periodEntries, hasHistoricalRecords: periodEntries.length > 0 || periodDeductions.length > 0, ...paymentAmountsForPeriod(member, periodEntries, periodDeductions) }
  }).filter((row) => !row.member.archived || row.hasHistoricalRecords)
}
const planPrices: Record<string, number> = { Starter: 29, Growth: 79, Scale: 149 }
const packageFeatures = ['Sales and revenue tracking', 'Team and permissions', 'Attendance and payroll', 'Inventory and stock', 'Reports and printing', 'Departments and roles']
const defaultPackages: PackageConfig[] = [{ name: 'Starter', price: 29, seats: 5, duration: 1, durationUnit: 'month', description: 'For a small team getting started.', features: ['Sales and revenue tracking', 'Team and permissions'], active: true }, { name: 'Growth', price: 79, seats: 12, duration: 1, durationUnit: 'month', description: 'For growing businesses and teams.', features: ['Sales and revenue tracking', 'Team and permissions', 'Attendance and payroll', 'Inventory and stock'], active: true }, { name: 'Scale', price: 149, seats: 30, duration: 1, durationUnit: 'month', description: 'For larger operations with more seats.', features: packageFeatures, active: true }]
const normalizePackages = (stored: Partial<PackageConfig>[] | null) => (stored?.length ? stored : defaultPackages).map((item) => ({ ...item, name: item.name || 'Package', price: Number(item.price) || 0, seats: Number(item.seats) || 1, duration: Number(item.duration) || 1, durationUnit: item.durationUnit === 'year' || item.durationUnit === 'month' || item.durationUnit === 'week' || item.durationUnit === 'day' ? item.durationUnit : 'month', description: item.description || '', features: Array.isArray(item.features) ? item.features : [], active: item.active !== false })) as PackageConfig[]
const normalizeBusinessAccount = (account: Partial<BusinessAccount> | any): BusinessAccount | null => {
  if (!account) return null
  const businessName = String(account.businessName || account.business_name || '').trim()
  const ownerName = String(account.ownerName || account.owner_name || '').trim()
  const username = String(account.username || '').trim().toLowerCase()
  if (!businessName || !ownerName || !username) return null
  return {
    id: Number(account.id ?? Date.now()),
    businessName,
    ownerName,
    email: String(account.email || '').trim().toLowerCase(),
    username,
    password: String(account.password || ''),
    industry: String(account.industry || 'General').trim(),
    plan: (account.plan || 'Starter') as SubscriptionPlan,
    status: (account.status || 'Active') as SubscriptionStatus,
    seats: Number(account.seats ?? 1),
    monthlyPrice: Number(account.monthlyPrice ?? account.monthly_price ?? 0),
    nextBilling: String(account.nextBilling || account.next_billing || '').trim(),
    createdAt: String(account.createdAt || account.created_at || today).trim(),
    tenantId: String(account.tenantId || account.tenant_id || `tenant-${Date.now()}`),
  }
}
const uniqueBusinessAccounts = (accounts: Array<BusinessAccount | null | undefined>) => {
  const seen = new Map<string, BusinessAccount>()
  for (const candidate of accounts) {
    const normalized = normalizeBusinessAccount(candidate)
    if (!normalized) continue
    const key = normalized.tenantId || normalized.username || `${normalized.businessName}:${normalized.email}`
    const existing = seen.get(key)
    if (!existing) {
      seen.set(key, normalized)
      continue
    }
    const best = Number(existing.id) > 0 ? existing : normalized
    seen.set(key, {
      ...best,
      ...normalized,
      id: Number(best.id) > 0 ? best.id : normalized.id,
      tenantId: best.tenantId || normalized.tenantId,
      username: normalized.username || best.username,
      businessName: normalized.businessName || best.businessName,
      ownerName: normalized.ownerName || best.ownerName,
    })
  }
  return Array.from(seen.values())
}
const defaultBusinessAccounts: BusinessAccount[] = []
const businessAccountsStorageKey = 'biztrack-business-accounts'
const workspaceStorageKey = 'biztrack-workspace-state'
const defaultPaymentRegisterFooter = 'By signing, I acknowledge receipt of the amount shown in the Amount received column for the selected pay period.'
const defaultPayrollReportOrder: PayrollReportOrder = 'chronological'
const readStoredBusinessAccounts = (): BusinessAccount[] => {
  try {
    const raw = localStorage.getItem(businessAccountsStorageKey)
    if (!raw) return defaultBusinessAccounts
    const parsed = JSON.parse(raw) as Partial<BusinessAccount>[] | null
    if (!Array.isArray(parsed)) return defaultBusinessAccounts
    return parsed.filter((account): account is BusinessAccount => Boolean(account && typeof account === 'object' && typeof account.username === 'string' && typeof account.password === 'string' && typeof account.businessName === 'string')).map((account) => ({ ...account, username: account.username.trim().toLowerCase(), password: account.password }))
  } catch {
    return defaultBusinessAccounts
  }
}
const readStoredWorkspaceState = (): Partial<{ members: Member[]; departmentList: string[]; casualEarnings: CasualEarning[]; accessByMember: Record<number, AccessArea[]>; workspaceName: string; paymentRegisterFooter: string; payrollReportOrder: PayrollReportOrder }> => {
  try {
    const raw = localStorage.getItem(workspaceStorageKey)
    if (!raw) return {}
    const parsed = JSON.parse(raw) as Partial<{ members: Member[]; departmentList: string[]; casualEarnings: CasualEarning[]; accessByMember: Record<number, AccessArea[]>; workspaceName: string; paymentRegisterFooter: string; payrollReportOrder: PayrollReportOrder }>
    return {
      members: Array.isArray(parsed.members) ? parsed.members : [],
      departmentList: Array.isArray(parsed.departmentList) ? parsed.departmentList : [],
      casualEarnings: Array.isArray(parsed.casualEarnings) ? parsed.casualEarnings : [],
      accessByMember: parsed.accessByMember && typeof parsed.accessByMember === 'object' ? normalizeAccessByMember(parsed.accessByMember) : {},
      workspaceName: typeof parsed.workspaceName === 'string' ? parsed.workspaceName : '',
      paymentRegisterFooter: typeof parsed.paymentRegisterFooter === 'string' ? parsed.paymentRegisterFooter : defaultPaymentRegisterFooter,
      payrollReportOrder: parsed.payrollReportOrder === 'deductions-bottom' || parsed.payrollReportOrder === 'deductions-top' ? parsed.payrollReportOrder : defaultPayrollReportOrder,
    }
  } catch {
    return {}
  }
}
const pagePaths: Record<string, string> = { Welcome: '/welcome/', 'Sign in': '/signin/', Register: '/register/', FAQs: '/faqs/', Terms: '/terms/', Privacy: '/privacy/', Delete: '/delete/', Admin: '/admin/', Dashboard: '/admin/', Business: '/admin/businesses/', Users: '/admin/users/', 'Register a new business': '/admin/register/', 'Activation codes': '/admin/activation-codes/', Packages: '/admin/packages/', 'Activate business': '/admin/activate-business/', 'Admin settings': '/admin/settings/', Overview: '/master/dashboard/', 'Business AI': '/master/business-ai/', Sales: '/master/sales/', Attendance: '/master/attendance/', Payroll: '/master/payroll/', Deductions: '/master/deductions/', Penalties: '/master/penalties/', Departments: '/master/departments/', Inventory: '/master/inventory/', Team: '/master/team/', 'Add member': '/add/', Permissions: '/master/permissions/', Settings: '/master/settings/', 'OFF MARK': '/master/offmark/', Print: '/master/print/', ROLL: '/master/roll/', 'Worker sign-in': '/master/roll/sign-in/', 'Worker checkout': '/master/roll/sign-out/' }
const visiblePageName = (page: string) => page === 'Business AI' ? 'AI' : page
const canonicalActivePage = (value: string) => {
  const normalized = value.trim()
  if (!normalized) return 'Overview'
  const aliases: Record<string, string> = {
    Dashboard: 'Overview',
    'Master dashboard': 'Overview',
    'Overview dashboard': 'Overview',
    'Business dashboard': 'Overview',
    'Sign-in': 'Sign in',
    'Sign in page': 'Sign in',
    'Admin dashboard': 'Dashboard',
    'Site admin': 'Dashboard',
  }
  return aliases[normalized] || normalized
}
const timeToMinutes = (value: string) => { const [hours, minutes] = value.split(':').map(Number); return (hours || 0) * 60 + (minutes || 0) }
const grantPagePaths: Record<string, string> = Object.fromEntries(Object.keys(pagePaths).filter((page) => pagePaths[page].startsWith('/master/')).map((page) => [page, `/grant/${page.toLowerCase().replace(/[^a-z0-9]+/g, '-')}/`]))
const pathPages: Record<string, string> = Object.fromEntries([...Object.entries(pagePaths), ...Object.entries(grantPagePaths)].map(([page, path]) => [path, page]))
pathPages['/admin'] = 'Admin'
pathPages['/admin/'] = 'Admin'
pathPages['/master/departments/add'] = 'Departments'
const siteAdminCredentials = { username: '1232@muli', password: '1232@muli' }
const defaultSiteAdminAccount: OwnerAccount = { name: 'Platform admin', username: siteAdminCredentials.username, password: siteAdminCredentials.password, business: 'Biz Track HQ' }
const siteAdminAccountKey = 'biztrack-site-admin-account'
const hasConfiguredSiteAdmin = (candidate: Partial<OwnerAccount> | null): candidate is OwnerAccount => Boolean(
  candidate &&
  typeof candidate.username === 'string' &&
  typeof candidate.password === 'string' &&
  candidate.username.trim() === siteAdminCredentials.username &&
  candidate.password === siteAdminCredentials.password
)
const readStoredSiteAdminAccount = (): OwnerAccount | null => {
  try {
    const raw = localStorage.getItem(siteAdminAccountKey)
    if (!raw) return null
    const parsed = JSON.parse(raw) as Partial<OwnerAccount> | null
    if (!hasConfiguredSiteAdmin(parsed)) {
      localStorage.removeItem(siteAdminAccountKey)
      return null
    }
    const cleaned = {
      ...defaultSiteAdminAccount,
      ...parsed,
      name: typeof parsed.name === 'string' && parsed.name.trim() ? parsed.name.trim() : defaultSiteAdminAccount.name,
      username: siteAdminCredentials.username,
      password: siteAdminCredentials.password,
      business: typeof parsed.business === 'string' && parsed.business.trim() ? parsed.business.trim() : defaultSiteAdminAccount.business,
    }
    return cleaned
  } catch {
    localStorage.removeItem(siteAdminAccountKey)
    return null
  }
}
const businessPackageExpired = (account: BusinessAccount) => Boolean(account.nextBilling && account.nextBilling < today)
const businessRequiresActivation = (account: BusinessAccount) => (account.status === 'Paused' || account.status === 'Canceled') || businessPackageExpired(account)
const pageForPath = (path: string) => {
  const cleaned = (path || '/').replace(/\/$/, '') || '/'
  if (cleaned === '/admin/subscriptions') return 'Admin'
  if (cleaned === '/add') return 'Add member'
  if (cleaned === '/') return 'Sign in'
  if (cleaned === '/welcome') return 'Welcome'
  if (cleaned === '/signin') return 'Sign in'
  if (cleaned === '/register') return 'Register'
  if (cleaned === '/faqs') return 'FAQs'
  if (cleaned === '/terms') return 'Terms'
  if (cleaned === '/privacy') return 'Privacy'
  if (cleaned === '/admin-signin') return 'Sign in'
  if (cleaned === '/grant') return 'Overview'
  if (cleaned.startsWith('/admin')) return pathPages[cleaned] || pathPages[cleaned + '/'] || 'Sign in'
  return pathPages[cleaned] || pathPages[cleaned + '/'] || 'Sign in'
}
const isProtectedPath = (path: string) => /^\/(?:admin|master|grant)(?:\/|$)/.test(path) || /^\/(?:add|delete)(?:\/|$)/.test(path)
async function persistSharedWorkspaceSession(account: Pick<BusinessAccount, 'username' | 'password' | 'tenantId' | 'businessName' | 'ownerName'>) {
  if (!isSupabaseConfigured || !supabase || !account.tenantId || !account.username) return
  const username = account.username.trim().toLowerCase()
  await supabase.from('workspace_sessions').upsert({
    username,
    tenant_id: account.tenantId,
    workspace_name: account.businessName.trim(),
    owner_name: account.ownerName.trim(),
    password_hash: account.password,
    updated_at: new Date().toISOString(),
  })
}
function initialsFor(name: string) { return name.split(' ').filter(Boolean).slice(0, 2).map((part) => part[0].toUpperCase()).join('') }
function businessNameParts(name: string) {
  const words = name.trim().split(/\s+/).filter(Boolean)
  if (words.length === 0) return ['', '']
  if (words.length <= 2) return [words.join(' '), '']

  const andIndex = words.findIndex((word) => word.toUpperCase() === 'AND')
  if (andIndex > 0 && andIndex < words.length - 1) {
    const first = words.slice(0, andIndex + 1).join(' ')
    const second = words.slice(andIndex + 1).join(' ')
    if (first.length <= 26 && second.length <= 26) return [first, second]
  }

  if (words.length === 3) return [words.slice(0, 2).join(' '), words[2]]

  const split = Math.ceil(words.length / 2)
  const first = words.slice(0, split).join(' ')
  const second = words.slice(split).join(' ')

  if (first.length <= 26 && second.length <= 26) return [first, second]
  return [first, second]
}
const workerIdNumber = (value: string | undefined) => (value || '').replace(/\D/g, '')
function normalizeMember(member: Partial<Member>, index: number, tenantId = 'workspace'): Member { const name = member.name || 'Unnamed member'; return { ...member, tenantId: member.tenantId || tenantId, id: member.id || Date.now() + index, name, username: member.username || '', password: member.password || '', hasAccount: member.hasAccount === true && Boolean(member.username?.trim() && member.password?.trim()), phone: member.phone || 'NA', email: workerIdNumber(member.email), department: member.department || 'Unassigned', role: member.role || 'Worker', initials: member.initials || initialsFor(name), color: member.color || 'mint', payRate: member.payRate ?? 1000, payTerms: member.payTerms === 'Casual' ? 'Casual' : 'Per shift', payFrequency: member.payFrequency || 'Daily', signInTime: member.signInTime || '08:00', signOutTime: member.signOutTime || '17:00' } as Member }
function whatsappHelpUrl(businessName: string, owner: OwnerAccount | null, members: Member[], sessionMemberId: number, whatsappNumber: string) {
  let number = whatsappNumber.replace(/[^0-9]/g, '')
    if (number.startsWith('00')) number = number.slice(2)
    if (number.startsWith('0')) number = `254${number.slice(1)}`
    if (!number) return ''
    const member = members.find((item) => item.id === sessionMemberId)
    const isOwner = sessionMemberId === -1 || (!member && Boolean(owner))
    const personName = isOwner ? owner?.name || 'Owner' : member?.name || 'Member'
    const department = isOwner ? 'Owner' : member?.department || 'Unassigned'
    const message = `Hello, I need help with my Biz Track workspace.\nName: ${personName}\nDepartment: ${department}\nBusiness: ${businessName}`
  return `https://wa.me/${number}?text=${encodeURIComponent(message)}`
}
const normalizeAccessAreas = (areas: unknown): AccessArea[] => {
  const list = Array.isArray(areas) ? areas : []
  const normalized = list
    .map((area) => typeof area === 'string' ? area.trim() : '')
    .filter((area): area is string => Boolean(area))
    .map((area) => uniqueAccessAreas.find((known) => known.toLowerCase() === area.toLowerCase()))
    .filter((area): area is AccessArea => Boolean(area))
    .filter((area, index, src) => src.findIndex((candidate) => candidate.toLowerCase() === area.toLowerCase()) === index)
  return normalized
}
const normalizeAccessByMember = (record: unknown): Record<number, AccessArea[]> => {
  if (!record || typeof record !== 'object') return {}
  return Object.fromEntries(
    Object.entries(record as Record<string, unknown>)
      .map(([memberId, areas]) => {
        const key = Number(memberId)
        if (!Number.isFinite(key) || key <= 0) return null
        return [key, normalizeAccessAreas(areas)]
      })
      .filter((entry): entry is [number, AccessArea[]] => Array.isArray(entry) && entry.length === 2)
  )
}
const emptyAccess: Record<number, AccessArea[]> = {}
type PayrollReportOrder = 'chronological' | 'deductions-bottom' | 'deductions-top'
type WorkspaceSnapshot = {
  members: Member[]
  departmentList: string[]
  attendance: AttendanceEntry[]
  casualEarnings: CasualEarning[]
  sales: Sale[]
  salesHistory: Sale[]
  deductions: Deduction[]
  expenses: Expense[]
  stockMovements: StockMovement[]
  inventory: InventoryItem[]
  storeCategories: string[]
  deletedCategories: string[]
  categoryUnits: Record<string, string>
  categoryThresholds: Record<string, number>
  workspaceName: string
  currency: string
  paymentRegisterFooter: string
    paymentRegisterFooter: string
    payrollReportOrder: PayrollReportOrder
  paymentMethods: string[]
  strictSignIn: boolean
  allowMultipleDailyShifts: boolean
  biometricSignIn: boolean
  biometricSignOut: boolean
  biometricMark: boolean
  biometricPayroll: boolean
  defaultSignIn: string
  defaultSignOut: string
  lateSignIn: string
  earlySignOut: string
  accessByMember: Record<number, AccessArea[]>
}
type PlatformSettings = { platformName: string; supportEmail: string; whatsappNumber: string; defaultPlan: SubscriptionPlan; maintenanceMode: boolean; maintenanceEndsAt: string }
const defaultPlatformSettings: PlatformSettings = { platformName: 'Biz Track', supportEmail: 'support@biztrack.app', whatsappNumber: '', defaultPlan: 'Starter', maintenanceMode: false, maintenanceEndsAt: '' }
const toDateTimeLocalValue = (value: string) => {
  const date = new Date(value)
  if (!value || !Number.isFinite(date.getTime())) return ''
  return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 19)
}
type RefreshSession = { owner?: OwnerAccount; memberId?: number; siteAdmin?: boolean; path?: string }
const refreshSessionKey = 'biztrack-refresh-session'
const readRefreshSession = (): RefreshSession | null => {
  try {
    const stored = JSON.parse(localStorage.getItem(refreshSessionKey) || 'null') as RefreshSession | null
    if (!stored) return null
    const { siteAdmin: _ignoredSiteAdmin, ...safeSession } = stored
    return Object.keys(safeSession).length ? safeSession : null
  } catch { return null }
}
const saveRefreshSession = (session: RefreshSession | null) => {
  if (session) localStorage.setItem(refreshSessionKey, JSON.stringify(session))
  else localStorage.removeItem(refreshSessionKey)
}
const withSupabaseRetry = async <T,>(label: string, action: () => Promise<T>, retries = 3): Promise<T | null> => {
  if (!isSupabaseConfigured || !supabase) return null
  if (typeof navigator !== 'undefined' && !navigator.onLine) {
    console.warn(`${label} skipped because the browser is offline.`)
    return null
  }
  let lastError: unknown
  for (let attempt = 0; attempt < retries; attempt += 1) {
    try {
      return await action()
    } catch (error) {
      lastError = error
      if (isNetworkFailure(error) || attempt === retries - 1) {
        console.error(isNetworkFailure(error) ? `${label} stopped after a network failure` : `${label} failed after ${retries} attempts`, error)
        return null
      }
      await new Promise((resolve) => window.setTimeout(resolve, 250 * (attempt + 1)))
    }
  }
  console.error(`${label} failed`, lastError)
  return null
}

const scrollPageToTop = () => {
  window.requestAnimationFrame(() => {
    const mainContent = document.querySelector<HTMLElement>('.app-shell > .main-content')
    if (mainContent && getComputedStyle(mainContent).overflowY !== 'visible') {
      mainContent.scrollTo({ top: 0, behavior: 'smooth' })
      return
    }
    window.scrollTo({ top: 0, behavior: 'smooth' })
  })
}

function WorkspaceLoadingPage({ businessName }: { businessName: string }) {
  return <main className="workspace-loading"><header className="workspace-loading-topbar"><div className="workspace-loading-brand"><span className="workspace-loading-dot"></span><strong>{businessName || 'Your workspace'}</strong></div><span className="workspace-loading-status">Loading workspace</span></header><div className="workspace-loading-content"><div className="workspace-loading-heading"><span className="loading-block loading-kicker"></span><span className="loading-block loading-title"></span><span className="loading-block loading-subtitle"></span></div><section className="workspace-loading-metrics">{[1, 2, 3, 4].map((item) => <div className="workspace-loading-card" key={item}><span className="loading-block loading-label"></span><span className="loading-block loading-value"></span><span className="loading-block loading-line"></span></div>)}</section><section className="workspace-loading-panel"><div className="workspace-loading-panel-head"><span className="loading-block loading-panel-title"></span><span className="loading-block loading-filter"></span></div>{[1, 2, 3, 4, 5].map((item) => <div className="workspace-loading-row" key={item}><span className="loading-block loading-avatar"></span><span className="loading-block loading-name"></span><span className="loading-block loading-cell"></span><span className="loading-block loading-cell"></span><span className="loading-block loading-status"></span></div>)}</section></div></main>
}

export function MobileInstallLink() {
  const [isOpen, setIsOpen] = useState(false)
  const dismissedKey = 'biztrack-install-prompt-dismissed'
  const isAppleMobile = /iphone|ipad|ipod/i.test(navigator.userAgent) || (navigator.userAgent.includes('Macintosh') && navigator.maxTouchPoints > 1)
  const instructions = isAppleMobile
    ? 'In Safari, tap Share, then choose Add to Home Screen.'
    : 'Open your browser menu and choose Install app or Add to Home screen.'
  const closePrompt = () => {
    sessionStorage.setItem(dismissedKey, 'true')
    setIsOpen(false)
  }
  useEffect(() => {
    const canShow = !sessionStorage.getItem(dismissedKey) && !window.matchMedia('(display-mode: standalone)').matches && !(navigator as any).standalone
    const isAppleMobile = /iphone|ipad|ipod/i.test(navigator.userAgent) || (navigator.userAgent.includes('Macintosh') && navigator.maxTouchPoints > 1)
    const timer = canShow && isAppleMobile ? window.setTimeout(() => { if (!sessionStorage.getItem(dismissedKey)) setIsOpen(true) }, 1200) : undefined
    const handleInstallRequest = () => setIsOpen(true)
    const handleAppInstalled = () => { setIsOpen(false); sessionStorage.setItem(dismissedKey, 'true') }
    window.addEventListener('biztrack-install-request', handleInstallRequest)
    window.addEventListener('appinstalled', handleAppInstalled)
    return () => {
      if (timer !== undefined) window.clearTimeout(timer)
      window.removeEventListener('biztrack-install-request', handleInstallRequest)
      window.removeEventListener('appinstalled', handleAppInstalled)
    }
  }, [])
  if (!isOpen) return null
  return <div className="install-prompt-backdrop" role="presentation" onClick={(event) => { if (event.target === event.currentTarget) closePrompt() }}><section className="install-prompt" role="dialog" aria-modal="true" aria-labelledby="install-prompt-title"><button type="button" className="install-prompt-close" aria-label="Cancel installation" onClick={closePrompt}>×</button><span className="install-prompt-mark">b</span><h2 id="install-prompt-title">Install BizTrack</h2><p>{instructions}</p><button type="button" className="primary-button" onClick={closePrompt}>Got it</button></section></div>
}

function App() {
  const initialRefreshSession = readRefreshSession()
  const initialPage = pageForPath(window.location.pathname) || 'Sign in'
  const savedWorkspacePath = initialRefreshSession?.owner && initialRefreshSession.memberId && isProtectedPath(initialRefreshSession.path || '') && !initialRefreshSession.path?.startsWith('/admin') ? initialRefreshSession.path || '' : ''
  const savedWorkspacePage = savedWorkspacePath ? pageForPath(savedWorkspacePath) : 'Sign in'
  const shouldRestoreWorkspacePath = initialPage === 'Sign in' && savedWorkspacePage !== 'Sign in'
  const [activeNav, setActiveNav] = useState(() => shouldRestoreWorkspacePath ? savedWorkspacePage : initialPage)
  const [businessAiOpen, setBusinessAiOpen] = useState(false)
  const [myCredentialsOpen, setMyCredentialsOpen] = useState(false)
  useEffect(() => { if (activeNav !== 'Overview') setBusinessAiOpen(false) }, [activeNav])
  useEffect(() => {
    if (shouldRestoreWorkspacePath) window.history.replaceState({}, '', savedWorkspacePath)
  }, [])
  useEffect(() => {
    const modalSelector = '.admin-modal-backdrop, .account-choice-backdrop, .attendance-choice-backdrop, .print-dialog-backdrop, .payroll-detail-dialog, .biometric-dialog-backdrop, .business-confirm-backdrop, .install-prompt-backdrop, .partial-payment-backdrop, .maintenance-schedule-backdrop, .paid-date-warning-backdrop'
    const closeModal = (modal: Element) => {
      const closeButton = modal.querySelector<HTMLElement>('.admin-modal-close, .choice-close, .print-dialog-close, .payroll-detail-close, .biometric-dialog-close, .install-prompt-close, .maintenance-schedule-close, .partial-payment-actions .secondary-button, .business-confirm-dialog .secondary-button, .business-confirm-dialog .primary-button, .paid-date-warning-dialog .primary-button, [data-confirm="cancel"]')
      if (closeButton) closeButton.click()
      else modal.remove()
    }
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return
      const modals = document.querySelectorAll(modalSelector)
      const modal = modals[modals.length - 1]
      if (modal) {
        event.preventDefault()
        closeModal(modal)
        return
      }
      const openDetails = document.querySelectorAll('details[open]')
      const dropdown = openDetails[openDetails.length - 1] as HTMLDetailsElement | undefined
      if (dropdown) {
        event.preventDefault()
        dropdown.open = false
      }
    }
    const handleOutsideClick = (event: MouseEvent) => { const target = event.target as HTMLElement; const modal = target.closest(modalSelector); if (modal && target === modal) closeModal(modal) }
    document.addEventListener('keydown', handleEscape)
    document.addEventListener('mousedown', handleOutsideClick)
    return () => { document.removeEventListener('keydown', handleEscape); document.removeEventListener('mousedown', handleOutsideClick) }
  }, [])
  useEffect(() => {
    const preventNumberWheelChange = (event: WheelEvent) => {
      const target = event.target as HTMLElement
      if (target instanceof HTMLInputElement && target.type === 'number' && document.activeElement === target) event.preventDefault()
    }
    document.addEventListener('wheel', preventNumberWheelChange, { capture: true, passive: false })
    return () => document.removeEventListener('wheel', preventNumberWheelChange, true)
  }, [])
  useEffect(() => {
    if (activeNav === 'Sign in' && window.location.pathname !== pagePaths['Sign in']) window.history.replaceState({}, '', pagePaths['Sign in'])
    if (activeNav === 'Welcome' && window.location.pathname !== pagePaths['Welcome']) window.history.replaceState({}, '', pagePaths['Welcome'])
    if (activeNav === 'Admin sign in' && window.location.pathname !== pagePaths['Sign in']) window.history.replaceState({}, '', pagePaths['Sign in'])
  }, [activeNav])
    const [role, setRole] = useState<Role>('Worker')
    const [isOnline, setIsOnline] = useState(() => typeof navigator === 'undefined' || navigator.onLine)
    const syncLabel = isOnline ? 'Online' : 'Offline — reconnect to save'
    useEffect(() => {
      const handleOnline = () => setIsOnline(true)
      const handleOffline = () => setIsOnline(false)
      window.addEventListener('online', handleOnline)
      window.addEventListener('offline', handleOffline)
      return () => {
        window.removeEventListener('online', handleOnline)
        window.removeEventListener('offline', handleOffline)
      }
    }, [])
    const [attendanceNotices, setAttendanceNotices] = useState<{ id: number; message: string; tone: 'success' | 'error'; durationMs?: number; page?: string }[]>([])
    const attendanceNoticeId = useRef(0)
    const attendanceNoticeToneRef = useRef<'success' | 'error'>('success')
    const pendingAttendanceNoticeToneId = useRef<number | null>(null)
    const setAttendanceNoticeTone = (tone: 'success' | 'error') => {
      attendanceNoticeToneRef.current = tone
      const pendingId = pendingAttendanceNoticeToneId.current
      if (pendingId === null) return
      const attendanceWindow = window as any
      if (attendanceWindow.__bulkAttendanceInProgress) {
        const responses = attendanceWindow.__bulkAttendanceResponses as { id: number; message: string; tone: 'success' | 'error'; durationMs?: number }[] | undefined
        const pendingNotice = responses?.find((notice) => notice.id === pendingId)
        if (pendingNotice) {
          pendingNotice.tone = tone
          if (tone === 'error') pendingNotice.durationMs = 1200
          const failures = attendanceWindow.__bulkAttendanceFailures as string[] | undefined
          if (tone === 'error' && failures && !failures.includes(pendingNotice.message)) failures.push(pendingNotice.message)
          if (tone === 'success' && failures) {
            const index = failures.lastIndexOf(pendingNotice.message)
            if (index >= 0) failures.splice(index, 1)
          }
        }
      } else {
        setAttendanceNotices((current) => current.map((notice) => notice.id === pendingId ? { ...notice, tone } : notice))
      }
      pendingAttendanceNoticeToneId.current = null
    }
    const queueAttendanceNotice = (message: string, tone: 'success' | 'error', durationMs?: number, page?: string) => {
      if (!message) return null
      const notice = { id: ++attendanceNoticeId.current, message, tone, durationMs, page }
      const attendanceWindow = window as any
      if (attendanceWindow.__bulkAttendanceInProgress) {
        if (tone === 'error' && notice.durationMs === undefined) notice.durationMs = 1200
        attendanceWindow.__bulkAttendanceResponses?.push(notice)
        if (tone === 'error') attendanceWindow.__bulkAttendanceFailures?.push(message)
        return notice.id
      }
      setAttendanceNotices((current) => [...current, notice])
      return notice.id
    }
    const setAttendanceNotice = (message: string) => {
      if (!message) {
        setAttendanceNotices((current) => current.slice(1))
        pendingAttendanceNoticeToneId.current = null
        return
      }
      const pendingId = queueAttendanceNotice(message, attendanceNoticeToneRef.current)
      pendingAttendanceNoticeToneId.current = pendingId
      if (pendingId !== null) {
        queueMicrotask(() => {
          if (pendingAttendanceNoticeToneId.current === pendingId) pendingAttendanceNoticeToneId.current = null
        })
      }
    }
    const workspaceTransitionMessages = ['Creating your workspace…', 'Setting up your owner profile…', 'Configuring your business modules…', 'Your workspace is ready'] as const
    const workspaceTransitionTimer = useRef<number | null>(null)
    const triggerWorkspaceTransition = (onComplete: () => void) => {
      const steps = workspaceTransitionMessages
      if (workspaceTransitionTimer.current) {
        window.clearInterval(workspaceTransitionTimer.current)
        workspaceTransitionTimer.current = null
      }
      setWorkspaceTransition({ step: 0, active: true })
      let stepIndex = 0
      workspaceTransitionTimer.current = window.setInterval(() => {
        stepIndex += 1
        setWorkspaceTransition((current) => ({ ...current, step: Math.min(stepIndex, steps.length - 1) }))
        if (stepIndex >= steps.length) {
          window.clearInterval(workspaceTransitionTimer.current ?? undefined)
          workspaceTransitionTimer.current = null
          window.setTimeout(() => {
            setWorkspaceTransition({ step: 0, active: false })
            onComplete()
          }, 260)
        }
      }, 650)
    }
    const [workspaceTransition, setWorkspaceTransition] = useState<{ step: number; active: boolean }>({ step: 0, active: false })
    useEffect(() => {
      if (!workspaceTransition.active) return
      const overlay = document.createElement('div')
      overlay.className = 'workspace-transition-backdrop'
      const card = document.createElement('section')
      card.className = 'workspace-transition-card register'
      card.setAttribute('role', 'status')
      card.setAttribute('aria-live', 'polite')
      const badge = document.createElement('span')
      badge.className = 'workspace-transition-badge'
      badge.textContent = 'Launching workspace'
      const title = document.createElement('strong')
      title.className = 'workspace-transition-message'
      title.textContent = 'Getting your business ready'
      const lines = document.createElement('ol')
      lines.className = 'workspace-transition-lines'
      workspaceTransitionMessages.forEach((message, index) => {
        const line = document.createElement('li')
        line.className = index < workspaceTransition.step ? 'complete' : index === workspaceTransition.step ? 'current' : ''
        const marker = document.createElement('span')
        marker.className = 'workspace-transition-line-marker'
        marker.textContent = index < workspaceTransition.step ? '✓' : index === workspaceTransition.step ? '●' : '○'
        const label = document.createElement('span')
        label.textContent = message
        line.append(marker, label)
        lines.appendChild(line)
      })
      const progress = document.createElement('div')
      progress.className = 'workspace-transition-progress'
      const bar = document.createElement('span')
      const progressValue = ((workspaceTransition.step + 1) / workspaceTransitionMessages.length) * 100
      bar.style.width = `${Math.max(progressValue, 18)}%`
      progress.appendChild(bar)
      card.append(badge, title, lines, progress)
      overlay.appendChild(card)
      document.body.appendChild(overlay)
      return () => overlay.remove()
    }, [workspaceTransition.active, workspaceTransition.step])
    const [ownerAccount, setOwnerAccount] = useState<OwnerAccount | null>(() => isSupabaseConfigured ? null : initialRefreshSession?.owner || null)
    const [siteAdminAccount, setSiteAdminAccount] = useState<OwnerAccount | null>(() => readStoredSiteAdminAccount() ?? defaultSiteAdminAccount)
    const [siteAdminSession, setSiteAdminSession] = useState(false)
    const [authSessionReady, setAuthSessionReady] = useState(!isSupabaseConfigured)
    const [siteAdminSnapshotLoaded, setSiteAdminSnapshotLoaded] = useState(false)
    const [businessAccounts, setBusinessAccounts] = useState<BusinessAccount[]>(() => readStoredBusinessAccounts())
    const [registrationRequests, setRegistrationRequests] = useState<RegistrationRequest[]>([])
    const [reviewDecisions, setReviewDecisions] = useState<Record<string, 'Activated' | 'Declined'>>(() => { try { return JSON.parse(localStorage.getItem('biztrack-review-decisions') || '{}') } catch { return {} } })
    const [activationCodes, setActivationCodes] = useState<ActivationCode[]>([])
    const [packages, setPackages] = useState<PackageConfig[]>(defaultPackages)
    const [platformSettings, setPlatformSettings] = useState<PlatformSettings>(defaultPlatformSettings)
    const [platformSettingsReady, setPlatformSettingsReady] = useState(!isSupabaseConfigured)
    const [supabaseReady, setSupabaseReady] = useState(!isSupabaseConfigured)
    const [siteAdminReady, setSiteAdminReady] = useState(!isSupabaseConfigured)
    const tenantId = ownerAccount?.tenantId || 'workspace'
    const savedWorkspaceState = readStoredWorkspaceState()
    const [members, setMembers] = useState<Member[]>(savedWorkspaceState.members || [])
    const [departmentList, setDepartmentList] = useState<string[]>(savedWorkspaceState.departmentList || [])
    const [casualEarnings, setCasualEarnings] = useState<CasualEarning[]>(savedWorkspaceState.casualEarnings || [])
    const [attendance, setAttendance] = useState<AttendanceEntry[]>([])
    const attendanceRef = useRef(attendance)
    const [deductions, setDeductions] = useState<Deduction[]>([])
    useEffect(() => {
      const applyDueUpdates = () => {
        const dueUpdates = members.filter((member) => member.scheduledUpdate && new Date(member.scheduledUpdate.effectiveAt).getTime() <= Date.now())
        if (!dueUpdates.length) return
        setMembers((current) => {
          const next = current.map((member) => {
            const scheduled = member.scheduledUpdate
            if (!scheduled || new Date(scheduled.effectiveAt).getTime() > Date.now()) return member
            return applyMemberUpdate(member, scheduled.changes, scheduled.effectiveAt, attendance, casualEarnings, deductions, scheduled.includeTodayShift ?? true)
          })
          return next
        })
        setAttendance((current) => current.map((entry) => {
          const due = dueUpdates.find((member) => member.id === entry.memberId)?.scheduledUpdate
          if (!due?.includeTodayShift || due.changes.payTerms === 'Casual' || entry.date !== nextPayTermsStart(due.effectiveAt) || !entry.checkIn || entry.checkIn === '—') return entry
          return { ...entry, payRate: due.changes.payRate ?? entry.payRate, workerName: due.changes.name ?? entry.workerName, workerDepartment: due.changes.department ?? entry.workerDepartment, workerPayTerms: due.changes.payTerms === 'Per shift' ? 'Per shift' : entry.workerPayTerms, workerPayFrequency: due.changes.payFrequency ?? entry.workerPayFrequency }
        }))
      }
      applyDueUpdates()
      const nextEffectiveAt = members.reduce((earliest, member) => {
        const effectiveAt = member.scheduledUpdate ? new Date(member.scheduledUpdate.effectiveAt).getTime() : NaN
        return Number.isFinite(effectiveAt) && effectiveAt > Date.now() ? Math.min(earliest, effectiveAt) : earliest
      }, Number.POSITIVE_INFINITY)
      if (!Number.isFinite(nextEffectiveAt)) return
      let timer = 0
      const scheduleNextCheck = () => {
        const delay = nextEffectiveAt - Date.now()
        timer = window.setTimeout(() => {
          if (Date.now() < nextEffectiveAt) scheduleNextCheck()
          else applyDueUpdates()
        }, Math.min(delay, 2147483647))
      }
      scheduleNextCheck()
      return () => window.clearTimeout(timer)
    }, [members, attendance, casualEarnings, deductions])
    useEffect(() => { attendanceRef.current = attendance }, [attendance])
    const [sales, setSales] = useState<Sale[]>([])
    const [salesHistory, setSalesHistory] = useState<Sale[]>([])
    const [expenses, setExpenses] = useState<Expense[]>([])
    const [stockMovements, setStockMovements] = useState<StockMovement[]>([])
    const [inventory, setInventory] = useState<InventoryItem[]>([])
    const [storeCategories, setStoreCategories] = useState<string[]>([])
    const [deletedCategories, setDeletedCategories] = useState<string[]>([])
    const [categoryUnits, setCategoryUnits] = useState<Record<string, string>>({})
      const [categoryThresholds, setCategoryThresholds] = useState<Record<string, number>>({})
    const [workspaceName, setWorkspaceName] = useState(() => ownerAccount?.business || savedWorkspaceState.workspaceName || '')
    const [currency, setCurrency] = useState('KES')
    const [paymentRegisterFooter, setPaymentRegisterFooter] = useState(savedWorkspaceState.paymentRegisterFooter ?? defaultPaymentRegisterFooter)
    const [payrollReportOrder, setPayrollReportOrder] = useState<PayrollReportOrder>(savedWorkspaceState.payrollReportOrder ?? defaultPayrollReportOrder)
    const [paymentMethods, setPaymentMethods] = useState<string[]>(['Cash', 'Credit', 'Mobile money'])
      const [strictSignIn, setStrictSignIn] = useState(false)
  const [allowMultipleDailyShifts, setAllowMultipleDailyShifts] = useState(false)
      const [biometricSignIn, setBiometricSignIn] = useState(false)
      const [biometricSignOut, setBiometricSignOut] = useState(false)
      const [biometricMark, setBiometricMark] = useState(false)
      const [biometricPayroll, setBiometricPayroll] = useState(false)
  const [defaultSignIn, setDefaultSignIn] = useState('08:00')
  const [defaultSignOut, setDefaultSignOut] = useState('17:00')
  const [lateSignIn, setLateSignIn] = useState('08:00')
  const [earlySignOut, setEarlySignOut] = useState('17:00')
  const [isCheckedIn, setIsCheckedIn] = useState(true)
    const [sessionMemberId, setSessionMemberId] = useState(() => isSupabaseConfigured ? 0 : initialRefreshSession?.memberId || 0)
  const [accessByMember, setAccessByMember] = useState<Record<number, AccessArea[]>>(savedWorkspaceState.accessByMember || emptyAccess)
  const [accountChoiceOpen, setAccountChoiceOpen] = useState(false)
  const [selectingExistingAccount, setSelectingExistingAccount] = useState(false)
  const [permissionTargetId, setPermissionTargetId] = useState<number | null>(null)
  const [deleteTargetId, setDeleteTargetId] = useState<number | null>(null)
  const [loadedTenantId, setLoadedTenantId] = useState(tenantId)
  const [remoteWorkspaceLoaded, setRemoteWorkspaceLoaded] = useState(!isSupabaseConfigured || tenantId === 'workspace')
  const [workspaceReloadKey, setWorkspaceReloadKey] = useState(0)
  const [startupReady, setStartupReady] = useState(!isSupabaseConfigured)
  const workspaceHydrationId = useRef(0)
  const workspaceRefreshTimer = useRef<number | null>(null)
  const workspaceSaveTimer = useRef<number | null>(null)
  const workspaceSaveVersion = useRef(0)
  const workspaceSaveQueue = useRef(Promise.resolve())
  const lastWorkspaceSnapshotAt = useRef<string | null>(null)
  const skipWorkspaceSnapshotSave = useRef(false)
  useEffect(() => {
    if (!supabase || !isSupabaseConfigured || !tenantId || tenantId === 'workspace') return
    lastWorkspaceSnapshotAt.current = null
    let connected = false
    let checkingSnapshotVersion = false
    const requestRefresh = () => {
      if (workspaceRefreshTimer.current !== null) window.clearTimeout(workspaceRefreshTimer.current)
      workspaceRefreshTimer.current = window.setTimeout(() => {
        workspaceRefreshTimer.current = null
        setWorkspaceReloadKey((current) => current + 1)
      }, 10)
    }
    const checkSnapshotVersion = async () => {
      if (checkingSnapshotVersion || document.visibilityState !== 'visible') return
      checkingSnapshotVersion = true
      try {
        const { data, error } = await supabase.from('workspace_snapshots').select('updated_at').eq('tenant_id', tenantId).maybeSingle()
        if (error || !data?.updated_at) return
        const previousUpdatedAt = lastWorkspaceSnapshotAt.current
        if (previousUpdatedAt && Date.parse(data.updated_at) > Date.parse(previousUpdatedAt)) {
          lastWorkspaceSnapshotAt.current = data.updated_at
          requestRefresh()
        }
      } catch {
        // Realtime and the next poll can recover from temporary network failures.
      } finally {
        checkingSnapshotVersion = false
      }
    }
    const catchUp = () => { if (document.visibilityState === 'visible') { requestRefresh(); void checkSnapshotVersion() } }
    const pollTimer = window.setInterval(() => {
      if (navigator.onLine && document.visibilityState === 'visible') void checkSnapshotVersion()
    }, 30_000)
    const channel = supabase.channel(`workspace-sync-${tenantId}`)
      .on('postgres_changes', { event: '*', schema: 'public', table: 'workspace_snapshots', filter: `tenant_id=eq.${tenantId}` }, (event) => {
        if (event.eventType !== 'DELETE') {
          const updatedAt = (event.new as { updated_at?: string }).updated_at
          const previousUpdatedAt = lastWorkspaceSnapshotAt.current
          if (updatedAt && previousUpdatedAt && Date.parse(updatedAt) <= Date.parse(previousUpdatedAt)) return
          if (updatedAt) lastWorkspaceSnapshotAt.current = updatedAt
        }
        requestRefresh()
      })
      .subscribe((status) => {
        if (status === 'SUBSCRIBED') {
          if (connected) requestRefresh()
          connected = true
        }
      })
    window.addEventListener('online', catchUp)
    window.addEventListener('focus', catchUp)
    document.addEventListener('visibilitychange', catchUp)
    return () => {
      if (workspaceRefreshTimer.current !== null) window.clearTimeout(workspaceRefreshTimer.current)
      workspaceRefreshTimer.current = null
      window.clearInterval(pollTimer)
      window.removeEventListener('online', catchUp)
      window.removeEventListener('focus', catchUp)
      document.removeEventListener('visibilitychange', catchUp)
      void supabase.removeChannel(channel)
    }
  }, [tenantId])
  useEffect(() => {
    const preventNumberWheel = (event: WheelEvent) => {
      const target = event.target as HTMLInputElement | null
      if (target?.matches('input[type="number"]')) event.preventDefault()
    }
    document.addEventListener('wheel', preventNumberWheel, { capture: true, passive: false })
    return () => document.removeEventListener('wheel', preventNumberWheel, true)
  }, [])
  useEffect(() => {
    const inputPolicy = (input: HTMLInputElement) => {
      if (input.type === 'number') return Number(input.step) % 1 !== 0 || input.step === 'any' ? 'decimal' : 'integer'
      if (input.inputMode === 'numeric') return 'integer'
      if (input.type === 'tel' || input.name.toLowerCase() === 'phone') return 'phone'
      return null
    }
    const isAllowedInput = (input: HTMLInputElement, value: string) => {
      const policy = inputPolicy(input)
      if (policy === 'integer') return /^\d*$/.test(value)
      if (policy === 'decimal') return /^\d*\.?\d*$/.test(value)
      if (policy === 'phone') return /^[\d+().\s-]*$/.test(value)
      return true
    }
    const validateBeforeInput = (event: InputEvent) => {
      const input = event.target instanceof HTMLInputElement ? event.target : null
      if (!input || !inputPolicy(input) || event.data === null) return
      if (!isAllowedInput(input, event.data)) event.preventDefault()
    }
    const validateKeydown = (event: KeyboardEvent) => {
      const input = event.target instanceof HTMLInputElement ? event.target : null
      if (!input || !inputPolicy(input) || event.ctrlKey || event.metaKey || event.altKey || event.key.length !== 1) return
      if (!isAllowedInput(input, event.key) || (input.type === 'number' && event.key === '.' && input.value.includes('.'))) event.preventDefault()
    }
    const validatePaste = (event: ClipboardEvent) => {
      const input = event.target instanceof HTMLInputElement ? event.target : null
      const pastedText = event.clipboardData?.getData('text')
      if (!input || !inputPolicy(input) || !pastedText) return
      if (!isAllowedInput(input, pastedText)) event.preventDefault()
    }
    document.addEventListener('keydown', validateKeydown, true)
    document.addEventListener('beforeinput', validateBeforeInput, true)
    document.addEventListener('paste', validatePaste, true)
    return () => {
      document.removeEventListener('keydown', validateKeydown, true)
      document.removeEventListener('beforeinput', validateBeforeInput, true)
      document.removeEventListener('paste', validatePaste, true)
    }
  }, [])

  useEffect(() => {
    if (!isSupabaseConfigured || !supabase) { setAuthSessionReady(true); return }
    let cancelled = false
    const restoreAuthenticatedRoute = async () => {
      let restored = false
      try {
        const { data, error } = await supabase.auth.getSession()
        if (error) throw error
        if (cancelled) return
        const authSession = data.session
        if (authSession?.user.app_metadata?.role === 'platform_admin') {
          setSiteAdminSession(true)
          restored = true
        } else if (authSession && initialRefreshSession?.owner?.tenantId && initialRefreshSession.memberId !== undefined) {
          const cachedOwner = initialRefreshSession.owner
          const cachedMemberId = initialRefreshSession.memberId
          const authenticatedEmail = (authSession.user.email || '').toLowerCase()
          const { data: membership, error: membershipError } = await supabase
            .from('tenant_memberships')
            .select('role')
            .eq('tenant_id', cachedOwner.tenantId)
            .maybeSingle()
          if (membershipError) throw membershipError
          let validWorkspaceIdentity = false
          if (cachedMemberId === -1) {
            const { data: ownerAuthEmail, error: ownerEmailError } = await supabase.rpc('account_login_email', {
              requested_tenant_id: cachedOwner.tenantId,
              requested_role: 'owner',
              requested_username: cachedOwner.username,
            })
            if (ownerEmailError) throw ownerEmailError
            validWorkspaceIdentity = membership?.role === 'owner'
              && [String(ownerAuthEmail).toLowerCase(), supabaseAuthEmailForUsername(cachedOwner.username)].includes(authenticatedEmail)
          }
          if (cachedMemberId > 0 && membership?.role === 'member') {
            const { data: snapshot, error: snapshotError } = await supabase
              .from('workspace_snapshots')
              .select('payload')
              .eq('tenant_id', cachedOwner.tenantId)
              .maybeSingle()
            if (snapshotError) throw snapshotError
            const payload = snapshot?.payload as Partial<WorkspaceSnapshot> | undefined
            const cachedMember = payload?.members?.find((member) => Number(member.id) === cachedMemberId)
            if (cachedMember?.hasAccount) {
              const { data: memberAuthEmail, error: memberEmailError } = await supabase.rpc('account_login_email', {
                requested_tenant_id: cachedOwner.tenantId,
                requested_role: 'member',
                requested_username: cachedMember.username,
              })
              if (memberEmailError) throw memberEmailError
              validWorkspaceIdentity = [String(memberAuthEmail).toLowerCase(), supabaseAuthEmailForUsername(cachedMember.username)].includes(authenticatedEmail)
            }
          }
          if (validWorkspaceIdentity) {
            setOwnerAccount(cachedOwner)
            setSessionMemberId(cachedMemberId)
            restored = true
          }
        }
      } catch (error) {
        console.warn('Could not restore authenticated route', error)
      } finally {
        if (cancelled) return
        if (!restored) {
          setOwnerAccount(null)
          setSessionMemberId(0)
          setSiteAdminSession(false)
          saveRefreshSession(null)
          if (isProtectedPath(window.location.pathname)) {
            setActiveNav('Sign in')
            window.history.replaceState({}, '', pagePaths['Sign in'])
          }
        }
        setAuthSessionReady(true)
      }
    }
    void restoreAuthenticatedRoute()
    return () => { cancelled = true }
  }, [])
  useEffect(() => {
    const path = window.location.pathname.replace(/\/$/, '') || '/'
    if (!authSessionReady) return
    const adminSession = siteAdminSession
    const owner = ownerAccount
    const hasWorkspaceSession = Boolean(owner && sessionMemberId !== 0)

    if (isProtectedPath(path) && !hasWorkspaceSession && !path.startsWith('/admin')) {
      setActiveNav('Sign in')
      window.history.replaceState({}, '', pagePaths['Sign in'])
      return
    }

    if (path.startsWith('/admin') && !adminSession) {
      setActiveNav('Admin sign in')
      window.history.replaceState({}, '', pagePaths['Admin sign in'])
    }
  }, [authSessionReady, ownerAccount, sessionMemberId, siteAdminSession])

  useEffect(() => {
    if (activeNav !== 'Sales') return
    const select = document.querySelector<HTMLSelectElement>('.sales-form select[name="paymentMethod"]')
    if (!select) return
    const allowedMethods = paymentMethods.filter((method): method is PaymentMethod => ['Cash', 'Credit', 'Mobile money'].includes(method))
    const currentMethod = select.value
    select.replaceChildren(...allowedMethods.map((method) => new Option(method, method)))
    if (allowedMethods.length) {
      select.value = allowedMethods.includes(currentMethod as PaymentMethod) ? currentMethod : allowedMethods[0]
      select.disabled = false
    } else {
      select.add(new Option('Enable a payment method in Settings', ''))
      select.disabled = true
    }
    const submitButton = select.form?.querySelector<HTMLButtonElement>('button[type="submit"]')
    if (submitButton) submitButton.disabled = allowedMethods.length === 0
  }, [activeNav, paymentMethods])
  useEffect(() => {
    if (activeNav !== 'Inventory') return
    const select = document.querySelector('.sales-form select[name="category"]') as HTMLSelectElement | null
    if (!select) return
    select.replaceChildren(new Option(storeCategories.length ? 'Select a category' : 'Add categories in Settings first', ''))
    storeCategories.forEach((item) => select.add(new Option(item, item)))
    select.disabled = storeCategories.length === 0
    select.required = true
  }, [activeNav, storeCategories])
  useEffect(() => {
    if (activeNav !== 'Inventory') return
    const categorySelect = document.querySelector('.sales-form select[name="category"]') as HTMLSelectElement | null
    const unitInput = document.querySelector('.sales-form input[name="unit"]') as HTMLInputElement | null
    const thresholdInput = document.querySelector('.sales-form input[name="reorderAt"]') as HTMLInputElement | null
    if (!categorySelect || !unitInput || !thresholdInput) return
    const syncUnit = () => { unitInput.value = categoryUnits[categorySelect.value] || 'pieces'; unitInput.readOnly = true; thresholdInput.value = String(categoryThresholds[categorySelect.value] ?? 5); thresholdInput.readOnly = true }
    categorySelect.addEventListener('change', syncUnit)
    syncUnit()
    return () => categorySelect.removeEventListener('change', syncUnit)
  }, [activeNav, storeCategories, categoryUnits, categoryThresholds])
  useEffect(() => {
    localStorage.setItem(businessAccountsStorageKey, JSON.stringify(businessAccounts))
  }, [businessAccounts])
  useEffect(() => {
    const payload = { members, departmentList, casualEarnings, accessByMember, workspaceName, paymentRegisterFooter, payrollReportOrder }
    localStorage.setItem(workspaceStorageKey, JSON.stringify(payload))
  }, [members, departmentList, casualEarnings, accessByMember, workspaceName, paymentRegisterFooter, payrollReportOrder])
  useEffect(() => {
    if (!isSupabaseConfigured || !supabase) return
    let cancelled = false
    const loadAdminData = async () => {
      if (!siteAdminSession) {
        const [{ data: platform }, packageResult] = await Promise.all([
          supabase.from('platform_settings').select('*').eq('id', 1).maybeSingle(),
          supabase.rpc('get_public_registration_packages'),
        ])
        if (!cancelled && platform) {
          const nextPlatformSettings = { platformName: platform.platform_name || defaultPlatformSettings.platformName, supportEmail: platform.support_email || defaultPlatformSettings.supportEmail, whatsappNumber: platform.whatsapp_number || '', defaultPlan: platform.default_plan || defaultPlatformSettings.defaultPlan, maintenanceMode: platform.maintenance_mode ?? false, maintenanceEndsAt: platform.maintenance_ends_at || '' }
          setPlatformSettings(nextPlatformSettings)
        }
        if (!cancelled) {
          const publicPackages = packageResult.error || !Array.isArray(packageResult.data) ? [] : packageResult.data
          setPackages(publicPackages.length ? normalizePackages(publicPackages) : [])
          setPlatformSettingsReady(true)
          setSupabaseReady(true)
          setSiteAdminReady(true)
        }
        return
      }
      const results = await withSupabaseRetry('load admin data', async () => {
        const accountQuery = supabase.from('business_accounts').select('*').order('created_at', { ascending: false })
        const requestQuery = supabase.from('registration_requests').select('*').order('id', { ascending: false })
        const platformQuery = supabase.from('platform_settings').select('*').eq('id', 1).maybeSingle()
        const [{ data: accounts }, { data: requests }, { data: platform }] = await Promise.all([
          accountQuery,
          requestQuery,
          platformQuery,
        ])
        return { accounts, requests: requests ?? [], platform }
      })
      const accounts = results?.accounts
      const requests = results?.requests
      const platform = results?.platform
      if (cancelled) return
      if (accounts?.length) {
        const remoteAccounts = accounts.map((account: any) => normalizeBusinessAccount(account)).filter(Boolean) as BusinessAccount[]
        setBusinessAccounts(uniqueBusinessAccounts(remoteAccounts))
      } else {
        setBusinessAccounts((current) => uniqueBusinessAccounts([...current, ...defaultBusinessAccounts]))
      }
      if (requests?.length) setRegistrationRequests(requests.map((request: any) => ({ id: request.id, applicantName: request.applicant_name, businessName: request.business_name, issue: request.issue, submittedAt: request.submitted_at, phone: request.phone, email: request.email, username: request.username, password: request.password, industry: request.industry, plan: request.plan, reviewStatus: request.review_status })))
      if (platform) {
        const nextPlatformSettings = { platformName: platform.platform_name || defaultPlatformSettings.platformName, supportEmail: platform.support_email || defaultPlatformSettings.supportEmail, whatsappNumber: platform.whatsapp_number || '', defaultPlan: platform.default_plan || defaultPlatformSettings.defaultPlan, maintenanceMode: platform.maintenance_mode ?? false, maintenanceEndsAt: platform.maintenance_ends_at || '' }
        setPlatformSettings(nextPlatformSettings)
      }
      setPlatformSettingsReady(true)
      setSupabaseReady(true)
      setSiteAdminReady(true)
    }
    void loadAdminData().catch(() => { setPlatformSettingsReady(true); setSupabaseReady(true); setSiteAdminReady(true) })
    return () => { cancelled = true }
  }, [siteAdminSession])
  useEffect(() => {
    if (!isSupabaseConfigured || !supabase) return
    let cancelled = false
    let refreshInFlight = false
    const refreshMaintenanceSettings = async () => {
      if (refreshInFlight) return
      refreshInFlight = true
      try {
        const { data, error } = await supabase.from('platform_settings').select('maintenance_mode, maintenance_ends_at').eq('id', 1).maybeSingle()
        if (cancelled || error || !data) return
        const nextMaintenanceMode = Boolean(data.maintenance_mode)
        const nextMaintenanceEndsAt = data.maintenance_ends_at || ''
        setPlatformSettings((current) => current.maintenanceMode === nextMaintenanceMode && current.maintenanceEndsAt === nextMaintenanceEndsAt
          ? current
          : { ...current, maintenanceMode: nextMaintenanceMode, maintenanceEndsAt: nextMaintenanceEndsAt })
      } catch (error) {
        if (!cancelled) console.warn('Could not refresh platform maintenance status.', error)
      } finally {
        refreshInFlight = false
      }
    }
    const refreshWhenVisible = () => { if (document.visibilityState === 'visible') void refreshMaintenanceSettings() }
    const timer = window.setInterval(() => {
      if (navigator.onLine && document.visibilityState === 'visible') void refreshMaintenanceSettings()
    }, 30_000)
    void refreshMaintenanceSettings()
    window.addEventListener('online', refreshWhenVisible)
    window.addEventListener('focus', refreshWhenVisible)
    document.addEventListener('visibilitychange', refreshWhenVisible)
    return () => {
      cancelled = true
      window.clearInterval(timer)
      window.removeEventListener('online', refreshWhenVisible)
      window.removeEventListener('focus', refreshWhenVisible)
      document.removeEventListener('visibilitychange', refreshWhenVisible)
    }
  }, [])
  useEffect(() => {
    if (!isSupabaseConfigured) { setStartupReady(true); return }
    const workspaceReady = !ownerAccount || sessionMemberId === 0 || remoteWorkspaceLoaded
    if (authSessionReady && platformSettingsReady && siteAdminReady && supabaseReady && workspaceReady) setStartupReady(true)
  }, [authSessionReady, ownerAccount, sessionMemberId, platformSettingsReady, siteAdminReady, supabaseReady, remoteWorkspaceLoaded])
  useEffect(() => {
    if (!siteAdminSession || !supabase) return
    let cancelled = false
    const loadSiteAdminSnapshot = async () => {
      const { data, error } = await supabase.from('site_admin_snapshots').select('payload').eq('id', 1).maybeSingle()
      if (cancelled) return
      if (error) {
        setAttendanceNotice(`Could not load live package settings: ${error.message}`)
        return
      }
      const siteData = data?.payload as { registrationRequests?: RegistrationRequest[]; activationCodes?: ActivationCode[]; packages?: Partial<PackageConfig>[]; reviewDecisions?: Record<string, 'Activated' | 'Declined'> } | undefined
      if (siteData?.registrationRequests) setRegistrationRequests(siteData.registrationRequests)
      if (siteData?.reviewDecisions) setReviewDecisions(siteData.reviewDecisions)
      if (siteData?.activationCodes) setActivationCodes(siteData.activationCodes)
      if (siteData?.packages) setPackages(normalizePackages(siteData.packages))
      setSiteAdminSnapshotLoaded(true)
    }
    void loadSiteAdminSnapshot()
    return () => { cancelled = true }
  }, [siteAdminSession])
  useEffect(() => {
    setAttendanceNotices((current) => current.filter((notice) => !notice.page || notice.page === activeNav))
  }, [activeNav])
  useEffect(() => {
    const attendanceNotice = attendanceNotices[0]
    if (!attendanceNotice || (attendanceNotice.page && attendanceNotice.page !== activeNav)) return
    const notice = document.createElement('div')
    notice.className = `attendance-success ${attendanceNotice.tone === 'error' ? 'attendance-error' : ''}`
    notice.setAttribute('role', attendanceNotice.tone === 'error' ? 'alert' : 'status')
    const message = document.createElement('span')
    message.textContent = attendanceNotice.message
    const close = document.createElement('button')
    close.type = 'button'
    close.className = 'attendance-success-close'
    close.setAttribute('aria-label', 'Dismiss notification')
    close.textContent = '×'
    const dismiss = () => setAttendanceNotices((current) => current.filter((item) => item.id !== attendanceNotice.id))
    close.addEventListener('click', dismiss)
    notice.append(message, close)
    document.body.appendChild(notice)
    const timer = window.setTimeout(dismiss, attendanceNotice.durationMs ?? (attendanceNotice.tone === 'error' ? 9000 : 3000))
    return () => { window.clearTimeout(timer); notice.remove() }
  }, [activeNav, attendanceNotices[0]?.id, attendanceNotices[0]?.tone])
  useEffect(() => {
    if (loadedTenantId === tenantId) return
    setLoadedTenantId(tenantId)
  }, [tenantId, workspaceReloadKey])
  useEffect(() => {
    if (!supabase || tenantId === 'workspace') {
      setRemoteWorkspaceLoaded(true)
      return
    }
    setRemoteWorkspaceLoaded(false)
    const hydrationId = workspaceHydrationId.current + 1
    workspaceHydrationId.current = hydrationId
    let cancelled = false
    const loadWorkspaceSnapshot = async () => {
      let results = await withSupabaseRetry('load workspace snapshot', async () => {
        const snapshotQuery = supabase.from('workspace_snapshots').select('payload,updated_at').eq('tenant_id', tenantId).maybeSingle()
        const biometricsQuery = remoteBiometricRegistryEnabled ? supabase.rpc('list_biometric_credentials', { requested_tenant_id: tenantId }) : Promise.resolve({ data: [] })
        const businessQuery = supabase.from('business_accounts').select('business_name').eq('tenant_id', tenantId).maybeSingle()
        const [{ data, error }, biometrics, { data: canonicalBusiness, error: businessError }] = await Promise.all([
          snapshotQuery,
          biometricsQuery,
          businessQuery,
        ])
        return { data, error, biometrics: biometrics?.data ?? [], canonicalBusiness, businessError }
      })
      let usedCachedSnapshot = false
      if (!results || results.error || results.businessError) {
        const cached = await readCachedWorkspaceSnapshot(tenantId).catch((cacheError) => {
          console.warn('Could not read the cached workspace snapshot.', cacheError)
          return null
        })
        const cachedPayload = cached?.payload as Partial<WorkspaceSnapshot> | undefined
        const cachedSnapshotIsComplete = Boolean(cachedPayload && ('members' in cachedPayload || 'attendance' in cachedPayload || 'workspaceName' in cachedPayload))
        if (!cached || !cachedSnapshotIsComplete) {
          if (!results) throw new Error('Workspace snapshot could not be loaded after retries.')
          if (results.error) throw results.error
          throw results.businessError
        }
        results = {
          data: { payload: cachedPayload, updated_at: cached.updatedAt },
          error: null,
          biometrics: [],
          canonicalBusiness: { business_name: ownerAccount?.business || cachedPayload.workspaceName || '' },
          businessError: null,
        }
        usedCachedSnapshot = true
      }
      const { data, error, biometrics, canonicalBusiness, businessError } = results
      if (cancelled || hydrationId !== workspaceHydrationId.current) return
      if (error) throw error
      if (businessError) throw businessError
      if (!canonicalBusiness) throw new Error('Workspace owner access could not be confirmed; refusing to initialize an empty snapshot.')
      lastWorkspaceSnapshotAt.current = data?.updated_at ?? null
      skipWorkspaceSnapshotSave.current = true
      const snapshot = data?.payload as Partial<WorkspaceSnapshot> | undefined
      const biometricIds = new Map((biometrics || []).map((item: { member_id: number; credential_id: string }) => [item.member_id, item.credential_id]))
      const snapshotIsComplete = Boolean(snapshot && ('members' in snapshot || 'attendance' in snapshot || 'workspaceName' in snapshot))
      if (data && !snapshotIsComplete) throw new Error('Existing workspace snapshot is incomplete; refusing to overwrite it.')
      if (!usedCachedSnapshot && snapshotIsComplete && snapshot) {
        void cacheWorkspaceSnapshot(tenantId, snapshot, data?.updated_at ?? null).catch((cacheError) => {
          console.warn('Could not save the workspace for offline use.', cacheError)
        })
      }
      if (snapshotIsComplete && snapshot) {
        if ('members' in snapshot) setMembers((snapshot.members || []).map((member, index) => normalizeMember({ ...member, biometricCredentialId: biometricIds.get(member.id) || '' }, index, tenantId)))
        if ('departmentList' in snapshot) setDepartmentList(snapshot.departmentList || [])
        if ('attendance' in snapshot) setAttendance(snapshot.attendance || [])
        setCasualEarnings(Array.isArray(snapshot.casualEarnings) ? snapshot.casualEarnings : [])
        if ('sales' in snapshot) setSales(snapshot.sales || [])
        if ('salesHistory' in snapshot) setSalesHistory(snapshot.salesHistory || [])
        if ('deductions' in snapshot) setDeductions(snapshot.deductions || [])
        if ('expenses' in snapshot) setExpenses(snapshot.expenses || [])
        if ('stockMovements' in snapshot) setStockMovements(snapshot.stockMovements || [])
        if ('inventory' in snapshot) setInventory(snapshot.inventory || [])
        if ('storeCategories' in snapshot) setStoreCategories(snapshot.storeCategories || [])
        setDeletedCategories(Array.isArray(snapshot.deletedCategories) ? snapshot.deletedCategories : [])
        if ('categoryUnits' in snapshot) setCategoryUnits(snapshot.categoryUnits || {})
        if ('categoryThresholds' in snapshot) setCategoryThresholds(snapshot.categoryThresholds || {})
        if ('workspaceName' in snapshot) setWorkspaceName(canonicalBusiness?.business_name || ownerAccount?.business || snapshot.workspaceName || '')
        if ('currency' in snapshot) setCurrency(snapshot.currency || 'KES')
        setPaymentRegisterFooter(typeof snapshot.paymentRegisterFooter === 'string' ? snapshot.paymentRegisterFooter : defaultPaymentRegisterFooter)
        setPayrollReportOrder(snapshot.payrollReportOrder === 'deductions-bottom' || snapshot.payrollReportOrder === 'deductions-top' ? snapshot.payrollReportOrder : defaultPayrollReportOrder)
        if ('paymentMethods' in snapshot) setPaymentMethods(snapshot.paymentMethods || [])
        if (snapshot.strictSignIn !== undefined) setStrictSignIn(snapshot.strictSignIn)
        if (snapshot.allowMultipleDailyShifts !== undefined) setAllowMultipleDailyShifts(snapshot.allowMultipleDailyShifts)
        if (snapshot.biometricSignIn !== undefined) setBiometricSignIn(snapshot.biometricSignIn)
        if (snapshot.biometricSignOut !== undefined) setBiometricSignOut(snapshot.biometricSignOut)
        if (snapshot.biometricMark !== undefined) setBiometricMark(snapshot.biometricMark)
        if (snapshot.biometricPayroll !== undefined) setBiometricPayroll(snapshot.biometricPayroll)
        if (snapshot.defaultSignIn) setDefaultSignIn(snapshot.defaultSignIn)
        if (snapshot.defaultSignOut) setDefaultSignOut(snapshot.defaultSignOut)
        if (snapshot.lateSignIn) setLateSignIn(snapshot.lateSignIn)
        if (snapshot.earlySignOut) setEarlySignOut(snapshot.earlySignOut)
        if (snapshot.accessByMember) setAccessByMember(normalizeAccessByMember(snapshot.accessByMember))
      } else {
        setMembers([])
        setDepartmentList([])
        setAttendance([])
        setCasualEarnings([])
        setSales([])
        setSalesHistory([])
        setDeductions([])
        setExpenses([])
        setStockMovements([])
        setInventory([])
        setStoreCategories([])
        setDeletedCategories([])
        setCategoryUnits({})
        setCategoryThresholds({})
        setWorkspaceName(canonicalBusiness.business_name || ownerAccount?.business || '')
        setCurrency('KES')
        setPaymentRegisterFooter(defaultPaymentRegisterFooter)
        setPayrollReportOrder(defaultPayrollReportOrder)
        setPaymentMethods(['Cash', 'Credit', 'Mobile money'])
        setStrictSignIn(false)
        setAllowMultipleDailyShifts(false)
        setBiometricSignIn(false)
        setBiometricSignOut(false)
        setBiometricMark(false)
        setBiometricPayroll(false)
        setDefaultSignIn('08:00')
        setDefaultSignOut('17:00')
        setLateSignIn('08:00')
        setEarlySignOut('17:00')
        setAccessByMember(emptyAccess)
      }
      if (usedCachedSnapshot) setAttendanceNotice('Connection is unavailable. Showing the last saved workspace copy; reconnect before saving changes.')
      setRemoteWorkspaceLoaded(true)
    }
    void loadWorkspaceSnapshot().catch((error) => { if (!cancelled && hydrationId === workspaceHydrationId.current) { console.error('Workspace snapshot load failed', error); setRemoteWorkspaceLoaded(false) } })
    return () => { cancelled = true }
  }, [tenantId, workspaceReloadKey])
  useEffect(() => {
    if (!startupReady || loadedTenantId !== tenantId || !remoteWorkspaceLoaded || !supabaseReady || !isSupabaseConfigured || !supabase || tenantId === 'workspace') return
    if (skipWorkspaceSnapshotSave.current) {
      skipWorkspaceSnapshotSave.current = false
      return
    }
    const snapshot: WorkspaceSnapshot = { members: members.map(({ biometricCredentialId: _biometricCredentialId, ...member }) => member), departmentList, attendance, casualEarnings, sales, salesHistory, deductions, expenses, stockMovements, inventory, storeCategories, deletedCategories, categoryUnits, categoryThresholds, workspaceName, currency, paymentRegisterFooter, payrollReportOrder, paymentMethods, strictSignIn, allowMultipleDailyShifts, biometricSignIn, biometricSignOut, biometricMark, biometricPayroll, defaultSignIn, defaultSignOut, lateSignIn, earlySignOut, accessByMember }
    const version = workspaceSaveVersion.current + 1
    workspaceSaveVersion.current = version
    if (workspaceSaveTimer.current !== null) window.clearTimeout(workspaceSaveTimer.current)
    workspaceSaveTimer.current = window.setTimeout(() => {
      const updatedAt = new Date().toISOString()
      const previousUpdatedAt = lastWorkspaceSnapshotAt.current
      lastWorkspaceSnapshotAt.current = updatedAt
      workspaceSaveQueue.current = workspaceSaveQueue.current.then(async () => {
        const result = await withSupabaseRetry('save workspace snapshot', async () => {
          const { error } = await supabase.from('workspace_snapshots').upsert({ tenant_id: tenantId, payload: snapshot, updated_at: updatedAt }, { onConflict: 'tenant_id' })
          if (error) throw error
          return true
        })
        if (!result) {
          if (lastWorkspaceSnapshotAt.current === updatedAt) lastWorkspaceSnapshotAt.current = previousUpdatedAt
          console.error('Workspace snapshot save failed after retries')
        }
      }).catch((error) => console.error('Workspace snapshot save failed', error))
    }, 250)
    return () => { if (workspaceSaveTimer.current !== null) { window.clearTimeout(workspaceSaveTimer.current); workspaceSaveTimer.current = null } }
  }, [members, departmentList, attendance, casualEarnings, sales, salesHistory, deductions, expenses, stockMovements, inventory, storeCategories, deletedCategories, categoryUnits, categoryThresholds, workspaceName, currency, paymentRegisterFooter, payrollReportOrder, paymentMethods, defaultSignIn, defaultSignOut, lateSignIn, earlySignOut, strictSignIn, allowMultipleDailyShifts, biometricSignIn, biometricSignOut, biometricMark, biometricPayroll, role, sessionMemberId, accessByMember, ownerAccount, tenantId, loadedTenantId, remoteWorkspaceLoaded, siteAdminAccount, siteAdminSession, businessAccounts, registrationRequests, activationCodes, packages, supabaseReady, startupReady])

  const todayAttendance = useMemo(() => members.map((member) => attendance.find((entry) => entry.memberId === member.id && entry.date === today) || { memberId: member.id, date: today, status: 'Absent' as AttendanceStatus, checkIn: '—', checkOut: '—' }), [members, attendance])
  const markChanged = () => undefined
  const buildWorkspaceSnapshot = (overrides: Partial<WorkspaceSnapshot> = {}): WorkspaceSnapshot => ({ members: members.map(({ biometricCredentialId: _biometricCredentialId, ...member }) => member), departmentList, attendance, casualEarnings, sales, salesHistory, deductions, expenses, stockMovements, inventory, storeCategories, deletedCategories, categoryUnits, categoryThresholds, workspaceName, currency, paymentRegisterFooter, payrollReportOrder, paymentMethods, strictSignIn, allowMultipleDailyShifts, biometricSignIn, biometricSignOut, biometricMark, biometricPayroll, defaultSignIn, defaultSignOut, lateSignIn, earlySignOut, accessByMember, ...overrides })
  const saveWorkspaceSnapshotNow = async (overrides: Partial<WorkspaceSnapshot> = {}, notifySuccess = true) => {
    if (!supabase || tenantId === 'workspace') {
      if (notifySuccess) {
        setAttendanceNotice('Changes saved successfully')
        setAttendanceNoticeTone('success')
      }
      return true
    }
    workspaceHydrationId.current += 1
    if (workspaceRefreshTimer.current !== null) {
      window.clearTimeout(workspaceRefreshTimer.current)
      workspaceRefreshTimer.current = null
    }
    if (workspaceSaveTimer.current !== null) {
      window.clearTimeout(workspaceSaveTimer.current)
      workspaceSaveTimer.current = null
    }
    const snapshot = buildWorkspaceSnapshot(overrides)
    const updatedAt = new Date().toISOString()
    const previousUpdatedAt = lastWorkspaceSnapshotAt.current
    lastWorkspaceSnapshotAt.current = updatedAt
    const queuedSave = workspaceSaveQueue.current.then(async () => {
      const result = await withSupabaseRetry('save workspace snapshot now', async () => {
        const { error } = await supabase.from('workspace_snapshots').upsert({ tenant_id: tenantId, payload: snapshot, updated_at: updatedAt }, { onConflict: 'tenant_id' })
        if (error) throw error
        return true
      })
      if (!result && lastWorkspaceSnapshotAt.current === updatedAt) lastWorkspaceSnapshotAt.current = previousUpdatedAt
      return Boolean(result)
    }).catch((error) => {
      console.error('Workspace snapshot save failed', error)
      if (lastWorkspaceSnapshotAt.current === updatedAt) lastWorkspaceSnapshotAt.current = previousUpdatedAt
      return false
    })
    workspaceSaveQueue.current = queuedSave.then(() => undefined)
    const result = await queuedSave
    if (!result || notifySuccess) {
      setAttendanceNotice(result ? 'Changes saved successfully' : 'Could not save changes. Please check your database connection and try again.')
      setAttendanceNoticeTone(result ? 'success' : 'error')
    }
    return Boolean(result)
  }
  const saveBusinessIdentity = async (requestedName: string, requestedCurrency: string) => {
    const nextName = requestedName.trim()
    if (!nextName) {
      setAttendanceNotice('Business name cannot be empty.')
      setAttendanceNoticeTone('error')
      return false
    }
    const identity = { workspaceName: nextName, currency: requestedCurrency }
    let saved = false
    if (!supabase || tenantId === 'workspace') {
      saved = await saveWorkspaceSnapshotNow(identity)
    } else {
      if (workspaceSaveTimer.current !== null) {
        window.clearTimeout(workspaceSaveTimer.current)
        workspaceSaveTimer.current = null
      }
      const payload = buildWorkspaceSnapshot(identity)
      const queuedSave = workspaceSaveQueue.current.then(async () => {
        const { error } = await supabase.rpc('save_workspace_settings', { requested_tenant_id: tenantId, requested_payload: payload })
        if (error) throw error
        return true
      }).catch((error) => {
        console.error('Business identity save failed', error)
        setAttendanceNotice(`Business identity was not saved: ${error instanceof Error ? error.message : 'Please check your connection and try again.'}`)
        setAttendanceNoticeTone('error')
        return false
      })
      workspaceSaveQueue.current = queuedSave.then(() => undefined)
      saved = await queuedSave
    }
    if (!saved) return false
    setWorkspaceName(nextName)
    setCurrency(requestedCurrency)
    setOwnerAccount((current) => current ? { ...current, business: nextName } : current)
    lastWorkspaceSnapshotAt.current = new Date().toISOString()
    setAttendanceNotice('Business identity and currency saved successfully.')
    setAttendanceNoticeTone('success')
    return true
  }
  const savePaymentMethodSettings = async (methods: string[]) => {
    const saved = await saveWorkspaceSnapshotNow({ paymentMethods: methods })
    if (saved) setPaymentMethods(methods)
    return saved
  }
  const requireBiometric = async (memberId: number, enabled: boolean, action: string) => {
    if (!enabled) return true
    const member = members.find((item) => item.id === memberId)
    if (!member?.biometricCredentialId) { showAttendanceNotice(`${member?.name || 'This worker'} has no registered biometric. Ask the owner to register it.`); return false }
    try { await verifyBiometric(member.biometricCredentialId, tenantId, action, workspaceName); return true } catch (error) { showAttendanceNotice(error instanceof Error ? `${action} blocked: ${error.message}` : `${action} blocked by biometric verification.`); return false }
  }
  const recordBiometricProof = async (memberId: number, action: 'sign-in' | 'sign-out' | 'mark' | 'payroll') => {
    const member = members.find((item) => item.id === memberId)
    if (!member?.biometricCredentialId) return undefined
    const proof = { action, verifiedAt: new Date().toISOString(), credentialId: member.biometricCredentialId }
    await saveBiometricRecord('biometric_proofs', { tenant_id: tenantId, member_id: memberId, action, credential_id: proof.credentialId, verified_at: proof.verifiedAt, attendance_date: today })
    return proof
  }
  useEffect(() => {
    const handlePopState = () => {
      if (!authSessionReady) return
      const path = window.location.pathname
      const adminPath = path.startsWith('/admin') || path === '/delete' || path === '/delete/'
      const workspacePath = /^\/(?:master|grant)(?:\/|$)/.test(path) || path === '/add' || path === '/add/'
      if (adminPath && !siteAdminSession || workspacePath && (!ownerAccount || sessionMemberId === 0)) {
        setActiveNav('Sign in')
        window.history.replaceState({}, '', pagePaths['Sign in'])
        scrollPageToTop()
        return
      }
      setActiveNav(pageForPath(path))
      scrollPageToTop()
    }
    window.addEventListener('popstate', handlePopState)
    return () => window.removeEventListener('popstate', handlePopState)
  }, [authSessionReady, ownerAccount, sessionMemberId, siteAdminSession])
  useEffect(() => {
    if (ownerAccount && sessionMemberId !== 0) saveRefreshSession({ owner: ownerAccount, memberId: sessionMemberId, path: window.location.pathname })
    else if (siteAdminSession) saveRefreshSession({ siteAdmin: true, path: window.location.pathname })
  }, [activeNav, ownerAccount, sessionMemberId, siteAdminSession])
  const resolveWorkerLandingPage = (memberId: number, fallback = 'Overview') => {
    const assignedPages = normalizeAccessAreas(accessByMember[memberId] || [])
    if (!assignedPages.length) return fallback
    return assignedPages.find((page) => page === 'Overview') || assignedPages.find((page) => uniqueAccessAreas.includes(page as AccessArea)) || fallback
  }
  const navigate = (page: string, memberId = sessionMemberId) => {
    const canonicalPage = page === 'Dashboard' ? 'Admin' : page === 'Add department' ? 'Departments' : page === 'Welcome' ? 'Welcome' : page === 'Terms' ? 'Terms' : page === 'Register' ? 'Register' : page === 'Register site admin' || page === 'Admin sign in' || page === 'Master' ? 'Sign in' : page
    const routePaths = memberId > 0 ? grantPagePaths : pagePaths
    const allowedPage = memberId > 0 && !routePaths[canonicalPage]
      ? resolveWorkerLandingPage(memberId, 'Overview')
      : canonicalPage
    const targetPage = routePaths[allowedPage] ? allowedPage : (memberId > 0 ? resolveWorkerLandingPage(memberId, 'Overview') : canonicalPage)
    const path = routePaths[targetPage] || pagePaths['Sign in']
    window.history.pushState({}, '', path)
    setAttendanceNotices((current) => current.filter((notice) => !notice.page || notice.page === targetPage))
    setActiveNav(targetPage)
    scrollPageToTop()
  }
  useEffect(() => {
    if (!window.location.pathname.startsWith('/admin/')) return
    const adminRoutes: Record<string, string> = { Overview: 'Admin', 'Business accounts': 'Business', Subscriptions: 'Packages', 'Platform settings': 'Admin settings', 'Sign out': 'Welcome' }
    const handleAdminNavigation = (event: MouseEvent) => {
      const button = (event.target as HTMLElement).closest('.app-shell > .sidebar button') as HTMLButtonElement | null
      const page = button?.textContent?.replace(/[↪⚙◈KES]/g, '').trim()
      if (!page || !adminRoutes[page]) return
      event.preventDefault()
      event.stopPropagation()
      if (page === 'Sign out') endSiteAdminSession()
      navigate(adminRoutes[page])
    }
    document.addEventListener('click', handleAdminNavigation, true)
    return () => document.removeEventListener('click', handleAdminNavigation, true)
  }, [activeNav])
  useEffect(() => {
    if (!siteAdminSession || window.location.pathname.replace(/\/$/, '') !== '/admin/subscriptions') return
    window.history.replaceState({}, '', pagePaths.Admin)
    setActiveNav('Admin')
  }, [siteAdminSession])
  const currentMember = members[0]
  const toggleCurrentAttendance = () => {
    const existing = attendance.find((entry) => entry.memberId === currentMember?.id && entry.date === today)
    if (!currentMember) return
    if (existing?.status === 'Off') {
      showAttendanceNotice(`${currentMember.name} is marked off for today.`)
      return
    }
    if (isCheckedIn) {
    } else {
      const now = new Date()
      const checkIn = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      const status = timeToMinutes(now.toTimeString().slice(0, 5)) > timeToMinutes(defaultSignIn) ? 'Late' as AttendanceStatus : 'Present' as AttendanceStatus
      const entry = { memberId: currentMember.id, date: today, status, checkIn, checkOut: '—', workerName: currentMember.name, workerDepartment: currentMember.department, workerRole: currentMember.role, workerPayTerms: currentMember.payTerms || 'Per shift', workerPayFrequency: currentMember.payFrequency, payRate: currentMember.payRate }
      setAttendance((current) => existing ? current.map((item) => item.memberId === currentMember.id && item.date === today ? entry : item) : [...current, entry])
    }
    setIsCheckedIn(!isCheckedIn); markChanged()
  }
  const hasAttendanceForToday = (memberId: number) => attendanceRef.current.some((entry) => entry.memberId === memberId && entry.date === today && (entry.checkIn !== '—' || entry.status === 'Present' || entry.status === 'Late' || entry.checkOut !== '—'))
  const markMemberAttendance = async (memberId: number, status: 'Present' | 'Absent', biometricEnabled = biometricMark, biometricAction = 'Mark attendance', persist = true, notifySuccess = true) => {
    const member = members.find((person) => person.id === memberId)
    const activeMember = member?.scheduledUpdate && member.scheduledUpdate.effectiveAt <= new Date().toISOString() ? { ...member, ...member.scheduledUpdate.changes, scheduledUpdate: undefined } : member
    if (member && activeMember !== member) setMembers((current) => current.map((item) => item.id === memberId ? activeMember : item))
    const currentAttendance = attendanceRef.current
    const existing = currentAttendance.find((entry) => entry.memberId === memberId && entry.date === today)
    if (existing?.status === 'Off') {
      showAttendanceNotice(`${member?.name || 'This worker'} is marked off for today.`)
      return false
    }
    const isAlreadySignedIn = Boolean(existing && (existing.status === 'Present' || existing.status === 'Late' || existing.checkOut !== '—'))
    if (status === 'Present') {
      if (isAlreadySignedIn) {
        showAttendanceNotice(`${member?.name || 'This worker'} has already signed in for today.`)
        return false
      }
      const existingStatus = existing?.status ?? 'Absent'
      if (hasAttendanceForToday(memberId) && (!existing || existingStatus === 'Absent' || existingStatus === 'Off')) {
        showAttendanceNotice(`${member?.name || 'This worker'} has already signed in for today.`)
        return false
      }
    }
    if (status === 'Absent') {
      if (existing && (existing.status === 'Present' || existing.status === 'Late' || existing.checkOut !== '—')) {
        showAttendanceNotice(`${member?.name || 'This worker'} has already signed in for today.`)
        return false
      }
    }
    const now = new Date()
    const nowMinutes = timeToMinutes(now.toTimeString().slice(0, 5))
    const scheduledSignIn = timeToMinutes(activeMember?.signInTime || defaultSignIn)
    if (status === 'Present' && strictSignIn && nowMinutes > scheduledSignIn) {
      showAttendanceNotice(`${activeMember?.name || 'This worker'} can only sign in at or before ${activeMember?.signInTime || defaultSignIn} today.`)
      return false
    }
    let biometricProof
    const actionBiometricEnabled = activeNav === 'Worker sign-in' ? biometricSignIn : biometricEnabled
    if (status === 'Present' && actionBiometricEnabled) {
      if (!(await requireBiometric(memberId, true, biometricAction))) return false
      biometricProof = await recordBiometricProof(memberId, 'mark')
    }
    const nextEntry = {
      memberId,
      date: today,
      workerName: activeMember?.name,
      workerDepartment: activeMember?.department,
      workerRole: activeMember?.role,
      workerPayTerms: activeMember?.payTerms || 'Per shift',
      workerPayFrequency: activeMember?.payFrequency,
      payRate: activeMember?.payRate,
      status: status === 'Present' ? (nowMinutes > scheduledSignIn ? 'Late' as AttendanceStatus : 'Present' as AttendanceStatus) : 'Absent' as AttendanceStatus,
      checkIn: status === 'Present' ? now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '—',
      checkOut: '—',
      biometricProof,
    }
    const nextAttendance = existing
      ? currentAttendance.map((entry) => entry.memberId === memberId && entry.date === today ? nextEntry : entry)
      : [...currentAttendance, nextEntry]
    if (persist && !await saveWorkspaceSnapshotNow({ attendance: nextAttendance }, false)) return false
    attendanceRef.current = nextAttendance
    setAttendance(nextAttendance)
    markChanged()
    if (status === 'Present' && notifySuccess) showAttendanceNotice(`${activeMember?.name || 'This worker'} signed in successfully`, 'success')
    return status === 'Present'
  }
  const markMemberSignOut = async (memberId: number, persist = true, notifySuccess = true) => {
    const member = members.find((person) => person.id === memberId)
    const activeMember = member?.scheduledUpdate && member.scheduledUpdate.effectiveAt <= new Date().toISOString() ? { ...member, ...member.scheduledUpdate.changes, scheduledUpdate: undefined } : member
    if (member && activeMember !== member) setMembers((current) => current.map((item) => item.id === memberId ? activeMember : item))
    const currentAttendance = attendanceRef.current
    const entry = currentAttendance.find((item) => item.memberId === memberId && item.date === today)
    if (!entry || entry.status === 'Off' || entry.status === 'Absent' || entry.checkIn === '—') {
      showAttendanceNotice(`${member?.name || 'This worker'} has already signed out for today.`)
      return false
    }
    if (entry.checkOut !== '—') {
      showAttendanceNotice(`${member?.name || 'This worker'} has already signed out for today.`)
      return false
    }
    const now = new Date()
    const scheduledSignOut = activeMember?.signOutTime || defaultSignOut
    if (strictSignIn && timeToMinutes(now.toTimeString().slice(0, 5)) < timeToMinutes(scheduledSignOut)) {
      showAttendanceNotice(`${member?.name || 'This worker'} can only sign out at or after ${scheduledSignOut} today.`)
      return false
    }
    let biometricProof
    if (biometricSignOut) {
      if (!(await requireBiometric(memberId, true, 'Sign out'))) return false
      biometricProof = await recordBiometricProof(memberId, 'sign-out')
    }
    const checkOut = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    const checkoutStatus = timeToMinutes(now.toTimeString().slice(0, 5)) < timeToMinutes(scheduledSignOut) ? 'Early' as AttendanceStatus : entry.status
    const nextAttendance = currentAttendance.map((item) => item.memberId === memberId && item.date === today ? { ...item, status: checkoutStatus, checkOut, workerName: item.workerName || member?.name, workerDepartment: item.workerDepartment || member?.department, payRate: item.payRate ?? member?.payRate, biometricProof: biometricProof || item.biometricProof } : item)
    if (persist && !await saveWorkspaceSnapshotNow({ attendance: nextAttendance }, false)) return false
    attendanceRef.current = nextAttendance
    setAttendance(nextAttendance)
    markChanged()
    if (notifySuccess) showAttendanceNotice(`${member?.name || 'This worker'} signed out successfully`, 'success')
    return true
  }
  const markBulkAttendance = async (memberIds: number[], action: 'Sign in' | 'Sign out') => {
    const previousAttendance = attendanceRef.current
    let successful = 0
    for (const memberId of memberIds) {
      try {
        const result = action === 'Sign in'
          ? await markMemberAttendance(memberId, 'Present', biometricSignIn, 'Sign in', false, false)
          : await markMemberSignOut(memberId, false, false)
        if (result !== false) successful += 1
      } catch (error) {
        const memberName = members.find((member) => member.id === memberId)?.name || `Worker ${memberId}`
        const reason = error instanceof Error ? `: ${error.message}` : '.'
        showAttendanceNotice(`${memberName}: could not ${action === 'Sign in' ? 'sign in' : 'sign out'}${reason}`)
      }
    }
    if (!successful) return 0
    const nextAttendance = attendanceRef.current
    if (!await saveWorkspaceSnapshotNow({ attendance: nextAttendance }, false)) {
      attendanceRef.current = previousAttendance
      setAttendance(previousAttendance)
      showAttendanceNotice(`Could not save the selected workers' ${action === 'Sign in' ? 'sign-ins' : 'sign-outs'}. Please try again.`)
      return 0
    }
    showAttendanceNotice(`${successful} worker${successful === 1 ? '' : 's'} signed ${action === 'Sign in' ? 'in' : 'out'} successfully`, 'success')
    return successful
  }
  const createBusinessAccount = async (account: { businessName: string; ownerName: string; email: string; username: string; password: string; industry: string; plan: SubscriptionPlan; status?: SubscriptionStatus }) => {
    const selectedPackage = packages.find((item) => item.name === account.plan) || defaultPackages.find((item) => item.name === account.plan)!
    const databasePlan = ['Starter', 'Growth', 'Scale'].includes(account.plan) ? account.plan : 'Starter'
    const durationDays = selectedPackage.durationUnit === 'year' ? selectedPackage.duration * 365 : selectedPackage.durationUnit === 'month' ? selectedPackage.duration * 30 : selectedPackage.durationUnit === 'week' ? selectedPackage.duration * 7 : selectedPackage.duration
    try {
      if (!await accountCredentialsAvailable(account.username, account.password)) {
        setAttendanceNotice('That username and password are already used by another account. Keep the username and choose a different password.')
        setAttendanceNoticeTone('error')
        return null
      }
    } catch (error) {
      setAttendanceNotice(error instanceof Error ? error.message : 'Could not verify the new account credentials.')
      setAttendanceNoticeTone('error')
      return null
    }
    const passwordHash = await hashPassword(account.password)
    const nextAccount: BusinessAccount = {
      id: Date.now(),
      businessName: account.businessName.trim(),
      ownerName: account.ownerName.trim(),
      email: account.email.trim(),
      username: account.username.trim().toLowerCase(),
      password: passwordHash,
      industry: account.industry,
      plan: databasePlan,
      status: account.status || 'Active',
      seats: selectedPackage.seats,
      monthlyPrice: selectedPackage.price,
      nextBilling: new Date(Date.now() + durationDays * 24 * 60 * 60 * 1000).toISOString().slice(0, 10),
      createdAt: today,
      tenantId: `tenant-${Date.now()}`,
    }
    if (isSupabaseConfigured && supabase) {
      const { error } = await supabase.from('business_accounts').upsert({ id: nextAccount.id, business_name: nextAccount.businessName, owner_name: nextAccount.ownerName, email: nextAccount.email, username: nextAccount.username, password: nextAccount.password, industry: nextAccount.industry, plan: nextAccount.plan, status: nextAccount.status, seats: nextAccount.seats, monthly_price: nextAccount.monthlyPrice, next_billing: nextAccount.nextBilling, created_at: nextAccount.createdAt, tenant_id: nextAccount.tenantId })
      if (error) throw new Error(error.message || error.details || error.hint || 'Database rejected the business account')
    }
    setMembers([]); setDepartmentList([]); setAttendance([]); setCasualEarnings([]); setSales([]); setSalesHistory([]); setDeductions([]); setInventory([]); setStoreCategories([]); setAccessByMember(emptyAccess); setSessionMemberId(0); setRole('Owner')
    setBusinessAccounts((current) => uniqueBusinessAccounts([nextAccount, ...current]))
    const workspaceOwner = { name: account.ownerName.trim(), username: nextAccount.username, password: passwordHash, business: account.businessName.trim(), tenantId: nextAccount.tenantId }
    setOwnerAccount(workspaceOwner)
    void persistSharedWorkspaceSession({ username: workspaceOwner.username, password: workspaceOwner.password, tenantId: workspaceOwner.tenantId || '', businessName: workspaceOwner.business || account.businessName.trim(), ownerName: workspaceOwner.name })
    setWorkspaceName(account.businessName.trim())
    setActiveNav('Overview')
    return nextAccount
  }
  const updateSubscription = (accountId: number, updates: Partial<Pick<BusinessAccount, 'status' | 'plan' | 'seats' | 'nextBilling'>>) => {
    const targetAccount = businessAccounts.find((account) => account.id === accountId)
    setBusinessAccounts((current) => {
      const next = current.map((account) => account.id === accountId ? { ...account, ...updates, monthlyPrice: updates.plan ? packages.find((item) => item.name === updates.plan)?.price || account.monthlyPrice : account.monthlyPrice } : account)
      const updated = next.find((account) => account.id === accountId)
      if (updated && isSupabaseConfigured && supabase) void (async () => {
        const values = { plan: updated.plan, status: updated.status, seats: updated.seats, monthly_price: updated.monthlyPrice, next_billing: updated.nextBilling }
        let result = await supabase.from('business_accounts').update(values).eq('id', accountId).select('id')
        if (!result.data?.length && targetAccount?.tenantId) result = await supabase.from('business_accounts').update(values).eq('tenant_id', targetAccount.tenantId).select('id')
        if (result.error || !result.data?.length) showBusinessAlert('Site admin', `Business status could not be saved: ${result.error?.message || 'No matching business account was found.'}`, 'Could not save business status')
      })()
      return next
    })
  }
  const deleteBusinessAccount = async (accountId: number) => {
    const account = businessAccounts.find((item) => item.id === accountId)
    if (!account) return
    setBusinessAccounts((current) => current.filter((item) => item.id !== accountId))
    if (isSupabaseConfigured && supabase) {
      await supabase.from('business_accounts').delete().eq('id', accountId)
      await supabase.from('workspace_snapshots').delete().eq('tenant_id', account.tenantId)
      await supabase.from('workspace_sessions').delete().eq('tenant_id', account.tenantId)
    }
    setDeleteTargetId(null)
    navigate('Business')
  }
  const createActivationCode = (packageName: SubscriptionPlan) => {
    const code = `BT-${Math.random().toString(36).slice(2, 8).toUpperCase()}`
    setActivationCodes((current) => [{ id: Date.now(), code, packageName, status: 'Available', createdAt: today }, ...current])
    return code
  }
  const consumeActivationCode = (code: string, packageName: SubscriptionPlan, businessName: string) => {
    const match = activationCodes.find((item) => item.code.toUpperCase() === code.trim().toUpperCase() && item.status === 'Available' && item.packageName === packageName)
    if (!match) return false
    setActivationCodes((current) => current.map((item) => item.id === match.id ? { ...item, status: 'Used', usedBy: businessName } : item))
    return true
  }
  const updatePackage = (name: SubscriptionPlan, updates: Partial<PackageConfig>) => setPackages((current) => current.map((item) => item.name === name ? { ...item, ...updates } : item))
  const savePackages = async () => {
    if (!supabase) { showBusinessAlert('Site admin', 'Supabase is not configured. Package changes cannot be saved.', 'Could not save packages'); return }
    if (!siteAdminSnapshotLoaded) { showBusinessAlert('Site admin', 'Live package settings are still loading. Wait a moment, then save again.', 'Packages are still loading'); return }
    const payload = { registrationRequests, activationCodes, packages }
    const updatedAt = new Date().toISOString()
    const { data: existing, error: readError } = await supabase.from('site_admin_snapshots').select('id').eq('id', 1).maybeSingle()
    if (readError) { showBusinessAlert('Site admin', `Package changes could not be saved: ${readError.message}`, 'Could not save packages'); return }
    const result = existing
      ? await supabase.from('site_admin_snapshots').update({ payload, updated_at: updatedAt }).eq('id', 1)
      : await supabase.from('site_admin_snapshots').insert({ id: 1, payload, updated_at: updatedAt })
    if (result.error) { showBusinessAlert('Site admin', `Package changes could not be saved: ${result.error.message}`, 'Could not save packages'); return }
    setAttendanceNotice('Package changes saved successfully')
  }
  const saveReviewDecision = async (key: string, decision: 'Activated' | 'Declined') => {
    const nextDecisions = { ...reviewDecisions, [key]: decision }
    setReviewDecisions(nextDecisions)
    localStorage.setItem('biztrack-review-decisions', JSON.stringify(nextDecisions))
    if (!supabase) return
    const { data } = await supabase.from('site_admin_snapshots').select('payload').eq('id', 1).maybeSingle()
    const payload = { ...(data?.payload || {}), reviewDecisions: nextDecisions }
    await supabase.from('site_admin_snapshots').upsert({ id: 1, payload, updated_at: new Date().toISOString() }, { onConflict: 'id' })
  }
  const activateRegistration = (request: RegistrationRequest, packageName: SubscriptionPlan, activationCode: string) => {
    if (!request.applicantName || !request.businessName || !request.email || !request.username || !request.password || !request.industry) return false
    if (!consumeActivationCode(activationCode, packageName, request.businessName)) return false
    createBusinessAccount({ businessName: request.businessName, ownerName: request.applicantName, email: request.email, username: request.username, password: request.password, industry: request.industry, plan: packageName })
    setRegistrationRequests((current) => current.filter((item) => item.id !== request.id))
    return true
  }
  const activateClientRegistration = async (request: RegistrationRequest) => {
    if (!request.username || !request.password || !request.businessName || !request.applicantName) return
    if (!await createBusinessAccount({ businessName: request.businessName, ownerName: request.applicantName, email: request.email || `${request.username}@biztrack.app`, username: request.username, password: request.password, industry: request.industry || 'General', plan: request.plan || packages[0]?.name || 'Starter', status: 'Active' })) return
    setRegistrationRequests((current) => current.map((item) => item.id === request.id ? { ...item, reviewStatus: 'Activated' } : item))
    await saveReviewDecision(`request:${request.id}`, 'Activated')
    setOwnerAccount(null)
    setSessionMemberId(0)
    setActiveNav('Activate business')
  }
  const declineClientRegistration = (requestId: number) => { setRegistrationRequests((current) => current.map((item) => item.id === requestId ? { ...item, reviewStatus: 'Declined' } : item)); void saveReviewDecision(`request:${requestId}`, 'Declined') }
  const showAttendanceNotice = (message: string, tone?: 'success' | 'error') => {
    const attendanceWindow = window as any
    const resolvedTone = tone || (/blocked|no registered|already|marked off|can only sign|could not|failed|error|cancelled|not configured/i.test(message) ? 'error' : 'success')
    pendingAttendanceNoticeToneId.current = null
    if (attendanceWindow.__bulkAttendanceInProgress) {
      attendanceWindow.__bulkAttendanceResponses?.push({ id: ++attendanceNoticeId.current, message, tone: resolvedTone, durationMs: resolvedTone === 'error' ? 1200 : undefined })
      if (resolvedTone === 'error') attendanceWindow.__bulkAttendanceFailures?.push(message)
      return
    }
    queueAttendanceNotice(message, resolvedTone, 3000, resolvedTone === 'error' ? activeNav : undefined)
  }
  useEffect(() => { (window as any).__attendanceSuccess = (message: string) => showAttendanceNotice(message, 'success'); return () => { delete (window as any).__attendanceSuccess } }, [attendanceNotices])
  const updatePayrollStatus = (memberIds: number[], startDate: string, endDate: string, paymentStatus: PaymentStatus, partialAmount?: number, paymentReasons: Record<number, string> = {}) => {
    const paidAt = localDateKey(new Date())
    const paymentBatchId = new Date().toISOString()
    const remainingByMember = new Map(memberIds.map((memberId) => [memberId, Math.max(0, partialAmount || 0)]))
    const carryAllocations = new Map<number, number>()
    if (paymentStatus === 'Partially paid') {
      memberIds.forEach((memberId) => {
        const member = members.find((item) => item.id === memberId)
        const carryBalance = Math.max(0, member?.payrollCarryBalance || 0)
        const allocation = Math.min(carryBalance, remainingByMember.get(memberId) || 0)
        carryAllocations.set(memberId, allocation)
        remainingByMember.set(memberId, (remainingByMember.get(memberId) || 0) - allocation)
      })
    }
    setAttendance((current) => {
      const partialAllocations = new Map<AttendanceEntry, number>()
      if (paymentStatus === 'Partially paid') {
        const eligibleEntries = current.filter((entry) => memberIds.includes(entry.memberId) && entry.checkOut !== '—' && isWithinDateRange(entry.date, startDate, endDate) && entry.paymentStatus !== 'Paid').sort((first, second) => first.date.localeCompare(second.date))
        eligibleEntries.forEach((entry) => {
          const remainingPayment = remainingByMember.get(entry.memberId) || 0
          if (remainingPayment <= 0) return
          const member = members.find((item) => item.id === entry.memberId)
          if (!member) return
          const earned = entry.payRate ?? member.payRate
          const balance = Math.max(0, earned - paymentReceivedForEntry(entry, member))
          const allocation = Math.min(balance, remainingPayment)
          if (allocation > 0) {
            partialAllocations.set(entry, allocation)
            remainingByMember.set(entry.memberId, remainingPayment - allocation)
          }
        })
      }
      return current.map((entry) => {
        const inScope = memberIds.includes(entry.memberId) && entry.checkOut !== '—' && isWithinDateRange(entry.date, startDate, endDate)
        const currentStatus = entry.paymentStatus ?? 'Pending'
        if (!inScope || !canTransitionPaymentStatus(currentStatus, paymentStatus)) return entry
        const member = members.find((item) => item.id === entry.memberId)
        if (paymentStatus === 'Paid' && member) {
          const earned = entry.payRate ?? member.payRate
          const amount = Math.max(0, earned - paymentReceivedForEntry(entry, member))
          const paymentHistory = amount > 0 ? [...(entry.paymentHistory || []), { id: `${paymentBatchId}-${entry.memberId}-${entry.date}-${entry.checkIn}`, date: paidAt, amount, reason: paymentReasons[entry.memberId]?.trim() || 'Payroll payment', status: 'Paid' as const, balanceRemaining: 0, paymentBatchId }] : entry.paymentHistory
          return { ...entry, paymentStatus, paymentReceived: earned, paymentHistory, paidAt, paymentBatchId }
        }
        const allocation = partialAllocations.get(entry)
        if (paymentStatus === 'Partially paid' && allocation && member) {
          const earned = entry.payRate ?? member.payRate
          const paymentReceived = paymentReceivedForEntry(entry, member) + allocation
          const nextStatus = paymentReceived >= earned ? 'Paid' : 'Partially paid'
          const paymentHistory = [...(entry.paymentHistory || []), { id: `${paymentBatchId}-${entry.memberId}-${entry.date}-${entry.checkIn}`, date: paidAt, amount: allocation, reason: paymentReasons[entry.memberId]?.trim() || 'Payroll payment', status: nextStatus, balanceRemaining: Math.max(0, earned - paymentReceived), paymentBatchId }]
          return { ...entry, paymentStatus: nextStatus, paymentReceived, paymentHistory, paidAt, paymentBatchId }
        }
        return paymentStatus === 'Pending' || paymentStatus === 'On hold' ? { ...entry, paymentStatus } : entry
      })
    })
    setCasualEarnings((current) => current.map((earning) => {
      const inScope = memberIds.includes(earning.memberId) && isWithinDateRange(earning.date, startDate, endDate)
      if (!inScope || !canTransitionPaymentStatus(earning.paymentStatus ?? 'Pending', paymentStatus)) return earning
      if (paymentStatus === 'Paid') {
        const amount = Math.max(0, earning.amount - earning.paymentReceived)
        const paymentHistory = amount > 0 ? [...(earning.paymentHistory || []), { id: `${paymentBatchId}-${earning.id}`, date: paidAt, amount, reason: paymentReasons[earning.memberId]?.trim() || 'Payroll payment', status: 'Paid' as const, balanceRemaining: 0, paymentBatchId }] : earning.paymentHistory
        return { ...earning, paymentStatus, paymentReceived: earning.amount, paymentHistory, paidAt, paymentBatchId }
      }
      return paymentStatus === 'Pending' || paymentStatus === 'On hold' ? { ...earning, paymentStatus } : earning
    }))
    if (paymentStatus === 'Paid' || paymentStatus === 'Partially paid') {
      setMembers((current) => current.map((member) => {
        if (!memberIds.includes(member.id) || !(member.payrollCarryBalance || 0)) return member
        const remaining = paymentStatus === 'Paid' ? 0 : Math.max(0, (member.payrollCarryBalance || 0) - (carryAllocations.get(member.id) || 0))
        const amount = paymentStatus === 'Paid' ? member.payrollCarryBalance || 0 : carryAllocations.get(member.id) || 0
        const balanceSourceTerms = member.payrollCarryPayTerms || (member.payTerms === 'Casual' ? 'Per shift' : 'Casual')
        const paymentHistory = amount > 0 ? [...(member.payrollPaymentHistory || []), { id: `${paymentBatchId}-${member.id}-carry`, date: paidAt, amount, reason: paymentReasons[member.id]?.trim() || 'Payroll payment', status: amount >= (member.payrollCarryBalance || 0) ? 'Paid' as const : 'Partially paid' as const, balanceRemaining: remaining, balanceSourceTerms, paymentBatchId }] : member.payrollPaymentHistory
        return { ...member, payrollCarryBalance: remaining, payrollCarryPayTerms: remaining > 0 ? balanceSourceTerms : undefined, payrollPaymentHistory: paymentHistory }
      }))
    }
    markChanged()
  }
  const recordCasualPartialPayment = (memberId: number, startDate: string, endDate: string, amount: number, reason = '') => {
    const member = members.find((item) => item.id === memberId)
    const carryBalance = Math.max(0, member?.payrollCarryBalance || 0)
    const carryPayment = Math.min(carryBalance, amount)
    let remaining = amount - carryPayment
    const paidAt = localDateKey(new Date())
    const paymentBatchId = new Date().toISOString()
    if (carryPayment > 0) setMembers((current) => current.map((item) => {
      if (item.id !== memberId) return item
      const remainingCarry = Math.max(0, (item.payrollCarryBalance || 0) - carryPayment)
      const balanceSourceTerms = item.payrollCarryPayTerms || (member?.payTerms === 'Casual' ? 'Per shift' : 'Casual')
      return { ...item, payrollCarryBalance: remainingCarry, payrollCarryPayTerms: remainingCarry > 0 ? balanceSourceTerms : undefined, payrollPaymentHistory: [...(item.payrollPaymentHistory || []), { id: `${paymentBatchId}-${memberId}-carry`, date: paidAt, amount: carryPayment, reason: reason.trim() || 'Payroll payment', status: carryPayment >= carryBalance ? 'Paid' as const : 'Partially paid' as const, balanceRemaining: Math.max(0, carryBalance - carryPayment), balanceSourceTerms, paymentBatchId }] }
    }))
    setCasualEarnings((current) => {
      const eligible = current.filter((earning) => earning.memberId === memberId && earning.paymentStatus !== 'Paid' && isWithinDateRange(earning.date, startDate, endDate)).sort((first, second) => first.date.localeCompare(second.date))
      const allocations = new Map<number, number>()
      eligible.forEach((earning) => {
        if (remaining <= 0) return
        const balance = Math.max(0, earning.amount - earning.paymentReceived)
        const allocation = Math.min(balance, remaining)
        if (allocation > 0) { allocations.set(earning.id, allocation); remaining -= allocation }
      })
      return current.map((earning) => {
        const allocation = allocations.get(earning.id)
        if (!allocation) return earning
        const paymentReceived = earning.paymentReceived + allocation
        const paymentStatus = paymentReceived >= earning.amount ? 'Paid' : 'Partially paid'
        const paymentHistory = [...(earning.paymentHistory || []), { id: `${paymentBatchId}-${earning.id}`, date: paidAt, amount: allocation, reason: reason.trim() || 'Payroll payment', status: paymentStatus, balanceRemaining: Math.max(0, earning.amount - paymentReceived), paymentBatchId }]
        return { ...earning, paymentReceived, paymentStatus, paymentHistory, reason: paymentStatus === 'Paid' && reason.trim() ? reason.trim() : earning.reason, paidAt, paymentBatchId }
      })
    })
    markChanged()
  }
  useEffect(() => { (window as any).__biztrackUpdatePayrollStatus = updatePayrollStatus; (window as any).__biztrackDeductions = deductions.filter((deduction) => !deduction.archived) }, [attendance, casualEarnings, deductions, members])
  const login = async (memberId: number, enteredPassword?: string) => {
    if (memberId < 0 && ownerAccount && isSupabaseConfigured) {
      if (!(await ensureOwnerTenantSession(ownerAccount.username, enteredPassword || ownerAccount.password, ownerAccount.tenantId))) return false
      setWorkspaceReloadKey((current) => current + 1)
    }
    setSessionMemberId(memberId)
    if (ownerAccount) saveRefreshSession({ owner: ownerAccount, memberId, path: window.location.pathname })
    const firstAssignedPage = memberId > 0 ? resolveWorkerLandingPage(memberId, 'Overview') : 'Overview'
    navigate(firstAssignedPage, memberId)
    return true
  }
  const gatedMarkMemberAttendance = async (memberId: number, status: 'Present' | 'Absent') => {
    return markMemberAttendance(memberId, status, biometricSignIn, 'Sign in')
  }
  const gatedMarkMemberSignOut = async (memberId: number) => {
    return markMemberSignOut(memberId)
  }
  const verifyPayrollPayment = async (memberId: number) => {
    if (!(await requireBiometric(memberId, biometricPayroll, 'mark payment as paid'))) return false
    if (biometricPayroll) await recordBiometricProof(memberId, 'payroll')
    return true
  }
  ;(window as any).__biztrackVerifyPayrollPayment = verifyPayrollPayment
  const loginBusinessAccount = async (account: BusinessAccount, memberId = -1, access?: AccessArea[], ownerPassword?: string, ownerVerified = false, initialSnapshot?: Partial<WorkspaceSnapshot>) => {
    const workspaceOwner = { name: account.ownerName, username: account.username, password: account.password, business: account.businessName, tenantId: account.tenantId, industry: account.industry, plan: account.plan }
    if (memberId <= 0 && isSupabaseConfigured && !ownerVerified && !(await ensureOwnerTenantSession(workspaceOwner.username, ownerPassword || workspaceOwner.password, workspaceOwner.tenantId))) return false
    let remoteSnapshot = initialSnapshot
    let canonicalBusinessName = workspaceOwner.business
    if (!remoteSnapshot && isSupabaseConfigured && supabase && workspaceOwner.tenantId) {
      const { data: snapshotData } = await supabase.from('workspace_snapshots').select('payload').eq('tenant_id', workspaceOwner.tenantId).maybeSingle()
      remoteSnapshot = snapshotData?.payload as Partial<WorkspaceSnapshot> | undefined
    }
    const verifiedWorkspaceOwner = { ...workspaceOwner, business: canonicalBusinessName }
    setOwnerAccount(verifiedWorkspaceOwner)
    if (memberId <= 0) void persistSharedWorkspaceSession({ username: verifiedWorkspaceOwner.username, password: verifiedWorkspaceOwner.password, tenantId: verifiedWorkspaceOwner.tenantId || '', businessName: verifiedWorkspaceOwner.business, ownerName: verifiedWorkspaceOwner.name })
    if (access) setAccessByMember((current) => ({ ...current, [memberId]: normalizeAccessAreas(access) }))
    if (remoteSnapshot) {
      if ('members' in remoteSnapshot) setMembers((remoteSnapshot.members || []).map((member, index) => normalizeMember(member, index, workspaceOwner.tenantId)))
      if ('departmentList' in remoteSnapshot) setDepartmentList(remoteSnapshot.departmentList || [])
      if ('attendance' in remoteSnapshot) setAttendance(remoteSnapshot.attendance || [])
      setCasualEarnings(Array.isArray(remoteSnapshot.casualEarnings) ? remoteSnapshot.casualEarnings : [])
      if ('sales' in remoteSnapshot) setSales(remoteSnapshot.sales || [])
      if ('salesHistory' in remoteSnapshot) setSalesHistory(remoteSnapshot.salesHistory || [])
      if ('deductions' in remoteSnapshot) setDeductions(remoteSnapshot.deductions || [])
      if ('expenses' in remoteSnapshot) setExpenses(remoteSnapshot.expenses || [])
      if ('stockMovements' in remoteSnapshot) setStockMovements(remoteSnapshot.stockMovements || [])
      if ('inventory' in remoteSnapshot) setInventory(remoteSnapshot.inventory || [])
      if ('storeCategories' in remoteSnapshot) setStoreCategories(remoteSnapshot.storeCategories || [])
      setDeletedCategories(Array.isArray(remoteSnapshot.deletedCategories) ? remoteSnapshot.deletedCategories : [])
      if ('categoryUnits' in remoteSnapshot) setCategoryUnits(remoteSnapshot.categoryUnits || {})
      if ('categoryThresholds' in remoteSnapshot) setCategoryThresholds(remoteSnapshot.categoryThresholds || {})
      if ('currency' in remoteSnapshot) setCurrency(remoteSnapshot.currency || 'KES')
      setPaymentRegisterFooter(typeof remoteSnapshot.paymentRegisterFooter === 'string' ? remoteSnapshot.paymentRegisterFooter : defaultPaymentRegisterFooter)
      setPayrollReportOrder(remoteSnapshot.payrollReportOrder === 'deductions-bottom' || remoteSnapshot.payrollReportOrder === 'deductions-top' ? remoteSnapshot.payrollReportOrder : defaultPayrollReportOrder)
      if ('paymentMethods' in remoteSnapshot) setPaymentMethods(remoteSnapshot.paymentMethods || [])
      if (remoteSnapshot.strictSignIn !== undefined) setStrictSignIn(remoteSnapshot.strictSignIn)
      if (remoteSnapshot.allowMultipleDailyShifts !== undefined) setAllowMultipleDailyShifts(remoteSnapshot.allowMultipleDailyShifts)
      if (remoteSnapshot.biometricSignIn !== undefined) setBiometricSignIn(remoteSnapshot.biometricSignIn)
      if (remoteSnapshot.biometricSignOut !== undefined) setBiometricSignOut(remoteSnapshot.biometricSignOut)
      if (remoteSnapshot.biometricMark !== undefined) setBiometricMark(remoteSnapshot.biometricMark)
      if (remoteSnapshot.biometricPayroll !== undefined) setBiometricPayroll(remoteSnapshot.biometricPayroll)
      if (remoteSnapshot.defaultSignIn) setDefaultSignIn(remoteSnapshot.defaultSignIn)
      if (remoteSnapshot.defaultSignOut) setDefaultSignOut(remoteSnapshot.defaultSignOut)
      if (remoteSnapshot.lateSignIn) setLateSignIn(remoteSnapshot.lateSignIn)
      if (remoteSnapshot.earlySignOut) setEarlySignOut(remoteSnapshot.earlySignOut)
      if (remoteSnapshot.accessByMember) setAccessByMember(normalizeAccessByMember(remoteSnapshot.accessByMember))
    }
    setWorkspaceName(canonicalBusinessName)
    setSessionMemberId(memberId)
    saveRefreshSession({ owner: verifiedWorkspaceOwner, memberId, path: window.location.pathname })
    const firstAssignedPage = memberId > 0 ? (access || []).find((page) => uniqueAccessAreas.includes(page)) : 'Overview'
    setRemoteWorkspaceLoaded(true)
    navigate(firstAssignedPage || 'Overview', memberId)
  }
  const clearAppSession = () => {
    setOwnerAccount(null)
    setSessionMemberId(0)
    setSiteAdminSession(false)
    setSiteAdminSnapshotLoaded(false)
    saveRefreshSession(null)
    window.history.replaceState({}, '', pagePaths['Sign in'])
    setActiveNav('Sign in')
  }
  const logout = () => {
    if (supabase) void supabase.auth.signOut()
    clearAppSession()
  }
  const logoutRef = useRef(logout)
  logoutRef.current = logout
  useEffect(() => {
    if (!ownerAccount && sessionMemberId === 0 && !siteAdminSession) return
    const idleLimit = DEFAULT_SESSION_IDLE_TIMEOUT_MS
    let idleTimer = 0
    const resetIdleTimer = () => {
      window.clearTimeout(idleTimer)
      idleTimer = window.setTimeout(() => logoutRef.current(), idleLimit)
    }
    const activityEvents = ['pointerdown', 'pointermove', 'keydown', 'touchstart', 'wheel'] as const
    activityEvents.forEach((eventName) => window.addEventListener(eventName, resetIdleTimer, { passive: true }))
    window.addEventListener('scroll', resetIdleTimer, { passive: true })
    resetIdleTimer()
    return () => {
      window.clearTimeout(idleTimer)
      activityEvents.forEach((eventName) => window.removeEventListener(eventName, resetIdleTimer))
      window.removeEventListener('scroll', resetIdleTimer)
    }
  }, [ownerAccount, sessionMemberId, siteAdminSession])
  useEffect(() => {
    const handleStorage = (event: StorageEvent) => {
      if ((event.key === refreshSessionKey || event.key === null) && !event.newValue) clearAppSession()
    }
    window.addEventListener('storage', handleStorage)
    const authSubscription = supabase?.auth.onAuthStateChange((event) => {
      if (event === 'SIGNED_OUT') clearAppSession()
    }).data.subscription
    return () => {
      window.removeEventListener('storage', handleStorage)
      authSubscription?.unsubscribe()
    }
  }, [])
  useEffect(() => {
    if (!ownerAccount || sessionMemberId === 0 || siteAdminSession) return
    let cancelled = false
    let refreshInFlight = false
    const checkBusinessAccess = async () => {
      if (refreshInFlight) return
      refreshInFlight = true
      try {
        if (isSupabaseConfigured && supabase) {
          const { data, error } = await supabase
            .from('business_accounts')
            .select('status,next_billing')
            .eq('tenant_id', tenantId)
            .maybeSingle()
          if (cancelled || error) return
          if (!data || data.status !== 'Active' || (data.next_billing && data.next_billing < today)) logout()
        } else {
          const accounts = readStoredBusinessAccounts()
          const account = accounts.find((item) => item.tenantId === tenantId)
          if (!account || businessRequiresActivation(account)) logout()
        }
      } catch {
        // Keep the current session if the status check cannot reach Supabase.
      } finally {
        refreshInFlight = false
      }
    }
    const refreshWhenVisible = () => { if (document.visibilityState === 'visible') void checkBusinessAccess() }
    void checkBusinessAccess()
    const timer = window.setInterval(() => {
      if (navigator.onLine && document.visibilityState === 'visible') void checkBusinessAccess()
    }, 60_000)
    window.addEventListener('focus', refreshWhenVisible)
    document.addEventListener('visibilitychange', refreshWhenVisible)
    const handleBusinessAccountsStorage = (event: StorageEvent) => {
      if (isSupabaseConfigured || event.key !== businessAccountsStorageKey || !event.newValue) return
      try {
        const accounts = JSON.parse(event.newValue) as BusinessAccount[]
        const account = accounts.find((item) => item.tenantId === tenantId)
        if (!account || businessRequiresActivation(account)) logout()
      } catch {
        // Ignore malformed storage updates and keep the current session.
      }
    }
    window.addEventListener('storage', handleBusinessAccountsStorage)
    return () => {
      cancelled = true
      window.clearInterval(timer)
      window.removeEventListener('focus', refreshWhenVisible)
      document.removeEventListener('visibilitychange', refreshWhenVisible)
      window.removeEventListener('storage', handleBusinessAccountsStorage)
    }
  }, [ownerAccount, sessionMemberId, siteAdminSession, tenantId])
  useEffect(() => {
    if (!ownerAccount || !isSupabaseConfigured || !supabase || tenantId === 'workspace' || sessionMemberId <= 0) return
    let cancelled = false
    let refreshInFlight = false
    const refreshRemotePermissions = async () => {
      if (refreshInFlight) return
      refreshInFlight = true
      try {
        const { data, error } = await supabase
          .from('workspace_snapshots')
          .select('payload')
          .eq('tenant_id', tenantId)
          .maybeSingle()
        if (cancelled || error || !data?.payload) return
        const snapshot = data.payload as Partial<WorkspaceSnapshot>
        const nextAccessByMember = snapshot.accessByMember ? normalizeAccessByMember(snapshot.accessByMember) : {}
        setAccessByMember((current) => {
          const currentValue = JSON.stringify(current)
          const nextValue = JSON.stringify(nextAccessByMember)
          return currentValue === nextValue ? current : nextAccessByMember
        })
        const grantedPages = normalizeAccessAreas(nextAccessByMember[sessionMemberId] || [])
        if (!grantedPages.length) {
          const landingPage = resolveWorkerLandingPage(sessionMemberId, 'Overview')
          const fallbackPath = grantPagePaths[landingPage] || pagePaths['Overview']
          if (window.location.pathname !== fallbackPath) {
            window.history.replaceState({}, '', fallbackPath)
            setActiveNav(landingPage)
          }
          return
        }
        const currentPage = activeNav
        const isRollAction = ['Worker sign-in', 'Worker checkout'].includes(currentPage)
        const hasDirectAccess = grantedPages.some((page) => page.toLowerCase() === currentPage.toLowerCase())
        const hasRollAccess = grantedPages.some((page) => page.toLowerCase() === 'roll')
        if (!hasDirectAccess && !(hasRollAccess && isRollAction)) {
          const landingPage = resolveWorkerLandingPage(sessionMemberId, 'Overview')
          const fallbackPath = grantPagePaths[landingPage] || pagePaths['Overview']
          if (window.location.pathname !== fallbackPath) {
            window.history.replaceState({}, '', fallbackPath)
            setActiveNav(landingPage)
          }
        }
      } catch {
        // Ignore remote permission refresh failures and keep the current session stable.
      } finally {
        refreshInFlight = false
      }
    }
    const refreshWhenVisible = () => { if (document.visibilityState === 'visible') void refreshRemotePermissions() }
    void refreshRemotePermissions()
    const timer = window.setInterval(() => {
      if (navigator.onLine && document.visibilityState === 'visible') void refreshRemotePermissions()
    }, 30_000)
    window.addEventListener('focus', refreshWhenVisible)
    document.addEventListener('visibilitychange', refreshWhenVisible)
    return () => {
      cancelled = true
      window.clearInterval(timer)
      window.removeEventListener('focus', refreshWhenVisible)
      document.removeEventListener('visibilitychange', refreshWhenVisible)
    }
  }, [ownerAccount, tenantId, sessionMemberId, activeNav, isSupabaseConfigured, supabase])
  useEffect(() => {
    if (!platformSettings.maintenanceMode || siteAdminSession) return
    setSessionMemberId(0)
    setOwnerAccount(null)
    saveRefreshSession(null)
  }, [platformSettings.maintenanceMode, siteAdminSession])
  const startSiteAdminSession = () => { setSiteAdminSession(true); saveRefreshSession({ siteAdmin: true, path: window.location.pathname }) }
  const endSiteAdminSession = () => { setSiteAdminSession(false); setSiteAdminSnapshotLoaded(false); if (supabase) void supabase.auth.signOut(); saveRefreshSession(null) }
  const normalizeAccessPage = (page: string) => {
    if (!page) return 'Overview'
    if (page === 'Dashboard' || page === 'Admin' || page === 'Master') return 'Overview'
    return page
  }
  const canAccess = (page: string) => {
    if (sessionMemberId === -1) return true
    if (sessionMemberId === 0) return ['Welcome', 'Register', 'Terms', 'Sign in'].includes(page)
    const normalizedPage = normalizeAccessPage(page)
    const assignedPages = normalizeAccessAreas(accessByMember[sessionMemberId] || [])
    if (!assignedPages.length) return false
    if (normalizedPage === 'Overview') return true
    const isPublicPage = ['Welcome', 'Register', 'FAQs', 'Terms', 'Sign in'].includes(normalizedPage)
    const hasDirectAccess = assignedPages.some((assignedPage) => assignedPage.toLowerCase() === normalizedPage.toLowerCase())
    const isRollAction = ['Worker sign-in', 'Worker checkout'].includes(normalizedPage)
    const hasRollAccess = assignedPages.some((assignedPage) => assignedPage.toLowerCase() === 'roll')
    return isPublicPage || hasDirectAccess || (hasRollAccess && isRollAction)
  }
  ;(window as any).__biztrackVisibleWorkspacePages = sessionMemberId === -1 ? sidebarGroups.flatMap((group) => group.links) : accessByMember[sessionMemberId] || []
  const dashboardName = siteAdminSession ? 'Site admin' : sessionMemberId === -1 ? ownerAccount?.name || 'Owner' : members.find((member) => member.id === sessionMemberId)?.name || 'Member'
  const dashboardDepartment = siteAdminSession ? 'Platform workspace' : sessionMemberId === -1 ? 'Owner' : members.find((member) => member.id === sessionMemberId)?.department || 'Unassigned'
  const businessNameVerified = !isSupabaseConfigured || tenantId === 'workspace' || (remoteWorkspaceLoaded && loadedTenantId === tenantId)
  const businessName = businessNameVerified ? workspaceName || ownerAccount?.business || 'Your workspace' : 'Your workspace'
  ;(window as any).__biztrackHelpOwner = ownerAccount
  ;(window as any).__biztrackHelpMembers = members
  ;(window as any).__biztrackHelpSessionMemberId = sessionMemberId
  const currentBusinessAccount = ownerAccount ? businessAccounts.find((account) => account.username.toLowerCase() === ownerAccount.username.toLowerCase() || (ownerAccount.tenantId && account.tenantId === ownerAccount.tenantId)) : undefined
  ;(window as any).__biztrackDeductions = deductions.filter((deduction) => !deduction.archived)
  ;(window as any).__biztrackWhatsappNumber = platformSettings.whatsappNumber
  useEffect(() => {
    if (sessionMemberId <= 0) return
    const grantedPages = normalizeAccessAreas(accessByMember[sessionMemberId] || [])
    if (!grantedPages.length) return
    const landingPage = resolveWorkerLandingPage(sessionMemberId, 'Overview')
    const isGrantRoute = window.location.pathname.startsWith('/grant/') || window.location.pathname.startsWith('/master/')
    if (!isGrantRoute) {
      const target = grantPagePaths[landingPage] || pagePaths['Overview']
      if (window.location.pathname !== target) window.history.replaceState({}, '', target)
      if (activeNav !== landingPage) setActiveNav(landingPage)
      return
    }
    if (!canAccess(activeNav)) {
      const target = grantPagePaths[landingPage] || pagePaths['Overview']
      if (window.location.pathname !== target) window.history.replaceState({}, '', target)
      if (activeNav !== landingPage) setActiveNav(landingPage)
      return
    }
    const grantPath = grantPagePaths[activeNav]
    if (grantPath && window.location.pathname !== grantPath) window.history.replaceState({}, '', grantPath)
  }, [activeNav, sessionMemberId, accessByMember])
  useEffect(() => {
    const isPublicPage = ['Welcome', 'Register', 'FAQs', 'Terms', 'Privacy', 'Sign in', 'Admin sign in', 'Register site admin'].includes(activeNav)
    const isSiteAdminPage = ['Admin', 'Business', 'Users', 'Register a new business', 'Activation codes', 'Packages', 'Activate business', 'Admin settings', 'Delete'].includes(activeNav) || window.location.pathname.startsWith('/admin')
    const verifiedBusinessWorkspace = Boolean(ownerAccount && sessionMemberId !== 0 && remoteWorkspaceLoaded && loadedTenantId === tenantId)
    document.title = siteAdminSession || isSiteAdminPage || isPublicPage || !verifiedBusinessWorkspace ? 'BizTrack' : ownerAccount.business || businessName || 'BizTrack'
  }, [activeNav, businessName, loadedTenantId, ownerAccount, remoteWorkspaceLoaded, sessionMemberId, siteAdminSession, tenantId])
  useEffect(() => {
    document.querySelectorAll('.app-shell .sidebar .workspace-switcher strong').forEach((element) => { const [first, second] = businessNameParts(businessName); element.replaceChildren(Object.assign(document.createElement('span'), { textContent: first }), Object.assign(document.createElement('span'), { textContent: second })) })
    const workspaceDot = document.querySelector('.app-shell .sidebar .workspace-dot')
    if (workspaceDot) workspaceDot.textContent = businessName.charAt(0).toUpperCase()
    document.querySelectorAll('.app-shell .sidebar-footer').forEach((footer) => { const label = Array.from(footer.children).find((child) => child.textContent?.trim() === 'Help center') as HTMLElement | undefined; if (!label || label.closest('.help-link')) return; const link = document.createElement('a'); link.className = 'help-link'; link.target = '_blank'; link.rel = 'noopener noreferrer'; link.href = whatsappHelpUrl(businessName, ownerAccount, members, sessionMemberId, platformSettings.whatsappNumber); if (!link.href) { link.removeAttribute('target'); link.addEventListener('click', (event) => { event.preventDefault(); showBusinessAlert(businessName, 'Help center WhatsApp number is not configured.', 'Support unavailable') }) } label.replaceWith(link); link.append(document.querySelector('.help-mark')?.cloneNode(true) || '?', document.createTextNode('Help center')) })
  }, [businessName, activeNav, ownerAccount, members, sessionMemberId, platformSettings.whatsappNumber])
  useEffect(() => {
    if (activeNav !== 'Sales') return
    const table = document.querySelector('.sales-layout .team-panel .table-wrap')
    const rows = Array.from(table?.querySelectorAll('tbody tr') || []) as HTMLTableRowElement[]
    if (!table || table.querySelector('.sales-table-filters')) return
    const filters = document.createElement('div')
    filters.className = 'sales-table-filters'
    const method = document.createElement('select')
    method.className = 'filter-button'
    method.setAttribute('aria-label', 'Filter payment method')
    ;['All methods', 'Cash', 'Credit', 'Mobile money'].forEach((value) => method.add(new Option(value, value)))
    const date = document.createElement('input')
    date.className = 'filter-button'
    date.type = 'date'
    date.setAttribute('aria-label', 'Filter sales date')
    const cashier = document.createElement('input')
    cashier.className = 'filter-button'
    cashier.type = 'search'
    cashier.placeholder = 'Search cashier'
    cashier.setAttribute('aria-label', 'Search cashier')
    filters.append(method, date, cashier)
    table.prepend(filters)
    const applyFilter = () => {
      const search = cashier.value.trim().toLowerCase()
      rows.forEach((row) => {
        const cells = Array.from(row.cells).map((cell) => cell.textContent?.trim() || '')
        const matchesMethod = method.value === 'All methods' || cells[1] === method.value
        const matchesDate = !date.value || cells[2] === date.value
        const matchesCashier = !search || cells[4].toLowerCase().includes(search)
        row.hidden = !(matchesMethod && matchesDate && matchesCashier)
      })
    }
    method.addEventListener('change', applyFilter)
    date.addEventListener('change', applyFilter)
    cashier.addEventListener('input', applyFilter)
    return () => { method.removeEventListener('change', applyFilter); date.removeEventListener('change', applyFilter); cashier.removeEventListener('input', applyFilter); filters.remove() }
  }, [activeNav, sales, salesHistory])
  useLayoutEffect(() => {
    if (activeNav !== 'Add member') return
    const form = document.querySelector<HTMLFormElement>('.page-content > form.member-form')
    const grid = form?.querySelector('.form-grid')
    const rateInput = form?.querySelector<HTMLInputElement>('input[name="payRate"]')
    const rateLabel = rateInput?.closest('label')
    const frequencySelect = form?.querySelector<HTMLSelectElement>('select[name="payFrequency"]')
    const frequencyLabel = frequencySelect?.closest('label')
    if (!form || !grid || !rateInput || !rateLabel || !frequencySelect || !frequencyLabel) return
    const termsLabel = document.createElement('label')
    termsLabel.innerHTML = '<span>Pay terms *</span>'
    const termsSelect = document.createElement('select')
    termsSelect.name = 'payTerms'
    termsSelect.required = true
    termsSelect.add(new Option('Amount per shift', 'Per shift'))
    termsSelect.add(new Option('Casual', 'Casual'))
    termsLabel.appendChild(termsSelect)
    grid.insertBefore(termsLabel, rateLabel)
    const fields = document.createElement('div')
    fields.className = 'pay-terms-fields is-visible'
    const inner = document.createElement('div')
    inner.className = 'pay-terms-fields-inner'
    grid.insertBefore(fields, rateLabel)
    inner.append(rateLabel, frequencyLabel)
    fields.appendChild(inner)
    const rateCaption = rateLabel.querySelector('span')
    if (rateCaption) rateCaption.textContent = 'Amount per complete shift *'
    const formHint = form.querySelector('.form-heading p')
    if (formHint) formHint.textContent = 'Choose Casual for individual earnings or an amount per completed shift.'
    const accountSection = form.querySelector<HTMLElement>('.account-access-section')
    const updateTerms = () => {
      const showShiftFields = termsSelect.value === 'Per shift'
      const casual = !showShiftFields
      fields.classList.toggle('is-visible', showShiftFields)
      fields.setAttribute('aria-hidden', String(!showShiftFields))
      fields.toggleAttribute('inert', !showShiftFields)
      rateInput.required = showShiftFields
      rateInput.disabled = !showShiftFields
      frequencySelect.required = showShiftFields
      frequencySelect.disabled = !showShiftFields
      if (accountSection) {
        accountSection.hidden = casual
        accountSection.setAttribute('aria-hidden', String(casual))
        accountSection.toggleAttribute('inert', casual)
        accountSection.querySelectorAll<HTMLInputElement>('input').forEach((input) => {
          if (casual && input.type === 'checkbox') input.checked = false
          input.disabled = casual
        })
      }
      if (!showShiftFields) rateInput.value = ''
    }
    termsSelect.addEventListener('change', updateTerms)
    updateTerms()
    return () => { termsSelect.removeEventListener('change', updateTerms); termsLabel.remove() }
  }, [activeNav])
  useEffect(() => {
    if (activeNav !== 'Team' || !selectingExistingAccount) return
    const panel = document.querySelector('.team-panel')
    const table = panel?.querySelector('table')
    const addButton = panel?.querySelector('.team-panel-footer button') as HTMLButtonElement | null
    if (!panel || !table || !addButton) return
    addButton.disabled = true
    addButton.textContent = 'Add member disabled'
    const header = table.querySelector('thead tr')
    const rows = Array.from(table.querySelectorAll('tbody tr'))
    const selectHeader = document.createElement('th')
    selectHeader.textContent = 'SELECT'
    header?.prepend(selectHeader)
    let selectedId: number | null = null
    rows.forEach((row) => {
      const memberId = Number(row.querySelector('td strong')?.textContent?.replace('#', ''))
      const cell = document.createElement('td')
      const input = document.createElement('input')
      input.type = 'radio'; input.name = 'permission-member'; input.setAttribute('aria-label', 'Select team member')
      input.addEventListener('change', () => { selectedId = memberId; proceed.disabled = false })
      cell.appendChild(input); row.prepend(cell)
    })
    const proceed = document.createElement('button')
    proceed.className = 'primary-button'; proceed.textContent = 'Proceed'; proceed.disabled = true
    proceed.addEventListener('click', () => {
      if (!selectedId) return
      setPermissionTargetId(selectedId)
      setSelectingExistingAccount(false)
      navigate('Permissions')
    })
    panel.querySelector('.team-panel-footer')?.appendChild(proceed)
    return () => { selectHeader.remove(); rows.forEach((row) => row.firstElementChild?.remove()); proceed.remove() }
  }, [activeNav, selectingExistingAccount])
  useEffect(() => {
    if (activeNav !== 'Permissions') return
    const headingAction = document.querySelector('.permissions-layout')?.previousElementSibling?.querySelector('.heading-actions') as HTMLElement | null
    const people = document.querySelector('.permissions-people')
    if (!people || people.querySelector('.permissions-add-account-dom')) return
    if (headingAction) headingAction.style.display = 'none'
    const button = document.createElement('button')
    button.className = 'primary-button permissions-add-account-dom'
    button.textContent = '+ Add account'
    button.addEventListener('click', () => setAccountChoiceOpen(true))
    people.appendChild(button)
    return () => button.remove()
  }, [activeNav])
  useEffect(() => {
    if (activeNav !== 'Settings') return
    const settings = document.querySelector('.settings-stack')
    if (!settings || settings.querySelector('.biometric-policy-panel')) return
    const panel = document.createElement('article')
    panel.className = 'panel member-form biometric-policy-panel'
    panel.innerHTML = `<div class="panel-heading"><div><h2>Biometric verification</h2><p>Choose which worker actions require the worker's registered device biometric.</p></div></div><div class="settings-choice-grid"><label class="settings-choice biometric-choice"><input type="checkbox" data-biometric="sign-in"><span>Worker sign-in</span></label><label class="settings-choice biometric-choice"><input type="checkbox" data-biometric="sign-out"><span>Worker sign-out</span></label><label class="settings-choice biometric-choice"><input type="checkbox" data-biometric="mark"><span>Mark selected workers</span></label><label class="settings-choice biometric-choice"><input type="checkbox" data-biometric="payroll"><span>Payroll payment</span></label></div><p class="subheading">Biometrics use your browser's secure WebAuthn prompt. Raw fingerprint data never enters Biz Track.</p>`
    settings.appendChild(panel)
    const saveButton = document.createElement('button')
    saveButton.type = 'button'
    saveButton.className = 'primary-button biometric-settings-save'
    saveButton.textContent = 'Save changes'
    saveButton.addEventListener('click', () => { void saveWorkspaceSnapshotNow() })
    panel.appendChild(saveButton)
    const controls = panel.querySelectorAll<HTMLInputElement>('input[data-biometric]')
    controls.forEach((control) => {
      const key = control.dataset.biometric
      control.checked = key === 'sign-in' ? biometricSignIn : key === 'sign-out' ? biometricSignOut : key === 'mark' ? biometricMark : biometricPayroll
      control.addEventListener('change', () => { if (key === 'sign-in') setBiometricSignIn(control.checked); if (key === 'sign-out') setBiometricSignOut(control.checked); if (key === 'mark') setBiometricMark(control.checked); if (key === 'payroll') setBiometricPayroll(control.checked); markChanged() })
    })
    return () => panel.remove()
  }, [activeNav, biometricSignIn, biometricSignOut, biometricMark, biometricPayroll, workspaceName, tenantId])
  /*
    <main className="main-content"><header className="topbar"><div className="breadcrumbs"><span>Workspace</span><b>/</b><strong>{activeNav}</strong></div><div className="top-actions"><div className={`sync-status ${isOnline ? 'online' : 'offline'}`}><span className="status-dot"></span>{syncLabel}</div><button className="icon-button" aria-label="Notifications">♧<span className="notification-dot"></span></button><div className="profile-menu"><div className="avatar avatar-olive">KA</div><span><strong>{sessionMemberId === 0 ? 'Kemi A.' : members.find((member) => member.id === sessionMemberId)?.name || 'Worker'}</strong><small>{sessionMemberId === 0 ? role : 'Worker'}</small></span><button className="text-button" onClick={logout}>Log out</button></div></div></header><div className="page-content">{activeNav === 'Login' ? <LoginPage members={members} onLogin={login} /> : !canAccess(activeNav) ? <AccessDeniedPage onBack={() => navigate('Overview')} /> : activeNav === 'Attendance' ? <AttendancePage members={members} entries={todayAttendance} /> : activeNav === 'Departments' ? <DepartmentsPage departments={departmentList} members={members} onAdd={() => navigate('Add department')} onDelete={deleteDepartment} /> : activeNav === 'Add department' ? <AddDepartmentPage onSubmit={addDepartment} onCancel={() => navigate('Departments')} /> : activeNav === 'Add member' ? <AddMemberPage departments={departmentList} defaultSignIn={defaultSignIn} defaultSignOut={defaultSignOut} onSubmit={addMember} onCancel={() => navigate('Team')} /> : activeNav === 'Team' ? <TeamPage members={members} onAdd={() => navigate('Add member')} onDelete={deleteMember} /> : activeNav === 'Payroll' ? <PayrollPage members={members} attendance={attendance} deductions={deductions} /> : activeNav === 'Sales' ? <SalesPage sales={sales} salesHistory={salesHistory} onAdd={addSale} onReset={resetSales} /> : activeNav === 'Inventory' ? <InventoryPage inventory={inventory} categories={storeCategories} onAdd={addInventoryItem} onAdjust={updateInventoryQuantity} /> : activeNav === 'Settings' ? <SettingsPage members={members} defaultSignIn={defaultSignIn} defaultSignOut={defaultSignOut} strictSignIn={strictSignIn} setStrictSignIn={setStrictSignIn} categories={storeCategories} setCategories={setStoreCategories} setDefaultSignIn={setDefaultSignIn} setDefaultSignOut={setDefaultSignOut} setMembers={setMembers} onChange={markChanged} /> : activeNav === 'Worker sign-in' ? <WorkerSignInPage members={members} entries={attendance} strictSignIn={strictSignIn} defaultSignIn={defaultSignIn} onAttendance={toggleCurrentAttendance} onMarkAttendance={markMemberAttendance} onMarkSignOut={markMemberSignOut} /> : <OverviewPage role={role} setRole={setRole} members={members} isCheckedIn={isCheckedIn} setIsCheckedIn={toggleCurrentAttendance} isOnline={isOnline} onAttendance={() => navigate('Attendance')} />}</div></main>
  */
  const addMember = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const formElement = event.currentTarget
    const form = new FormData(formElement)
    const name = String(form.get('fullName') || '').trim(); const phone = String(form.get('phone') || '').trim(); const email = workerIdNumber(String(form.get('email') || '')); const department = String(form.get('department') || departmentList[0])
    if (!name || !phone || !department) return
    const payTerms = String(form.get('payTerms') || 'Per shift') as PayTerms
    const payRate = payTerms === 'Casual' ? 0 : Number(form.get('payRate') || 0)
    const payFrequency = String(form.get('payFrequency') || 'Daily') as PayFrequency
    const signInTime = String(form.get('signInTime') || defaultSignIn)
    const signOutTime = String(form.get('signOutTime') || defaultSignOut)
    const hasAccount = payTerms !== 'Casual' && form.get('hasAccount') === 'on'
    const username = payTerms === 'Casual' ? '' : String(form.get('username') || '').trim()
    const password = payTerms === 'Casual' ? '' : String(form.get('password') || '')
    if (hasAccount && (!username || password.length < 6)) return
    if (hasAccount && members.some((member) => member.hasAccount && member.username.trim().toLowerCase() === username.trim().toLowerCase())) {
      setAttendanceNotice('That username is already assigned to a worker in this business.')
      setAttendanceNoticeTone('error')
      return
    }
    if (hasAccount && isSupabaseConfigured && supabase) {
      try {
        if (!await accountCredentialsAvailable(username, password)) {
          setAttendanceNotice('That username and password are already used by another account. Keep the username and choose a different password.')
          setAttendanceNoticeTone('error')
          return
        }
      } catch (error) {
        setAttendanceNotice(error instanceof Error ? error.message : 'Could not verify the new worker credentials.')
        setAttendanceNoticeTone('error')
        return
      }
    }
    const id = Date.now()
    const passwordHash = await hashPassword(password)
    let biometricCredentialId = ''
    const biometricRequired = biometricSignIn || biometricSignOut || biometricMark || biometricPayroll
    if (biometricRequired) {
      try {
        biometricCredentialId = await registerBiometric(id, name, workspaceName || ownerAccount?.business || 'your business', tenantId, ownerAccount ? { username: ownerAccount.username, password: ownerAccount.password } : undefined)
        await saveBiometricRecord('biometric_credentials', { tenant_id: tenantId, member_id: id, member_name: name, credential_id: biometricCredentialId, registered_at: new Date().toISOString() }, ownerAccount ? { username: ownerAccount.username, password: ownerAccount.password } : undefined)
      } catch (error) { setAttendanceNotice(error instanceof Error ? error.message : 'Biometric registration failed.'); return }
    }
    const newMember = { id, tenantId, name, username, password: passwordHash, hasAccount, joinedAt: today, biometricCredentialId, phone, email, department, role: 'Worker' as Role, initials: initialsFor(name), color: 'mint', payRate, payTerms, payFrequency, signInTime, signOutTime }
    if (hasAccount && !await saveWorkspaceSnapshotNow({ members: [...members, newMember] })) return
    setMembers((current) => [...current, newMember])
    markChanged(); formElement.reset(); navigate('Team')
  }
  const addDepartment = (name: string) => {
    const nextName = name.trim()
    if (!nextName || departmentList.some((department) => department.toLowerCase() === nextName.toLowerCase())) return
    setDepartmentList((current) => [...current, nextName]); markChanged()
  }
  const renameDepartment = (currentName: string, nextName: string) => {
    const normalizedName = nextName.trim()
    if (!normalizedName || departmentList.some((department) => department !== currentName && department.toLowerCase() === normalizedName.toLowerCase())) return false
    setDepartmentList((current) => current.map((department) => department === currentName ? normalizedName : department))
    setMembers((current) => current.map((member) => member.department === currentName ? { ...member, department: normalizedName } : member))
    markChanged()
    return true
  }
  ;(window as any).__biztrackAddDepartment = addDepartment
  ;(window as any).__biztrackRenameDepartment = renameDepartment
  const deleteDepartment = async (name: string) => {
    if (!await showBusinessConfirm(workspaceName || ownerAccount?.business || 'Your business', `Delete the ${name} department?`)) return
    setDepartmentList((current) => current.filter((department) => department !== name)); markChanged()
  }
  const addSale = (sale: Sale) => { const now = new Date(); setSales((current) => [...current, { ...sale, cashier: dashboardName, date: localDateKey(now), time: now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) }]); markChanged() }
  const deleteSale = async (id: number) => { if (!await showBusinessConfirm(businessName, 'Remove this transaction from sales history? It will remain in printed reports.')) return; setSales((current) => current.map((sale) => sale.id === id ? { ...sale, archived: true } : sale)); setSalesHistory((current) => current.map((sale) => sale.id === id ? { ...sale, archived: true } : sale)); markChanged() }
  const addDeduction = (deduction: Deduction) => { setDeductions((current) => [deduction, ...current]); markChanged() }
  const deleteDeduction = async (id: number) => { if (!await showBusinessConfirm(workspaceName || ownerAccount?.business || 'Your business', 'Remove this deduction from active payroll? It will remain in printed history.')) return; setDeductions((current) => current.map((deduction) => deduction.id === id ? { ...deduction, archived: true } : deduction)); markChanged() }
  const resetSales = async () => { if (!await showBusinessConfirm(workspaceName || ownerAccount?.business || 'Your business', 'Reset current sales? The dated history will be kept.')) return; setSalesHistory((current) => [...current, ...sales]); setSales([]); markChanged() }
  const addInventoryItem = (item: InventoryItem) => { const now = new Date(); setInventory((current) => { const existing = current.find((entry) => entry.name.toLowerCase() === item.name.toLowerCase() && entry.category === item.category && entry.unit === item.unit); const inventoryItemId = existing?.id || item.id; setStockMovements((movements) => [{ id: Date.now(), type: 'Stocked', inventoryItemId, itemName: item.name, category: item.category, quantity: item.quantity, unit: item.unit, reason: 'Stock added', date: today, time: now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) }, ...movements]); if (!existing) return [...current, { ...item, initialQuantity: item.quantity }]; return current.map((entry) => entry.id === existing.id ? { ...entry, quantity: entry.quantity + item.quantity, initialQuantity: (entry.initialQuantity ?? entry.quantity) + item.quantity, reorderAt: item.reorderAt } : entry) }); markChanged(); setAttendanceNotice(`${item.name} stock added successfully`); navigate('Overview') }
  const updateInventoryQuantity = (id: number, amount: number) => { setInventory((current) => current.map((item) => item.id === id ? { ...item, quantity: Math.max(0, item.quantity + amount) } : item)); markChanged() }
  const addExpense = (expense: Expense) => { const item = inventory.find((entry) => entry.id === expense.inventoryItemId); if (!item || expense.quantity > item.quantity) { if (item) showBusinessAlert(businessName, ` ${item.name} has ${item.quantity} ${item.unit} remaining, but ${expense.quantity} ${item.unit} was entered.`); return } setExpenses((current) => [expense, ...current]); setStockMovements((current) => [{ ...expense, type: 'Used' }, ...current]); setInventory((current) => current.map((entry) => entry.id === expense.inventoryItemId ? { ...entry, quantity: entry.quantity - expense.quantity } : entry)); markChanged(); setAttendanceNotice(`${expense.itemName} usage recorded successfully`); navigate('Overview') }
  const deleteMember = async (id: number) => {
    const member = members.find((item) => item.id === id)
    if (!member) return
    if (supabase && tenantId) {
      const cleanup = supabase.rpc('delete_biometric_credential', { requested_tenant_id: tenantId, requested_member_id: id, requested_credential_id: member.biometricCredentialId || '' })
      const { error } = await cleanup
      if (error) { setAttendanceNotice(`Could not remove ${member.name}'s biometric record. Run the latest Supabase SQL, then try again.`); return }
    }
    setMembers((current) => current.map((item) => item.id === id ? { ...item, archived: true, hasAccount: false } : item)); markChanged()
  }
  const updateMember = (id: number, updates: Partial<Member> & { effectiveAt?: string; includeTodayShift?: boolean }) => {
    const { effectiveAt, includeTodayShift, ...changes } = updates
    setMembers((current) => current.map((member) => {
      if (member.id !== id) return member
      if (effectiveAt && effectiveAt > new Date().toISOString()) return { ...member, scheduledUpdate: { effectiveAt, changes, includeTodayShift } }
      return applyMemberUpdate(member, changes, effectiveAt || new Date().toISOString(), attendance, casualEarnings, deductions, includeTodayShift ?? true)
    }))
    if (includeTodayShift && changes.payTerms !== 'Casual') setAttendance((current) => current.map((entry) => entry.memberId === id && entry.date === nextPayTermsStart(effectiveAt || new Date().toISOString()) && entry.checkIn && entry.checkIn !== '—' ? { ...entry, payRate: changes.payRate ?? entry.payRate, workerName: changes.name ?? entry.workerName, workerDepartment: changes.department ?? entry.workerDepartment, workerPayTerms: changes.payTerms === 'Per shift' ? 'Per shift' : entry.workerPayTerms, workerPayFrequency: changes.payFrequency ?? entry.workerPayFrequency } : entry))
    markChanged()
  }
  const getMemberPayrollBalance = (id: number) => {
    const member = members.find((item) => item.id === id)
    if (!member) return { payrollAmountOwed: 0, totalUnpaidBalance: 0 }
    return {
      payrollAmountOwed: payrollAmountOwedForPeriod(member, attendance, casualEarnings, deductions, today, today),
      totalUnpaidBalance: Math.max(0, member.payrollCarryBalance || 0) + outstandingPayrollBalance(member, attendance, casualEarnings, deductions, today),
    }
  }
  const toggleMemberSuspension = async (id: number) => {
    const member = members.find((item) => item.id === id)
    if (!member?.hasAccount || !member.username.trim() || !member.password.trim()) return
    const nextMembers = members.map((item) => item.id === id ? { ...item, suspended: !item.suspended } : item)
    const persistedMembers = nextMembers.map(({ biometricCredentialId: _biometricCredentialId, ...item }) => item)
    if (!await saveWorkspaceSnapshotNow({ members: persistedMembers })) return
    setMembers(nextMembers)
    markChanged()
  }
  ;(window as any).__biztrackUpdateMember = updateMember
  const setMemberCredentials = async (memberId: number, username: string, password: string) => {
    const normalizedUsername = username.trim().toLowerCase()
    const currentMember = members.find((member) => member.id === memberId)
    if (!currentMember) throw new Error('Member not found')
    if (normalizedUsername.length < 3) throw new Error('Username must be at least 3 characters.')
    if (members.some((member) => member.id !== memberId && member.hasAccount && member.username.trim().toLowerCase() === normalizedUsername)) throw new Error('That username is already assigned to another worker.')
    if (currentMember.hasAccount && normalizedUsername !== currentMember.username.trim().toLowerCase() && !password) throw new Error('Enter a password when changing this worker username so the new login can be checked.')
    if (!password && !currentMember.hasAccount) throw new Error('A password of at least 6 characters is required for a new account.')
    if (password && password.length < 6) throw new Error('Password must be at least 6 characters.')
    if (!currentMember.hasAccount && supabase && !await accountCredentialsAvailable(normalizedUsername, password)) throw new Error('That username and password are already used by another account. Keep the username and choose a different password.')
    if (currentMember.hasAccount && supabase && tenantId && tenantId !== 'workspace') {
      const { error } = await supabase.rpc('update_worker_auth_credentials', {
        requested_tenant_id: tenantId,
        requested_member_id: memberId,
        requested_username: normalizedUsername,
        requested_password: password,
      })
      if (error) throw new Error(`Could not update this worker's Supabase login. Apply the latest worker-credentials migration, then try again. ${error.message}`)
    }
    const passwordHash = password ? await hashPassword(password) : currentMember.password
    const updatedMember = { ...currentMember, username: normalizedUsername, password: passwordHash, hasAccount: true }
    const nextMembers = members.map((member) => member.id === memberId ? updatedMember : member)
    const persistedMembers = nextMembers.map(({ biometricCredentialId: _biometricCredentialId, ...member }) => member)
    if (!await saveWorkspaceSnapshotNow({ members: persistedMembers })) throw new Error('Worker credentials were not saved to the shared workspace. Check the connection and try again.')
    setMembers((current) => current.map((member) => member.id === memberId ? { ...member, username: normalizedUsername, password: passwordHash, hasAccount: true } : member))
    markChanged()
    return updatedMember
  }
  ;(window as any).__biztrackSetMemberCredentials = setMemberCredentials
  const saveMyLoginCredentials = async (username: string, currentPassword: string, newPassword: string) => {
    const isOwner = sessionMemberId === -1
    const currentMember = isOwner ? null : members.find((member) => member.id === sessionMemberId)
    const storedUsername = isOwner ? ownerAccount?.username || '' : currentMember?.username || ''
    const storedPassword = isOwner ? currentBusinessAccount?.password || ownerAccount?.password || '' : currentMember?.password || ''
    const normalizedUsername = storedUsername.trim().toLowerCase()
    if (!ownerAccount || (!isOwner && !currentMember)) throw new Error('Your signed-in account could not be found.')
    if (!storedUsername || storedUsername.length < 3) throw new Error('Username must be at least 3 characters.')
    if (newPassword && newPassword.length < 6) throw new Error('New password must be at least 6 characters.')
    if (!isSupabaseConfigured && !(await verifyPassword(storedPassword, currentPassword))) throw new Error('Current password is incorrect.')

    if (isSupabaseConfigured) {
      if (!supabase || !tenantId || tenantId === 'workspace') throw new Error('Could not connect to the shared workspace. Please try again.')
      const { error } = await supabase.rpc('update_my_login_credentials', {
        requested_tenant_id: tenantId,
        requested_username: normalizedUsername,
        requested_current_password: currentPassword,
        requested_new_password: newPassword,
      })
      if (error) throw new Error(`Could not update your shared sign-in. Apply migration 202610110001_self_service_login_credentials.sql, then try again. ${error.message}`)
      const { error: refreshError } = await supabase.auth.refreshSession()
      if (refreshError) {
        await supabase.auth.signOut()
        clearAppSession()
        throw new Error('Your details were updated. Sign in again with the new details to continue on this device.')
      }
    }

    const passwordHash = await hashPassword(newPassword || currentPassword)
    if (isOwner) {
      const updatedOwner = { ...ownerAccount, username: normalizedUsername, password: passwordHash }
      setOwnerAccount(updatedOwner)
      setBusinessAccounts((current) => current.map((account) => account.tenantId === tenantId ? { ...account, username: normalizedUsername, password: passwordHash } : account))
      void persistSharedWorkspaceSession({ username: normalizedUsername, password: passwordHash, tenantId, businessName: updatedOwner.business || workspaceName, ownerName: updatedOwner.name })
      saveRefreshSession({ owner: updatedOwner, memberId: sessionMemberId, path: window.location.pathname })
    } else if (currentMember) {
      setMembers((current) => current.map((member) => member.id === currentMember.id ? { ...member, username: normalizedUsername, password: passwordHash } : member))
    }
  }
  if (activeNav === 'Admin sign in' || activeNav === 'Register site admin') return <CrossDeviceSignInPage ownerAccount={ownerAccount} members={members.filter((member) => member.tenantId === tenantId && member.hasAccount)} businessAccounts={businessAccounts} siteAdminAccount={siteAdminReady ? siteAdminAccount : null} onLogin={login} onBusinessLogin={loginBusinessAccount} onAdminLogin={(success) => { if (success) { startSiteAdminSession(); navigate('Admin') } }} onNavigate={navigate} />
  const adminSignOut = () => { endSiteAdminSession(); navigate('Sign in') }
  const adminPages = ['Admin', 'Business', 'Users', 'Register a new business', 'Activation codes', 'Packages', 'Activate business', 'Admin settings', 'Delete']
  const recordRegistrationRequest = async (issue: string, details: { name: string; business: string; phone?: string; email?: string; username?: string; password?: string; industry?: string; plan?: string }) => {
    const passwordHash = details.password ? await hashPassword(details.password) : undefined
    setRegistrationRequests((current) => [{ id: Date.now(), applicantName: details.name || 'Not provided', businessName: details.business || 'Not provided', issue, submittedAt: formatDate(new Date().toISOString()), phone: details.phone, email: details.email, username: details.username, password: passwordHash, industry: details.industry, plan: details.plan as SubscriptionPlan }, ...current])
  }
  if (!startupReady) return <WorkspaceLoadingPage businessName="BizTrack" />
  if (adminPages.includes(activeNav) && !siteAdminSession) return <CrossDeviceSignInPage ownerAccount={ownerAccount} members={members.filter((member) => member.tenantId === tenantId && member.hasAccount)} businessAccounts={businessAccounts} siteAdminAccount={siteAdminReady ? siteAdminAccount : null} onLogin={login} onBusinessLogin={loginBusinessAccount} onAdminLogin={(success) => { if (success) { startSiteAdminSession(); navigate('Admin') } }} onNavigate={navigate} />
  if (activeNav === 'Admin') return <AdminDashboardPage accounts={businessAccounts} activeNav="Dashboard" onNavigate={navigate} onCreate={() => navigate('Register a new business')} onSignOut={adminSignOut} />
  if (activeNav === 'Register a new business') return <div className="app-shell"><AdminSidebar activeNav={activeNav} onNavigate={navigate} onSignOut={adminSignOut} /><main className="main-content admin-registration-content"><AdminBusinessRegistrationWizard packages={packages} defaultPlan={platformSettings.defaultPlan} onNavigate={navigate} onBack={() => navigate('Dashboard')} onCreate={async (account, activationCode) => {
    const codeIsAvailable = activationCodes.some((item) => item.code.toUpperCase() === activationCode.trim().toUpperCase() && item.status === 'Available' && item.packageName === account.plan)
    if (!codeIsAvailable || !await createBusinessAccount(account)) return false
    consumeActivationCode(activationCode, account.plan, account.businessName)
    startSiteAdminSession()
    navigate('Business')
    return true
  }} /></main></div>
  if (activeNav === 'Activation codes') return <ActivationCodesPage codes={activationCodes} packages={packages} onCreate={createActivationCode} activeNav={activeNav} onNavigate={navigate} onSignOut={adminSignOut} />
  if (activeNav === 'Packages') return <ConfiguredPackagesPage packages={packages} onUpdate={updatePackage} onSave={savePackages} activeNav={activeNav} onNavigate={navigate} onSignOut={adminSignOut} />
  if (activeNav === 'Activate business') return <ActivateBusinessPage accounts={businessAccounts} requests={registrationRequests} reviewDecisions={reviewDecisions} onSaveReviewDecision={saveReviewDecision} onActivateAccount={(accountId) => { const account = businessAccounts.find((item) => item.id === accountId); const packageConfig = account && packages.find((item) => item.name === account.plan); const durationDays = packageConfig ? packageConfig.durationUnit === 'year' ? packageConfig.duration * 365 : packageConfig.durationUnit === 'month' ? packageConfig.duration * 30 : packageConfig.durationUnit === 'week' ? packageConfig.duration * 7 : packageConfig.duration : 30; const nextBilling = account && businessPackageExpired(account) ? new Date(Date.now() + durationDays * 24 * 60 * 60 * 1000).toISOString().slice(0, 10) : account?.nextBilling; updateSubscription(accountId, { status: 'Active', ...(nextBilling ? { nextBilling } : {}) }); void saveReviewDecision(`account:${accountId}`, 'Activated') }} onDeclineAccount={(accountId) => { updateSubscription(accountId, { status: 'Paused' }); void saveReviewDecision(`account:${accountId}`, 'Declined') }} onActivateRequest={activateClientRegistration} onDeclineRequest={declineClientRegistration} activeNav={activeNav} onNavigate={navigate} onSignOut={adminSignOut} />
  if (activeNav === 'Business') return <BusinessAccountsPage accounts={businessAccounts} activeNav="Business" onNavigate={navigate} onCreate={() => navigate('Register a new business')} onSignOut={adminSignOut} onUpdateStatus={async (accountId, updates) => { if (updates.status === 'Paused' && !await showBusinessConfirm('Site admin', 'All owners and workers will be unable to log in.', 'Suspend business?')) return; updateSubscription(accountId, updates) }} onDelete={(accountId) => { setDeleteTargetId(accountId); navigate('Delete') }} />
  if (activeNav === 'Delete') { const account = businessAccounts.find((item) => item.id === deleteTargetId); return <DeleteBusinessPage account={account} onCancel={() => navigate('Business')} onDelete={deleteBusinessAccount} /> }
  if (activeNav === 'Users') return <AdminUsersPage accounts={businessAccounts} activeNav={activeNav} onNavigate={navigate} onSignOut={adminSignOut} />
  const savePlatformSettings = async (settings: PlatformSettings) => {
    if (!supabase) throw new Error('Supabase is not configured. Platform settings were not saved.')
    const { error } = await supabase.rpc('save_platform_settings', {
      requested_platform_name: settings.platformName,
      requested_support_email: settings.supportEmail,
      requested_whatsapp_number: settings.whatsappNumber,
      requested_default_plan: settings.defaultPlan,
      requested_maintenance_mode: settings.maintenanceMode,
      requested_maintenance_ends_at: settings.maintenanceEndsAt || null,
      requested_public_registration_enabled: false,
    })
    if (error) throw new Error(`Platform settings were not saved: ${error.message}`)
    const savedSettings = { ...settings, whatsappNumber: settings.whatsappNumber.replace(/[^0-9]/g, '') }
    setPlatformSettings(savedSettings)
    ;(window as any).__biztrackPlatformSettings = savedSettings
    setAttendanceNotice('Platform settings saved successfully')
    setAttendanceNoticeTone('success')
    navigate('Dashboard')
  }
  if (activeNav === 'Admin settings') return <AdminPlatformSettingsShell activeNav="Admin settings" onNavigate={navigate} onSignOut={adminSignOut} settings={platformSettings} onSave={savePlatformSettings} />
  const currentPath = window.location.pathname.replace(/\/$/, '') || '/'
  const maintenanceActive = platformSettings.maintenanceMode
  const publicMaintenanceAllowed = currentPath === '/' || currentPath === '/welcome' || currentPath === '/welcome/' || activeNav === 'Welcome' || activeNav === 'FAQs'
  const canRenderPublicPageWhileSettingsLoad = ['Sign in', 'Welcome', 'FAQs', 'Terms', 'Privacy', 'Register'].includes(activeNav)
  const maintenanceView = maintenanceActive && !window.location.pathname.startsWith('/admin') && !publicMaintenanceAllowed
  if (!platformSettingsReady && !window.location.pathname.startsWith('/admin') && !canRenderPublicPageWhileSettingsLoad) return <WorkspaceLoadingPage businessName="BizTrack" />
  if (maintenanceView) return <MaintenancePage settings={platformSettings} siteAdminAccount={siteAdminAccount} onAdminLogin={() => { startSiteAdminSession(); navigate('Admin') }} onNavigate={navigate} />
  if (maintenanceActive && window.location.pathname.startsWith('/admin') && !siteAdminSession) return <CrossDeviceSignInPage ownerAccount={null} members={[]} businessAccounts={[]} siteAdminAccount={siteAdminReady ? siteAdminAccount : null} onLogin={() => false} onBusinessLogin={() => false} onAdminLogin={(success) => { if (success) { startSiteAdminSession(); navigate('Admin') } }} onNavigate={navigate} adminOnly />
  if (ownerAccount && sessionMemberId !== 0 && !remoteWorkspaceLoaded && !window.location.pathname.startsWith('/admin')) return <WorkspaceLoadingPage businessName="BizTrack" />
  if (activeNav === 'Welcome') return <WelcomePage onNavigate={navigate} hasOwnerAccount={Boolean(ownerAccount)} businessName={workspaceName || ownerAccount?.business || 'Your workspace'} supportEmail={platformSettings.supportEmail} whatsappNumber={platformSettings.whatsappNumber} />
  if (activeNav === 'FAQs') return <FAQPage onNavigate={navigate} supportEmail={platformSettings.supportEmail} whatsappNumber={platformSettings.whatsappNumber} />
  if (activeNav === 'Terms') return <TermsPage onNavigate={navigate} />
  if (activeNav === 'Privacy') return <PrivacyPage onNavigate={navigate} supportEmail={platformSettings.supportEmail} />
  if (activeNav === 'Register') return <ConfiguredRegisterPage packages={packages} defaultPlan={platformSettings.defaultPlan} onNavigate={navigate} onRequestIssue={recordRegistrationRequest} onComplete={async (account) => {
    const nextAccount = { businessName: account.business || 'New business', ownerName: account.name, email: `${account.username}@biztrack.app`, username: account.username, password: account.password, industry: account.industry || 'General', plan: account.plan || 'Starter' }
    if (!await createBusinessAccount(nextAccount)) return
    triggerWorkspaceTransition(() => navigate('Sign in'))
  }} />
  if (activeNav === 'Master' || activeNav === 'Sign in') return <CrossDeviceSignInPage ownerAccount={ownerAccount} members={members.filter((member) => member.tenantId === tenantId && member.hasAccount)} businessAccounts={businessAccounts} siteAdminAccount={siteAdminReady ? siteAdminAccount : null} onLogin={login} onBusinessLogin={loginBusinessAccount} onAdminLogin={(success) => { if (success) { startSiteAdminSession(); navigate('Admin') } }} onNavigate={navigate} />
  if (!ownerAccount) return <CrossDeviceSignInPage ownerAccount={ownerAccount} members={members.filter((member) => member.tenantId === tenantId && member.hasAccount)} businessAccounts={businessAccounts} siteAdminAccount={siteAdminReady ? siteAdminAccount : null} onLogin={login} onBusinessLogin={loginBusinessAccount} onAdminLogin={(success) => { if (success) { startSiteAdminSession(); navigate('Admin') } }} onNavigate={navigate} />
  if (sessionMemberId > 0 && !normalizeAccessAreas(accessByMember[sessionMemberId] || []).length) return <WorkerNoPagesPage onLogout={logout} />
  if (!canAccess(activeNav)) return <AccessDeniedPage onBack={() => navigate('Overview')} />
  const openAttendanceMode = (page: 'Worker sign-in' | 'Worker checkout', mode: 'individual' | 'bulk') => {
    navigate(page)
    if (mode === 'bulk') {
      const route = sessionMemberId > 0 ? grantPagePaths[page] : pagePaths[page]
      window.history.replaceState({}, '', `${route}?mode=bulk`)
    }
  }
  const canonicalNav = canonicalActivePage(activeNav)
  const renderWorkspacePage = () => {
    switch (activeNav) {
      case 'ROLL':
        return <RollPage onOpenSignIn={(mode) => openAttendanceMode('Worker sign-in', mode)} onOpenSignOut={(mode) => openAttendanceMode('Worker checkout', mode)} />
      case 'Attendance':
        return <AttendancePage members={members} entries={attendance} />
      case 'Departments':
        return <DepartmentsPage departments={departmentList} members={members} onAdd={() => navigate('Add department')} onDelete={deleteDepartment} />
      case 'Add department':
        return <AddDepartmentPage onSubmit={addDepartment} onCancel={() => navigate('Departments')} />
      case 'Add member':
        return <AddMemberPage departments={departmentList} defaultSignIn={defaultSignIn} defaultSignOut={defaultSignOut} onSubmit={addMember} onCancel={() => navigate('Team')} />
      case 'Team':
        return <TeamPage members={members} attendance={attendance} onAdd={() => navigate('Add member')} onDelete={deleteMember} onToggleSuspended={toggleMemberSuspension} onGetPayrollBalance={getMemberPayrollBalance} />
      case 'Payroll':
        return <PayrollPage members={members} attendance={attendance} casualEarnings={casualEarnings} deductions={deductions} onAddCasualEarning={(earning) => setCasualEarnings((current) => [...current, earning])} onRecordCasualPartialPayment={recordCasualPartialPayment} onUpdateStatus={updatePayrollStatus} onNavigate={navigate} />
      case 'Sales':
        return <SalesPage sales={sales} salesHistory={salesHistory} paymentMethods={paymentMethods} onAdd={addSale} onReset={resetSales} onDelete={deleteSale} />
      case 'Inventory':
        return <StockPage businessName={businessName} inventory={inventory} expenses={expenses} categories={storeCategories} categoryUnits={categoryUnits} categoryThresholds={categoryThresholds} onAddStock={addInventoryItem} onAddExpense={addExpense} />
      case 'Worker checkout':
        return <WorkerSignOutPage members={members} entries={attendance} onMarkSignOut={markMemberSignOut} onBulkAction={markBulkAttendance} onSuccess={(_count, failures = [], responses = []) => { navigate('ROLL'); const reported = new Set(responses.map((response) => response.message)); responses.forEach((response) => queueAttendanceNotice(response.message, response.tone, response.durationMs, 'ROLL')); failures.filter((message) => !reported.has(message)).forEach((message) => queueAttendanceNotice(message, 'error', 1200, 'ROLL')) }} />
      case 'Worker sign-in':
        return <WorkerSignInPage members={members} entries={attendance} strictSignIn={strictSignIn} defaultSignIn={defaultSignIn} allowMultipleDailyShifts={allowMultipleDailyShifts} onAttendance={() => navigate('Attendance')} onMarkAttendance={markMemberAttendance} onBulkAction={markBulkAttendance} onSuccess={(_count, failures = [], responses = []) => { navigate('ROLL'); const reported = new Set(responses.map((response) => response.message)); responses.forEach((response) => queueAttendanceNotice(response.message, response.tone, response.durationMs, 'ROLL')); failures.filter((message) => !reported.has(message)).forEach((message) => queueAttendanceNotice(message, 'error', 1200, 'ROLL')) }} />
      case 'Permissions':
        return <PermissionsPage members={members} accessByMember={accessByMember} setAccessByMember={setAccessByMember} selectedMemberId={permissionTargetId} onAddMember={() => setAccountChoiceOpen(true)} onSetCredentials={setMemberCredentials} onSave={async (member, grantedPages) => {
          const persistedMembers = members.map((currentMember) => {
            const source = currentMember.id === member.id ? member : currentMember
            const { biometricCredentialId: _biometricCredentialId, ...persistedMember } = source
            return persistedMember
          })
          const saved = await saveWorkspaceSnapshotNow({ members: persistedMembers, accessByMember: { ...accessByMember, [member.id]: grantedPages } })
          if (!saved) {
            setAttendanceNotice('Worker access was not saved to the shared workspace. Check the owner Supabase sign-in and try again.')
            setAttendanceNoticeTone('error')
            return
          }
          setAttendanceNotice(`${member.name}, ${member.role}, now has access to ${grantedPages.join(', ') || 'no pages'}`)
          setPermissionTargetId(null)
          navigate('Team')
        }} onCancel={() => navigate('Team')} />
      case 'OFF MARK':
        return <OffMarkPage members={members} attendance={attendance} onMark={(memberIds, dates) => { setAttendance((current) => { const next = [...current]; memberIds.forEach((memberId) => dates.forEach((date) => { const existingIndex = next.findIndex((entry) => entry.memberId === memberId && entry.date === date); const existing = existingIndex >= 0 ? next[existingIndex] : undefined; const hasSignedIn = Boolean(existing && (existing.status === 'Present' || existing.status === 'Late' || existing.checkIn !== '—' || existing.checkOut !== '—')); if (hasSignedIn) return; const entry = { memberId, date, status: 'Off' as AttendanceStatus, checkIn: '—', checkOut: '—' }; if (existingIndex >= 0) next[existingIndex] = { ...next[existingIndex], ...entry }; else next.push(entry) })); return next }); markChanged() }} />
      case 'Print':
        return <PrintPage businessName={businessName} members={members} sales={[...sales, ...salesHistory]} attendance={attendance} casualEarnings={casualEarnings} deductions={deductions} expenses={expenses} stockMovements={stockMovements} inventory={inventory} categoryThresholds={categoryThresholds} currency={currency} paymentRegisterFooter={paymentRegisterFooter} payrollReportOrder={payrollReportOrder} />
      case 'Settings':
        return <><WorkspaceSettingsPage businessName={workspaceName} currency={currency} paymentMethods={paymentMethods} defaultSignIn={defaultSignIn} defaultSignOut={defaultSignOut} strictSignIn={strictSignIn} allowMultipleDailyShifts={allowMultipleDailyShifts} categories={storeCategories} setCategories={setStoreCategories} deletedCategories={deletedCategories} setDeletedCategories={setDeletedCategories} categoryUnits={categoryUnits} setCategoryUnits={setCategoryUnits} categoryThresholds={categoryThresholds} setCategoryThresholds={setCategoryThresholds} inventory={inventory} setInventory={setInventory} onSaveIdentity={saveBusinessIdentity} onSavePaymentMethods={savePaymentMethodSettings} onSaveAttendanceRules={async (rules: { defaultSignIn: string; defaultSignOut: string; strictSignIn: boolean; allowMultipleDailyShifts: boolean }) => { const saved = await saveWorkspaceSnapshotNow(rules); if (saved) { setDefaultSignIn(rules.defaultSignIn); setDefaultSignOut(rules.defaultSignOut); setStrictSignIn(rules.strictSignIn); setAllowMultipleDailyShifts(rules.allowMultipleDailyShifts) } return saved }} /><PayrollReportOrderSettings value={payrollReportOrder} onSave={async (value) => { const saved = await saveWorkspaceSnapshotNow({ payrollReportOrder: value }); if (saved) setPayrollReportOrder(value); return saved }} />{sessionMemberId === -1 && <PaymentRegisterFooterSettings value={paymentRegisterFooter} onSave={async (value) => { const saved = await saveWorkspaceSnapshotNow({ paymentRegisterFooter: value }); if (saved) setPaymentRegisterFooter(value); return saved }} />}</>
      case 'Deductions':
      case 'Penalties':
        return <DeductionsPage members={members} attendance={attendance} casualEarnings={casualEarnings} deductions={deductions} onAdd={addDeduction} onDelete={deleteDeduction} />
      case 'Business AI':
        return sessionMemberId === -1 ? <BusinessAssistantPage businessName={businessName} ownerName={dashboardName} tenantId={tenantId} currency={currency} members={members} attendance={attendance} casualEarnings={casualEarnings} deductions={deductions} sales={sales} salesHistory={salesHistory} inventory={inventory} categoryThresholds={categoryThresholds} /> : <AccessDeniedPage onBack={() => navigate('Overview')} />
      default:
        return <LiveWorkspaceOverview businessName={businessName} memberName={dashboardName} memberRole={sessionMemberId === -1 ? 'Owner' : members.find((member) => member.id === sessionMemberId)?.role || role} members={members} attendance={todayAttendance} entries={attendance} sales={sales} salesHistory={salesHistory} casualEarnings={casualEarnings} deductions={deductions} inventory={inventory} categoryThresholds={categoryThresholds} onAttendance={() => navigate('Attendance')} />
    }
  }
  return (
    <div className="app-shell">
      <WorkspaceSidebar businessName={businessName} activeNav={canonicalNav} onNavigate={navigate} onLogout={logout} />
      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumbs"><span>Workspace</span><b>/</b><strong>{visiblePageName(activeNav)}</strong></div>
          <div className="top-actions">
            <div className={`sync-status ${isOnline ? 'online' : 'offline'}`}><span className="status-dot"></span>{syncLabel}</div>
            <button className="icon-button" aria-label="Notifications">♧<span className="notification-dot"></span></button>
            <button className="icon-button credentials-button" type="button" aria-label="Change credentials" onClick={() => setMyCredentialsOpen(true)}>⚿</button>
            <div className="workspace-switcher topbar-workspace">
              <span className="workspace-dot">{dashboardName.trim().split(/\s+/).slice(0, 2).map((part) => part.charAt(0)).join('').toUpperCase() || 'U'}</span>
              <span><strong>{dashboardName}</strong><small>{dashboardDepartment}</small></span>
            </div>
          </div>
        </header>
        <div className="page-content">{renderWorkspacePage()}</div>
        <PrintBrandFooter />
      </main>
      {activeNav === 'Overview' && sessionMemberId === -1 && <>
        <button className="business-ai-launcher" type="button" aria-label={businessAiOpen ? 'Close AI' : 'Open AI'} aria-expanded={businessAiOpen} title="AI" onClick={() => setBusinessAiOpen((open) => !open)}><span aria-hidden="true">✦</span></button>
        {businessAiOpen && <BusinessAssistantPage businessName={businessName} ownerName={dashboardName} tenantId={tenantId} currency={currency} members={members} attendance={attendance} casualEarnings={casualEarnings} deductions={deductions} sales={sales} salesHistory={salesHistory} inventory={inventory} categoryThresholds={categoryThresholds} isDrawer onClose={() => setBusinessAiOpen(false)} />}
      </>}
    </div>
  )
}

  function LiveOverviewPage({ memberName, members, isCheckedIn, setIsCheckedIn, isOnline, onAttendance }: { memberName: string; members: Member[]; isCheckedIn: boolean; setIsCheckedIn: () => void; isOnline: boolean; onAttendance: () => void }) { const [now, setNow] = useState(new Date()); useEffect(() => { const timer = window.setInterval(() => setNow(new Date()), 60000); return () => window.clearInterval(timer) }, []); const dateLabel = formatDate(now.toISOString()); const timeLabel = now.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }); return <LegacyOverviewPage role="Owner" setRole={() => undefined} members={members} isCheckedIn={isCheckedIn} setIsCheckedIn={setIsCheckedIn} isOnline={isOnline} onAttendance={onAttendance} liveMemberName={memberName} liveDate={dateLabel} liveTime={timeLabel} /> }
  function PageHeading({ title, subtitle, action }: { eyebrow: string; title: string; subtitle: string; action?: React.ReactNode }) { const visibleTitle = title === 'App configuration' ? 'Platform settings' : title.replace(/\s*✦/g, ''); return <div className="page-heading"><div><h1>{visibleTitle}</h1><p className="subheading">{subtitle}</p></div>{action && <div className="heading-actions">{action}</div>}</div> }
function PanelHeading({ title, subtitle, action }: { title: string; subtitle: string; action?: React.ReactNode }) { return <div className="panel-heading"><div><h2>{title}</h2><p>{subtitle}</p></div>{action}</div> }
function Metric({ title, value, detail, accent, progress = 72, outflow = false }: { title: string; value: string; detail: string; accent: string; progress?: number; outflow?: boolean }) {
  const safeProgress = Math.max(0, Math.min(100, Number.isFinite(progress) ? progress : 72))
  return <article className={`metric-card accent-${accent} ${outflow || title.toLowerCase().includes('payroll') ? 'figure-outflow' : ''}`}><div className="metric-top"><span>{title}</span><span className="metric-icon">↗</span></div><strong>{value}</strong><div className="metric-foot"><span className={detail.toLowerCase().includes('needs') || detail.toLowerCase().includes('absent') ? 'negative' : 'positive'}>{detail}</span></div><div className="progress-track"><span style={{ width: `${safeProgress}%` }}></span></div></article>
}

function LegacyOverviewPage({ role, setRole, members, isCheckedIn, setIsCheckedIn, isOnline, onAttendance }: { role: Role; setRole: (role: Role) => void; members: Member[]; isCheckedIn: boolean; setIsCheckedIn: () => void; isOnline: boolean; onAttendance: () => void }) { return <><PageHeading eyebrow="MONDAY, 24 JUNE 2024" title="Good morning, Kemi ✦" subtitle="Here’s what’s happening across Biz Track today." action={<><label className="role-select"><span>Viewing as</span><select value={role} onChange={(event) => setRole(event.target.value as Role)}>{roles.map((item) => <option key={item}>{item}</option>)}</select></label><button className="primary-button" onClick={onAttendance}>View attendance <span>→</span></button></>} /><section className="metric-grid"><Metric title="Today’s sales" value="KES 284,500" detail="↑ 12.8% vs. yesterday" accent="coral" /><Metric title="Team attendance" value="18 / 21" detail="85.7% present today" accent="teal" /><Metric title="Payroll this month" value="KES 1.84m" detail="62% of monthly budget" accent="yellow" /><Metric title="Stock alerts" value="03" detail="Needs attention" accent="lilac" /></section><section className="dashboard-grid"><article className="panel attendance-panel"><PanelHeading title="Attendance today" subtitle="Live view of your team’s day" action={<button className="text-button" onClick={onAttendance}>View all <span>→</span></button>} /><div className="attendance-summary"><div><strong>18</strong><span>Present</span></div><div><strong>02</strong><span>Late</span></div><div><strong>01</strong><span>Off today</span></div><div className="attendance-ring"><div><strong>86%</strong><span>of team</span></div></div></div><div className="table-wrap"><table><thead><tr><th>TEAM MEMBER</th><th>DEPARTMENT</th><th>STATUS</th><th>CHECK-IN</th></tr></thead><tbody>{members.slice(0, 4).map((member, index) => <tr key={member.id}><td><div className="person-cell"><span className={`avatar avatar-${member.color}`}>{member.initials}</span><strong>{member.name}</strong></div></td><td>{member.department}</td><td><span className={`status-pill ${index === 2 ? 'late' : 'present'}`}><i></i>{index === 2 ? 'Late' : 'Present'}</span></td><td>{index === 2 ? '09:17 AM' : '08:52 AM'}</td></tr>)}</tbody></table></div></article><article className="panel checkin-panel"><PanelHeading title="Your attendance" subtitle="Keep your day on track" action={<span className="today-tag">TODAY</span>} /><div className="checkin-state"><span className="checkin-icon">{isCheckedIn ? '✓' : '○'}</span><div><strong>{isCheckedIn ? 'You are checked in' : 'You are checked out'}</strong><span>{isCheckedIn ? 'Started at 08:46 AM' : 'Tap below to start your day'}</span></div></div><button className="attendance-button" onClick={setIsCheckedIn}>{isCheckedIn ? 'Check out' : 'Check in'} <span>→</span></button><div className="checkin-note">◷ Automatic sync is {isOnline ? 'on' : 'paused offline'}</div></article></section><section className="lower-grid"><article className="panel insight-panel"><PanelHeading title="Sales performance" subtitle="Revenue across the last 7 days" /><div className="fake-chart"><span>KES 300k</span><div className="chart-bars"><i></i><i></i><i></i><i></i><i></i><i></i><i></i></div><span>KES 0</span></div></article><article className="panel insight-panel"><PanelHeading title="Inventory watchlist" subtitle="Items that need your attention" action={<button className="text-button">Manage <span>→</span></button>} /><div className="inventory-list"><div className="inventory-item"><span className="product-icon product-red">☕</span><div><strong>Arabica coffee beans</strong><small>Warehouse · 2kg left</small></div><span className="stock-status critical">Critical</span></div><div className="inventory-item"><span className="product-icon product-green">◒</span><div><strong>Fresh milk</strong><small>Cold storage · 8L left</small></div><span className="stock-status low">Low stock</span></div></div></article></section></> }

function AttendancePage({ members, entries }: { members: Member[]; entries: AttendanceEntry[] }) {
  const [selectedDate, setSelectedDate] = useState(today)
  const [selectedDepartment, setSelectedDepartment] = useState('All departments')
  const activeMembers = members.filter((member) => !member.archived)
  const departments = Array.from(new Set(activeMembers.map((member) => member.department))).sort((first, second) => first.localeCompare(second))
  const departmentFilter = selectedDepartment === 'All departments' || departments.includes(selectedDepartment) ? selectedDepartment : 'All departments'
  const visibleMembers = departmentFilter === 'All departments' ? activeMembers : activeMembers.filter((member) => member.department === departmentFilter)
  const rows = visibleMembers.map((member) => ({
    member,
    entry: entries.find((entry) => entry.memberId === member.id && entry.date === selectedDate) || {
      memberId: member.id,
      date: selectedDate,
      status: 'Absent' as AttendanceStatus,
      checkIn: '—',
      checkOut: '—',
    },
  }))
  const recordedTimeInMinutes = (value: string) => {
    const match = value.trim().match(/^(\d{1,2}):(\d{2})(?:\s*(AM|PM))?$/i)
    if (!match) return null
    let hours = Number(match[1])
    const minutes = Number(match[2])
    if (minutes > 59 || hours > 23) return null
    if (match[3]) hours = (hours % 12) + (match[3].toUpperCase() === 'PM' ? 12 : 0)
    return hours * 60 + minutes
  }
  const counts = rows.reduce((result, row) => {
    const { entry, member } = row
    const checkIn = recordedTimeInMinutes(entry.checkIn)
    const scheduledStart = recordedTimeInMinutes(member.signInTime || '08:00')
    const checkOut = recordedTimeInMinutes(entry.checkOut)
    const scheduledEnd = recordedTimeInMinutes(member.signOutTime || '17:00')
    const signedIn = checkIn !== null || entry.status === 'Present' || entry.status === 'Late' || entry.status === 'Early'
    if (signedIn) {
      if (checkIn !== null && scheduledStart !== null ? checkIn > scheduledStart : entry.status === 'Late') result.late += 1
      else result.present += 1
    }
    if (checkOut !== null && scheduledEnd !== null && checkOut < scheduledEnd) result.earlyDepartures += 1
    if (entry.status === 'Off') result.off += 1
    return result
  }, { present: 0, late: 0, earlyDepartures: 0, off: 0 })
  const scheduledCount = rows.length - counts.off
  const checkedInCount = counts.present + counts.late
  const coverage = scheduledCount ? Math.round(checkedInCount / scheduledCount * 100) : 0
  const progressFor = (count: number) => scheduledCount ? count / scheduledCount * 100 : 0

  return <>
    <PageHeading eyebrow="TEAM MANAGEMENT / ATTENDANCE" title="Attendance" subtitle="Review sign-ins, early departures, and team coverage for the selected date." action={<div className="attendance-filters"><input type="date" value={selectedDate} max={today} aria-label="Attendance date" onChange={(event) => setSelectedDate(event.target.value || today)} /></div>} />
    <section className="metric-grid attendance-metrics">
      <Metric title={selectedDate === today ? 'Present today' : 'Present'} value={String(counts.present)} detail="Signed in by scheduled start" accent="teal" progress={progressFor(counts.present)} />
      <Metric title="Late arrivals" value={String(counts.late).padStart(2, '0')} detail="Signed in after scheduled start" accent="yellow" progress={progressFor(counts.late)} />
      <Metric title="Early departures" value={String(counts.earlyDepartures).padStart(2, '0')} detail="Signed out before scheduled end" accent="coral" progress={progressFor(counts.earlyDepartures)} />
      <Metric title="Team coverage" value={`${checkedInCount} / ${scheduledCount}`} detail={`${coverage}% of scheduled team · ${counts.off} off`} accent="lilac" progress={coverage} />
    </section>
    <article className="panel attendance-review">
      <PanelHeading title="Employee attendance" subtitle={`Daily sign-in and sign-out records for ${formatDate(selectedDate)}`} action={<div className="attendance-filters"><select aria-label="Attendance department" value={departmentFilter} onChange={(event) => setSelectedDepartment(event.target.value)}><option>All departments</option>{departments.map((department) => <option key={department}>{department}</option>)}</select></div>} />
      <div className="table-wrap"><table><thead><tr><th>EMPLOYEE</th><th>DEPARTMENT</th><th>ROLE</th><th>STATUS</th><th>CHECK-IN</th><th>CHECK-OUT</th></tr></thead><tbody>
        {rows.length ? rows.map(({ member, entry }) => <tr key={member.id}><td><div className="person-cell"><span className={`avatar avatar-${member.color}`}>{member.initials}</span><strong>{member.name}</strong></div></td><td>{member.department}</td><td>{member.role}</td><td><span className={`status-pill ${entry.status.toLowerCase()}`}><i></i>{entry.status}</span></td><td>{entry.checkIn}</td><td>{entry.checkOut}</td></tr>) : <tr><td colSpan={6}>No workers found for this department.</td></tr>}
      </tbody></table></div>
    </article>
    <p className="page-footer"><span><i className="footer-dot"></i>Attendance records for {formatDate(selectedDate)}</span><span>Showing {rows.length} workers</span></p>
  </>
}

function ExistingAccountTeamPage({ members, onProceed, onBack }: { members: Member[]; onProceed: (id: number) => void; onBack: () => void }) { const accountMembers = members.filter((member) => member.hasAccount === true && Boolean(member.username?.trim() && member.password?.trim())); const [selectedId, setSelectedId] = useState<number | null>(null); return <><PageHeading eyebrow="PEOPLE / TEAM" title="Select an account" subtitle="Choose one existing worker to give workspace access." action={<button className="secondary-button" onClick={onBack}>Back to permissions</button>} /><article className="panel team-panel account-selection-panel"><PanelHeading title="Existing worker accounts" subtitle="Only one account can be selected." /><div className="table-wrap"><table className="team-members-table"><thead><tr><th>SELECT</th><th>WORKER ID</th><th>WORKER</th><th>PHONE</th><th>ID NUMBER</th><th>DEPARTMENT</th></tr></thead><tbody>{accountMembers.map((member) => <tr key={member.id}><td><input type="radio" name="existing-account" checked={selectedId === member.id} onChange={() => setSelectedId(member.id)} aria-label={`Select ${member.name}`} /></td><td><strong>#{member.id}</strong></td><td><div className="person-cell"><span className={`avatar avatar-${member.color}`}>{member.initials}</span><strong>{member.name}</strong></div></td><td>{member.phone}</td><td>{workerIdNumber(member.email)}</td><td>{member.department}</td></tr>)}</tbody></table></div><div className="team-panel-footer"><button className="primary-button" disabled={!selectedId} onClick={() => selectedId && onProceed(selectedId)}>Proceed</button></div></article></> }

function TeamPage({ members, attendance, onAdd, onDelete, onToggleSuspended, onGetPayrollBalance }: { members: Member[]; attendance: AttendanceEntry[]; onAdd: () => void; onDelete: (id: number) => void; onToggleSuspended: (id: number) => void; onGetPayrollBalance: (memberId: number) => { payrollAmountOwed: number; totalUnpaidBalance: number } }) {
  const [selectedDepartment, setSelectedDepartment] = useState('All departments')
  const [editing, setEditing] = useState<Member | null>(null)
  const [deleting, setDeleting] = useState<Member | null>(null)
  const [confirmations, setConfirmations] = useState(['', '', ''])
  const [payTermsPrompt, setPayTermsPrompt] = useState<{ updates: Partial<Member> & { effectiveAt: string }; username: string; password: string; payrollAmountOwed: number; totalUnpaidBalance: number; includeTodayAvailable: boolean } | null>(null)
  const activeMembers = members.filter((member) => !member.archived)
  const departmentOptions = ['All departments', ...Array.from(new Set(activeMembers.map((member) => member.department)))]
  const visibleMembers = selectedDepartment === 'All departments' ? activeMembers : activeMembers.filter((member) => member.department === selectedDepartment)
  useEffect(() => {
    if (!editing) return
    const form = document.querySelector('form.admin-modal') as HTMLFormElement | null
    if (!form || form.querySelector('.effective-change-fields')) return
    const credentials = document.createElement('div')
    credentials.className = 'worker-credentials-fields'
    const credentialsHeading = document.createElement('strong')
    credentialsHeading.textContent = 'Login credentials'
    const credentialsHint = document.createElement('small')
    credentialsHint.textContent = 'Leave these unchanged to keep the current login settings. Enter a password only when changing login access.'
    const credentialGrid = document.createElement('div')
    credentialGrid.className = 'form-grid'
    const usernameLabel = document.createElement('label')
    const usernameCaption = document.createElement('span')
    usernameCaption.textContent = 'Username'
    const usernameInput = document.createElement('input')
    usernameInput.name = 'username'
    usernameInput.type = 'text'
    usernameInput.value = editing.username || ''
    usernameInput.minLength = 3
    usernameInput.autocomplete = 'username'
    usernameLabel.append(usernameCaption, usernameInput)
    const passwordLabel = document.createElement('label')
    const passwordCaption = document.createElement('span')
    passwordCaption.textContent = 'Password'
    const passwordInput = document.createElement('input')
    passwordInput.name = 'password'
    passwordInput.type = 'password'
    passwordInput.minLength = 6
    passwordInput.autocomplete = 'new-password'
    passwordInput.placeholder = editing.hasAccount ? 'Leave blank to keep current password' : 'At least 6 characters'
    passwordLabel.append(passwordCaption, passwordInput)
    credentialGrid.append(usernameLabel, passwordLabel)
    const credentialError = document.createElement('p')
    credentialError.className = 'worker-credentials-error'
    credentialError.setAttribute('role', 'alert')
    credentials.append(credentialsHeading, credentialsHint, credentialGrid, credentialError)
    const fields = document.createElement('div')
    fields.className = 'form-grid effective-change-fields'
    const now = new Date()
    const date = localDateKey(now)
    const time = now.toTimeString().slice(0, 5)
    fields.innerHTML = `<label><span>Scheduled sign-in</span><input name="signInTime" type="time" required></label><label><span>Scheduled sign-out</span><input name="signOutTime" type="time" required></label><label><span>Changes take effect on</span><input name="effectiveDate" type="date" value="${date}" required></label><label><span>Effective time</span><input name="effectiveTime" type="time" value="${time}" required></label>`
    fields.querySelector<HTMLInputElement>('input[name="signInTime"]')!.value = editing.signInTime || '08:00'
    fields.querySelector<HTMLInputElement>('input[name="signOutTime"]')!.value = editing.signOutTime || '17:00'
    const rateInput = form.querySelector<HTMLInputElement>('input[name="payRate"]')
    const rateLabel = rateInput?.closest('label')
    const frequencySelect = form.querySelector<HTMLSelectElement>('select[name="payFrequency"]')
    const frequencyLabel = frequencySelect?.closest('label')
    const grid = form.querySelector('.form-grid')
    let termsLabel: HTMLLabelElement | null = null
    if (rateInput && rateLabel && frequencySelect && frequencyLabel && grid) {
      termsLabel = document.createElement('label')
      termsLabel.innerHTML = '<span>Pay terms</span>'
      const termsSelect = document.createElement('select')
      termsSelect.name = 'payTerms'
      termsSelect.add(new Option('Amount per shift', 'Per shift'))
      termsSelect.add(new Option('Casual', 'Casual'))
      termsSelect.value = editing.payTerms === 'Casual' ? 'Casual' : 'Per shift'
      termsLabel.appendChild(termsSelect)
      grid.insertBefore(termsLabel, rateLabel)
      const credentialInputs = credentials.querySelectorAll<HTMLInputElement>('input')
      const updateTerms = () => {
        const casual = termsSelect.value === 'Casual'
        rateLabel.hidden = casual
        frequencyLabel.hidden = casual
        rateInput.required = !casual
        credentials.hidden = casual
        credentials.setAttribute('aria-hidden', String(casual))
        credentials.toggleAttribute('inert', casual)
        credentialInputs.forEach((input) => { input.disabled = casual })
      }
      termsSelect.addEventListener('change', updateTerms)
      const cleanupTerms = () => { termsSelect.removeEventListener('change', updateTerms); termsLabel?.remove() }
      updateTerms()
      form.querySelector('.form-actions')?.before(credentials, fields)
      return () => { credentials.remove(); fields.remove(); cleanupTerms() }
    }
    form.querySelector('.form-actions')?.before(credentials, fields)
    return () => { credentials.remove(); fields.remove(); termsLabel?.remove() }
  }, [editing])
  const finishEdit = async (updates: Partial<Member> & { effectiveAt: string }, username: string, password: string, includeTodayShift: boolean) => {
    if (!editing) return false
    const credentialsChanged = updates.payTerms !== 'Casual' && (username !== (editing.username || '').trim().toLowerCase() || Boolean(password))
    if (credentialsChanged) {
      const updateCredentials = (window as any).__biztrackSetMemberCredentials
      const errorMessage = document.querySelector('.admin-modal.member-form .worker-credentials-error')
      try {
        await updateCredentials(editing.id, username, password)
      } catch (error) {
        if (errorMessage) errorMessage.textContent = error instanceof Error ? error.message : 'Could not save worker credentials.'
        return false
      }
    }
    ;(window as any).__biztrackUpdateMember?.(editing.id, { ...updates, includeTodayShift })
    setEditing(null)
    setPayTermsPrompt(null)
    return true
  }
  const saveEdit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!editing) return
    const form = new FormData(event.currentTarget)
    const payTerms = String(form.get('payTerms') || editing.payTerms || 'Per shift') as PayTerms
    const username = String(form.get('username') || '').trim().toLowerCase()
    const password = String(form.get('password') || '')
    const effectiveAt = new Date(`${String(form.get('effectiveDate') || today)}T${String(form.get('effectiveTime') || '00:00')}`).toISOString()
    const updates = { name: String(form.get('name') || '').trim(), phone: String(form.get('phone') || '').trim(), email: workerIdNumber(String(form.get('email') || '')), department: String(form.get('department') || 'Unassigned'), payRate: payTerms === 'Casual' ? 0 : Number(form.get('payRate') || 0), payTerms, payFrequency: String(form.get('payFrequency') || 'Daily') as PayFrequency, signInTime: String(form.get('signInTime') || editing.signInTime), signOutTime: String(form.get('signOutTime') || editing.signOutTime), initials: initialsFor(String(form.get('name') || editing.name)), effectiveAt }
    const balance = onGetPayrollBalance(editing.id)
    const includeTodayAvailable = attendance.some((entry) => entry.memberId === editing.id && entry.date === today && (Boolean(entry.checkIn && entry.checkIn !== '—') || entry.status === 'Present' || entry.status === 'Late') && (!entry.checkOut || entry.checkOut === '—'))
    if (editing.payTerms === 'Casual' && payTerms === 'Per shift' && (balance.totalUnpaidBalance > 0 || includeTodayAvailable)) {
      setPayTermsPrompt({ updates, username, password, ...balance, includeTodayAvailable })
      return
    }
    await finishEdit(updates, username, password, editing.payTerms === 'Casual' && payTerms === 'Per shift' ? false : true)
  }
  useEffect(() => {
    if (!payTermsPrompt || !editing) return
    const overlay = document.createElement('div')
    overlay.className = 'admin-modal-backdrop'
    const dialog = document.createElement('section')
    dialog.className = 'admin-modal member-form payroll-balance-confirm'
    dialog.setAttribute('role', 'alertdialog')
    dialog.setAttribute('aria-modal', 'true')
    dialog.setAttribute('aria-labelledby', 'payroll-balance-confirm-title')
    const title = document.createElement('h2')
    title.id = 'payroll-balance-confirm-title'
    title.textContent = 'Confirm pay change'
    const message = document.createElement('p')
    message.textContent = payTermsPrompt.totalUnpaidBalance > 0
      ? `${editing.name} has KES ${payTermsPrompt.payrollAmountOwed.toLocaleString()} owed in today's Payroll view. Total unpaid balance through today is KES ${payTermsPrompt.totalUnpaidBalance.toLocaleString()}; this full balance will remain payable after the change to amount per shift.`
      : `${editing.name} is signed in and has not signed out today. Choose whether today's set shift amount should apply to this shift.`
    const includeToday = document.createElement('input')
    includeToday.type = 'checkbox'
    includeToday.name = 'includeTodayShift'
    const includeLabel = document.createElement('label')
    includeLabel.className = 'payroll-balance-include-today'
    const includeText = document.createElement('span')
    includeText.textContent = `Include today's shift amount (KES ${payTermsPrompt.updates.payRate?.toLocaleString() || '0'})`
    includeLabel.append(includeToday, includeText)
    if (payTermsPrompt.includeTodayAvailable) dialog.append(title, message, includeLabel)
    else dialog.append(title, message)
    const actions = document.createElement('div')
    actions.className = 'form-actions'
    const cancel = document.createElement('button')
    cancel.type = 'button'
    cancel.className = 'secondary-button'
    cancel.textContent = 'Cancel'
    const confirm = document.createElement('button')
    confirm.type = 'button'
    confirm.className = 'primary-button'
    confirm.textContent = 'OK'
    cancel.addEventListener('click', () => setPayTermsPrompt(null))
    confirm.addEventListener('click', () => { void finishEdit(payTermsPrompt.updates, payTermsPrompt.username, payTermsPrompt.password, !payTermsPrompt.includeTodayAvailable || includeToday.checked) })
    actions.append(cancel, confirm)
    dialog.append(actions)
    overlay.append(dialog)
    document.body.append(overlay)
    return () => overlay.remove()
  }, [payTermsPrompt, editing])
  const confirmDelete = () => { if (!deleting || confirmations.some((value) => value.trim().toLowerCase() !== deleting.name.trim().toLowerCase())) return; onDelete(deleting.id); setDeleting(null); setConfirmations(['', '', '']) }
  return <><PageHeading eyebrow="PEOPLE / TEAM" title="Your team" subtitle="Manage workers and keep everyone connected to the right department." /><article className="panel team-panel"><PanelHeading title={`${visibleMembers.length} workers`} subtitle="Contact details and current assignments" action={<select className="filter-button" value={selectedDepartment} onChange={(event) => setSelectedDepartment(event.target.value)}>{departmentOptions.map((department) => <option key={department}>{department}</option>)}</select>} /><div className="table-wrap"><table className="team-members-table"><thead><tr><th>#</th><th>WORKER ID</th><th>WORKER</th><th>DATE JOINED</th><th>ID NUMBER</th><th>DEPARTMENT</th><th>ACTIONS</th></tr></thead><tbody>{visibleMembers.map((member, index) => <tr key={member.id}><td>{index + 1}</td><td><strong>#{member.id}</strong></td><td><div className={`person-cell ${member.suspended ? 'is-suspended' : ''}`}><span className={`avatar avatar-${member.color}`}>{member.initials}</span><strong>{member.name}</strong></div></td><td>{formatShortDate(member.joinedAt || (member.id >= 1000000000000 ? localDateKey(new Date(member.id)) : ''))}</td><td>{workerIdNumber(member.email)}</td><td>{member.department}</td><td><div className="team-actions"><button className="table-action" type="button" onClick={() => setEditing(member)}>Edit</button>{member.hasAccount && Boolean(member.username.trim() && member.password.trim()) && <button className={`table-action ${member.suspended ? 'table-action-view' : 'table-action-danger'}`} type="button" onClick={() => onToggleSuspended(member.id)}>{member.suspended ? 'Activate' : 'Suspend'}</button>}<button className="delete-button" aria-label={`Delete ${member.name}`} onClick={() => setDeleting(member)}>×</button></div></td></tr>)}</tbody></table></div><div className="team-panel-footer"><button className="primary-button" onClick={onAdd}><span>＋</span> Add worker</button></div></article>{editing && <div className="admin-modal-backdrop"><form className="admin-modal member-form" onSubmit={saveEdit}><button className="admin-modal-close" type="button" onClick={() => setEditing(null)}>×</button><h2>Edit worker</h2><p className="admin-modal-user"><span>Worker ID cannot be changed</span>#{editing.id}</p><div className="form-grid"><label><span>Name</span><input name="name" defaultValue={editing.name} required /></label><label><span>Phone</span><input name="phone" defaultValue={editing.phone} required /></label><label><span>ID number</span><input name="email" type="text" inputMode="numeric" pattern="[0-9]*" defaultValue={workerIdNumber(editing.email)} onChange={(event) => { event.target.value = workerIdNumber(event.target.value) }} /></label><label><span>Department</span><input name="department" defaultValue={editing.department} required /></label><label><span>Pay rate</span><input name="payRate" type="number" min="0" step="0.01" defaultValue={editing.payRate} required /></label><label><span>Pay frequency</span><select name="payFrequency" defaultValue={editing.payFrequency}><option>Daily</option><option>Weekly</option><option>Monthly</option></select></label></div><div className="form-actions"><button type="button" className="secondary-button" onClick={() => setEditing(null)}>Cancel</button><button type="submit" className="primary-button">Save worker</button></div></form></div>}{deleting && <div className="admin-modal-backdrop"><section className="admin-modal member-form"><button className="admin-modal-close" type="button" onClick={() => setDeleting(null)}>×</button><h2>Delete worker</h2><p>Type <strong>{deleting.name}</strong> three times to permanently remove this worker. Existing attendance and payroll records will remain available in Print.</p>{confirmations.map((value, index) => <label className="login-field" key={index}><span>Confirmation {index + 1}</span><input value={value} onChange={(event) => setConfirmations((current) => current.map((item, itemIndex) => itemIndex === index ? event.target.value : item))} /></label>)}<div className="form-actions"><button type="button" className="secondary-button" onClick={() => setDeleting(null)}>Cancel</button><button type="button" className="primary-button delete-confirm-button" disabled={confirmations.some((value) => value.trim().toLowerCase() !== deleting.name.trim().toLowerCase())} onClick={confirmDelete}>Delete worker</button></div></section></div>}</>
}

function PayrollPage({ members, attendance, casualEarnings, deductions, onAddCasualEarning, onRecordCasualPartialPayment, onUpdateStatus, onVerifyPayment, onNavigate }: { members: Member[]; attendance: AttendanceEntry[]; casualEarnings: CasualEarning[]; deductions: Deduction[]; onAddCasualEarning: (earning: CasualEarning) => void; onRecordCasualPartialPayment: (memberId: number, startDate: string, endDate: string, amount: number, reason?: string) => void; onUpdateStatus?: (memberIds: number[], startDate: string, endDate: string, status: PaymentStatus, partialAmount?: number, paymentReasons?: Record<number, string>) => void; onVerifyPayment?: (memberId: number) => Promise<boolean>; onNavigate: (page: string) => void }) {
  const [period, setPeriod] = useState('today')
  const [selectedDay, setSelectedDay] = useState(today)
  const [customStart, setCustomStart] = useState(today)
  const [customEnd, setCustomEnd] = useState(today)
  const [statusFilter, setStatusFilter] = useState('All statuses')
  const [departmentFilter, setDepartmentFilter] = useState('All departments')
  const [selectedMembers, setSelectedMembers] = useState<number[]>([])
  const [detailMemberId, setDetailMemberId] = useState<number | null>(null)
  const [casualStatusPrompt, setCasualStatusPrompt] = useState<PaymentStatus | null>(null)
  const [casualPromptMemberIds, setCasualPromptMemberIds] = useState<number[]>([])
  const [casualPaymentError, setCasualPaymentError] = useState('')
  const [paymentReasonPrompt, setPaymentReasonPrompt] = useState<{ memberIds: number[]; casualMemberIds: number[] } | null>(null)
  const range = period === 'today' ? { start: today, end: today } : period === 'day' ? { start: selectedDay, end: selectedDay } : period === 'week' ? { start: currentWeekStart, end: currentWeekEnd } : period === 'custom' ? { start: customStart, end: customEnd } : { start: currentMonthStart, end: today }
  const completedEntries = attendance.filter((entry) => entry.checkOut !== '—' && members.find((member) => member.id === entry.memberId)?.payTerms !== 'Casual' && entry.date >= (members.find((member) => member.id === entry.memberId)?.payTermsSince || '') && isWithinDateRange(entry.date, range.start, range.end))
  const activeMembers = members.filter((member) => !member.archived)
  const rows = activeMembers.map((member) => {
    const signedInDates = member.payTerms === 'Casual' ? Array.from(new Set(attendance.filter((entry) => entry.memberId === member.id && entry.date >= (member.payTermsSince || '') && Boolean(entry.checkIn && entry.checkIn !== '—') && isWithinDateRange(entry.date, range.start, range.end)).map((entry) => entry.date))).sort() : []
    const recordedCasualEntries = casualEarnings.filter((earning) => earning.memberId === member.id && earning.date >= (member.payTermsSince || '') && earning.amount > 0 && signedInDates.includes(earning.date)).map((earning) => ({ memberId: earning.memberId, date: earning.date, status: 'Present' as AttendanceStatus, checkIn: '—', checkOut: '—', payRate: earning.amount, earningType: 'casual' as const, earningId: earning.id, reason: earning.reason, paymentStatus: earning.paymentStatus, paymentReceived: earning.paymentReceived, paidAt: earning.paidAt, paymentBatchId: earning.paymentBatchId }))
    const entries = member.payTerms === 'Casual' ? recordedCasualEntries : completedEntries.filter((entry) => entry.memberId === member.id)
    const unpaidEntries = entries.filter((entry) => entry.paymentStatus !== 'Paid')
    const carryBalance = Math.max(0, member.payrollCarryBalance || 0)
    const statuses = entries.length === 0 ? [carryBalance > 0 ? 'Pending' : member.payTerms === 'Casual' ? 'No earnings' : 'No shifts'] : Array.from(new Set([...entries.map((entry) => entry.paymentStatus || 'Pending'), ...(carryBalance > 0 ? ['Pending'] : [])]))
    const status = statuses.length === 1 ? statuses[0] : 'Mixed'
    const rowDeductions = deductions.filter((deduction) => !deduction.archived && deduction.memberId === member.id && deduction.date >= (member.payTermsSince || '') && isWithinDateRange(deduction.date, range.start, range.end))
    const paymentAmounts = paymentAmountsForPeriod(member, entries, rowDeductions)
    const amountOwed = paymentAmounts.amountOwed + carryBalance
    return { member, entries, signedInDates, unpaidEntries, shifts: unpaidEntries.length, ...paymentAmounts, amountOwed, owed: amountOwed, balanceRemaining: amountOwed, carryBalance, deductions: rowDeductions, status }
  }).filter((row) => departmentFilter === 'All departments' || row.member.department === departmentFilter).filter((row) => statusFilter === 'All statuses' || row.status === statusFilter)
  const departments = ['All departments', ...Array.from(new Set(activeMembers.map((member) => member.department)))]
  const totalOwed = rows.reduce((sum, row) => sum + row.amountOwed, 0)
  const visibleIds = rows.map((row) => row.member.id)
  const selectableIds = rows.filter((row) => row.entries.length > 0 || row.carryBalance > 0).map((row) => row.member.id)
  const detailMember = members.find((member) => member.id === detailMemberId)
  const detailEntries = detailMember ? rows.find((row) => row.member.id === detailMember.id)?.entries || [] : []
  const detailIsCasual = detailMember?.payTerms === 'Casual'
  const detailGross = detailEntries.reduce((sum, entry) => sum + (entry.payRate ?? detailMember?.payRate ?? 0), 0)
  const detailPaid = detailMember ? detailEntries.reduce((sum, entry) => sum + paymentReceivedForEntry(entry, detailMember), 0) : 0
  const detailDeductionRows = detailMember ? deductions.filter((deduction) => !deduction.archived && deduction.memberId === detailMember.id && isWithinDateRange(deduction.date, range.start, range.end)) : []
  const detailDeductions = detailDeductionRows.reduce((sum, deduction) => sum + deduction.amount, 0)
  const detailDeductionKey = detailDeductionRows.map((deduction) => `${deduction.id}:${deduction.date}:${deduction.amount}`).join('|')
  const detailEntryKey = detailEntries.map((entry) => `${entry.date}:${entry.paymentStatus || 'Pending'}:${entry.paymentReceived || 0}`).join('|')
  useLayoutEffect(() => {
    const table = document.querySelector('.payroll-toolbar + .table-wrap table')
    if (!table) return
    const headers = table.querySelector('thead tr')
    const bodyRows = Array.from(table.querySelectorAll('tbody tr'))
    const headerCells = headers?.querySelectorAll('th')
    if (headerCells?.[2]) headerCells[2].textContent = 'PAY TERMS'
    if (headerCells?.[4]) headerCells[4].textContent = 'UNPAID ITEMS'
    const statusSelect = document.querySelector<HTMLSelectElement>('.payroll-toolbar label:nth-of-type(2) select')
    if (statusSelect && !Array.from(statusSelect.options).some((option) => option.value === 'No earnings')) statusSelect.add(new Option('No earnings', 'No earnings'))
    const viewHeader = document.createElement('th')
    viewHeader.textContent = 'VIEW'
    headers?.appendChild(viewHeader)
    bodyRows.forEach((tableRow, index) => {
      const row = rows[index]
      if (!row) return
      const checkbox = tableRow.querySelector<HTMLInputElement>('input[type="checkbox"]')
      if (checkbox) checkbox.disabled = !row.entries.length && row.carryBalance <= 0
      const cells = tableRow.cells
      if (row.member.payTerms === 'Casual') {
        if (cells[2]) cells[2].textContent = 'Casual'
        if (cells[3]) cells[3].textContent = 'Entered per earning'
        if (cells[4]) cells[4].textContent = `${row.shifts} earning${row.shifts === 1 ? '' : 's'}`
      } else {
        if (cells[2]) cells[2].textContent = row.member.payFrequency
        if (cells[3]) cells[3].textContent = `KES ${row.member.payRate.toLocaleString()} / ${row.member.payFrequency === 'Daily' ? 'day' : row.member.payFrequency === 'Weekly' ? 'week' : 'month'}`
        if (cells[4]) cells[4].textContent = `${row.shifts} shift${row.shifts === 1 ? '' : 's'}`
      }
      const cell = document.createElement('td')
      const button = document.createElement('button')
      button.type = 'button'
      button.className = 'text-button payroll-view-button'
      const isCasualWorker = row.member.payTerms === 'Casual'
      button.textContent = isCasualWorker ? row.signedInDates.length ? 'Add earning' : 'Sign in first' : 'View'
      button.addEventListener('click', () => {
        if (isCasualWorker && !row.signedInDates.length) {
          onNavigate('ROLL')
          return
        }
        if (isCasualWorker) {
          setCasualPaymentError('')
          setCasualStatusPrompt('Pending')
          setCasualPromptMemberIds([row.member.id])
          return
        }
        setDetailMemberId(row.member.id)
      })
      cell.appendChild(button)
      tableRow.appendChild(cell)
    })
    return () => { viewHeader.remove(); bodyRows.forEach((tableRow) => tableRow.lastElementChild?.remove()) }
  }, [rows])
  useEffect(() => {
    document.querySelector('.payroll-detail-dialog')?.remove()
    if (!detailMember) return
    const dialog = document.createElement('div')
    dialog.className = 'payroll-detail-dialog'
    dialog.innerHTML = `<div class="payroll-detail-sheet" role="dialog" aria-modal="true"><button class="payroll-detail-close" aria-label="Close">×</button><p class="eyebrow">EMPLOYEE EARNINGS</p><h2>${detailMember.name}</h2><p class="payroll-detail-id">ID ${detailMember.id} · ${detailMember.department} · ${detailMember.role}</p><div class="payroll-detail-summary"><div><span>${detailIsCasual ? 'Casual pay' : 'Pay rate'}</span><strong>${detailIsCasual ? 'Entered per earning' : `KES ${detailMember.payRate.toLocaleString()}`}</strong><small>${detailIsCasual ? 'No fixed daily or monthly rate' : `per ${detailMember.payFrequency.toLowerCase()}`}</small></div><div><span>${detailIsCasual ? 'Recorded earnings' : 'Completed shifts'}</span><strong>${detailEntries.length}</strong><small>in selected period</small></div></div><dl><div><dt>Gross earned</dt><dd>KES ${detailGross.toLocaleString()}</dd></div><div><dt>Paid so far</dt><dd>KES ${detailPaid.toLocaleString()}</dd></div><div><dt>Deductions</dt><dd>KES ${detailDeductions.toLocaleString()}</dd></div><div class="payroll-detail-total"><dt>Net earned</dt><dd>KES ${(detailGross - detailDeductions).toLocaleString()}</dd></div></dl><p class="payroll-detail-note">${detailIsCasual ? 'Casual earnings are entered individually for each recorded workday.' : "Gross pay is completed shifts multiplied by the worker's pay rate."} Net earned is gross pay less approved deductions.</p></div>`
    const detailRecords = document.createElement('section')
    detailRecords.className = 'payroll-detail-records'
    detailRecords.innerHTML = `<h3>${detailIsCasual ? 'Individual earnings and deductions' : 'Earnings and deductions'}</h3>${detailEntries.map((entry) => `<div class="payroll-detail-record"><span>${formatDate(entry.date)}</span><strong>Earning · KES ${(detailIsCasual ? entry.payRate ?? 0 : detailMember.payRate).toLocaleString()}${detailIsCasual ? '' : ` · ${detailMember.payFrequency.toLowerCase()}`} · Received KES ${paymentReceivedForEntry(entry, detailMember).toLocaleString()}</strong><b>${entry.paymentStatus || 'Pending'}</b></div>`).join('')}${detailDeductionRows.map((deduction) => `<div class="payroll-detail-record"><span>${formatDate(deduction.date)}</span><strong>Deduction · KES ${deduction.amount.toLocaleString()}</strong><b>Applied</b></div>`).join('') || '<p>No deductions in this period.</p>'}`
    dialog.querySelector('.payroll-detail-sheet')?.appendChild(detailRecords)
    const closeDialog = () => setDetailMemberId(null)
    dialog.addEventListener('click', (event) => { if (event.target === dialog || (event.target as HTMLElement).closest('.payroll-detail-close')) closeDialog() })
    const handleEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') closeDialog() }
    document.addEventListener('keydown', handleEscape)
    document.body.appendChild(dialog)
    return () => { document.removeEventListener('keydown', handleEscape); dialog.remove() }
  }, [detailMember, detailIsCasual, detailEntries.length, detailEntryKey, detailGross, detailPaid, detailDeductionKey, range.start, range.end])
  const toggleMember = (memberId: number) => setSelectedMembers((current) => current.includes(memberId) ? current.filter((id) => id !== memberId) : [...current, memberId])
  const toggleVisible = () => setSelectedMembers((current) => selectableIds.length > 0 && selectableIds.every((id) => current.includes(id)) ? current.filter((id) => !selectableIds.includes(id)) : Array.from(new Set([...current, ...selectableIds])))
  const updateSelected = async (status: PaymentStatus) => {
    const selectedRows = rows.filter((row) => selectedMembers.includes(row.member.id) && (row.entries.length > 0 || row.carryBalance > 0))
    const casualIds = selectedRows.filter((row) => row.member.payTerms === 'Casual' && (status !== 'Paid' || row.balanceRemaining > 0)).map((row) => row.member.id)
    const ids = selectedRows.filter((row) => row.member.payTerms !== 'Casual' && (status === 'Paid'
      ? row.carryBalance > 0 || row.entries.some((entry) => paymentReceivedForEntry(entry, row.member) < (entry.payRate ?? row.member.payRate))
      : row.entries.some((entry) => canTransitionPaymentStatus(entry.paymentStatus ?? 'Pending', status)))).map((row) => row.member.id)
    if (!ids.length && !casualIds.length) return
    const updateStatus = onUpdateStatus || (window as any).__biztrackUpdatePayrollStatus
    if (casualIds.length && (status === 'Pending' || status === 'On hold')) updateStatus?.(casualIds, range.start, range.end, status)
    const verifyPayment = onVerifyPayment || (window as any).__biztrackVerifyPayrollPayment
    const verifiedIds: number[] = []
    for (const id of ids) {
      const selectedRow = rows.find((row) => row.member.id === id)
      const hasUnpaid = Boolean(selectedRow?.carryBalance) || (selectedRow?.entries || []).some((entry) => (entry.paymentStatus || 'Pending') !== 'Paid')
      if (!['Paid', 'Partially paid'].includes(status) || !hasUnpaid || Boolean(verifyPayment && await verifyPayment(id))) verifiedIds.push(id)
    }
    if (status === 'Paid' && verifiedIds.length) {
      setPaymentReasonPrompt({ memberIds: verifiedIds, casualMemberIds: casualIds })
      return
    }
    if (verifiedIds.length) updateStatus?.(verifiedIds, range.start, range.end, status)
    if (casualIds.length && status !== 'Pending' && status !== 'On hold') {
      setCasualPaymentError('')
      setCasualStatusPrompt(status)
      setCasualPromptMemberIds(casualIds)
      return
    }
    setSelectedMembers([])
  }
  const updatePartialSelected = async (amounts: Record<number, number>, reasons: Record<number, string> = {}) => {
    const selectedRows = rows.filter((row) => selectedMembers.includes(row.member.id) && row.balanceRemaining > 0)
    const verifyPayment = onVerifyPayment || (window as any).__biztrackVerifyPayrollPayment
    const updateStatus = onUpdateStatus || (window as any).__biztrackUpdatePayrollStatus
    const verifiedRows: typeof selectedRows = []
    for (const row of selectedRows) {
      const amount = amounts[row.member.id]
      const hasUnpaid = row.carryBalance > 0 || row.entries.some((entry) => paymentReceivedForEntry(entry, row.member) < (entry.payRate ?? row.member.payRate))
      if (!Number.isFinite(amount) || amount <= 0 || amount > row.balanceRemaining) continue
      if (hasUnpaid && verifyPayment && !(await verifyPayment(row.member.id))) return false
      if (hasUnpaid) verifiedRows.push(row)
    }
    if (verifiedRows.length !== selectedRows.length || !updateStatus) return false
    verifiedRows.forEach((row) => updateStatus([row.member.id], range.start, range.end, 'Partially paid', amounts[row.member.id], { [row.member.id]: reasons[row.member.id] }))
    setSelectedMembers([])
    return true
  }
  const partialPaymentContext = useRef({ rows, selectedMembers, updatePartialSelected })
  partialPaymentContext.current = { rows, selectedMembers, updatePartialSelected }
  const saveCasualEarnings = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!casualStatusPrompt) return
    const form = new FormData(event.currentTarget)
    const verifyPayment = onVerifyPayment || (window as any).__biztrackVerifyPayrollPayment
    if (casualStatusPrompt === 'Partially paid') {
      const payments = casualPromptMemberIds.map((memberId) => ({ memberId, amount: Number(form.get(`received-${memberId}`)), reason: String(form.get(`reason-${memberId}`) || '').trim(), due: rows.find((row) => row.member.id === memberId)?.balanceRemaining || 0 }))
      const invalidPayment = payments.find((payment) => !Number.isFinite(payment.amount) || payment.amount <= 0 || payment.amount > payment.due || !payment.reason)
      if (invalidPayment) {
        const member = members.find((item) => item.id === invalidPayment.memberId)
        setCasualPaymentError(invalidPayment.reason ? `${member?.name || 'This worker'} is owed KES ${invalidPayment.due.toLocaleString()}. Enter an amount equal to or below the amount owed.` : `Enter a reason for ${member?.name || 'this worker'}'s partial payment.`)
        return
      }
      for (const payment of payments) {
        if (verifyPayment && !(await verifyPayment(payment.memberId))) return
      }
      payments.forEach((payment) => onRecordCasualPartialPayment(payment.memberId, range.start, range.end, payment.amount, payment.reason))
      setCasualStatusPrompt(null)
      setCasualPromptMemberIds([])
      setCasualPaymentError('')
      setSelectedMembers([])
      return
    }
    const batchId = new Date().toISOString()
    const paidAt = localDateKey(new Date())
    const records: CasualEarning[] = []
    const balancePayments: Array<{ memberId: number; amount: number; reason: string }> = []
    for (const [index, memberId] of casualPromptMemberIds.entries()) {
      const row = rows.find((item) => item.member.id === memberId)
      const amount = casualStatusPrompt === 'Paid' ? row?.balanceRemaining || 0 : Number(form.get(`amount-${memberId}`))
      const received = casualStatusPrompt === 'Paid' ? amount : 0
      const reason = String(form.get(`reason-${memberId}`) || '').trim()
      if (!Number.isFinite(amount) || (casualStatusPrompt !== 'Paid' && amount <= 0)) return
      const member = members.find((item) => item.id === memberId)
      if (!member) return
      if (casualStatusPrompt === 'Paid' && amount <= 0) continue
      if (casualStatusPrompt === 'Paid' && !reason) {
        setCasualPaymentError(`Enter the reason for paying ${member.name}.`)
        return
      }
      if (casualStatusPrompt === 'Paid' && row && row.balanceRemaining > 0) {
        if (verifyPayment && !(await verifyPayment(memberId))) return
        balancePayments.push({ memberId, amount, reason })
        continue
      }
      if (casualStatusPrompt === 'Paid') continue
      const earningDate = casualStatusPrompt === 'Pending' ? row?.signedInDates[row.signedInDates.length - 1] || paidAt : paidAt
      records.push({ id: Date.now() + index, memberId, date: earningDate, amount, paymentStatus: casualStatusPrompt, paymentReceived: received, workerName: member.name, workerDepartment: member.department, workerRole: member.role, workerPayTerms: 'Casual', workerPayFrequency: member.payFrequency, reason: casualStatusPrompt === 'Paid' ? reason : undefined, paidAt: received > 0 ? paidAt : undefined, paymentBatchId: batchId })
    }
    balancePayments.forEach((payment) => onRecordCasualPartialPayment(payment.memberId, range.start, range.end, payment.amount, payment.reason))
    records.forEach(onAddCasualEarning)
    setCasualStatusPrompt(null)
    setCasualPromptMemberIds([])
    setCasualPaymentError('')
    setSelectedMembers([])
  }
  const statusClass = (status: string) => status.toLowerCase().replace(' ', '-')
  useEffect(() => {
    if (!paymentReasonPrompt) return
    const overlay = document.createElement('div')
    overlay.className = 'partial-payment-backdrop'
    const dialog = document.createElement('section')
    dialog.className = 'partial-payment-dialog'
    dialog.setAttribute('role', 'dialog')
    dialog.setAttribute('aria-modal', 'true')
    dialog.setAttribute('aria-labelledby', 'payroll-payment-reason-title')
    const heading = document.createElement('div')
    heading.innerHTML = '<p class="eyebrow">PAYROLL PAYMENT</p><h2 id="payroll-payment-reason-title">Record payment reasons</h2><p>Enter the reason for each payment being recorded.</p>'
    const form = document.createElement('form')
    const fields = document.createElement('div')
    fields.className = 'partial-payment-fields'
    paymentReasonPrompt.memberIds.forEach((memberId) => {
      const member = members.find((item) => item.id === memberId)
      if (!member) return
      const label = document.createElement('label')
      const caption = document.createElement('span')
      caption.textContent = `${member.name} · reason for payment`
      const input = document.createElement('input')
      input.type = 'text'
      input.name = String(memberId)
      input.placeholder = 'Reason for payment'
      input.required = true
      label.append(caption, input)
      fields.appendChild(label)
    })
    const error = document.createElement('p')
    error.className = 'partial-payment-error'
    error.setAttribute('role', 'alert')
    const buttons = document.createElement('div')
    buttons.className = 'partial-payment-actions'
    const cancel = document.createElement('button')
    cancel.type = 'button'
    cancel.className = 'secondary-button'
    cancel.textContent = 'Cancel'
    const submit = document.createElement('button')
    submit.type = 'submit'
    submit.className = 'primary-button'
    submit.textContent = 'Record payment'
    buttons.append(cancel, submit)
    form.append(fields, error, buttons)
    dialog.append(heading, form)
    overlay.appendChild(dialog)
    const close = () => setPaymentReasonPrompt(null)
    cancel.addEventListener('click', close)
    overlay.addEventListener('click', (event) => { if (event.target === overlay) close() })
    const handleEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') close() }
    document.addEventListener('keydown', handleEscape)
    form.addEventListener('submit', (event) => {
      event.preventDefault()
      const reasons: Record<number, string> = {}
      fields.querySelectorAll<HTMLInputElement>('input').forEach((input) => { reasons[Number(input.name)] = input.value.trim() })
      if (paymentReasonPrompt.memberIds.some((memberId) => !reasons[memberId])) { error.textContent = 'Enter a reason for each payment.'; return }
      const updateStatus = onUpdateStatus || (window as any).__biztrackUpdatePayrollStatus
      updateStatus?.(paymentReasonPrompt.memberIds, range.start, range.end, 'Paid', undefined, reasons)
      setSelectedMembers([])
      setPaymentReasonPrompt(null)
      if (paymentReasonPrompt.casualMemberIds.length) {
        setCasualPaymentError('')
        setCasualStatusPrompt('Paid')
        setCasualPromptMemberIds(paymentReasonPrompt.casualMemberIds)
      }
    })
    document.body.appendChild(overlay)
    return () => { document.removeEventListener('keydown', handleEscape); overlay.remove() }
  }, [paymentReasonPrompt, members, range.start, range.end, onUpdateStatus])
  useEffect(() => {
    if (casualStatusPrompt !== 'Partially paid') return
    const reasonLabels: HTMLLabelElement[] = []
    document.querySelectorAll<HTMLElement>('.casual-payment-fields').forEach((fields) => {
      const amountInput = fields.querySelector<HTMLInputElement>('input[name^="received-"]')
      if (!amountInput) return
      const memberId = Number(amountInput.name.slice('received-'.length))
      const member = members.find((item) => item.id === memberId)
      if (!member || fields.querySelector('.casual-payment-reason')) return
      const label = document.createElement('label')
      label.className = 'casual-payment-reason'
      const caption = document.createElement('span')
      caption.textContent = `${member.name} · reason for payment`
      const input = document.createElement('input')
      input.type = 'text'
      input.name = `reason-${memberId}`
      input.placeholder = 'Reason for payment'
      input.required = true
      label.append(caption, input)
      fields.appendChild(label)
      reasonLabels.push(label)
    })
    return () => reasonLabels.forEach((label) => label.remove())
  }, [casualStatusPrompt, casualPromptMemberIds, members])
  useEffect(() => {
    const partialButton = document.querySelector<HTMLButtonElement>('.payroll-partial-button')
    if (!partialButton) return
    const openDialog = () => {
      const { rows: currentRows, selectedMembers: currentSelectedMembers, updatePartialSelected: recordPartialPayment } = partialPaymentContext.current
      const selectedRows = currentRows.filter((row) => currentSelectedMembers.includes(row.member.id) && (row.entries.length > 0 || row.carryBalance > 0) && row.balanceRemaining > 0)
      if (!selectedRows.length) return
      const casualRows = selectedRows.filter((row) => row.member.payTerms === 'Casual')
      if (casualRows.length) {
        setCasualPaymentError('')
        setCasualStatusPrompt('Partially paid')
        setCasualPromptMemberIds(casualRows.map((row) => row.member.id))
        return
      }
      const overlay = document.createElement('div')
      overlay.className = 'partial-payment-backdrop'
      const dialog = document.createElement('section')
      dialog.className = 'partial-payment-dialog'
      dialog.setAttribute('role', 'dialog')
      dialog.setAttribute('aria-modal', 'true')
      const heading = document.createElement('div')
      heading.innerHTML = '<p class="eyebrow">PAYROLL PAYMENT</p><h2>Record partial payment</h2><p>Enter the amount received by each selected worker for this period.</p>'
      const form = document.createElement('form')
      const fields = document.createElement('div')
      fields.className = 'partial-payment-fields'
      selectedRows.forEach((row) => {
        const due = row.balanceRemaining
        if (due <= 0) return
        const label = document.createElement('label')
        const caption = document.createElement('span')
        caption.textContent = `${row.member.name} · balance ${due.toLocaleString()}`
        const input = document.createElement('input')
        input.type = 'number'
        input.name = String(row.member.id)
        input.min = '0.01'
        input.max = String(due)
        input.step = '0.01'
        input.placeholder = 'Amount received (KES)'
        input.required = true
        label.append(caption, input)
        fields.appendChild(label)
        const reasonLabel = document.createElement('label')
        const reasonCaption = document.createElement('span')
        reasonCaption.textContent = `${row.member.name} · reason for payment`
        const reasonInput = document.createElement('input')
        reasonInput.type = 'text'
        reasonInput.name = `reason-${row.member.id}`
        reasonInput.placeholder = 'Reason for payment'
        reasonInput.required = true
        reasonLabel.append(reasonCaption, reasonInput)
        fields.appendChild(reasonLabel)
      })
      const disclaimer = document.createElement('p')
      disclaimer.className = 'partial-payment-disclaimer'
      disclaimer.textContent = 'Record only funds already received and independently verified. This entry is for tracking only; it does not transfer money or replace your bank, mobile-money or cash records.'
      const error = document.createElement('p')
      error.className = 'partial-payment-error'
      error.setAttribute('role', 'alert')
      const buttons = document.createElement('div')
      buttons.className = 'partial-payment-actions'
      const cancel = document.createElement('button')
      cancel.type = 'button'
      cancel.className = 'secondary-button'
      cancel.textContent = 'Cancel'
      const submit = document.createElement('button')
      submit.type = 'submit'
      submit.className = 'primary-button'
      submit.textContent = 'Record payment'
      buttons.append(cancel, submit)
      form.append(fields, disclaimer, error, buttons)
      dialog.append(heading, form)
      overlay.appendChild(dialog)
      const close = () => overlay.remove()
      cancel.addEventListener('click', close)
      overlay.addEventListener('click', (event) => { if (event.target === overlay) close() })
      form.addEventListener('submit', (event) => {
        event.preventDefault()
        const amounts: Record<number, number> = {}
        const reasons: Record<number, string> = {}
        let valid = true
        fields.querySelectorAll<HTMLInputElement>('input').forEach((input) => {
          if (input.type === 'number') {
            const amount = Number(input.value)
            const maximum = Number(input.max)
            if (!Number.isFinite(amount) || amount <= 0 || amount > maximum) valid = false
            amounts[Number(input.name)] = amount
          } else {
            reasons[Number(input.name.replace('reason-', ''))] = input.value.trim()
          }
        })
        if (!valid || selectedRows.some((row) => !reasons[row.member.id])) { error.textContent = 'Enter a valid amount and reason for each worker’s payment.'; return }
        void recordPartialPayment(amounts, reasons).then((updated) => { if (updated) close(); else error.textContent = 'Payment was not recorded. Complete the required verification and try again.' })
      })
      document.body.appendChild(overlay)
    }
    partialButton.addEventListener('click', openDialog)
    return () => { partialButton.removeEventListener('click', openDialog); document.querySelector('.partial-payment-backdrop')?.remove() }
  }, [])
  const canRecordPartial = selectedMembers.some((id) => rows.some((row) => row.member.id === id && row.balanceRemaining > 0))
  return <>
    <PageHeading eyebrow="WORKSPACE / PAYROLL" title="Payroll" subtitle="Review completed-shift wages and record casual earnings independently of attendance." />
    <section className="metric-grid">
      <Metric title="Amount owed" value={`KES ${totalOwed.toLocaleString()}`} detail={`${rows.filter((row) => row.owed > 0).length} employees with unpaid earnings`} accent="yellow" outflow />
      <Metric title="Unpaid items" value={String(rows.reduce((sum, row) => sum + row.shifts, 0))} detail="Earnings with an outstanding balance" accent="teal" outflow />
      <Metric title="Paid in view" value={`KES ${rows.reduce((sum, row) => sum + row.entries.reduce((received, entry) => received + paymentReceivedForEntry(entry, row.member), 0), 0).toLocaleString()}`} detail="Recorded receipts" accent="coral" outflow />
      <Metric title="Team in view" value={String(rows.length)} detail="Matching employees" accent="lilac" outflow />
    </section>
    <article className="panel team-panel">
      <PanelHeading title="Employee pay schedule" subtitle={`Showing ${formatDate(range.start)} to ${formatDate(range.end)}. Casual workers must sign in, but do not need to sign out for pay.`} action={<div className="payroll-filters"><select aria-label="Payroll period" className="filter-button" value={period} onChange={(event) => setPeriod(event.target.value)}><option value="month">This month</option><option value="week">This week</option><option value="today">Today</option><option value="day">Particular day</option><option value="custom">Custom range</option></select>{period === 'day' && <input aria-label="Particular day" type="date" value={selectedDay} onChange={(event) => setSelectedDay(event.target.value)} />}{period === 'custom' && <><input aria-label="Start date" type="date" value={customStart} onChange={(event) => setCustomStart(event.target.value)} /><input aria-label="End date" type="date" value={customEnd} onChange={(event) => setCustomEnd(event.target.value)} /></>}</div>} />
      <div className="payroll-toolbar">
        <label><span>Department</span><select value={departmentFilter} onChange={(event) => setDepartmentFilter(event.target.value)}>{departments.map((department) => <option key={department}>{department}</option>)}</select></label>
        <label><span>Payment status</span><select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}><option>All statuses</option><option>Pending</option><option>Paid</option><option>Partially paid</option><option>On hold</option><option>Mixed</option><option>No shifts</option></select></label>
        <div className="payroll-bulk-actions">
          <button className="secondary-button" onClick={() => updateSelected('Pending')} disabled={!selectedMembers.length}>Mark pending</button>
          <button className="secondary-button" onClick={() => updateSelected('On hold')} disabled={!selectedMembers.length}>Put on hold</button>
          <button className="secondary-button payroll-partial-button" disabled={!canRecordPartial}>Mark selected partially paid</button>
          <button className="primary-button" onClick={() => updateSelected('Paid')} disabled={!selectedMembers.length}><span>＋</span> Mark selected paid</button>
        </div>
      </div>
      <div className="table-wrap"><table><thead><tr><th><input aria-label="Select payable employees" type="checkbox" checked={selectableIds.length > 0 && selectableIds.every((id) => selectedMembers.includes(id))} disabled={!selectableIds.length} onChange={toggleVisible} /></th><th>EMPLOYEE</th><th>FREQUENCY</th><th>PAY RATE</th><th>UNPAID SHIFTS</th><th>AMOUNT OWED</th><th>STATUS</th></tr></thead><tbody>{rows.map((row) => <tr key={row.member.id}><td><input aria-label={`Select ${row.member.name}`} type="checkbox" checked={selectedMembers.includes(row.member.id)} onChange={() => toggleMember(row.member.id)} disabled={!row.entries.length && row.carryBalance <= 0} /></td><td><div className="person-cell"><span className={`avatar avatar-${row.member.color}`}>{row.member.initials}</span><strong>{row.member.name}</strong><small className="payroll-member-id">ID #{row.member.id}</small></div></td><td>{row.member.payFrequency}</td><td>KES {row.member.payRate.toLocaleString()} / {row.member.payFrequency === 'Daily' ? 'day' : row.member.payFrequency === 'Weekly' ? 'week' : 'month'}</td><td>{row.shifts}</td><td><strong>KES {row.owed.toLocaleString()}</strong></td><td><span className={`status-pill ${statusClass(row.status)}`}><i></i>{row.status}</span></td></tr>)}</tbody></table></div>
    </article>
    {casualStatusPrompt && <div className="partial-payment-backdrop" role="presentation"><section className="partial-payment-dialog" role="dialog" aria-modal="true" aria-labelledby="casual-payroll-title"><p className="eyebrow">CASUAL PAYROLL</p><h2 id="casual-payroll-title">{casualStatusPrompt === 'Partially paid' ? 'Record partial payment' : casualStatusPrompt === 'Paid' ? 'Record payment' : 'Record pending earning'}</h2><p>{casualStatusPrompt === 'Partially paid' ? 'Enter the amount received for each selected worker, up to their remaining balance.' : casualStatusPrompt === 'Paid' ? 'The full outstanding balance will be recorded as paid.' : 'Enter the earning amount for each selected casual worker.'}</p><form onSubmit={(event) => void saveCasualEarnings(event)}><div className="partial-payment-fields">{casualPromptMemberIds.map((memberId) => { const member = members.find((item) => item.id === memberId); const row = rows.find((item) => item.member.id === memberId); if (!member || !row) return null; return <div className="casual-payment-fields" key={memberId}>{casualStatusPrompt !== 'Paid' && <label><span>{casualStatusPrompt === 'Partially paid' ? `${member.name} · balance KES ${row.balanceRemaining.toLocaleString()} · amount received (KES)` : `${member.name} · earning amount (KES)`}</span><input name={casualStatusPrompt === 'Partially paid' ? `received-${memberId}` : `amount-${memberId}`} type="number" min="0.01" step="0.01" required /></label>}{casualStatusPrompt === 'Paid' && <label><span>{member.name} · reason for payment</span><input name={`reason-${memberId}`} type="text" placeholder="e.g. Weekend catering" required /></label>}</div>})}</div>{casualPaymentError && <p className="partial-payment-error" role="alert">{casualPaymentError}</p>}<p className="partial-payment-disclaimer">Record only funds received for Paid or Partially paid entries. Recording a payment does not transfer money.</p><div className="partial-payment-actions"><button type="button" className="secondary-button" onClick={() => { setCasualStatusPrompt(null); setCasualPromptMemberIds([]); setCasualPaymentError('') }}>Cancel</button><button type="submit" className="primary-button">{casualStatusPrompt === 'Paid' ? 'Record paid balance' : casualStatusPrompt === 'Partially paid' ? 'Record partial payment' : 'Record earning'}</button></div></form></section></div>}
  </>
}


function PenaltiesPage(props: { members: Member[]; attendance: AttendanceEntry[]; casualEarnings?: CasualEarning[]; deductions: Deduction[]; onAdd: (deduction: Deduction) => void; onDelete: (id: number) => void }) {
  useEffect(() => { const heading = document.querySelector('.page-heading h1'); if (heading) heading.textContent = 'Penalties' }, [])
  return <DeductionsPage {...props} />
}

function DeductionsPage({ members, attendance, casualEarnings = [], deductions: storedDeductions, onAdd, onDelete }: { members: Member[]; attendance: AttendanceEntry[]; casualEarnings?: CasualEarning[]; deductions: Deduction[]; onAdd: (deduction: Deduction) => void; onDelete: (id: number) => void }) {
  const deductions = storedDeductions.filter((deduction) => !deduction.archived)
  const latestPaidDateFor = (memberId: number) => [...attendance.filter((entry) => entry.memberId === memberId && entry.paymentStatus === 'Paid' && entry.checkOut !== '—').map((entry) => entry.date), ...casualEarnings.filter((earning) => earning.memberId === memberId && earning.paymentStatus === 'Paid').map((earning) => earning.date)].reduce((latest, date) => date > latest ? date : latest, '')
  const minimumEffectiveDateFor = (memberId: number) => {
    const latestPaidDate = latestPaidDateFor(memberId)
    if (!latestPaidDate) return today
    const nextPaidPeriodDate = new Date(`${latestPaidDate}T00:00:00`)
    nextPaidPeriodDate.setDate(nextPaidPeriodDate.getDate() + 1)
    const nextDate = localDateKey(nextPaidPeriodDate)
    return nextDate > today ? nextDate : today
  }
  const [selectedMemberIds, setSelectedMemberIds] = useState<number[]>([])
  const [effectiveDates, setEffectiveDates] = useState<Record<number, string>>({})
  const [dateWarning, setDateWarning] = useState('')
  const total = deductions.reduce((sum, deduction) => sum + deduction.amount, 0)
  useEffect(() => {
    if (!dateWarning) return
    const overlay = document.createElement('div')
    overlay.className = 'paid-date-warning-backdrop'
    const dialog = document.createElement('section')
    dialog.className = 'paid-date-warning-dialog'
    dialog.setAttribute('role', 'alertdialog')
    dialog.setAttribute('aria-modal', 'true')
    dialog.setAttribute('aria-labelledby', 'paid-date-warning-title')
    const eyebrow = document.createElement('p')
    eyebrow.className = 'eyebrow'
    eyebrow.textContent = 'PAYROLL NOTICE'
    const warningIcon = document.createElement('span')
    warningIcon.className = 'business-alert-icon'
    warningIcon.setAttribute('aria-hidden', 'true')
    warningIcon.textContent = '!'
    const title = document.createElement('h2')
    title.id = 'paid-date-warning-title'
    title.textContent = 'Check deduction details'
    const message = document.createElement('p')
    message.textContent = dateWarning
    const actions = document.createElement('div')
    actions.className = 'business-confirm-actions'
    const button = document.createElement('button')
    button.type = 'button'
    button.className = 'primary-button'
    button.textContent = 'Got it'
    const close = () => setDateWarning('')
    const handleEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') close() }
    button.addEventListener('click', close)
    overlay.addEventListener('click', (event) => { if (event.target === overlay) close() })
    document.addEventListener('keydown', handleEscape)
    actions.append(button)
    dialog.append(eyebrow, warningIcon, title, message, actions)
    overlay.append(dialog)
    document.body.append(overlay)
    button.focus()
    return () => { document.removeEventListener('keydown', handleEscape); overlay.remove() }
  }, [dateWarning])
  const effectiveDateFor = (memberId: number) => effectiveDates[memberId] ?? minimumEffectiveDateFor(memberId)
  const changeEffectiveDate = (memberId: number, date: string) => {
    if (!date) { setEffectiveDates((current) => ({ ...current, [memberId]: '' })); return }
    const paidThroughDate = latestPaidDateFor(memberId)
    if (paidThroughDate && date <= paidThroughDate) {
      const memberName = members.find((member) => member.id === memberId)?.name || 'This worker'
      setDateWarning(`${memberName} has already been paid through ${formatDate(paidThroughDate)}. Choose an effective date after that date.`)
      setEffectiveDates((current) => ({ ...current, [memberId]: minimumEffectiveDateFor(memberId) }))
      return
    }
    if (date < today) {
      setDateWarning('Choose today or a future effective date.')
      setEffectiveDates((current) => ({ ...current, [memberId]: minimumEffectiveDateFor(memberId) }))
      return
    }
    setEffectiveDates((current) => ({ ...current, [memberId]: date }))
  }
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const formElement = event.currentTarget
    const form = new FormData(formElement)
    const amount = Number(form.get('amount'))
    const reason = String(form.get('reason') || '').trim()
    if (amount <= 0 || !reason) return
    const selectedMembers = members.filter((member) => selectedMemberIds.includes(member.id))
    if (!selectedMembers.length) {
      setDateWarning('Select at least one worker to record this deduction.')
      return
    }
    const entries = selectedMembers.map((member) => ({ member, date: effectiveDateFor(member.id) }))
    for (const { member, date } of entries) {
      const paidThroughDate = latestPaidDateFor(member.id)
      if (paidThroughDate && date <= paidThroughDate) {
        setDateWarning(`${member.name} has already been paid through ${formatDate(paidThroughDate)}. Choose an effective date after that date.`)
        setEffectiveDates((current) => ({ ...current, [member.id]: minimumEffectiveDateFor(member.id) }))
        return
      }
      if (!date || date < today) {
        setDateWarning('Choose today or a future effective date for every selected worker.')
        setEffectiveDates((current) => ({ ...current, [member.id]: minimumEffectiveDateFor(member.id) }))
        return
      }
    }
    const firstId = Date.now()
    entries.forEach(({ member, date }, index) => onAdd({ id: firstId + index, memberId: member.id, amount, reason, date }))
    formElement.reset()
    setSelectedMemberIds([])
    setEffectiveDates({})
    formElement.querySelector('details')?.removeAttribute('open')
  }
  const allWorkersSelected = members.length > 0 && members.every((member) => selectedMemberIds.includes(member.id))
  const selectedMembers = members.filter((member) => selectedMemberIds.includes(member.id))
  return <>
    <PageHeading eyebrow="PEOPLE / PAYROLL" title="Deductions" subtitle="Record approved deductions when an employee needs an amount taken from their pay." action={<span className="deduction-note">Changes save to this workspace</span>} />
    <section className="metric-grid">
      <Metric title="Total deducted" value={`KES ${total.toLocaleString()}`} detail={`${deductions.length} recorded deduction${deductions.length === 1 ? '' : 's'}`} accent="coral" />
      <Metric title="This month" value={`KES ${deductions.filter((deduction) => deduction.date.slice(0, 7) === today.slice(0, 7)).reduce((sum, deduction) => sum + deduction.amount, 0).toLocaleString()}`} detail="Current payroll period" accent="yellow" />
      <Metric title="Employees affected" value={String(new Set(deductions.map((deduction) => deduction.memberId)).size)} detail="With deductions on file" accent="teal" />
      <Metric title="Average deduction" value={`KES ${deductions.length ? Math.round(total / deductions.length).toLocaleString() : '0'}`} detail="Across all records" accent="lilac" />
    </section>
    <div className="deductions-layout">
      <form className="panel member-form sales-form" onSubmit={submit}>
        <PanelHeading title="Add a deduction" subtitle="Only record deductions that have been reviewed and approved." />
        <div className="deduction-name-field">
          <span className="deduction-name-label">Name <b>*</b></span>
          <details className="deduction-worker-picker">
            <summary className="deduction-worker-picker-trigger" title={selectedMembers.map((member) => member.name).join(', ')}>
              <span className="deduction-worker-picker-names">{selectedMembers.length ? selectedMembers.map((member) => member.name).join(', ') : 'Select worker(s)'}</span>
              <span className="deduction-worker-picker-count">{selectedMembers.length ? `${selectedMembers.length} selected` : 'Choose'}</span>
            </summary>
            <div className="deduction-worker-menu">
              <div className="table-wrap deduction-worker-wrap">
                <table className="deduction-worker-table">
                  <thead><tr>
                    <th><input aria-label="Select all workers" type="checkbox" checked={allWorkersSelected} disabled={!members.length} onChange={() => setSelectedMemberIds(allWorkersSelected ? [] : members.map((member) => member.id))} /></th>
                    <th>WORKER</th>
                    <th>PAYMENT</th>
                    <th>EFFECTIVE DATE</th>
                  </tr></thead>
                  <tbody>{members.map((member) => {
                    const isSelected = selectedMemberIds.includes(member.id)
                    const paidDate = latestPaidDateFor(member.id)
                    return <tr key={member.id}>
                      <td><input aria-label={`Select ${member.name}`} type="checkbox" checked={isSelected} onChange={() => setSelectedMemberIds((current) => isSelected ? current.filter((id) => id !== member.id) : [...current, member.id])} /></td>
                      <td><div className="person-cell"><span className={`avatar avatar-${member.color}`}>{member.initials}</span><strong>{member.name}</strong></div></td>
                      <td>{paidDate ? `Paid through ${formatDate(paidDate)}` : 'No payment received'}</td>
                      <td><input aria-label={`${member.name} effective date`} name={`date-${member.id}`} type="date" min={minimumEffectiveDateFor(member.id)} value={effectiveDateFor(member.id)} onChange={(event) => changeEffectiveDate(member.id, event.currentTarget.value)} disabled={!isSelected} /></td>
                    </tr>
                  })}</tbody>
                </table>
              </div>
            </div>
          </details>
        </div>
        <div className="form-grid single-field">
          <label><span>Amount <b>*</b></span><input name="amount" type="number" min="1" step="0.01" placeholder="e.g. 5000" required /></label>
          <label><span>Reason <b>*</b></span><input name="reason" placeholder="e.g. Stock shortage" required /></label>
        </div>
        <div className="form-actions"><button type="submit" className="primary-button"><span>＋</span> Record deduction</button></div>
      </form>
      <article className="panel team-panel">
        <PanelHeading title="Deduction history" subtitle="Review amounts recorded against employee pay." />
        {deductions.length ? <div className="table-wrap"><table><thead><tr><th>EMPLOYEE</th><th>REASON</th><th>DATE</th><th>AMOUNT</th><th>ACTION</th></tr></thead><tbody>{deductions.map((deduction) => { const member = members.find((item) => item.id === deduction.memberId); return <tr key={deduction.id}><td><div className="person-cell"><span className={`avatar avatar-${member?.color || 'mint'}`}>{member?.initials || '?'}</span><strong>{member?.name || 'Removed employee'}</strong></div></td><td>{deduction.reason}</td><td>{formatDate(deduction.date)}</td><td><strong>KES {deduction.amount.toLocaleString()}</strong></td><td><button className="delete-button" aria-label={`Remove deduction for ${member?.name || 'employee'}`} onClick={() => onDelete(deduction.id)}>×</button></td></tr>})}</tbody></table></div> : <div className="deductions-empty"><strong>No deductions recorded</strong><p>Approved deductions will appear here for review.</p></div>}
      </article>
    </div>
  </>
}
function SalesPage({ sales, salesHistory, onAdd, onReset, onDelete }: { sales: Sale[]; salesHistory: Sale[]; onAdd: (sale: Sale) => void; onReset: () => void; onDelete: (id: number) => void }) {
  const activeSales = sales.filter((sale) => !sale.archived)
  const allHistory = [...sales, ...salesHistory].filter((sale) => !sale.archived)
  const total = activeSales.reduce((sum, sale) => sum + sale.amount, 0)
  const cashTotal = activeSales.filter((sale) => sale.paymentMethod === 'Cash').reduce((sum, sale) => sum + sale.amount, 0)
  const creditTotal = activeSales.filter((sale) => sale.paymentMethod === 'Credit').reduce((sum, sale) => sum + sale.amount, 0)
  const mobileTotal = activeSales.filter((sale) => sale.paymentMethod === 'Mobile money').reduce((sum, sale) => sum + sale.amount, 0)
  const submit = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); const form = new FormData(event.currentTarget); onAdd({ id: Date.now(), amount: Number(form.get('amount')), paymentMethod: String(form.get('paymentMethod')) as PaymentMethod, date: today, time: '', cashier: '' }); event.currentTarget.reset() }
  return <><PageHeading eyebrow="WORKSPACE / SALES" title="Sales" subtitle="Record the total sales received today and track how customers paid." action={<button className="secondary-button" onClick={onReset}>Archive today</button>} /><section className="metric-grid"><Metric title="Today’s sales" value={`KES ${total.toLocaleString()}`} detail={`${activeSales.length} record${activeSales.length === 1 ? '' : 's'} today`} accent="coral" /><Metric title="Cash" value={`KES ${cashTotal.toLocaleString()}`} detail="Received in cash" accent="yellow" /><Metric title="Credit" value={`KES ${creditTotal.toLocaleString()}`} detail="Recorded on credit" accent="teal" /><Metric title="Mobile money" value={`KES ${mobileTotal.toLocaleString()}`} detail="Received by mobile money" accent="lilac" /></section><div className="sales-layout"><form className="panel member-form sales-form" onSubmit={submit}><PanelHeading title="Record daily sales" subtitle="Choose where the money was received." /><div className="form-grid single-field"><label><span>Total amount <b>*</b></span><input name="amount" type="number" min="0.01" step="0.01" required placeholder="e.g. 12500" /></label><label><span>Money received through <b>*</b></span><select name="paymentMethod" defaultValue="Cash" required><option>Cash</option><option>Credit</option><option>Mobile money</option></select></label></div><button className="primary-button" type="submit"><span>＋</span> Record sales</button></form><article className="panel team-panel"><PanelHeading title="Sales history" subtitle="Every record includes the registered cashier name and exact recording time." /><div className="table-wrap"><table><thead><tr><th>AMOUNT</th><th>PAYMENT METHOD</th><th>DATE</th><th>TIME</th><th>RECORDED BY</th><th>ACTION</th></tr></thead><tbody>{allHistory.length ? allHistory.map((sale) => <tr key={`${sale.id}-${sale.time}`}><td><strong>KES {sale.amount.toLocaleString()}</strong></td><td><span className="role-pill">{sale.paymentMethod || 'Cash'}</span></td><td>{formatDate(sale.date)}</td><td>{sale.time || 'Time unavailable'}</td><td>{sale.cashier || 'Registered account'}</td><td><button type="button" className="delete-button" aria-label={`Remove sales transaction ${sale.id}`} onClick={() => onDelete(sale.id)}>×</button></td></tr>) : <tr><td colSpan={6}>No sales recorded yet.</td></tr>}</tbody></table></div></article></div></> }

function InventoryPage({ inventory, categories, onAdd, onAdjust }: { inventory: InventoryItem[]; categories: string[]; onAdd: (item: InventoryItem) => void; onAdjust: (id: number, amount: number) => void }) { const [category, setCategory] = useState('All'); const visibleItems = category === 'All' ? inventory : inventory.filter((item) => item.category === category); const submit = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); const form = new FormData(event.currentTarget); onAdd({ id: Date.now(), name: String(form.get('name')), category: String(form.get('category')), quantity: Number(form.get('quantity')), unit: String(form.get('unit')), reorderAt: Number(form.get('reorderAt')) }); event.currentTarget.reset() }; return <><PageHeading eyebrow="WORKSPACE / STORE" title="Store inventory" subtitle="See what is in the store, grouped by category, and keep stock levels healthy." /><section className="metric-grid"><Metric title="Items tracked" value={String(inventory.length)} detail="Across all categories" accent="teal" /><Metric title="Low stock" value={String(inventory.filter((item) => item.quantity <= item.reorderAt).length).padStart(2, '0')} detail="Needs restocking" accent="coral" /><Metric title="Categories" value={String(categories.length - 1)} detail="Organized stock" accent="yellow" /><Metric title="Units in store" value={String(inventory.reduce((sum, item) => sum + item.quantity, 0))} detail="Total quantity" accent="lilac" /></section><div className="sales-layout"><form className="panel member-form sales-form" onSubmit={submit}><PanelHeading title="Add stock item" subtitle="Add products, supplies, or ingredients" /><div className="form-grid single-field"><label><span>Item name <b>*</b></span><input name="name" placeholder="e.g. Sugar" required /></label><label><span>Category <b>*</b></span><select name="category"><option>Beverages</option><option>Food</option><option>Dairy</option><option>Supplies</option><option>Retail</option></select></label><label><span>Quantity <b>*</b></span><input name="quantity" type="number" min="0" required placeholder="20" /></label><label><span>Unit <b>*</b></span><input name="unit" placeholder="kg, L, pieces" required /></label><label><span>Reorder at</span><input name="reorderAt" type="number" min="0" defaultValue="5" /></label></div><button className="primary-button" type="submit"><span>＋</span> Add to store</button></form><article className="panel team-panel"><PanelHeading title="Stock by category" subtitle="Adjust quantities when stock arrives or is used" action={<select className="filter-button" value={category} onChange={(event) => setCategory(event.target.value)}>{categories.map((item) => <option key={item}>{item}</option>)}</select>} /><div className="table-wrap"><table><thead><tr><th>ITEM</th><th>CATEGORY</th><th>IN STORE</th><th>STATUS</th><th>ADJUST</th></tr></thead><tbody>{visibleItems.map((item) => <tr key={item.id}><td><strong>{item.name}</strong></td><td><span className="role-pill">{item.category}</span></td><td>{item.quantity} {item.unit}</td><td><span className={`status-pill ${item.quantity <= item.reorderAt ? 'late' : 'present'}`}><i></i>{item.quantity <= item.reorderAt ? 'Low stock' : 'In stock'}</span></td><td><button className="quantity-button" onClick={() => onAdjust(item.id, -1)}>-</button><button className="quantity-button" onClick={() => onAdjust(item.id, 1)}>+</button></td></tr>)}</tbody></table></div></article></div></> }

function StockPage({ businessName, inventory, expenses, categories, categoryUnits, categoryThresholds, onAddStock, onAddExpense }: { businessName: string; inventory: InventoryItem[]; expenses: Expense[]; categories: string[]; categoryUnits: Record<string, string>; categoryThresholds: Record<string, number>; onAddStock: (item: InventoryItem) => void; onAddExpense: (expense: Expense) => void }) {
  const [category, setCategory] = useState('')
  const availableCategories = useMemo(() => Array.from(new Set([...categories, ...inventory.map((item) => item.category)])).filter(Boolean), [categories, inventory])
  useEffect(() => { if (category !== 'All' && !availableCategories.includes(category) && availableCategories.length) setCategory(availableCategories[0]) }, [availableCategories, category])
  const selectedCategory = category === 'All' || availableCategories.includes(category) ? category : availableCategories[0] || ''
  const visibleItems = selectedCategory === 'All' ? inventory : inventory.filter((item) => item.category === selectedCategory)
    const [stockCategory, setStockCategory] = useState(categories[0] || inventory[0]?.category || '')
    const [stockItemName, setStockItemName] = useState('')
    const [stockUnit, setStockUnit] = useState(categoryUnits[categories[0] || inventory[0]?.category || ''] || '')
    const [stockReorderAt, setStockReorderAt] = useState(categoryThresholds[categories[0] || inventory[0]?.category || ''] ?? 5)
    const [stockItemPickerOpen, setStockItemPickerOpen] = useState(false)
    const [stockItemPickerSuppressed, setStockItemPickerSuppressed] = useState(false)
    const stockItemsInCategory = inventory.filter((item) => item.category === stockCategory).sort((first, second) => first.name.localeCompare(second.name))
  const categoryRows = availableCategories.map((name) => { const items = inventory.filter((item) => item.category === name); const used = expenses.filter((expense) => expense.category === name).reduce((sum, expense) => sum + expense.quantity, 0); const stocked = items.reduce((sum, item) => sum + (item.initialQuantity ?? item.quantity), 0); return { name, items, stocked, used, remaining: items.reduce((sum, item) => sum + item.quantity, 0) } })
  const addStock = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const stockForm = event.currentTarget
    const form = new FormData(stockForm)
    const selectedCategory = String(form.get('category') || stockCategory)
    const enteredName = String(form.get('name') || '').trim()
    const existingItem = inventory.find((item) => item.category === selectedCategory && item.name.trim().toLowerCase() === enteredName.toLowerCase())
    if (!enteredName) return
    if (existingItem && !await showBusinessConfirm(businessName, `“${existingItem.name}” already exists in ${selectedCategory}. Add stock to the existing item?`)) return
    onAddStock({ id: existingItem?.id || Date.now(), name: existingItem?.name || enteredName, category: selectedCategory, quantity: Number(form.get('quantity')), unit: existingItem?.unit || String(form.get('unit') || categoryUnits[selectedCategory] || 'pieces'), reorderAt: existingItem?.reorderAt ?? (form.get('reorderAt') === null ? categoryThresholds[selectedCategory] ?? 5 : Number(form.get('reorderAt'))) })
    stockForm.reset()
    setStockItemName('')
    setStockUnit(categoryUnits[selectedCategory] || '')
    setStockReorderAt(categoryThresholds[selectedCategory] ?? 5)
    setStockItemPickerOpen(false)
    setStockItemPickerSuppressed(false)
  }
  const addExpense = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); const form = new FormData(event.currentTarget); const item = inventory.find((entry) => entry.id === Number(form.get('inventoryItemId'))); const quantity = Number(form.get('quantity')); if (!item || quantity <= 0) return; if (quantity > item.quantity) { showBusinessAlert(businessName, `${item.name} has ${item.quantity} ${item.unit} remaining, but ${quantity} ${item.unit} was entered. Add stock or enter a smaller quantity.`); return } const now = new Date(); onAddExpense({ id: Date.now(), inventoryItemId: item.id, itemName: item.name, category: item.category, quantity, unit: item.unit, reason: String(form.get('reason')), date: String(form.get('date') || today), time: now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) }); event.currentTarget.reset() }
  const total = (key: 'stocked' | 'used' | 'remaining') => categoryRows.reduce((sum, row) => sum + row[key], 0)
  return <>
    <PageHeading eyebrow="WORKSPACE / STORE" title="Stock movement" subtitle="Record what enters the store, what is used, and what remains by category." />
    <section className="metric-grid"><Metric title="Stocked" value={String(total('stocked'))} detail="Units added" accent="teal" /><Metric title="Used / consumed" value={String(total('used'))} detail="Units leaving stock" accent="coral" /><Metric title="Remaining" value={String(total('remaining'))} detail="Units currently in store" accent="yellow" /><Metric title="Categories" value={String(categoryRows.length)} detail="Tracked stock groups" accent="lilac" /></section>
    <div className="stock-forms">
      <form className="panel member-form sales-form" onSubmit={addStock}>
        <PanelHeading title="Add stock" subtitle="All incoming stock is recorded here." />
        <div className="form-grid single-field">
          <label className="stock-item-field">
            <span>Item name <b>*</b></span>
            <input name="name" value={stockItemName} onChange={(event) => { setStockItemName(event.target.value); if (!stockItemPickerSuppressed) setStockItemPickerOpen(true) }} onFocus={() => { if (!stockItemPickerSuppressed) setStockItemPickerOpen(true) }} onClick={() => { if (!stockItemPickerSuppressed) setStockItemPickerOpen(true) }} autoComplete="off" required aria-haspopup="listbox" aria-expanded={stockItemPickerOpen} aria-controls="stock-item-options" />
            <div className="stock-item-picker" id="stock-item-options" role="listbox" aria-label={`${stockCategory} items`} hidden={!stockItemPickerOpen || !availableCategories.includes(stockCategory)}>
              <span className="stock-item-picker-title">{stockCategory} items in store</span>
              {stockItemsInCategory.map((item) => <button type="button" role="option" aria-selected={stockItemName === item.name} key={item.id} onMouseDown={(event) => event.preventDefault()} onClick={() => { setStockItemName(item.name); setStockUnit(item.unit); setStockReorderAt(item.reorderAt); setStockItemPickerSuppressed(false); setStockItemPickerOpen(false) }}><span>{item.name}</span><small>{item.quantity} {item.unit} remaining</small></button>)}
              {availableCategories.includes(stockCategory) && <button type="button" className="stock-item-add-new" onMouseDown={(event) => event.preventDefault()} onClick={() => { setStockItemPickerSuppressed(true); setStockItemPickerOpen(false) }}>+ Add new</button>}
            </div>
          </label>
          <label><span>Category <b>*</b></span><select name="category" value={stockCategory} onChange={(event) => { const nextCategory = event.target.value; setStockCategory(nextCategory); setStockItemName(''); setStockUnit(categoryUnits[nextCategory] || ''); setStockReorderAt(categoryThresholds[nextCategory] ?? 5); setStockItemPickerSuppressed(false); setStockItemPickerOpen(false) }} required>{availableCategories.map((item) => <option key={item}>{item}</option>)}</select></label>
          <label><span>Quantity added <b>*</b></span><input name="quantity" type="number" min="1" required /></label>
          <label><span>Unit <b>*</b></span><input name="unit" value={stockUnit} onChange={(event) => setStockUnit(event.target.value)} placeholder="kg, pieces" required /></label>
          <label><span>Reorder at</span><input name="reorderAt" type="number" min="0" value={stockReorderAt} onChange={(event) => setStockReorderAt(Number(event.target.value))} required /></label>
        </div>
        <button className="primary-button" type="submit">+ Add stock</button>
      </form>
      <form className="panel member-form sales-form" onSubmit={addExpense}>
        <PanelHeading title="Record used / consumed" subtitle="Outgoing stock is deducted from the selected item." />
        <div className="form-grid single-field">
          <label><span>Category</span><select value={category} onChange={(event) => setCategory(event.target.value)}><option>All</option>{availableCategories.map((item) => <option key={item}>{item}</option>)}</select></label>
          <label><span>Item <b>*</b></span><select name="inventoryItemId" required>{visibleItems.map((item) => <option key={item.id} value={item.id}>{item.name} · {item.quantity} {item.unit} remaining</option>)}</select></label>
          <label><span>Quantity used <b>*</b></span><input name="quantity" type="number" min="1" required /></label>
          <label><span>Reason <b>*</b></span><input name="reason" placeholder="Kitchen use, issued, damaged" required /></label>
          <label><span>Date <b>*</b></span><input name="date" type="date" defaultValue={today} required /></label>
        </div>
        <button className="primary-button" type="submit" disabled={!visibleItems.length}>− Record usage</button>
      </form>
    </div>
    <article className="panel stock-category-panel"><PanelHeading title="Stock by category" subtitle="Incoming, outgoing, and remaining quantities. Use the forms above to change stock." /><div className="table-wrap"><table><thead><tr><th>Category</th><th>Stocked</th><th>Used / consumed</th><th>Remaining</th><th>Items</th></tr></thead><tbody>{categoryRows.map((row) => <tr key={row.name}><td>{row.name}</td><td>{row.stocked}</td><td>{row.used}</td><td><strong>{row.remaining}</strong></td><td>{row.items.length}</td></tr>)}</tbody></table></div></article>
  </>
}

function ExpensesPage({ expenses, inventory, onAdd }: { expenses: Expense[]; inventory: InventoryItem[]; onAdd: (expense: Expense) => void }) {
  const [category, setCategory] = useState('All')
  const categories = Array.from(new Set(inventory.map((item) => item.category)))
  const visibleItems = category === 'All' ? inventory : inventory.filter((item) => item.category === category)
  const totalUnits = expenses.reduce((sum, expense) => sum + expense.quantity, 0)
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const item = inventory.find((entry) => entry.id === Number(form.get('inventoryItemId')))
    const quantity = Number(form.get('quantity'))
    if (!item || quantity <= 0 || quantity > item.quantity) return
    const now = new Date()
    onAdd({ id: Date.now(), inventoryItemId: item.id, itemName: item.name, category: item.category, quantity, unit: item.unit, reason: String(form.get('reason') || 'Store usage'), date: String(form.get('date') || today), time: now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) })
    event.currentTarget.reset()
  }
  return <><PageHeading eyebrow="WORKSPACE / STORE" title="Expenses" subtitle="Track stock leaving the store by item, category, reason, and date." /><section className="metric-grid"><Metric title="Expense records" value={String(expenses.length)} detail="Outgoing stock entries" accent="coral" /><Metric title="Units issued" value={String(totalUnits)} detail="Removed from inventory" accent="yellow" /><Metric title="Categories used" value={String(new Set(expenses.map((expense) => expense.category)).size)} detail="Categories with movement" accent="teal" /><Metric title="Items available" value={String(inventory.length)} detail="Linked to inventory" accent="lilac" /></section><div className="sales-layout"><form className="panel member-form sales-form" onSubmit={submit}><PanelHeading title="Record stock leaving" subtitle="Saving an expense automatically reduces stock on hand." /><div className="form-grid single-field"><label><span>Category</span><select value={category} onChange={(event) => setCategory(event.target.value)}><option>All</option>{categories.map((item) => <option key={item}>{item}</option>)}</select></label><label><span>Inventory item <b>*</b></span><select name="inventoryItemId" required>{visibleItems.length ? visibleItems.map((item) => <option key={item.id} value={item.id}>{item.name} · {item.quantity} {item.unit} available</option>) : <option value="">No stock items available</option>}</select></label><label><span>Quantity used <b>*</b></span><input name="quantity" type="number" min="1" required /></label><label><span>Reason <b>*</b></span><input name="reason" placeholder="e.g. Kitchen use, damaged, issued" required /></label><label><span>Date <b>*</b></span><input name="date" type="date" defaultValue={today} required /></label></div><div className="form-actions"><button className="primary-button" type="submit" disabled={!visibleItems.length}>− Record expense</button></div></form><article className="panel inventory-panel"><PanelHeading title="Recent stock movement" subtitle="Outgoing quantities are reflected in Inventory immediately." /><div className="table-wrap"><table><thead><tr><th>Date</th><th>Item</th><th>Category</th><th>Reason</th><th>Quantity</th></tr></thead><tbody>{expenses.slice(0, 12).map((expense) => <tr key={expense.id}><td>{formatDate(expense.date)}<small>{expense.time}</small></td><td>{expense.itemName}</td><td>{expense.category}</td><td>{expense.reason}</td><td>{expense.quantity} {expense.unit}</td></tr>)}</tbody></table></div></article></div></>
}

function DepartmentsPage({ departments, members, onAdd, onDelete }: { departments: string[]; members: Member[]; onAdd: (name: string) => void; onDelete: (name: string) => void }) {
  const [name, setName] = useState('')
  const [editing, setEditing] = useState<string | null>(null)
  const submit = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); const nextName = name.trim(); if (!nextName) return; (window as any).__biztrackAddDepartment?.(nextName); setName('') }
  return <><PageHeading eyebrow="WORKSPACE / ORGANIZATION" title="Departments" subtitle="Organize your team and see where every worker is assigned." /><section className="settings-stack"><form className="panel member-form" onSubmit={submit}><PanelHeading title="Add a department" subtitle="Create departments here and assign workers from their profiles." /><div className="form-grid"><label><span>Department name</span><input value={name} onChange={(event) => setName(event.target.value)} placeholder="e.g. Customer service" required /></label><div className="form-actions"><button className="primary-button" type="submit"><span>＋</span> Add department</button></div></div></form><article className="panel department-panel"><PanelHeading title={`${departments.length} departments`} subtitle="Available departments in this workspace" /><div className="department-grid">{departments.map((department, index) => <div className="department-card" key={department}><div className={`department-icon department-icon-${index % 4}`}>▦</div><div className="department-card-copy"><h3>{editing === department ? <input className="department-edit-input" defaultValue={department} onKeyDown={(event) => { if (event.key === 'Enter') { const input = event.currentTarget; if ((window as any).__biztrackRenameDepartment?.(department, input.value)) setEditing(null) } }} /> : department}</h3><p>{members.filter((member) => member.department === department).length} workers</p></div>{editing === department ? <button className="table-action" type="button" onClick={(event) => { const input = (event.currentTarget.parentElement?.querySelector('input') as HTMLInputElement | null); if (input && (window as any).__biztrackRenameDepartment?.(department, input.value)) setEditing(null) }}>Save</button> : <button className="table-action" type="button" onClick={() => setEditing(department)}>Edit</button>}<button className="delete-button" aria-label={`Delete ${department}`} onClick={() => onDelete(department)}>×</button></div>)}</div></article></section></>
}

function AddDepartmentPage({ onSubmit, onCancel }: { onSubmit: (event: FormEvent<HTMLFormElement>) => void; onCancel: () => void }) { return <><PageHeading eyebrow="WORKSPACE / ORGANIZATION" title="Add a department" subtitle="Create a department to make team assignments easier to manage." /><form className="panel member-form" onSubmit={onSubmit}><div className="form-heading"><div><h2>Department details</h2><p>Give the department a clear name your team will recognize.</p></div><span className="required-note">* Required</span></div><div className="form-grid single-field"><label><span>Department name <b>*</b></span><input name="departmentName" placeholder="e.g. Customer service" required /></label></div><div className="form-actions"><button type="button" className="secondary-button" onClick={onCancel}>Cancel</button><button type="submit" className="primary-button"><span>＋</span> Add department</button></div></form></> }

function AddMemberPage({ departments, defaultSignIn, defaultSignOut, onSubmit, onCancel }: { departments: string[]; defaultSignIn: string; defaultSignOut: string; onSubmit: (event: FormEvent<HTMLFormElement>) => void; onCancel: () => void }) { return <><PageHeading eyebrow="PEOPLE / TEAM" title="Add a worker" subtitle="Create a profile, pay schedule, and attendance schedule." /><form className="panel member-form" onSubmit={onSubmit}><div className="form-heading"><div><h2>Worker details</h2><p>Pay is added when the employee completes a sign-in and sign-out shift.</p></div><span className="required-note">* Required</span></div><div className="form-grid"><label><span>Full name <b>*</b></span><input name="fullName" placeholder="e.g. Chidi Okafor" required /></label><label><span>Phone number <b>*</b></span><input name="phone" placeholder="e.g. +234 803 123 4567" required /></label><label><span>ID number</span><input name="email" type="text" inputMode="numeric" pattern="[0-9]*" placeholder="Worker ID number" onChange={(event) => { event.target.value = workerIdNumber(event.target.value) }} /></label><label><span>Department <b>*</b></span><select name="department" defaultValue={departments[0]} required>{departments.length ? departments.map((department) => <option key={department}>{department}</option>) : <option value="Unassigned">Unassigned</option>}</select></label><label><span>Pay rate <b>*</b></span><input name="payRate" type="number" min="0" step="0.01" placeholder="1000" required /></label><label><span>Pay frequency <b>*</b></span><select name="payFrequency" defaultValue="Daily"><option>Daily</option><option>Weekly</option><option>Monthly</option></select></label><label><span>Sign-in time</span><input name="signInTime" type="time" defaultValue={defaultSignIn} /></label><label><span>Sign-out time</span><input name="signOutTime" type="time" defaultValue={defaultSignOut} /></label></div><section className="account-access-section"><div><h2>Login account</h2><p>Enable this only if the employee should sign in and receive page access from the owner.</p></div><label className="account-toggle"><input name="hasAccount" type="checkbox" /><span><strong>Give this worker a login account</strong><small>Only enabled account holders appear in Permissions.</small></span></label><div className="form-grid account-fields"><label><span>Username</span><input name="username" placeholder="e.g. chidi.okafor" /></label><label><span>Password</span><input name="password" type="password" minLength={6} placeholder="At least 6 characters" /></label></div></section><div className="form-actions"><button type="button" className="secondary-button" onClick={onCancel}>Cancel</button><button type="submit" className="primary-button"><span>＋</span> Add worker</button></div></form></> }

function SettingsPage({ members, defaultSignIn, defaultSignOut, strictSignIn, setStrictSignIn, categories, setCategories, setDefaultSignIn, setDefaultSignOut, setMembers, onChange }: { members: Member[]; defaultSignIn: string; defaultSignOut: string; strictSignIn: boolean; setStrictSignIn: (value: boolean) => void; categories: string[]; setCategories: (value: string[]) => void; setDefaultSignIn: (value: string) => void; setDefaultSignOut: (value: string) => void; setMembers: (members: Member[]) => void; onChange: () => void }) { return <><PageHeading eyebrow="WORKSPACE / SETTINGS" title="Settings" subtitle="Set attendance rules and individual employee schedules." /><section className="settings-stack"><article className="panel member-form"><PanelHeading title="Default attendance times" subtitle="New members use these times unless you set a specific schedule." /><div className="form-grid settings-times"><label><span>Default sign-in time</span><input type="time" value={defaultSignIn} onChange={(event) => { setDefaultSignIn(event.target.value); onChange() }} /></label><label><span>Default sign-out time</span><input type="time" value={defaultSignOut} onChange={(event) => { setDefaultSignOut(event.target.value); onChange() }} /></label><label><span>Strict sign-in checks</span><input type="checkbox" checked={strictSignIn} onChange={(event) => { setStrictSignIn(event.target.checked); onChange() }} /></label><label><span>Inventory categories</span><input type="text" value={categories.join(', ')} onChange={(event) => { const nextCategories = event.target.value.split(',').map((item) => item.trim()).filter(Boolean); setCategories(nextCategories.length ? nextCategories : categories); onChange() }} /></label></div></article><article className="panel team-panel"><PanelHeading title="Employee attendance settings" subtitle="Set the expected sign-in and sign-out time for specific people" /><div className="table-wrap"><table><thead><tr><th>EMPLOYEE</th><th>EXPECTED SIGN-IN</th><th>EXPECTED SIGN-OUT</th><th>ACTION</th></tr></thead><tbody>{members.map((member) => <tr key={member.id}><td><div className="person-cell"><span className={`avatar avatar-${member.color}`}>{member.initials}</span><strong>{member.name}</strong></div></td><td><input className="table-input" type="time" value={member.signInTime} onChange={(event) => { setMembers(members.map((item) => item.id === member.id ? { ...item, signInTime: event.target.value } : item)); onChange() }} /></td><td><input className="table-input" type="time" value={member.signOutTime} onChange={(event) => { setMembers(members.map((item) => item.id === member.id ? { ...item, signOutTime: event.target.value } : item)); onChange() }} /></td><td><span className="status-pill present"><i></i>Saved locally</span></td></tr>)}</tbody></table></div></article></section></> }

function LegacyWorkerSignInPage({ members, entries, strictSignIn, defaultSignIn, onAttendance, onMarkAttendance, onMarkSignOut }: { members: Member[]; entries: AttendanceEntry[]; strictSignIn: boolean; defaultSignIn: string; onAttendance: () => void; onMarkAttendance: (memberId: number, status: 'Present' | 'Absent') => boolean | void | Promise<boolean | void>; onMarkSignOut?: (memberId: number) => boolean | Promise<boolean> }) { const [selectedDepartment, setSelectedDepartment] = useState(''); const [selectedWorkerId, setSelectedWorkerId] = useState<number | ''>(''); const departments = Array.from(new Set(members.map((member) => member.department))); const visibleMembers = selectedDepartment ? members.filter((member) => member.department === selectedDepartment) : []; const selectedMember = visibleMembers.find((member) => member.id === selectedWorkerId) ?? null; const selectedEntry = selectedMember ? entries.find((entry) => entry.memberId === selectedMember.id && entry.date === today) : undefined; const isLockedAbsent = selectedEntry?.status === 'Off'; const [selectedStatus, setSelectedStatus] = useState<'Present' | 'Absent'>('Present');

  useEffect(() => {
    if (!selectedMember) {
      setSelectedStatus('Present')
      return
    }
    setSelectedStatus(selectedEntry?.status === 'Off' ? 'Absent' : selectedEntry?.status === 'Absent' ? 'Absent' : 'Present')
  }, [selectedMember, selectedEntry])

  if (new URLSearchParams(window.location.search).get('mode') === 'bulk') return <BulkAttendancePage action="Sign in" members={members} entries={entries} onMarkAttendance={onMarkAttendance} onMarkSignOut={() => false} onSuccess={(count) => (window as any).__attendanceSuccess?.(`${count} worker${count === 1 ? '' : 's'} signed in successfully`)} />

  const handleStatusChange = async (status: 'Present' | 'Absent') => {
    if (!selectedMember || isLockedAbsent) return
    setSelectedStatus(status)
    const success = await onMarkAttendance(selectedMember.id, status)
    if (status === 'Present' && success !== false) (window as any).__attendanceSuccess?.('1 worker signed in successfully')
  }

  return <><PageHeading eyebrow="PEOPLE / SIGN-IN" title="Worker sign-in" subtitle={strictSignIn ? 'Strict sign-in checks are enabled for hourly staff.' : 'Flexible sign-in mode is active for this workspace.'} /><article className="panel member-form worker-attendance-form"><PanelHeading title="Today’s check-in" subtitle="Use the default time or update it from settings." /><div className="worker-attendance-grid"><label className="worker-attendance-field"><span>Department filter</span><select value={selectedDepartment} onChange={(event) => { setSelectedDepartment(event.target.value); setSelectedWorkerId('') }}><option value="">Select department</option>{departments.map((department) => <option key={department} value={department}>{department}</option>)}</select></label><label className="worker-attendance-field"><span>Worker</span><select value={selectedWorkerId} onChange={(event) => setSelectedWorkerId(Number(event.target.value) || '')} disabled={!selectedDepartment}><option value="">{selectedDepartment ? 'Select worker (ID)' : 'Choose a department first'}</option>{visibleMembers.map((member) => <option key={member.id} value={member.id}>{member.name} (ID: {member.id})</option>)}</select></label></div>{selectedMember && <><div className="worker-attendance-detail"><label><span>Registered worker</span><input value={selectedMember.name} readOnly /></label></div><div className="worker-attendance-detail"><label><span>Default sign-in time</span><input value={defaultSignIn} readOnly /></label></div><div className="worker-attendance-actions"><button type="button" className={selectedStatus === 'Present' ? 'primary-button' : 'secondary-button'} disabled={isLockedAbsent || selectedStatus === 'Present'} onClick={() => handleStatusChange('Present')}>Present</button><button type="button" className={selectedStatus === 'Absent' ? 'primary-button' : 'secondary-button'} disabled={isLockedAbsent || selectedStatus === 'Absent'} onClick={() => handleStatusChange('Absent')}>Absent</button>{isLockedAbsent && <span style={{ alignSelf: 'center', color: '#7a5b3f', fontWeight: 600 }}>Off-day lock: absent is fixed</span>}</div>{selectedMember && <div style={{ marginTop: '1rem', display: 'grid', gap: '0.75rem' }}><div className="table-wrap"><table><thead><tr><th>WORKER ID</th><th>NAME</th><th>PHONE</th></tr></thead><tbody>{visibleMembers.map((member) => <tr key={member.id}><td>#{member.id}</td><td>{member.name}</td><td>{member.phone}</td></tr>)}</tbody></table></div></div>}</> }<div className="form-actions"><button type="button" className="primary-button" disabled={!selectedMember || isLockedAbsent} onClick={() => handleStatusChange('Present')}>Mark attendance</button></div></article></> }

function ConfiguredRegisterPage({ packages, defaultPlan, onNavigate, onComplete, onRequestIssue }: { packages: PackageConfig[]; defaultPlan: SubscriptionPlan; onNavigate: (page: string) => void; onComplete: (account: OwnerAccount) => void; onRequestIssue?: (issue: string, details: { name: string; business: string }) => void }) {
  const [step, setStep] = useState(1)
  const availablePackages = packages.filter((item) => item.name && item.active)
  const initialPlan = availablePackages.find((item) => item.name === defaultPlan)?.name || availablePackages[0]?.name || ''
  const [details, setDetails] = useState({ name: '', username: '', password: '', phone: '', business: '', industry: '', plan: initialPlan, code: '' })
  const [accepted, setAccepted] = useState(false)
  const [error, setError] = useState('')
  const [generatedCode] = useState(() => `BT-${Math.floor(100000 + Math.random() * 900000)}`)
  const selectedPackage = availablePackages.find((item) => item.name === details.plan) || availablePackages.find((item) => item.name === defaultPlan) || availablePackages[0]
  useEffect(() => {
    if (selectedPackage && details.plan !== selectedPackage.name) setDetails((current) => ({ ...current, plan: selectedPackage.name }))
  }, [selectedPackage, details.plan])
  const update = (event: FormEvent<HTMLInputElement | HTMLSelectElement>) => { const { name, value } = event.currentTarget; setDetails((current) => ({ ...current, [name]: value })) }
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setError('')
    if (step === 1 && (!details.name.trim() || details.username.trim().length < 3 || details.password.length < 6 || !details.phone.trim())) { setError('Enter your name, phone, a username of at least 3 characters, and a password of at least 6 characters.'); onRequestIssue?.('Missing or invalid owner details', details); return }
    if (step === 2 && (!details.business.trim() || !details.industry)) { setError('Add your business name and choose an industry.'); return }
    if (step === 3 && (!selectedPackage || !accepted)) { setError(availablePackages.length ? 'Choose an available package and accept the terms to continue.' : 'No packages are currently available. Please contact the site administrator.'); return }
    if (step === 4) { if (details.code.trim().toUpperCase() !== generatedCode) { setError('That confirmation code does not match.'); return } onComplete({ name: details.name.trim(), username: details.username.trim(), password: details.password, business: details.business.trim(), phone: details.phone.trim(), industry: details.industry, plan: details.plan }); return }
    setStep((current) => current + 1)
  }
  const titles = ['Your details', 'Your business', 'Package and terms', 'Confirm purchase']
  return <div className="register-page"><header className="register-header"><button className="welcome-brand" onClick={() => onNavigate('Welcome')}><span className="welcome-mark">b</span><span>biz track</span></button><button className="register-back" onClick={() => onNavigate('Welcome')}>Back to welcome</button></header><main className="register-layout"><section className="register-intro"><p className="welcome-kicker">SET UP YOUR WORKSPACE</p><h1>A clear start for<br /><em>better work.</em></h1><p>Choose the package configured by the site admin for your workspace.</p></section><section className="register-card"><div className="register-progress">{titles.map((title, index) => <div key={title} className={index + 1 <= step ? 'complete' : ''}><b>0{index + 1}</b><span>{title}</span></div>)}</div><form onSubmit={submit}><p className="eyebrow">STEP 0{step} OF 04</p><h2>{titles[step - 1]}</h2>{error && <p className="register-error" role="alert">{error}</p>}{step === 1 && <div className="form-grid register-fields"><label><span>Full name *</span><input name="name" value={details.name} onChange={update} /></label><label><span>Phone number *</span><input name="phone" value={details.phone} onChange={update} /></label><label><span>Username *</span><input name="username" value={details.username} onChange={update} /></label><label><span>Password *</span><input name="password" type="password" value={details.password} onChange={update} /></label></div>}{step === 2 && <div className="form-grid register-fields"><label><span>Business name *</span><input name="business" value={details.business} onChange={update} /></label><label><span>Industry *</span><input name="industry" value={details.industry} onChange={update} placeholder="Retail, hospitality..." /></label></div>}{step === 3 && <div className="package-choice"><label><span>Choose a package *</span><select name="plan" value={selectedPackage?.name || ''} onChange={update} disabled={!availablePackages.length}><option value="" disabled>{availablePackages.length ? 'Select a package' : 'No packages available'}</option>{availablePackages.map((item) => <option key={item.name} value={item.name}>{item.name}{item.name === defaultPlan ? ' (Default)' : ''}</option>)}</select></label>{selectedPackage && <article><span>{selectedPackage.name === defaultPlan ? 'Default package' : 'Available package'}</span><h3>{selectedPackage.name}</h3><strong>KES {selectedPackage.price.toLocaleString()} <small>/ {selectedPackage.duration} {selectedPackage.durationUnit}{selectedPackage.duration === 1 ? '' : 's'}</small></strong><p>{selectedPackage.description}</p><div className="package-features">{selectedPackage.features.map((feature) => <span key={feature}>✓ {feature}</span>)}</div><small>{selectedPackage.seats} seats included</small></article>}{!availablePackages.length && <p role="status">Package options are unavailable right now. Please contact the site administrator.</p>}<label className="terms-check"><input type="checkbox" checked={accepted} onChange={(event) => setAccepted(event.target.checked)} /><span>I accept the Biz Track <a href={pagePaths.Terms} onClick={(event) => { event.preventDefault(); onNavigate('Terms') }}>terms and conditions</a>.</span></label></div>}{step === 4 && <div className="confirmation-box"><p>Your one-time confirmation code</p><strong>{generatedCode}</strong><label><span>Enter the code above *</span><input name="code" value={details.code} onChange={update} placeholder="BT-000000" /></label></div>}<div className="register-actions"><button type="button" className="secondary-button" onClick={() => step === 1 ? onNavigate('Welcome') : setStep((current) => current - 1)}>{step === 1 ? 'Cancel' : 'Back'}</button><button className="primary-button" type="submit" disabled={step === 3 && !availablePackages.length}>{step === 4 ? 'Confirm and create workspace' : 'Continue'} <span>→</span></button></div></form></section></main></div>
}

function RegisterPage({ packages, onNavigate, onComplete, onRequestIssue }: { packages: PackageConfig[]; onNavigate: (page: string) => void; onComplete: (account: OwnerAccount) => void; onRequestIssue?: (issue: string, details: { name: string; business: string }) => void }) {
  const [step, setStep] = useState(1)
  const availablePackages = (packages || []).filter((item) => item.name && item.active)
  const [details, setDetails] = useState({ name: '', username: '', password: '', phone: '', business: '', industry: '', plan: availablePackages[0]?.name || '' })
  const [code, setCode] = useState('')
  const [generatedCode] = useState(() => `BT-${Math.floor(100000 + Math.random() * 900000)}`)
  const [error, setError] = useState('')
  const update = (event: FormEvent<HTMLInputElement | HTMLSelectElement>) => { const next = { ...details, [event.currentTarget.name]: event.currentTarget.value }; setDetails(next) }
  const next = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setError('')
    if (step === 1 && (!details.name.trim() || details.username.trim().length < 3 || details.password.length < 6 || !details.phone.trim())) { const issue = 'Missing or invalid owner details'; setError('Enter your name, phone, a username of at least 3 characters, and a password of at least 6 characters.'); onRequestIssue?.(issue, details); return }
    if (step === 2 && (!details.business.trim() || !details.industry)) { const issue = 'Missing business name or industry'; setError('Add your business name and choose an industry.'); onRequestIssue?.(issue, details); return }
    if (step === 3) { setStep(4); return }
    if (step === 4) { if (code.trim().toUpperCase() !== generatedCode) { const issue = 'Confirmation code did not match'; setError('That confirmation code does not match.'); onRequestIssue?.(issue, details); return } onComplete({ name: details.name.trim(), username: details.username.trim(), password: details.password, business: details.business.trim(), phone: details.phone.trim(), industry: details.industry, plan: details.plan as SubscriptionPlan }); return }
    setStep(step + 1)
  }
  const stepTitles = ['Your details', 'Your business', 'Terms and package', 'Confirm purchase']
  return <div className="register-page"><header className="register-header"><button className="welcome-brand" onClick={() => onNavigate('Welcome')}><span className="welcome-mark">b</span><span>biz track</span></button><button className="register-back" onClick={() => onNavigate('Welcome')}>Back to welcome</button></header><main className="register-layout"><section className="register-intro"><p className="welcome-kicker">SET UP YOUR WORKSPACE</p><h1>A clear start for<br /><em>better work.</em></h1><p>Take four short steps to create the owner account, choose a package, and open your business workspace.</p><div className="register-assurance"><span>✓</span><div><strong>Owner-led by design</strong><small>You decide who joins and what each person can access.</small></div></div></section><section className="register-card"><div className="register-progress">{stepTitles.map((title, index) => <div key={title} className={index + 1 <= step ? 'complete' : ''}><b>0{index + 1}</b><span>{title}</span></div>)}</div><form onSubmit={next}><p className="eyebrow">STEP 0{step} OF 04</p><h2>{stepTitles[step - 1]}</h2><p className="register-help">{step === 1 ? 'This will be your owner profile and sign-in.' : step === 2 ? 'Tell us where Biz Track will help your team.' : step === 3 ? 'Review the plan and accept the terms to continue.' : 'The system created a purchase code. Enter it to finish.'}</p>{step === 1 && <div className="form-grid register-fields"><label><span>Full name *</span><input name="name" value={details.name} onChange={update} placeholder="e.g. Kemi Adebayo" /></label><label><span>Phone number *</span><input name="phone" value={details.phone} onChange={update} placeholder="e.g. +234 803 123 4567" /></label><label><span>Username *</span><input name="username" value={details.username} onChange={update} placeholder="Choose a username" /></label><label><span>Password *</span><input name="password" type="password" value={details.password} onChange={update} placeholder="At least 6 characters" /></label></div>}{step === 2 && <div className="form-grid register-fields"><label><span>Business name *</span><input name="business" value={details.business} onChange={update} placeholder="e.g. Northstar Cafe" /></label><label><span>Industry *</span><select name="industry" value={details.industry} onChange={update}><option value="">Choose an industry</option><option>Retail</option><option>Restaurant and hospitality</option><option>Professional services</option><option>Other</option></select></label></div>}{step === 3 && <div className="package-choice"><article><span>Recommended</span><h3>Starter workspace</h3><strong>KES 15,000 <small>/ month</small></strong><p>Owner dashboard, attendance, payroll, inventory, sales, and up to 10 team accounts.</p></article><label className="terms-check"><input type="checkbox" required /><span>I accept the Biz Track terms and conditions and understand that package access begins after confirmation.</span></label></div>}{step === 4 && <div className="confirmation-box"><p>Your one-time confirmation code</p><strong>{generatedCode}</strong><label><span>Enter the code above *</span><input value={code} onChange={(event) => setCode(event.target.value)} placeholder="BT-000000" /></label><small>Keep this code private. It confirms the package purchase for this workspace.</small></div>}{error && <p className="register-error">{error}</p>}<div className="register-actions"><button type="button" className="secondary-button" onClick={() => step === 1 ? onNavigate('Welcome') : setStep(step - 1)}>{step === 1 ? 'Cancel' : 'Back'}</button><button className="primary-button" type="submit">{step === 4 ? 'Confirm and create workspace' : step === 3 ? 'Continue to confirmation' : 'Continue'} <span>→</span></button></div></form></section></main></div>
}

function OffMarkPage({ members, attendance, onMark }: { members: Member[]; attendance: AttendanceEntry[]; onMark: (memberIds: number[], dates: string[]) => void }) {
  const tomorrow = new Date()
  tomorrow.setHours(0, 0, 0, 0)
  tomorrow.setDate(tomorrow.getDate() + 1)
  const firstFutureDate = tomorrow.toISOString().slice(0, 10)
  const [date, setDate] = useState(firstFutureDate)
  const [selectedDates, setSelectedDates] = useState<string[]>([firstFutureDate])
  const [selectedIds, setSelectedIds] = useState<number[]>([])
  const eligibleMembers = members.filter((member) => member.payTerms !== 'Casual')
  useEffect(() => setSelectedIds((current) => current.filter((id) => eligibleMembers.some((member) => member.id === id))), [members])
  const toggle = (id: number) => setSelectedIds((current) => current.includes(id) ? current.filter((item) => item !== id) : [...current, id])
  const addDate = () => { if (date <= today || selectedDates.includes(date)) return; setSelectedDates((current) => [...current, date].sort()) }
  const removeDate = (value: string) => setSelectedDates((current) => current.filter((item) => item !== value))
  const alreadyOff = (id: number) => selectedDates.length > 0 && selectedDates.every((value) => attendance.some((entry) => entry.memberId === id && entry.date === value && entry.status === 'Off'))
  const signedIn = (id: number) => selectedDates.some((value) => attendance.some((entry) => entry.memberId === id && entry.date === value && (entry.status === 'Present' || entry.status === 'Late' || entry.checkIn !== '—' || entry.checkOut !== '—')))
  return <><PageHeading eyebrow="PEOPLE / ATTENDANCE" title="OFF MARK" subtitle="Choose one or more future dates. Consecutive and separate days are supported." /><article className="panel member-form off-mark-panel"><div className="off-date-editor"><div><strong>Future off dates</strong><small>Only dates after today are valid.</small></div><div className="off-date-controls"><input className="filter-button" type="date" min={today} value={date} onChange={(event) => setDate(event.target.value)} /><button type="button" className="secondary-button" onClick={addDate}>Add date</button></div></div><div className="off-date-list">{selectedDates.map((value) => <span className="off-date-chip" key={value}>{formatDate(value)}<button type="button" aria-label={`Remove ${value}`} onClick={() => removeDate(value)}>×</button></span>)}</div><PanelHeading title="Select workers to mark off" subtitle={`${selectedIds.length} worker${selectedIds.length === 1 ? '' : 's'} selected for ${selectedDates.length} date${selectedDates.length === 1 ? '' : 's'}.`} /><div className="off-mark-list">{eligibleMembers.map((member) => <label className={`off-mark-worker ${selectedIds.includes(member.id) ? 'selected' : ''}`} key={member.id}><input type="checkbox" checked={selectedIds.includes(member.id)} disabled={signedIn(member.id)} onChange={() => toggle(member.id)} /><span className={`avatar avatar-${member.color}`}>{member.initials}</span><span><strong>{member.name}</strong><small>{member.role} · {member.department}</small></span><b>{signedIn(member.id) ? 'Signed in' : alreadyOff(member.id) ? 'Already off' : selectedIds.includes(member.id) ? 'Selected' : 'Working'}</b></label>)}</div><div className="form-actions"><button className="primary-button" disabled={!selectedIds.length || !selectedDates.length} onClick={() => { const eligibleIds = selectedIds.filter((id) => eligibleMembers.some((member) => member.id === id)); onMark(eligibleIds, selectedDates); setSelectedIds([]) }}>Mark off</button></div></article></>
}

function PaymentRegisterFooterSettings({ value, onSave }: { value: string; onSave: (value: string) => Promise<boolean> }) {
  const [draft, setDraft] = useState(value)
  const [saving, setSaving] = useState(false)
  useEffect(() => setDraft(value), [value])
  const saveChanges = async () => {
    setSaving(true)
    try { await onSave(draft) } finally { setSaving(false) }
  }
  return <section className="settings-stack payment-register-footer-settings"><article className="panel member-form"><PanelHeading title="Payment register" subtitle="Set the acknowledgement printed beneath each payment register." /><label className="payment-register-footer-setting"><span>Worker acknowledgement</span><textarea rows={4} maxLength={600} value={draft} onChange={(event) => setDraft(event.target.value)} placeholder={defaultPaymentRegisterFooter} /><small>By signing, a worker confirms the amount received for the selected pay period. Update this wording to match your business records.</small></label><div className="form-actions"><button type="button" className="primary-button" disabled={saving || draft === value} onClick={() => void saveChanges()}>{saving ? 'Saving...' : 'Save changes'}</button></div></article></section>
}

function PrintPage({ businessName, members, sales, attendance, casualEarnings, deductions, expenses, stockMovements, inventory, categoryThresholds, currency, paymentRegisterFooter, payrollReportOrder }: { businessName: string; members: Member[]; sales: Sale[]; attendance: AttendanceEntry[]; casualEarnings: CasualEarning[]; deductions: Deduction[]; expenses: Expense[]; stockMovements: StockMovement[]; inventory: InventoryItem[]; categoryThresholds: Record<string, number>; currency: string; paymentRegisterFooter: string; payrollReportOrder: PayrollReportOrder }) {
  const [selectedReport, setSelectedReport] = useState('overview')
  const [showExportDialog, setShowExportDialog] = useState(false)
  const [showSummaryPrint, setShowSummaryPrint] = useState(false)
  const [exportPeriod, setExportPeriod] = useState('today')
  const [exportStart, setExportStart] = useState(today)
  const [exportEnd, setExportEnd] = useState(today)
  const [reportRanges, setReportRanges] = useState<Record<string, { period: string; start: string; end: string }>>(() => Object.fromEntries(['overview', 'sales', 'payroll', 'payments', 'expenses', 'off', 'inventory', 'register'].map((report) => [report, { period: 'today', start: today, end: today }])))
  const defaultReportRange = { period: 'today', start: today, end: today }
  const rangeForReport = (report: string) => reportRanges[report] || defaultReportRange
  const saveReportRange = (report: string, period: string, start: string, end: string) => setReportRanges((current) => ({ ...current, [report]: { period, start, end } }))
  const salesCardRange = rangeForReport('sales')
  const payrollCardRange = rangeForReport('payroll')
  const offCardRange = rangeForReport('off')
  const inventoryCardRange = rangeForReport('inventory')
  const registerCardRange = rangeForReport('register')
  const paymentsCardRange = rangeForReport('payments')
  const salesCardSales = sales.filter((sale) => sale.date >= salesCardRange.start && sale.date <= salesCardRange.end)
  const payrollCardShifts = attendance.filter((entry) => entry.paymentStatus === 'Paid' && entry.checkOut !== '—' && members.find((member) => member.id === entry.memberId)?.payTerms !== 'Casual' && entry.date >= payrollCardRange.start && entry.date <= payrollCardRange.end)
  const payrollCardCasualEarnings = casualEarnings.filter((earning) => earning.paymentStatus === 'Paid' && earning.date >= payrollCardRange.start && earning.date <= payrollCardRange.end)
  const offCardRows = datesBetween(offCardRange.start, offCardRange.end).flatMap((date) => members.map((member) => ({ member, entry: attendance.find((item) => item.memberId === member.id && item.date === date) })))
  const offCardCounts = offCardRows.reduce((counts, row) => { const status = row.entry?.status || 'Absent'; counts[status] += 1; return counts }, { Present: 0, Late: 0, Absent: 0, Off: 0 } as Record<AttendanceStatus, number>)
  const inventoryCardMovements = stockMovements.filter((movement) => movement.date >= inventoryCardRange.start && movement.date <= inventoryCardRange.end)
  const inventoryCardAdded = inventoryCardMovements.filter((movement) => movement.type === 'Stocked').reduce((sum, movement) => sum + movement.quantity, 0)
  const inventoryCardUsed = inventoryCardMovements.filter((movement) => movement.type === 'Used').reduce((sum, movement) => sum + movement.quantity, 0)
  const registerCardEntries = attendance.filter((entry) => entry.date >= registerCardRange.start && entry.date <= registerCardRange.end && (entry.status === 'Off' || Boolean(entry.checkIn && entry.checkIn !== '—')))
  const registerCardWorkers = new Set(registerCardEntries.map((entry) => entry.memberId)).size
  const paymentsCardWorkers = paymentRegisterRows(members, attendance, deductions, paymentsCardRange.start, paymentsCardRange.end, true, casualEarnings)
  const cardRangeLabel = (range: { period: string; start: string; end: string }) => range.period === 'today' ? 'today' : range.period === 'day' ? formatDate(range.start) : `From ${formatDate(range.start)} to ${formatDate(range.end)}`
  const inExportRange = (date: string) => date >= exportStart && date <= exportEnd
  const periodSales = sales.filter((sale) => inExportRange(sale.date))
  const completedShifts = attendance.filter((entry) => entry.paymentStatus === 'Paid' && entry.checkOut !== '—' && members.find((member) => member.id === entry.memberId)?.payTerms !== 'Casual' && inExportRange(entry.date))
  const paidCasualEntries = casualEarnings.filter((earning) => earning.paymentStatus === 'Paid' && inExportRange(earning.date))
  const offDays = attendance.filter((entry) => entry.status === 'Off' && inExportRange(entry.date))
  const attendanceRows = datesBetween(exportStart, exportEnd).flatMap((date) => members.map((member) => ({ date, member, entry: attendance.find((item) => item.memberId === member.id && item.date === date) })))
  const attendanceCounts = attendanceRows.reduce((counts, row) => { const status = row.entry?.status || 'Absent'; counts[status] += 1; return counts }, { Present: 0, Late: 0, Absent: 0, Off: 0 } as Record<AttendanceStatus, number>)
    const payrollWorkers = members.map((member) => {
      const earnings = completedShifts.filter((entry) => entry.memberId === member.id)
      const workerDeductions = deductions.filter((deduction) => deduction.memberId === member.id && inExportRange(deduction.date))
      const gross = earnings.length * member.payRate
      const deducted = workerDeductions.reduce((sum, deduction) => sum + deduction.amount, 0)
      return { member, earnings, deductions: workerDeductions, gross, deducted, net: Math.max(0, gross - deducted) }
    }).filter((worker) => worker.earnings.length > 0)
    if (false) {
    return <div className="print-page"><PageHeading eyebrow="WORKSPACE / PRINT" title="Business reports" subtitle="Choose a report and export a clean PDF for records, review, or sharing." action={<button className="primary-button print-all-button" onClick={() => printReport('overview')}><span>▤</span> Print summary</button>} /><section className="print-report-grid">{cards.map((card) => <article className={`print-report-card accent-${card.accent}`} key={card.id}><div className="print-card-icon">{card.icon}</div><div><p>{card.title}</p><strong>{card.value}</strong><small>{card.detail}</small></div><button className="secondary-button" onClick={() => printReport(card.id)}>Export PDF <span>↗</span></button></article>)}</section><article className="panel print-preview"><PanelHeading title={reportNames[selectedReport]} subtitle="The selected report will be printed with the business name and current records." /><div className="print-preview-summary"><strong>{businessName}</strong><span>{exportStart} to {exportEnd}</span></div>{selectedReport === 'payroll' ? <div className="payroll-print-workers">{payrollWorkers.length ? payrollWorkers.map(({ member, earnings, deductions: workerDeductions, gross, deducted, net }) => <section className="payroll-print-worker" key={member.id}><header><div><h3>{member.name}</h3><span>{member.department} · {member.payFrequency} pay · {currency} {member.payRate.toLocaleString()} per shift</span></div><strong>{currency} {net.toLocaleString()} <small>received</small></strong></header><table><thead><tr><th>Date</th><th>Description</th><th>Amount</th></tr></thead><tbody>{earnings.map((entry) => <tr key={`${member.id}-${formatDate(entry.date)}`}><td>{formatDate(entry.date)}</td><td>Completed shift</td><td>{currency} {member.payRate.toLocaleString()}</td></tr>)}{workerDeductions.map((deduction) => <tr className="payroll-print-deduction" key={`deduction-${deduction.id}`}><td>{formatDate(deduction.date)}</td><td>Deduction: {deduction.reason}</td><td>- {currency} {deduction.amount.toLocaleString()}</td></tr>)}<tr className="payroll-print-total"><td colSpan={2}>Gross {currency} {gross.toLocaleString()} less deductions {currency} {deducted.toLocaleString()}</td><td>{currency} {net.toLocaleString()}</td></tr></tbody></table></section>) : <p className="print-empty">No payroll records in this period.</p>}</div> : <div className="print-preview-list">{selectedReport === 'sales' && sales.slice(-6).reverse().map((sale) => <div key={sale.id}><span>{formatDate(sale.date)} · {sale.cashier}</span><strong>{currency} {sale.amount.toLocaleString()}</strong></div>)}{selectedReport === 'off' && offDays.slice(-6).reverse().map((entry) => <div key={`${entry.memberId}-${formatDate(entry.date)}`}><span>{members.find((member) => member.id === entry.memberId)?.name || 'Worker'}</span><strong>{formatDate(entry.date)}</strong></div>)}{selectedReport === 'inventory' && inventory.slice(0, 6).map((item) => <div key={item.id}><span>{item.name} · {item.category}</span><strong>{item.quantity} {item.unit}</strong></div>)}{selectedReport === 'overview' && <><div><span>Sales in period</span><strong>{currency} {salesTotal.toLocaleString()}</strong></div><div><span>Payroll in period</span><strong>{currency} {payrollTotal.toLocaleString()}</strong></div><div><span>Completed shifts</span><strong>{completedShifts.length}</strong></div></>}</div>}</article>{showExportDialog && null}</div>
    }
  const salesTotal = periodSales.reduce((sum, sale) => sum + sale.amount, 0)
  const salesCardTotal = salesCardSales.reduce((sum, sale) => sum + sale.amount, 0)
  const payrollCardTotal = payrollCardShifts.reduce((sum, entry) => sum + (members.find((member) => member.id === entry.memberId)?.payRate || 0), 0) + payrollCardCasualEarnings.reduce((sum, earning) => sum + earning.amount, 0)
  const reportNames: Record<string, string> = { overview: 'Business summary', sales: 'Sales report', payroll: 'Payroll report', payments: 'Payroll Payment Register', expenses: 'Expenses report', off: 'OFF MARK report', inventory: 'Inventory report', register: 'Attendance register' }
  const selectReport = (report: string) => { const range = rangeForReport(report); setSelectedReport(report); setExportPeriod(range.period); setExportStart(range.start); setExportEnd(range.end); document.querySelector('.print-preview')?.scrollIntoView({ behavior: 'smooth', block: 'start' }) }
  const openExport = (report: string) => { const range = rangeForReport(report); setSelectedReport(report); setExportPeriod(range.period); setExportStart(range.start); setExportEnd(range.end); setShowExportDialog(true) }
  const printReport = (report?: string, selectedRange = { period: exportPeriod, start: exportStart, end: exportEnd }) => { const reportToPrint = report || selectedReport; if (report) setSelectedReport(report); setShowExportDialog(false); setShowSummaryPrint(reportToPrint === 'overview'); const dateLabel = document.querySelector('.print-preview-summary span'); if (dateLabel) dateLabel.textContent = formatReportPeriod(selectedRange.period, selectedRange.start, selectedRange.end); window.setTimeout(() => window.print(), 80) }
  const remainingQuantity = inventory.reduce((sum, item) => sum + item.quantity, 0)
  const cards = [
    { id: 'sales', title: 'Sales', value: `${currency} ${salesCardTotal.toLocaleString()}`, detail: `${salesCardSales.length} recorded sale${salesCardSales.length === 1 ? '' : 's'} · ${cardRangeLabel(salesCardRange)}`, accent: 'teal', icon: '↗' },
    { id: 'payroll', title: 'Payroll', value: `${currency} ${payrollCardTotal.toLocaleString()}`, detail: `${payrollCardShifts.length + payrollCardCasualEarnings.length} paid earning${payrollCardShifts.length + payrollCardCasualEarnings.length === 1 ? '' : 's'} · ${cardRangeLabel(payrollCardRange)}`, accent: 'coral', icon: 'KES' },
    { id: 'payments', title: 'Payments register', value: `${currency} ${paymentsCardWorkers.reduce((sum, row) => sum + row.amountOwed, 0).toLocaleString()}`, detail: `${paymentsCardWorkers.length} worker${paymentsCardWorkers.length === 1 ? '' : 's'} · ${cardRangeLabel(paymentsCardRange)}`, accent: 'blue', icon: '▤' },
    { id: 'off', title: 'OFF MARK', value: String(offCardRows.length), detail: `${offCardCounts.Present} present · ${offCardCounts.Late} late · ${offCardCounts.Absent} absent · ${offCardCounts.Off} off · ${cardRangeLabel(offCardRange)}`, accent: 'slate', icon: '◉' },
    { id: 'inventory', title: 'Stock movement', value: String(remainingQuantity), detail: `${inventoryCardAdded} added · ${inventoryCardUsed} used · ${remainingQuantity} remaining · ${cardRangeLabel(inventoryCardRange)}`, accent: 'yellow', icon: '□' },
    { id: 'register', title: 'Register', value: String(registerCardWorkers), detail: `${registerCardEntries.length} attendance record${registerCardEntries.length === 1 ? '' : 's'} · ${cardRangeLabel(registerCardRange)}`, accent: 'sky', icon: '▤' },
  ]
  useEffect(() => {
    const reportIds: Record<string, string> = { Sales: 'sales', Payroll: 'payroll', 'Payments register': 'payments', Expenses: 'expenses', 'OFF MARK': 'off', Inventory: 'inventory', 'Stock movement': 'inventory', Register: 'register' }
    const handleReportClick = (event: MouseEvent) => {
      const target = event.target as HTMLElement
      if (target.closest('.print-all-button')) { event.preventDefault(); event.stopPropagation(); openExport('overview'); return }
      const card = target.closest('.print-report-card') as HTMLElement | null
      if (!card) return
      const title = card.querySelector('p')?.textContent || ''
      const report = reportIds[title]
      if (!report) return
      const button = target.closest('button')
      if (!button) { selectReport(report); return }
      event.preventDefault(); event.stopPropagation(); openExport(report)
    }
    document.addEventListener('click', handleReportClick, true)
    return () => document.removeEventListener('click', handleReportClick, true)
  }, [reportRanges])
  useEffect(() => {
    if (!showExportDialog) return
    const overlay = document.createElement('div')
    overlay.className = 'print-dialog-backdrop'
    overlay.innerHTML = `<section class="print-dialog" role="dialog" aria-modal="true"><button class="print-dialog-close" aria-label="Close">×</button><p class="eyebrow">EXPORT REPORT</p><h2>${reportNames[selectedReport]}</h2><p class="print-dialog-copy">Choose the dates to include in this PDF report.</p><label>Period<select class="print-period"><option value="today" ${exportPeriod === 'today' ? 'selected' : ''}>Today</option><option value="day" ${exportPeriod === 'day' ? 'selected' : ''}>Particular day</option><option value="week" ${exportPeriod === 'week' ? 'selected' : ''}>This week</option><option value="month" ${exportPeriod === 'month' ? 'selected' : ''}>This month</option><option value="custom" ${exportPeriod === 'custom' ? 'selected' : ''}>Custom dates</option></select></label><div class="print-custom-dates${exportPeriod === 'day' ? ' is-single-day' : ''}"><label><span>${exportPeriod === 'day' ? 'Date' : 'From'}</span><input type="date" value="${exportStart}"></label><label class="print-end-date" aria-hidden="${exportPeriod === 'day'}"><span>To</span><input type="date" value="${exportEnd}" ${exportPeriod === 'day' ? 'disabled' : ''}></label></div><button class="primary-button print-dialog-confirm">Print / Save PDF</button></section>`
    const close = () => setShowExportDialog(false)
    const periodSelect = overlay.querySelector<HTMLSelectElement>('.print-period')!
    const dateFields = overlay.querySelector<HTMLElement>('.print-custom-dates')!
    const dateLabels = dateFields.querySelectorAll('label')
    const dateInputs = dateFields.querySelectorAll<HTMLInputElement>('input')
    const updateRange = (period: string, start: string, end: string) => {
      setExportPeriod(period)
      setExportStart(start)
      setExportEnd(end)
      saveReportRange(selectedReport, period, start, end)
      dateFields.classList.toggle('is-single-day', period === 'day')
      dateLabels[0]?.querySelector('span')?.replaceChildren(period === 'day' ? 'Date' : 'From')
      dateLabels[1]?.setAttribute('aria-hidden', String(period === 'day'))
      if (dateInputs[0]) dateInputs[0].value = start
      if (dateInputs[1]) { dateInputs[1].value = end; dateInputs[1].disabled = period === 'day' }
    }
    overlay.addEventListener('click', (event) => { if (event.target === overlay || (event.target as HTMLElement).closest('.print-dialog-close')) close() })
    periodSelect.addEventListener('change', () => {
      const value = periodSelect.value
      const selectedStart = dateInputs[0]?.value || exportStart
      if (value === 'today') updateRange(value, today, today)
      else if (value === 'day') updateRange(value, selectedStart, selectedStart)
      else if (value === 'week') updateRange(value, currentWeekStart, currentWeekEnd)
      else if (value === 'month') updateRange(value, currentMonthStart, today)
      else updateRange(value, selectedStart, dateInputs[1]?.value || exportEnd)
    })
    dateInputs[0]?.addEventListener('change', () => {
      const value = dateInputs[0].value
      updateRange(periodSelect.value === 'day' ? 'day' : 'custom', value, periodSelect.value === 'day' ? value : dateInputs[1]?.value || value)
    })
    dateInputs[1]?.addEventListener('change', () => updateRange('custom', dateInputs[0]?.value || exportStart, dateInputs[1].value))
    overlay.querySelector('.print-dialog-confirm')?.addEventListener('click', () => {
      const period = periodSelect.value
      const start = dateInputs[0]?.value || exportStart
      const end = period === 'day' ? start : dateInputs[1]?.value || exportEnd
      printReport(undefined, { period, start, end })
    })
    document.body.appendChild(overlay)
    return () => overlay.remove()
  }, [showExportDialog, selectedReport])
  useEffect(() => {
    const resetReport = () => { setSelectedReport('overview'); setShowSummaryPrint(false) }
    window.addEventListener('afterprint', resetReport)
    return () => window.removeEventListener('afterprint', resetReport)
  }, [])
  if (!showExportDialog && showSummaryPrint) return <SummaryPrintReport businessName={businessName} sales={periodSales} attendanceRows={attendanceRows} casualEarnings={paidCasualEntries} inventory={inventory} stockMovements={stockMovements} currency={currency} period={exportPeriod} exportStart={exportStart} exportEnd={exportEnd} />
  if (!showExportDialog && selectedReport === 'payments') return <PaymentRegisterPrintReport businessName={businessName} members={members} attendance={attendance} casualEarnings={casualEarnings} deductions={deductions} currency={currency} paymentRegisterFooter={paymentRegisterFooter} period={exportPeriod} exportStart={exportStart} exportEnd={exportEnd} />
  if (!showExportDialog && selectedReport === 'payroll') return <PayrollPrintReport businessName={businessName} members={members} attendance={attendance} casualEarnings={casualEarnings} deductions={deductions} currency={currency} period={exportPeriod} exportStart={exportStart} exportEnd={exportEnd} payrollReportOrder={payrollReportOrder} />
  if (!showExportDialog && selectedReport !== 'overview') return <UnifiedPrintReport businessName={businessName} report={selectedReport} members={members} sales={sales} attendance={attendance} expenses={expenses} stockMovements={stockMovements} inventory={inventory} categoryThresholds={categoryThresholds} currency={currency} period={exportPeriod} exportStart={exportStart} exportEnd={exportEnd} />
  return <div className="print-page"><PageHeading eyebrow="WORKSPACE / PRINT" title="Business reports" subtitle="Choose a report and export a clean PDF for records, review, or sharing." action={<button className="primary-button print-all-button" onClick={() => printReport('overview')}><span>▤</span> Print summary</button>} /><section className="print-report-grid">{cards.map((card) => <article className={`print-report-card accent-${card.accent}`} key={card.id}><div className="print-card-icon">{card.icon}</div><div><p>{card.title}</p><strong>{card.value}</strong><small>{card.detail}</small></div><button className="secondary-button" onClick={() => printReport(card.id)}>Export PDF <span>↗</span></button></article>)}</section><article className="panel print-preview"><PanelHeading title={reportNames[selectedReport]} subtitle="The selected report will be printed with the business name and current records." /><div className="print-preview-summary"><strong>{businessName}</strong><span>{formatDate(new Date().toISOString())}</span></div><div className="print-preview-list">{selectedReport === 'sales' && sales.slice(-6).reverse().map((sale) => <div key={sale.id}><span>{formatDate(sale.date)} · {sale.cashier}</span><strong>{currency} {sale.amount.toLocaleString()}</strong></div>)}{selectedReport === 'payroll' && completedShifts.slice(-6).reverse().map((entry) => <div key={`${entry.memberId}-${formatDate(entry.date)}`}><span>{members.find((member) => member.id === entry.memberId)?.name || 'Worker'} · {formatDate(entry.date)}</span><strong>{currency} {(members.find((member) => member.id === entry.memberId)?.payRate || 0).toLocaleString()}</strong></div>)}{selectedReport === 'off' && offDays.slice(-6).reverse().map((entry) => <div key={`${entry.memberId}-${formatDate(entry.date)}`}><span>{members.find((member) => member.id === entry.memberId)?.name || 'Worker'}</span><strong>{formatDate(entry.date)}</strong></div>)}{selectedReport === 'inventory' && inventory.slice(0, 6).map((item) => <div key={item.id}><span>{item.name} · {item.category}</span><strong>{item.quantity} {item.unit}</strong></div>)}{selectedReport === 'overview' && <><div><span>Total sales</span><strong>{currency} {salesTotal.toLocaleString()}</strong></div><div><span>Completed shifts</span><strong>{completedShifts.length}</strong></div><div><span>Scheduled days off</span><strong>{offDays.length}</strong></div><div><span>Stock items</span><strong>{inventory.length}</strong></div></>}</div></article></div>
}

function PrintBrandFooter() {
  return <footer className="print-brand-footer"><span className="brand-mark">b</span><span>Powered by</span><strong>BizTrack</strong></footer>
}

function SummaryPrintReport({ businessName, sales, attendanceRows, casualEarnings, inventory, stockMovements, currency, period, exportStart, exportEnd }: { businessName: string; sales: Sale[]; attendanceRows: { date: string; member: Member; entry?: AttendanceEntry }[]; casualEarnings: CasualEarning[]; inventory: InventoryItem[]; stockMovements: StockMovement[]; currency: string; period: string; exportStart: string; exportEnd: string }) {
  const paidPayroll = attendanceRows.reduce((sum, row) => sum + (row.entry ? paymentReceivedForEntry(row.entry, row.member) : 0), 0) + casualEarnings.reduce((sum, earning) => sum + earning.paymentReceived, 0)
  const salesTotal = sales.reduce((sum, sale) => sum + sale.amount, 0)
  const stocked = (itemId: number) => stockMovements.filter((movement) => movement.inventoryItemId === itemId && movement.type === 'Stocked').reduce((sum, movement) => sum + movement.quantity, 0)
  const used = (itemId: number) => stockMovements.filter((movement) => movement.inventoryItemId === itemId && movement.type === 'Used').reduce((sum, movement) => sum + movement.quantity, 0)
  return <div className="print-page unified-print-page"><article className="panel print-preview"><header className="payroll-print-header"><p className="eyebrow">BUSINESS REPORT</p><h1>{businessName}</h1><h2>Business summary</h2><p className="payroll-print-period">{formatReportPeriod(period, exportStart, exportEnd)}<span>AS AT {formatDate(new Date().toISOString())} {new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span></p></header><section className="print-summary-grid"><div><span>Total sales</span><strong>{currency} {salesTotal.toLocaleString()}</strong></div><div><span>Paid payroll</span><strong>{currency} {paidPayroll.toLocaleString()}</strong></div><div><span>Attendance records</span><strong>{attendanceRows.length}</strong></div></section><h3 className="print-section-title">Attendance details</h3><table className="unified-report-table"><thead><tr><th>Date</th><th>Worker</th><th>Status</th><th>Check-in</th><th>Check-out</th></tr></thead><tbody>{attendanceRows.map((row) => <tr key={`${row.member.id}-${formatDate(row.date)}`}><td>{formatDate(row.date)}</td><td>{row.member.name}</td><td>{row.entry?.status || 'Absent'}</td><td>{row.entry?.checkIn || '?'}</td><td>{row.entry?.checkOut || '?'}</td></tr>)}</tbody></table></article><article className="panel print-preview print-store-page"><header className="payroll-print-header"><p className="eyebrow">STORE / INVENTORY</p><h1>{businessName}</h1><h2>Inventory and store information</h2><p className="payroll-print-period">Stock position and movement summary<span>AS AT {formatDate(new Date().toISOString())}</span></p></header><table className="unified-report-table"><thead><tr><th>Item</th><th>Category</th><th>Stocked</th><th>Used</th><th>Remaining</th><th>Unit</th></tr></thead><tbody>{inventory.length ? inventory.map((item) => <tr key={item.id}><td>{item.name}</td><td>{item.category}</td><td>{stocked(item.id)}</td><td>{used(item.id)}</td><td>{item.quantity}</td><td>{item.unit}</td></tr>) : <tr><td colSpan={6}>No inventory items recorded.</td></tr>}</tbody></table><PrintBrandFooter /></article></div>
}

function AttendancePrintReport({ businessName, members, attendance, currency, period, exportStart, exportEnd }: { businessName: string; members: Member[]; attendance: AttendanceEntry[]; currency: string; period: string; exportStart: string; exportEnd: string }) {
  const attendanceFor = (memberId: number, date: string) => {
    const matches = attendance.filter((item) => item.memberId === memberId && item.date === date)
    return matches.find((item) => item.status === 'Present' || item.status === 'Late' || item.checkIn !== '—' || item.checkOut !== '—') || matches[matches.length - 1]
  }
  const statusFor = (entry?: AttendanceEntry) => entry && entry.status === 'Absent' && (entry.checkIn !== '—' || entry.checkOut !== '—') ? 'Present' : entry?.status || 'Absent'
  const rows = datesBetween(exportStart, exportEnd).flatMap((date) => members.map((member) => ({ date, member, entry: attendanceFor(member.id, date) })))
  const dates = Array.from(new Set(rows.map((row) => row.date)))
  return <div className="print-page unified-print-page"><article className="panel print-preview"><header className="payroll-print-header"><p className="eyebrow">BUSINESS REPORT</p><h1>{businessName}</h1><h2>Attendance report</h2><p className="payroll-print-period">{formatReportPeriod(period, exportStart, exportEnd)}<span>AS AT {formatDate(new Date().toISOString())} {new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span></p></header>{dates.map((date) => <section className="attendance-print-day" key={date}><h3>{formatDate(date)}</h3><table className="unified-report-table"><thead><tr><th>Worker</th><th>Status</th><th>Check-in</th><th>Check-out</th><th>Payment</th></tr></thead><tbody>{rows.filter((row) => row.date === date).map((row) => <tr key={`${row.member.id}-${formatDate(row.date)}`}><td>{row.member.name}</td><td>{statusFor(row.entry)}</td><td>{row.entry?.checkIn || '—'}</td><td>{row.entry?.checkOut || '—'}</td><td>{row.entry?.paymentStatus || '—'}</td></tr>)}</tbody></table></section>)}<PrintBrandFooter /></article></div>
}

function RegisterPrintReport({ businessName, members, attendance, period, exportStart, exportEnd }: { businessName: string; members: Member[]; attendance: AttendanceEntry[]; period: string; exportStart: string; exportEnd: string }) {
  const printedAt = new Date()
  const dates = datesBetween(exportStart, exportEnd)
  return <div className="print-page unified-print-page register-print-page">{dates.map((date, index) => {
    const dayEntries = attendance.filter((entry) => entry.date === date)
    const entriesByMember = new Map(dayEntries.map((entry) => [entry.memberId, entry]))
    const dayMembers = members.filter((member) => {
      const entry = entriesByMember.get(member.id)
      return (!member.archived || Boolean(entry)) && Boolean(entry && (entry.status === 'Off' || (entry.checkIn && entry.checkIn !== '—')))
    }).sort((first, second) => first.department.localeCompare(second.department) || first.name.localeCompare(second.name))
    const departments = Array.from(new Set(dayMembers.map((member) => member.department || 'Unassigned')))
    return <section className={`register-day${index ? ' register-day-new-page' : ''}`} key={date}>
      <article className="panel print-preview">
        <header className="payroll-print-header"><p className="eyebrow">BUSINESS REPORT</p><h1>{businessName}</h1><h2>Attendance register</h2><p className="payroll-print-period">{formatReportPeriod(period, exportStart, exportEnd)}<span>{formatDate(date)} · AS AT {formatDate(printedAt.toISOString())} {printedAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span></p></header>
        {departments.length ? departments.map((department) => {
          const departmentMembers = dayMembers.filter((member) => (member.department || 'Unassigned') === department)
          const departmentRows = departmentMembers.filter((member) => entriesByMember.get(member.id)?.status !== 'Off').concat(departmentMembers.filter((member) => entriesByMember.get(member.id)?.status === 'Off'))
          return <section className="register-department" key={department}>
            <h4>{department}</h4>
            <table className="unified-report-table register-table"><thead><tr><th>Name</th><th>Recorded in</th><th>Sign in</th><th>Sign out</th></tr></thead><tbody>{departmentRows.map((member) => {
              const entry = entriesByMember.get(member.id)
              const isOff = entry?.status === 'Off'
              return <tr key={member.id}><td>{member.name}</td><td className={isOff ? 'register-off-label' : undefined}>{isOff ? 'NOT IN' : entry?.checkIn && entry.checkIn !== '—' ? entry.checkIn : '—'}</td><td className={isOff ? 'register-off-label' : 'register-handwrite-cell'}>{isOff ? 'OFF' : '\u00a0'}</td><td className={isOff ? 'register-off-label' : 'register-handwrite-cell'}>{isOff ? 'OFF' : '\u00a0'}</td></tr>
            })}</tbody></table>
          </section>
        }) : <p className="empty-state">No workers were signed in for this date.</p>}
        <PrintBrandFooter />
      </article>
    </section>
  })}</div>
}

function UnifiedPrintReport({ businessName, report, members, sales, attendance, expenses, stockMovements, inventory, categoryThresholds, currency, period, exportStart, exportEnd }: { businessName: string; report: string; members: Member[]; sales: Sale[]; attendance: AttendanceEntry[]; expenses: Expense[]; stockMovements: StockMovement[]; inventory: InventoryItem[]; categoryThresholds: Record<string, number>; currency: string; period: string; exportStart: string; exportEnd: string }) {
  const printedAt = new Date()
  const periodSales = sales.filter((sale) => sale.date >= exportStart && sale.date <= exportEnd)
  const reportTitle = report === 'sales' ? 'Sales report' : report === 'expenses' ? 'Expenses report' : report === 'off' ? 'OFF MARK report' : 'Inventory report'
  const periodExpenses = expenses.filter((expense) => expense.date >= exportStart && expense.date <= exportEnd)
  if (report === 'inventory') return <StockPrintReport businessName={businessName} inventory={inventory} stockMovements={stockMovements} categoryThresholds={categoryThresholds} currency={currency} period={period} exportStart={exportStart} exportEnd={exportEnd} />
  if (report === 'register') return <RegisterPrintReport businessName={businessName} members={members} attendance={attendance} period={period} exportStart={exportStart} exportEnd={exportEnd} />
  if (report === 'off') return <AttendancePrintReport businessName={businessName} members={members} attendance={attendance} currency={currency} period={period} exportStart={exportStart} exportEnd={exportEnd} />
  return <div className="print-page unified-print-page"><article className="panel print-preview"><header className="payroll-print-header"><p className="eyebrow">BUSINESS REPORT</p><h1>{businessName}</h1><h2>{reportTitle}</h2><p className="payroll-print-period">{formatReportPeriod(period, exportStart, exportEnd)}<span>AS AT {formatDate(printedAt.toISOString())} {printedAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span></p></header><table className="unified-report-table"><thead><tr>{report === 'sales' && <><th>Date</th><th>Time</th><th>Cashier</th><th>Payment method</th><th>Amount</th></>}{report === 'expenses' && <><th>Date</th><th>Time</th><th>Item</th><th>Category</th><th>Reason</th><th>Quantity used</th></>}{report === 'off' && <><th>Date</th><th>Worker</th><th>Status</th></>}{report === 'inventory' && <><th>Item</th><th>Category</th><th>Added</th><th>Used</th><th>Remaining</th><th>Unit</th></>}</tr></thead><tbody>{report === 'sales' && periodSales.map((sale) => <tr key={sale.id}><td>{formatDate(sale.date)}</td><td>{sale.time || '?'}</td><td>{sale.cashier || '?'}</td><td>{sale.paymentMethod}</td><td className="print-income-value">{currency} {sale.amount.toLocaleString()}</td></tr>)}{report === 'expenses' && periodExpenses.map((expense) => <tr key={expense.id}><td>{formatDate(expense.date)}</td><td>{expense.time}</td><td>{expense.itemName}</td><td>{expense.category}</td><td>{expense.reason}</td><td>{expense.quantity} {expense.unit}</td></tr>)}{report === 'off' && attendance.filter((entry) => entry.status === 'Off' && entry.date >= exportStart && entry.date <= exportEnd).map((entry) => <tr key={`${entry.memberId}-${formatDate(entry.date)}`}><td>{formatDate(entry.date)}</td><td>{members.find((member) => member.id === entry.memberId)?.name || `Worker ${entry.memberId}`}</td><td>OFF</td></tr>)}{report === 'inventory' && inventory.map((item) => { const used = expenses.filter((expense) => expense.inventoryItemId === item.id && expense.date >= exportStart && expense.date <= exportEnd).reduce((sum, expense) => sum + expense.quantity, 0); const stocked = stockMovements.filter((movement) => movement.inventoryItemId === item.id && movement.type === 'Stocked' && movement.date >= exportStart && movement.date <= exportEnd).reduce((sum, movement) => sum + movement.quantity, 0); return <tr key={item.id}><td>{item.name}</td><td>{item.category}</td><td>{stocked}</td><td>{used}</td><td>{item.quantity}</td><td>{item.unit}</td></tr> })}</tbody></table><PrintBrandFooter /></article></div>
}

function StockPrintReport({ businessName, inventory, stockMovements, categoryThresholds, currency, period, exportStart, exportEnd }: { businessName: string; inventory: InventoryItem[]; stockMovements: StockMovement[]; categoryThresholds: Record<string, number>; currency: string; period: string; exportStart: string; exportEnd: string }) {
  const printedAt = new Date()
  const periodMovements = stockMovements.filter((movement) => movement.date >= exportStart && movement.date <= exportEnd).sort((first, second) => `${first.date}T${first.time}`.localeCompare(`${second.date}T${second.time}`))
  const categories = Array.from(new Set([...inventory.map((item) => item.category), ...periodMovements.map((movement) => movement.category)])).filter(Boolean)
  const rows = categories.map((category) => { const items = inventory.filter((item) => item.category === category); const stocked = periodMovements.filter((movement) => movement.category === category && movement.type === 'Stocked').reduce((sum, movement) => sum + movement.quantity, 0); const used = periodMovements.filter((movement) => movement.category === category && movement.type === 'Used').reduce((sum, movement) => sum + movement.quantity, 0); return { category, stocked, used, remaining: items.reduce((sum, item) => sum + item.quantity, 0), unit: items[0]?.unit || periodMovements.find((movement) => movement.category === category)?.unit || 'units' } })
  const restockItems = inventory.filter((item) => item.quantity <= (categoryThresholds[item.category] ?? item.reorderAt)).sort((first, second) => first.category.localeCompare(second.category) || first.name.localeCompare(second.name))
  const restockCategories = Array.from(new Set(restockItems.map((item) => item.category)))
  return <>
    <div className="print-page unified-print-page">
      <article className="panel print-preview">
        <header className="payroll-print-header"><p className="eyebrow">BUSINESS REPORT</p><h1>{businessName}</h1><h2>Stock movement report</h2><p className="payroll-print-period">{formatReportPeriod(period, exportStart, exportEnd)}<span>AS AT {formatDate(printedAt.toISOString())} {printedAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span></p></header>
        <h3 className="print-section-title">Complete stock movement by category</h3>
        {categories.length ? categories.map((category) => {
          const row = rows.find((item) => item.category === category)!
          const categoryItemsByKey = new Map<string, { id: number; name: string; unit: string; currentItem?: InventoryItem }>()
          inventory.filter((item) => item.category === category).forEach((item) => categoryItemsByKey.set(`${item.id}:${item.name}`, { id: item.id, name: item.name, unit: item.unit, currentItem: item }))
          periodMovements.filter((movement) => movement.category === category).forEach((movement) => {
            const key = `${movement.inventoryItemId}:${movement.itemName}`
            if (!categoryItemsByKey.has(key)) categoryItemsByKey.set(key, { id: movement.inventoryItemId, name: movement.itemName, unit: movement.unit, currentItem: inventory.find((item) => item.id === movement.inventoryItemId) })
          })
          const categoryItems = Array.from(categoryItemsByKey.values()).sort((first, second) => first.name.localeCompare(second.name))
          return <section className="stock-category-print" key={category}>
            <h3>{category}</h3>
            {categoryItems.map((item) => {
              const itemMovements = periodMovements.filter((movement) => movement.category === category && movement.inventoryItemId === item.id && movement.itemName === item.name)
              const itemStocked = itemMovements.filter((movement) => movement.type === 'Stocked').reduce((sum, movement) => sum + movement.quantity, 0)
              const itemUsed = itemMovements.filter((movement) => movement.type === 'Used').reduce((sum, movement) => sum + movement.quantity, 0)
              const itemIsCurrent = item.currentItem?.category === category && item.currentItem.name === item.name
              const remaining = itemIsCurrent ? `${item.currentItem.quantity} ${item.currentItem.unit}` : item.currentItem ? `Tracked as ${item.currentItem.name} in ${item.currentItem.category}` : 'Removed from inventory'
              return <section className="stock-item-print" key={item.id}>
                <h4>{item.name}</h4>
                <table className="unified-report-table">
                  <thead><tr><th>Date</th><th>Time</th><th>Type</th><th>Quantity</th><th>Reason</th></tr></thead>
                  <tbody>{itemMovements.length ? itemMovements.map((movement) => <tr key={movement.id}><td>{formatDate(movement.date)}</td><td>{movement.time}</td><td>{movement.type}</td><td>{movement.quantity} {movement.unit}</td><td>{movement.reason}</td></tr>) : <tr><td colSpan={5}>No movements recorded in this period.</td></tr>}</tbody>
                </table>
                <table className="unified-report-table stock-category-total stock-item-total"><tbody><tr><th>Item total</th><td>Stocked: {itemStocked} {item.unit}</td><td>Used: {itemUsed} {item.unit}</td><td>Remaining: <strong>{remaining}</strong></td></tr></tbody></table>
              </section>
            })}
            <table className="unified-report-table stock-category-total"><tbody><tr><th>Category total</th><td>Stocked: {row.stocked} {row.unit}</td><td>Used: {row.used} {row.unit}</td><td>Remaining: <strong>{row.remaining} {row.unit}</strong></td></tr></tbody></table>
          </section>
        }) : <p className="empty-state">No stock movements in this period.</p>}
        <PrintBrandFooter />
      </article>
    </div>
    {restockItems.length > 0 && <div className="print-page unified-print-page stock-restock-page">
      <article className="panel print-preview">
        <header className="payroll-print-header"><p className="eyebrow">BUSINESS REPORT</p><h1>{businessName}</h1><h2>Stock movement report</h2><p className="payroll-print-period">{formatReportPeriod(period, exportStart, exportEnd)}<span>AS AT {formatDate(printedAt.toISOString())} {printedAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span></p></header>
        <h3 className="print-section-title">Stock insufficiency: {restockItems.length} item{restockItems.length === 1 ? '' : 's'} {restockItems.length === 1 ? 'needs' : 'need'} attention</h3>
        {restockCategories.map((category) => <section className="stock-category-print" key={category}><h3>{category}</h3><table className="unified-report-table"><thead><tr><th>Item</th><th>In stock</th><th>Reorder at</th><th>Shortfall</th></tr></thead><tbody>{restockItems.filter((item) => item.category === category).map((item) => { const threshold = categoryThresholds[item.category] ?? item.reorderAt; return <tr key={item.id}><td>{item.name}</td><td>{item.quantity} {item.unit}</td><td>{threshold} {item.unit}</td><td>{Math.max(0, threshold - item.quantity)} {item.unit}</td></tr> })}</tbody></table></section>)}
        <PrintBrandFooter />
      </article>
    </div>}
  </>
      {myCredentialsOpen && <MyLoginCredentialsDialog username={sessionMemberId === -1 ? ownerAccount?.username || '' : members.find((member) => member.id === sessionMemberId)?.username || ''} onSave={saveMyLoginCredentials} onClose={() => setMyCredentialsOpen(false)} />}
}

function PaymentRegisterPrintReport({ businessName, members, attendance, casualEarnings, deductions, currency, paymentRegisterFooter, period, exportStart, exportEnd }: { businessName: string; members: Member[]; attendance: AttendanceEntry[]; casualEarnings: CasualEarning[]; deductions: Deduction[]; currency: string; paymentRegisterFooter: string; period: string; exportStart: string; exportEnd: string }) {
  const printedAt = new Date()
  const rows = paymentRegisterRows(members, attendance, deductions, exportStart, exportEnd, true, casualEarnings).sort((first, second) => first.member.department.localeCompare(second.member.department) || first.member.name.localeCompare(second.member.name))
  const departments = Array.from(new Set(rows.map((row) => row.member.department || 'Unassigned')))
  const totals = rows.reduce((result, row) => ({ netEarned: result.netEarned + row.netEarned, amountReceived: result.amountReceived + row.amountReceived }), { netEarned: 0, amountReceived: 0 })
  const amount = (value: number) => `${currency} ${value.toLocaleString()}`
  return (
    <div className="print-page unified-print-page payment-register-print-page">
      <article className="panel print-preview">
        <header className="payroll-print-header">
          <p className="eyebrow">BUSINESS REPORT</p>
          <h1>{businessName}</h1>
          <h2>Payroll Payment Register</h2>
          <p className="payroll-print-period">{formatReportPeriod(period, exportStart, exportEnd)}<span>AS AT {formatDate(localDateKey(printedAt))} {printedAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span></p>
        </header>
        {departments.length ? departments.map((department) => (
          <section className="payment-register-department" key={department}>
            <h3>{department}</h3>
            <div className="payment-register-table-wrap">
              <table className="unified-report-table payment-register-table payment-register-data-table">
                <thead><tr><th>Worker</th><th>Amount owed</th><th>Amount received</th><th>Worker signature</th></tr></thead>
                <tbody>{rows.filter((row) => (row.member.department || 'Unassigned') === department).map((row) => <tr key={row.member.id}><td>{row.member.name}</td><td>{amount(row.netEarned)}</td><td>{amount(row.amountReceived)}</td><td className="payment-signature-cell"><span className="payment-signature-line"></span></td></tr>)}</tbody>
              </table>
            </div>
          </section>
        )) : <p className="empty-state">No completed shifts or payment receipts were recorded in this period.</p>}
        {rows.length > 0 && <section className="payment-register-total">
          <h3>Register totals</h3>
          <div className="payment-register-table-wrap">
            <table className="unified-report-table payment-register-table payment-register-data-table">
              <tbody><tr><th>Total</th><td>{amount(totals.netEarned)}</td><td>{amount(totals.amountReceived)}</td><td></td></tr></tbody>
            </table>
          </div>
        </section>}
        {paymentRegisterFooter.trim() && <footer className="payment-register-disclaimer"><p>{paymentRegisterFooter.trim()}</p></footer>}
        <PrintBrandFooter />
      </article>
    </div>
  )
}

function PayrollPrintReport({ businessName, members, attendance, casualEarnings, deductions, currency, period, exportStart, exportEnd, payrollReportOrder }: { businessName: string; members: Member[]; attendance: AttendanceEntry[]; casualEarnings: CasualEarning[]; deductions: Deduction[]; currency: string; period: string; exportStart: string; exportEnd: string; payrollReportOrder: PayrollReportOrder }) {
  const printedAt = new Date()
  const printedTime = printedAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
  const shiftEntries = attendance.filter((entry) => entry.checkOut !== '—' && (entry.paymentStatus === 'Paid' || entry.paymentStatus === 'Partially paid') && entry.date >= exportStart && entry.date <= exportEnd).flatMap((entry) => {
    const member = members.find((item) => item.id === entry.memberId)
    const termsAtEarning = entry.workerPayTerms || (member?.payTermsSince && entry.date < member.payTermsSince ? 'Per shift' : member?.payTerms || 'Per shift')
    return termsAtEarning === 'Casual' ? [] : [{ ...entry, earningType: 'shift' as const, workerPayTerms: termsAtEarning }]
  })
  const casualEntries = casualEarnings.filter((earning) => (earning.paymentStatus === 'Paid' || earning.paymentStatus === 'Partially paid') && earning.date >= exportStart && earning.date <= exportEnd).map((earning) => ({ memberId: earning.memberId, date: earning.date, status: 'Present' as AttendanceStatus, checkIn: '—', checkOut: '—', payRate: earning.amount, earningType: 'casual' as const, earningId: earning.id, workerName: earning.workerName, workerDepartment: earning.workerDepartment, workerRole: earning.workerRole, workerPayTerms: earning.workerPayTerms || 'Casual', workerPayFrequency: earning.workerPayFrequency, earningReason: earning.earningReason, reason: earning.reason, paymentStatus: earning.paymentStatus, paymentReceived: earning.paymentReceived, paymentHistory: earning.paymentHistory, paidAt: earning.paidAt, paymentBatchId: earning.paymentBatchId }))
  const payrollWorkers = members.map((member) => {
    const earnings = [...shiftEntries.filter((entry) => entry.memberId === member.id), ...casualEntries.filter((entry) => entry.memberId === member.id)].sort((first, second) => first.date.localeCompare(second.date))
    const workerDeductions = deductions.filter((deduction) => deduction.memberId === member.id && deduction.date >= exportStart && deduction.date <= exportEnd)
    const gross = earnings.reduce((sum, entry) => sum + (entry.payRate ?? member.payRate), 0)
    const deducted = workerDeductions.reduce((sum, deduction) => sum + deduction.amount, 0)
    const payments = [...earnings.flatMap((entry) => payrollPaymentEventsForEntry(entry, entry.payRate ?? member.payRate)), ...(member.payrollPaymentHistory || []).filter((payment) => payment.date >= exportStart && payment.date <= exportEnd)]
    const received = payments.reduce((sum, payment) => sum + payment.amount, 0)
    const net = Math.max(0, gross - deducted)
    return { member, earnings, payments, deductions: workerDeductions, gross, deducted, net, received, outstanding: Math.max(0, net - received) }
  }).filter((worker) => worker.earnings.length > 0 || worker.deductions.length > 0 || worker.payments.length > 0)
  const periodGross = payrollWorkers.reduce((sum, worker) => sum + worker.gross, 0)
  const periodDeductions = payrollWorkers.reduce((sum, worker) => sum + worker.deducted, 0)
  const periodNet = payrollWorkers.reduce((sum, worker) => sum + worker.net, 0)
  const periodReceived = payrollWorkers.reduce((sum, worker) => sum + worker.received, 0)
  const periodOutstanding = payrollWorkers.reduce((sum, worker) => sum + worker.outstanding, 0)
  return (
    <div className="print-page payroll-print-page">
      <article className="panel print-preview">
        <header className="payroll-print-header"><p className="eyebrow payroll-print-brand">BUSINESS REPORT</p><p className="payroll-print-kicker">BUSINESS REPORT</p><h1>{businessName}</h1><h2>Payroll report</h2><p className="payroll-print-period">{formatPayrollReportPeriod(period, exportStart, exportEnd)}<span>AS AT {formatPayrollReportDate(localDateKey(printedAt))} {printedTime}</span></p></header>
        {payrollWorkers.length ? payrollWorkers.map(({ member, earnings, payments, deductions: workerDeductions, gross, deducted, net, received, outstanding }) => {
          const rows = payrollPrintRows(earnings, payments, workerDeductions, member.payRate)
          return (
            <section className="payroll-worker-report" key={member.id}>
              <h3>{member.name} (ID #{member.id})</h3>
              <p className="payroll-worker-meta">{member.department}</p>
              <table>
                <thead><tr><th>Date</th><th>Type</th><th>Worker particulars / reason</th><th>Amount</th></tr></thead>
                <tbody>{rows.map((row) => {
                  if (row.type === 'earning') {
                    const entry = row.entry
                    const termsAtEarning = entry.workerPayTerms || (member.payTermsSince && entry.date < member.payTermsSince ? 'Per shift' : member.payTerms || 'Per shift')
                    const amount = entry.payRate ?? member.payRate
                    const paymentBalance = entry.paymentStatus === 'Partially paid' ? Math.max(0, amount - (entry.paymentReceived || 0)) : 0
                    const previousBalanceAmount = row.previousBalanceEvents.reduce((sum, payment) => sum + payment.amount, 0)
                    const sourceTerms = new Set(row.previousBalanceEvents.map((payment) => payment.balanceSourceTerms || 'Mixed'))
                    const previousBalanceSource = sourceTerms.size > 1 || sourceTerms.has('Mixed') ? 'mixed' : sourceTerms.has('Casual') ? 'casual' : 'shift'
                    let earningReason = termsAtEarning === 'Casual' ? entry.earningReason || 'Casual earning' : entry.paymentStatus === 'Partially paid' ? `Partially paid (${currency} ${paymentBalance.toLocaleString()} left)` : '1 shift'
                    if (previousBalanceAmount > 0) {
                      earningReason = termsAtEarning === 'Casual'
                        ? `${earningReason} + previous ${previousBalanceSource} balance (${currency} ${previousBalanceAmount.toLocaleString()})`
                        : `${earningReason} + previous ${previousBalanceSource} balance (${currency} ${previousBalanceAmount.toLocaleString()})`
                    }
                    if (termsAtEarning === 'Casual' && entry.paymentStatus === 'Partially paid') earningReason += ` · Partially paid (${currency} ${paymentBalance.toLocaleString()} left)`
                    const paymentNotes = row.paymentEvents.map((payment) => `${payment.reason || 'Payment recorded'} (${currency} ${payment.amount.toLocaleString()})`).join('; ')
                    return <tr key={`${member.id}-earning-${entry.earningId ?? entry.date}-${entry.checkIn}-${entry.paymentBatchId || entry.payRate}`}><td>{formatDate(entry.date)}</td><td>{termsAtEarning === 'Casual' ? 'Casual earning' : 'Shift earning'}</td><td>{earningReason}{paymentNotes && <small className="payroll-payment-note">Payment: {paymentNotes}</small>}</td><td className="print-income-value">{currency} {amount.toLocaleString()}</td></tr>
                  }
                  if (row.type === 'payment') {
                    const balanceText = row.payment.status === 'Partially paid' || (row.payment.balanceRemaining || 0) > 0 ? ` (KES ${(row.payment.balanceRemaining || 0).toLocaleString()} left)` : ''
                    return <tr key={`${member.id}-payment-${row.payment.id}`}><td>{formatDate(row.payment.date)}</td><td>{row.payment.status === 'Partially paid' ? 'Partial payment' : 'Payment received'}</td><td>{row.payment.reason || 'Payment recorded'}{balanceText}</td><td className="print-income-value">{currency} {row.payment.amount.toLocaleString()}</td></tr>
                  }
                  return <tr className="payroll-deduction-row" key={`deduction-${row.deduction.id}`}><td>{formatDate(row.deduction.date)}</td><td>Deduction</td><td>{row.deduction.reason}</td><td className="print-income-value">- {currency} {row.deduction.amount.toLocaleString()}</td></tr>
                })}
                  <tr className="payroll-total-row"><td colSpan={3}>Gross earnings</td><td className="print-income-value">{currency} {gross.toLocaleString()}</td></tr>
                  <tr className="payroll-total-row"><td colSpan={3}>Total deductions</td><td className="print-income-value">- {currency} {deducted.toLocaleString()}</td></tr>
                  <tr className="payroll-total-row"><td colSpan={3}>Amount received</td><td className="print-income-value">{currency} {received.toLocaleString()}</td></tr>
                  <tr className="payroll-net-row"><td colSpan={3}>Outstanding balance</td><td className="print-outflow-value">{currency} {outstanding.toLocaleString()}</td></tr>
                  <tr className="payroll-net-row"><td colSpan={3}>Net earned</td><td className="print-outflow-value">{currency} {net.toLocaleString()}</td></tr>
                </tbody>
              </table>
            </section>
          )
        }) : <p className="empty-state">No earnings or deductions in this period.</p>}
        <section className="payroll-period-summary"><h3>Payroll period totals</h3><table><tbody><tr><th>Total earnings</th><td className="print-income-value">{currency} {periodGross.toLocaleString()}</td></tr><tr><th>Total deductions</th><td className="print-income-value">- {currency} {periodDeductions.toLocaleString()}</td></tr><tr><th>Amount received</th><td className="print-income-value">{currency} {periodReceived.toLocaleString()}</td></tr><tr><th>Outstanding balance</th><td className="print-outflow-value">{currency} {periodOutstanding.toLocaleString()}</td></tr><tr className="payroll-net-row"><th>Total net earned</th><td className="print-outflow-value">{currency} {periodNet.toLocaleString()}</td></tr></tbody></table></section>
        <PrintBrandFooter />
      </article>
    </div>
  )
}

function AccountChoiceModal({ onClose, onExisting, onCreate }: { onClose: () => void; onExisting: () => void; onCreate: () => void }) { return <div className="account-choice-backdrop" role="dialog" aria-modal="true"><section className="account-choice-modal"><button className="choice-close" aria-label="Close" onClick={onClose}>×</button><p className="eyebrow">ADD ACCOUNT</p><h2>Choose how to continue</h2><p>Select an existing worker or create a new account.</p><div className="account-choice-actions"><button className="choice-card" onClick={onExisting}><strong>Existing worker</strong><span>Choose one worker from Team and assign access.</span><b>→</b></button><button className="choice-card choice-card-accent" onClick={onCreate}><strong>Create new account</strong><span>Open the worker form and create a login account.</span><b>→</b></button></div></section></div> }

function PermissionsPage({ members, accessByMember, setAccessByMember, selectedMemberId, onAddMember, onSave, onSetCredentials, onCancel }: { members: Member[]; accessByMember: Record<number, AccessArea[]>; setAccessByMember: (value: Record<number, AccessArea[]>) => void; selectedMemberId?: number | null; onAddMember: () => void; onSave: (member: Member, grantedPages: AccessArea[]) => void | Promise<void>; onSetCredentials: (memberId: number, username: string, password: string) => Promise<Member>; onCancel: () => void }) {
  const accountMembers = members.filter((member) => member.hasAccount === true && Boolean(member.username?.trim() && member.password?.trim()))
  const [selectedId, setSelectedId] = useState(selectedMemberId || accountMembers[0]?.id || 0)
  const selected = accountMembers.find((member) => member.id === selectedId)
  const [draftAccess, setDraftAccess] = useState<AccessArea[]>([])
  const [credentialsOpen, setCredentialsOpen] = useState(false)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [credentialError, setCredentialError] = useState('')
  const granted = draftAccess
  useEffect(() => { if (selectedMemberId) setSelectedId(selectedMemberId) }, [selectedMemberId])
  useEffect(() => { setDraftAccess(selected ? normalizeAccessAreas(accessByMember[selected.id] || []) : []) }, [selectedId, accessByMember])
  useEffect(() => {
    const container = document.querySelector('.permission-confirm')
    if (!container || container.querySelector('.permission-cancel')) return
    const cancel = document.createElement('button')
    cancel.type = 'button'
    cancel.className = 'secondary-button permission-cancel'
    cancel.textContent = 'Cancel'
    cancel.addEventListener('click', onCancel)
    container.prepend(cancel)
    return () => cancel.remove()
  }, [selectedId, onCancel])
  const toggle = (area: AccessArea) => setDraftAccess((current) => current.includes(area) ? current.filter((item) => item !== area) : [...current, area])
  const saveAccess = async (member: Member) => {
    const nextAccess = normalizeAccessAreas(draftAccess)
    setAccessByMember((current) => ({ ...current, [member.id]: nextAccess }))
    await onSave(member, nextAccess)
  }
  const confirmAccess = async () => {
    if (!selected) return
    if (!selected.username || !selected.password) {
      setUsername(selected.username || '')
      setPassword('')
      setCredentialError('')
      setCredentialsOpen(true)
      return
    }
    await saveAccess(selected)
  }
  const submitCredentials = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!selected) return
    const nextUsername = username.trim().toLowerCase()
    if (nextUsername.length < 3) { setCredentialError('Username must be at least 3 characters.'); return }
    if (password.length < 6) { setCredentialError('Password must be at least 6 characters.'); return }
    const updateCredentials = onSetCredentials || (window as any).__biztrackSetMemberCredentials
    if (!updateCredentials) { setCredentialError('Unable to save login details.'); return }
    const updatedMember = await updateCredentials(selected.id, nextUsername, password)
    setCredentialsOpen(false)
    saveAccess(updatedMember)
  }
  return <><PageHeading eyebrow="OWNER CONTROL / PERMISSIONS" title="Permissions" subtitle="Choose which parts of Biz Track each worker can access." action={<button className="primary-button" onClick={onAddMember}>＋ Add worker account</button>} /><div className="permissions-layout"><article className="panel permissions-people"><PanelHeading title="Worker accounts" subtitle="Only workers with login accounts appear here." />{accountMembers.length ? accountMembers.map((member) => <button key={member.id} className={`permission-person ${selectedId === member.id ? 'selected' : ''}`} onClick={() => setSelectedId(member.id)}><span className={`avatar avatar-${member.color}`}>{member.initials}</span><span><strong>{member.name}</strong><small>{member.role} · {member.department}</small></span><b>→</b></button>) : <div className="permission-empty"><strong>No worker accounts yet</strong><p>Enable a login account when adding a worker, then return here to set their access.</p><button className="secondary-button" onClick={onAddMember}>Add worker account</button></div>}</article><article className="panel permission-editor"><PanelHeading title={selected ? `Access for ${selected.name}` : 'Choose an account'} subtitle="Select the pages this worker can access, then confirm." />{selected ? <><div className="permission-grid">{accessAreas.map((area) => <label key={area} className={`permission-toggle ${granted.includes(area) ? 'enabled' : ''}`}><input type="checkbox" checked={granted.includes(area)} onChange={() => toggle(area)} /><span><strong>{area}</strong><small>{area === 'Overview' ? 'Business summary and daily activity' : `Open and work with ${area.toLowerCase()} records`}</small></span><i>{granted.includes(area) ? 'On' : 'Off'}</i></label>)}</div><div className="permission-confirm"><button className="primary-button" onClick={confirmAccess}>OK</button></div></> : <div className="permission-empty"><strong>Choose an account to begin</strong><p>Your access controls will appear here after you select a worker with a login account.</p></div>}</article></div>{credentialsOpen && selected && <div className="admin-modal-backdrop" role="presentation"><section className="admin-modal" role="dialog" aria-modal="true" aria-labelledby="member-credentials-title"><button className="admin-modal-close" type="button" aria-label="Close" onClick={() => setCredentialsOpen(false)}>×</button><p className="eyebrow">WORKER LOGIN</p><h2 id="member-credentials-title">Set login details</h2><p className="admin-modal-user"><strong>{selected.name}</strong><span>Create credentials so this worker can sign in and use the pages you selected.</span></p><form onSubmit={submitCredentials}><label className="login-field"><span>Username</span><input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" required /></label><label className="login-field"><span>Password</span><input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password" minLength={6} required /></label>{credentialError && <p className="login-error" role="alert">{credentialError}</p>}<div className="form-actions"><button type="button" className="secondary-button" onClick={() => setCredentialsOpen(false)}>Cancel</button><button type="submit" className="primary-button">Save login</button></div></form></section></div>}</>
}

function WorkspaceSidebar({ businessName, activeNav, onNavigate, onLogout }: { businessName: string; activeNav: string; onNavigate: (page: string) => void; onLogout: () => void }) {
  const [expanded, setExpanded] = useState(false)
  const allowedPages = Array.from(new Set(((window as any).__biztrackVisibleWorkspacePages || uniqueAccessAreas) as AccessArea[])) as AccessArea[]
  const canSee = (link: string) => allowedPages.includes(link as AccessArea)
  const iconFor = (link: string) => navItems.find((item) => item.label === link)?.icon || (link === 'Permissions' ? '⌘' : link === 'OFF MARK' ? '◉' : link === 'Team' ? '◎' : link === 'Add member' ? '+' : link === 'Settings' ? '⚙' : link === 'ROLL' ? '◷' : '◈')
  const navigateFromSidebar = (page: string) => { setExpanded(false); onNavigate(page) }
  const openHelp = () => {
    const url = whatsappHelpUrl(businessName, (window as any).__biztrackHelpOwner || null, (window as any).__biztrackHelpMembers || [], (window as any).__biztrackHelpSessionMemberId ?? 0, (window as any).__biztrackWhatsappNumber || '')
    if (!url) { showBusinessAlert('Site admin', 'Help center WhatsApp number is not configured.', 'Support unavailable'); return }
    const link = document.createElement('a')
    link.href = url
    link.target = '_blank'
    link.rel = 'noopener noreferrer'
    link.click()
  }
  return <><button className="sidebar-toggle" aria-label={expanded ? 'Collapse sidebar' : 'Expand sidebar'} aria-expanded={expanded} onClick={() => setExpanded((value) => !value)}><span>{expanded ? '‹' : '☰'}</span><b>{expanded ? 'Collapse menu' : 'Menu'}</b></button><aside className={`sidebar ${expanded ? 'sidebar-expanded' : ''}`}><div className="business-sidebar-name" aria-label="Business name"><span>{businessName}</span></div><nav aria-label="Workspace navigation">{sidebarGroups.map((group) => { const visibleLinks = group.links.filter(canSee); return visibleLinks.length ? <section className={`sidebar-group ${group.label ? '' : 'sidebar-group-primary'}`} key={group.label || 'primary'}>{group.label && <p className="nav-label">{group.label}</p>}{visibleLinks.map((link) => <button key={link} className={`nav-item ${activeNav === link ? 'active' : ''}`} title={visiblePageName(link)} onClick={() => navigateFromSidebar(link)}><span className="nav-icon">{iconFor(link)}</span><span className="nav-item-label">{visiblePageName(link)}</span></button>)}</section> : null })}</nav><div className="sidebar-footer"><button className="help-link" type="button" onClick={openHelp}><span className="help-mark">?</span><span>Help center</span></button><button className="sidebar-signout" onClick={onLogout}>↪ Sign out</button></div></aside></>
}

function BusinessAssistantPage({ businessName, ownerName, tenantId, currency, members, attendance, casualEarnings, deductions, sales, salesHistory, inventory, categoryThresholds, isDrawer = false, onClose }: { businessName: string; ownerName: string; tenantId: string; currency: string; members: Member[]; attendance: AttendanceEntry[]; casualEarnings: CasualEarning[]; deductions: Deduction[]; sales: Sale[]; salesHistory: Sale[]; inventory: InventoryItem[]; categoryThresholds: Record<string, number>; isDrawer?: boolean; onClose?: () => void }) {
  type Message = { role: 'assistant' | 'user'; text: string }
  const [messages, setMessages] = useState<Message[]>([])
  const [question, setQuestion] = useState('')
  const [availability, setAvailability] = useState<'checking' | 'ready' | 'missing-key' | 'unavailable'>('checking')
  const [notice, setNotice] = useState('')
  const [sending, setSending] = useState(false)
  useEffect(() => {
    let cancelled = false
    const checkAvailability = async () => {
      if (!isSupabaseConfigured || !supabase || !tenantId || tenantId === 'workspace') {
        if (!cancelled) { setAvailability('unavailable'); setNotice('AI requires a connected owner account and shared workspace.') }
        return
      }
      try {
        const { data, error } = await supabase.auth.getSession()
        if (error || !data.session?.access_token) throw new Error('Please sign in again as the business owner.')
        const response = await fetch('/api/business-assistant', { method: 'POST', headers: { Authorization: `Bearer ${data.session.access_token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ action: 'status', tenantId }) })
        const result = await response.json() as { configured?: boolean; mode?: 'gemini' | 'openai' | 'local'; error?: string }
        if (!response.ok) throw new Error(result.error || 'Could not verify AI access.')
        if (!cancelled) {
          setAvailability(result.configured ? 'ready' : 'missing-key')
          setNotice('')
        }
      } catch (error) {
        if (!cancelled) { setAvailability('unavailable'); setNotice(error instanceof Error ? error.message : 'AI is currently unavailable.') }
      }
    }
    void checkAvailability()
    return () => { cancelled = true }
  }, [tenantId])
  const createSummary = () => {
    const month = today.slice(0, 7)
    const activeMembers = members.filter((member) => !member.archived)
    const activeMemberById = new Map(activeMembers.map((member) => [member.id, member]))
    const workersByDepartment = activeMembers.reduce<Record<string, number>>((counts, member) => {
      counts[member.department] = (counts[member.department] || 0) + 1
      return counts
    }, {})
    const attendanceToday = attendance.filter((entry) => entry.date === today)
    const attendanceCounts = Object.fromEntries(['Present', 'Late', 'Absent', 'Off'].map((status) => [status, attendanceToday.filter((entry) => entry.status === status).length]))
    const shiftEarnings = attendance.filter((entry) => entry.date.startsWith(month) && entry.checkOut !== '—' && entry.earningType !== 'casual').map((entry) => {
      const member = activeMemberById.get(entry.memberId)
      const gross = Number(entry.payRate ?? member?.payRate ?? 0)
      return { status: entry.paymentStatus || 'Pending', gross, received: Number(entry.paymentReceived ?? (entry.paymentStatus === 'Paid' ? gross : 0)) }
    })
    const casualEarningsThisMonth = casualEarnings.filter((earning) => earning.date.startsWith(month)).map((earning) => ({ status: earning.paymentStatus, gross: Number(earning.amount) || 0, received: Number(earning.paymentReceived ?? (earning.paymentStatus === 'Paid' ? earning.amount : 0)) }))
    const earnings = [...shiftEarnings, ...casualEarningsThisMonth]
    const monthSales = [...sales, ...salesHistory].filter((sale) => !sale.archived && sale.date.startsWith(month))
    const salesByDate = [...sales, ...salesHistory].filter((sale) => !sale.archived).reduce<Record<string, { records: number; total: number }>>((totals, sale) => {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(sale.date)) return totals
      const dailyTotal = totals[sale.date] || { records: 0, total: 0 }
      dailyTotal.records += 1
      dailyTotal.total += Number(sale.amount) || 0
      totals[sale.date] = dailyTotal
      return totals
    }, {})
    const recentSalesByDate = Object.fromEntries(Object.entries(salesByDate).sort(([dateA], [dateB]) => dateB.localeCompare(dateA)).slice(0, 500))
    const monthDeductions = deductions.filter((deduction) => !deduction.archived && deduction.date.startsWith(month))
    const lowStockItems = inventory.filter((item) => item.quantity <= (categoryThresholds[item.category] ?? item.reorderAt))
    return {
      business: { name: businessName, ownerName, currency, date: today },
      team: { activeWorkers: activeMembers.length, workersByDepartment },
      attendanceToday: { recordedWorkers: attendanceToday.length, statusCounts: attendanceCounts },
      payrollThisMonth: {
        earnings: earnings.length,
        gross: earnings.reduce((sum, earning) => sum + earning.gross, 0),
        received: earnings.reduce((sum, earning) => sum + earning.received, 0),
        outstanding: earnings.reduce((sum, earning) => sum + Math.max(0, earning.gross - earning.received), 0),
        statusCounts: Object.fromEntries(['Paid', 'Partially paid', 'Pending', 'On hold'].map((status) => [status, earnings.filter((earning) => earning.status === status).length])),
      },
      salesThisMonth: { records: monthSales.length, total: monthSales.reduce((sum, sale) => sum + (Number(sale.amount) || 0), 0) },
      salesByDate: recentSalesByDate,
      salesByDateFrom: Object.keys(recentSalesByDate).sort()[0] || '',
      deductionsThisMonth: { records: monthDeductions.length, total: monthDeductions.reduce((sum, deduction) => sum + (Number(deduction.amount) || 0), 0) },
      inventory: { trackedItems: inventory.length, lowStockItems: lowStockItems.length, unitsInStock: inventory.reduce((sum, item) => sum + (Number(item.quantity) || 0), 0) },
    }
  }
  const sendQuestion = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const trimmedQuestion = question.trim()
    if (!trimmedQuestion || availability !== 'ready' || sending || !supabase) return
    setSending(true)
    setMessages((current) => [...current, { role: 'user', text: trimmedQuestion }])
    setQuestion('')
    try {
      const { data, error } = await supabase.auth.getSession()
      if (error || !data.session?.access_token) throw new Error('Please sign in again as the business owner.')
      const response = await fetch('/api/business-assistant', { method: 'POST', headers: { Authorization: `Bearer ${data.session.access_token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ tenantId, question: trimmedQuestion, summary: createSummary() }) })
      const result = await response.json() as { answer?: string; mode?: string; error?: string }
      if (!response.ok) throw new Error(result.error || 'AI could not answer right now.')
      if (result.mode === 'local-fallback') setNotice('The AI provider is unavailable. I answered using workspace totals instead.')
      setMessages((current) => [...current, { role: 'assistant', text: result.answer || 'I could not form an answer. Please try again.' }])
    } catch (error) {
      const message = error instanceof Error ? error.message : 'AI could not answer right now.'
      setNotice(message)
      if (message.includes('API_KEY')) setAvailability('missing-key')
    } finally {
      setSending(false)
    }
  }
  const hour = new Date().getHours()
  const greeting = hour < 12 ? 'Good morning' : hour < 18 ? 'Good afternoon' : hour < 22 ? 'Good evening' : 'Good night'
  const suggestions = ['How is my business doing this month?', 'What needs attention today?', 'How much payroll is still unpaid?', 'Which stock items are low?']
  useEffect(() => {
    if (!isDrawer) return
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose?.() }
    document.addEventListener('keydown', closeOnEscape)
    return () => document.removeEventListener('keydown', closeOnEscape)
  }, [isDrawer, onClose])
  const chatPanel = <article className="business-ai-chat panel">
    <header className="business-ai-heading"><span className="business-ai-mark" aria-hidden="true">✦</span><div><h2 id="business-ai-chat-title">AI</h2><p>Direct answers to your questions</p></div><span className={`business-ai-status ${availability}`}>{availability === 'checking' ? 'Checking' : availability === 'ready' ? 'Ready' : availability === 'missing-key' ? 'Setup needed' : 'Unavailable'}</span></header>
    {notice && <div className={`business-ai-notice ${availability === 'ready' ? '' : 'needs-setup'}`} role="status">{notice}</div>}
    <div className="business-ai-messages" aria-live="polite">
      {!messages.length && <div className="business-ai-welcome"><strong>What would you like to know?</strong><p>Ask about sales, payroll, attendance, your team, or stock.</p><div className="business-ai-suggestions">{suggestions.map((suggestion) => <button key={suggestion} type="button" onClick={() => setQuestion(suggestion)} disabled={availability !== 'ready'}>{suggestion}</button>)}</div></div>}
      {messages.map((message, index) => <div className={`business-ai-message ${message.role}`} key={`${message.role}-${index}`}><span className="business-ai-message-label">{message.role === 'user' ? 'You' : 'AI answer'}</span><p>{message.role === 'assistant' ? message.text.split(/(\*\*[^*]+\*\*)/g).map((part, partIndex) => part.startsWith('**') && part.endsWith('**') ? <strong key={partIndex}>{part.slice(2, -2)}</strong> : part) : message.text}</p></div>)}
      {sending && <div className="business-ai-message assistant"><span className="business-ai-message-label">AI answer</span><p>Checking your business totals...</p></div>}
    </div>
    <form className="business-ai-form" onSubmit={(event) => void sendQuestion(event)}>
      <label className="business-ai-input-label" htmlFor="business-ai-question">Your question</label>
      <div className="business-ai-input-row"><textarea id="business-ai-question" value={question} onChange={(event) => setQuestion(event.target.value)} maxLength={1500} placeholder={availability === 'ready' ? 'Ask a question...' : 'AI setup is required'} disabled={availability !== 'ready' || sending} required /><button className="primary-button" type="submit" disabled={availability !== 'ready' || sending || !question.trim()}>{sending ? 'Working...' : 'Ask'}</button></div>
      <small>Only totals and counts are shared. Worker names and individual records are not.</small>
    </form>
  </article>
  if (isDrawer) return <section className="business-ai-drawer" role="dialog" aria-modal="false" aria-labelledby="business-ai-chat-title"><header className="business-ai-drawer-heading"><div><p className="eyebrow">AI</p><h2>{greeting}, {ownerName}</h2><p>Ask a question and get a direct answer.</p></div><button type="button" className="business-ai-close" aria-label="Close AI" onClick={onClose}>×</button></header>{chatPanel}</section>
  return <>
    <PageHeading eyebrow="OWNER WORKSPACE / AI" title={`${greeting}, ${ownerName}`} subtitle="Ask a question for a short, direct answer." />
    <section className="business-ai-layout">
      {chatPanel}
      <aside className="business-ai-data"><h2>Available business context</h2><p>Current owner workspace totals, refreshed when you ask a question.</p><dl><div><dt>Active workers</dt><dd>{members.filter((member) => !member.archived).length}</dd></div><div><dt>Sales this month</dt><dd>{currency} {[...sales, ...salesHistory].filter((sale) => !sale.archived && sale.date.startsWith(today.slice(0, 7))).reduce((sum, sale) => sum + (Number(sale.amount) || 0), 0).toLocaleString()}</dd></div><div><dt>Open stock alerts</dt><dd>{inventory.filter((item) => item.quantity <= (categoryThresholds[item.category] ?? item.reorderAt)).length}</dd></div><div><dt>Deductions this month</dt><dd>{deductions.filter((deduction) => !deduction.archived && deduction.date.startsWith(today.slice(0, 7))).length}</dd></div></dl><p className="business-ai-disclaimer">AI responses are operational guidance, not accounting, legal, or employment advice.</p></aside>
    </section>
  </>
}

function FAQPage({ onNavigate, supportEmail, whatsappNumber }: { onNavigate: (page: string) => void; supportEmail: string; whatsappNumber: string }) {
  const topics = ['All topics', 'About Biz Track', 'Getting started', 'Security & privacy', 'People & access', 'Daily operations', 'Plans & support']
  const [activeTopic, setActiveTopic] = useState('All topics')
  const [search, setSearch] = useState('')
  useEffect(() => {
    const number = whatsappNumber.replace(/[^0-9]/g, '')
    if (number) {
      document.querySelectorAll<HTMLAnchorElement>('.faq-contact-link, .faq-bottom .primary-button').forEach((link) => {
        link.href = `https://wa.me/${number}`
        link.target = '_blank'
        link.rel = 'noopener noreferrer'
        link.textContent = 'WhatsApp support ↗'
      })
    }
    document.querySelectorAll<HTMLDetailsElement>('.faq-item').forEach((item) => {
      item.name = 'biztrack-faq'
    })
  }, [activeTopic, search, whatsappNumber])
  const faqs = [
    { topic: 'About Biz Track', question: 'Who founded Biz Track, and how does it help businesses run smoothly?', answer: 'Biz Track was founded and is led by Joseph Muli, CEO and entrepreneur focused on helping businesses across Africa run more smoothly. Seeing business owners lose time to manual processes and disconnected records, Joseph set out to bring everyday operations into one practical workspace. Biz Track helps teams keep track of people, attendance, sales, inventory, and payroll records, making it easier for owners and staff to stay coordinated and focus on growing the business. The platform is shaped around the needs of day-to-day business operations, with tools designed to be straightforward to use.' },
    { topic: 'Getting started', question: 'What is Biz Track designed to do?', answer: 'Biz Track brings team records, attendance, sales summaries, inventory, and payroll calculations into one business workspace. It supports day-to-day record keeping; it is not a bank, payment processor, or substitute for professional accounting or legal advice.' },
    { topic: 'Getting started', question: 'How do I set up a business workspace?', answer: 'Use Create account to submit the business registration details. Once the registration process is complete, sign in with the owner credentials and add your departments, workers, and workspace settings.' },
    { topic: 'Getting started', question: 'Can I use Biz Track on more than one device?', answer: 'Yes. Sign in to the same workspace from a supported browser. Keep your credentials private, and sign out on shared or public devices.' },
    { topic: 'Security & privacy', question: 'How is one business kept separate from another?', answer: 'Configured workspaces use Supabase authentication, tenant membership, and row-level security to limit data access to authorized workspace members. Access depends on correct project configuration and current security policies.' },
    { topic: 'Security & privacy', question: 'Are passwords or biometric scans stored?', answer: 'Passwords are stored as hashes rather than readable passwords. Browser biometric sign-in uses WebAuthn credential metadata; Biz Track does not store raw fingerprint images or templates. If a business connects an external scanner bridge, that provider may process biometric data under its own controls and terms.' },
    { topic: 'Security & privacy', question: 'Who is responsible for staff access and device security?', answer: 'The business owner is responsible for issuing accounts, granting only the pages each person needs, removing access when someone leaves, and protecting owner credentials and devices. No online service can guarantee absolute security.' },
    { topic: 'People & access', question: 'How do I give an employee access?', answer: 'Add a worker or enable login credentials for an existing worker, then open Permissions to assign the pages they need. Workers sign in with their own username and password; they should not share another person’s account.' },
    { topic: 'People & access', question: 'Why can a worker sign in but see no pages?', answer: 'A worker account needs page access assigned by the owner. Open Permissions, select the worker, choose the appropriate pages, and save the changes. Assign only the access needed for the worker’s role.' },
    { topic: 'People & access', question: 'What should I do when a worker leaves?', answer: 'Remove or disable their account promptly and review any other access they may have had. The business owner should also secure shared devices and change any credentials that were shared.' },
    { topic: 'Daily operations', question: 'How are attendance and days off recorded?', answer: 'Workers can record their sign-in and sign-out in the workspace. Owners can review attendance and mark approved off days. Printed Register sheets can be used to complete handwritten sign-in and sign-out records.' },
    { topic: 'Daily operations', question: 'Does the payroll page send wages?', answer: 'No. Payroll summarizes completed attendance records and configured pay rates, with deductions where entered. It does not transfer money; the business remains responsible for checking calculations and making payments through its chosen method.' },
    { topic: 'Daily operations', question: 'How does the Payroll Payment Register calculate receipts?', answer: 'The register uses completed shifts and deductions recorded within the selected day or date range. Amount owed shows total earnings for that period minus its deductions. If the period is fully paid, Amount received shows that net amount; if payment is partial, it shows the amount entered in the partial-payment form. Use Mark selected partially paid to record the amount received for each selected worker, or Mark selected paid when the full net amount has been paid. The form records payments for tracking only and does not transfer funds. Verify payment records independently before signing the register.' },
    { topic: 'Daily operations', question: 'How do stock and sales records work?', answer: 'Record sales totals and their payment methods in Sales. In Inventory, add stock when items arrive and record stock as used or consumed when it leaves. Check the quantities and reports against your physical records.' },
    { topic: 'Daily operations', question: 'Can I keep working while offline?', answer: 'The workspace requires an internet connection to read and save shared data. Do not assume offline changes will be saved; reconnect and confirm the latest records before continuing.' },
    { topic: 'Plans & support', question: 'Can I print or save reports?', answer: 'Yes. Open Print, choose a report and period, then select Print / Save PDF. Reports can contain staff and business information, so store and share them carefully.' },
    { topic: 'Plans & support', question: 'Where can I get help?', answer: 'For workspace questions, contact your business owner. For platform or registration questions, message Biz Track support using the WhatsApp link above. Include the business name and a clear description, but never send passwords or secret keys.' },
  ]
  const normalizedSearch = search.trim().toLowerCase()
  const visibleTopics = topics.slice(1).map((topic) => ({
    topic,
    questions: faqs.filter((faq) => faq.topic === topic && (activeTopic === 'All topics' || activeTopic === topic) && (!normalizedSearch || `${faq.question} ${faq.answer}`.toLowerCase().includes(normalizedSearch))),
  })).filter((group) => group.questions.length)
  const resultCount = visibleTopics.reduce((count, group) => count + group.questions.length, 0)
  return <main className="faq-page"><header className="faq-nav"><button className="welcome-brand" onClick={() => onNavigate('Welcome')}><span className="welcome-mark">b</span><span>biz track</span></button><nav><button className="faq-nav-link" onClick={() => onNavigate('Welcome')}>Back to site</button><button className="welcome-nav-cta" onClick={() => onNavigate('Sign in')}>Sign in <span>→</span></button></nav></header><div className="faq-content"><section className="faq-intro"><p className="welcome-kicker">BIZ TRACK / HELP</p><h1>Clear answers<br /><em>for the workday.</em></h1><p>Practical guidance on protecting your workspace, setting up your team, and keeping daily records in order.</p><a className="faq-contact-link" href={`mailto:${supportEmail}?subject=${encodeURIComponent('Biz Track support question')}`}>Contact support <span>↗</span></a></section><section className="faq-browser" aria-label="Frequently asked questions"><div className="faq-search-row"><label><span>Search the FAQs</span><input type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Try “staff access” or “offline”" /></label><span className="faq-result-count">{resultCount} answers</span></div><nav className="faq-topics" aria-label="FAQ topics">{topics.map((topic) => <button key={topic} type="button" className={activeTopic === topic ? 'active' : ''} aria-pressed={activeTopic === topic} onClick={() => setActiveTopic(topic)}>{topic}</button>)}</nav>{visibleTopics.length ? <div className="faq-results" aria-live="polite">{visibleTopics.map((group) => <section className="faq-topic" key={group.topic}><header><p className="welcome-kicker">TOPIC</p><h2>{group.topic}</h2></header><div className="faq-list">{group.questions.map((faq) => <details className="faq-item" key={faq.question}><summary>{faq.question}<span aria-hidden="true">+</span></summary><p>{faq.answer}</p></details>)}</div></section>)}</div> : <p className="faq-empty">No answers match that search. Try a different term or contact support.</p>}</section><section className="faq-bottom"><div><p className="welcome-kicker">NEED A HAND?</p><h2>We’re here to help.</h2><p>For account access, start with your business owner. For platform questions, contact Biz Track support.</p></div><a className="primary-button" href={`mailto:${supportEmail}?subject=${encodeURIComponent('Biz Track support')}`}>Email support <span>↗</span></a></section><footer className="faq-footer"><button onClick={() => onNavigate('Welcome')}>Biz Track</button><div><button onClick={() => onNavigate('Terms')}>Terms</button><button onClick={() => onNavigate('Privacy')}>Privacy</button><button onClick={() => onNavigate('Sign in')}>Sign in</button></div></footer></div></main>
}

function TermsPage({ onNavigate }: { onNavigate: (page: string) => void }) {
  const sections = [{ title: '1. Introduction', body: 'Welcome to BizTrack (the App). These Terms and Conditions govern your use of BizTrack, which provides business record-keeping, workspace management, package registration, and user access controls. By registering a business account or using the App, you agree to these Terms.' }, { title: '2. Definitions', body: 'Business Owner means the person or organization that registers a business workspace. User means a person invited by the Business Owner with account credentials. Credentials means a username and password. Pages or Modules means the App sections assigned to a User. Data means information entered, stored, or processed in the workspace.' }, { title: '3. Account Registration', body: 'Business Owners must provide accurate and complete registration information, choose an available package, and keep account information current. Business Owners are responsible for registering Users, creating their credentials, and assigning appropriate page access. Users must keep their Credentials confidential and must not share them.' }, { title: '4. User Access and Responsibilities', body: 'Users may access only the Pages or Modules assigned by the Business Owner. Attempts to bypass access restrictions, use another person’s Credentials, or access a workspace without authorization are prohibited. Users and Business Owners must enter accurate, lawful, and appropriate Data.' }, { title: '5. Data Management', body: 'Workspace Data is associated with the Business Owner’s workspace and may include team, attendance, sales, payroll, inventory, settings, and access-control records. The Business Owner is responsible for the accuracy, legality, integrity, and appropriate retention of that Data. BizTrack provides structured record-keeping and does not guarantee compliance with external legal, tax, employment, or financial requirements.' }, { title: '6. Security', body: 'Business Owners choose or issue User Credentials through the App and must use reasonable care when creating and managing them. Users must keep passwords confidential, use strong passwords, and report suspected unauthorized access promptly. BizTrack uses reasonable technical measures, but no online system can be guaranteed completely secure.' }, { title: '7. Privacy', body: 'BizTrack does not sell workspace Data. Data may be processed by service providers needed to operate the App, including hosting and database providers, or disclosed where required by law. Business Owners are responsible for informing their Users about the Data they enter and how the workspace is managed.' }, { title: '8. Package and Service Changes', body: 'Package names, prices, durations, included features, seat limits, and availability are set by the site administrator and may change for future registrations. Existing workspace records remain associated with their workspace, subject to the service configuration and applicable law.' }, { title: '9. Limitations of Liability', body: 'The App is provided as available and without warranties to the extent permitted by law. BizTrack is not responsible for losses caused by inaccurate Data, unauthorized disclosure of Credentials, misuse of the App, service interruptions, or decisions made solely from records stored in the App. Business Owners remain responsible for their business decisions and compliance obligations.' }, { title: '10. Termination', body: 'A Business Owner may stop using a workspace subject to any applicable package or service arrangements. BizTrack may suspend or terminate access for misuse, unauthorized access, security risks, non-payment, or violation of these Terms. Access restrictions do not remove the Business Owner’s responsibility for lawful handling of Data.' }, { title: '11. Amendments', body: 'These Terms may be updated when the App, packages, or applicable requirements change. The updated version will be published in the App. Continued use after publication means you accept the updated Terms.' }, { title: '12. Governing Law', body: 'These Terms are governed by the applicable laws of the jurisdiction in which BizTrack is operated, unless a written agreement states otherwise. Contact BizTrack support for questions about these Terms.' }]
  return <main className="terms-page"><header className="register-header"><button className="welcome-brand" onClick={() => onNavigate('Welcome')}><span className="welcome-mark">b</span><span>biz track</span></button><button className="register-back" onClick={() => onNavigate('Welcome')}>Back to welcome</button></header><article className="terms-card"><p className="welcome-kicker">BIZTRACK / LEGAL</p><h1>Terms and Conditions</h1><p className="terms-intro">Last updated: September 19, 2026</p>{sections.map((section) => <section key={section.title}><h2>{section.title}</h2><p>{section.body}</p></section>)}<div className="terms-actions"><button className="secondary-button" onClick={() => onNavigate('Welcome')}>Return to welcome</button><button className="primary-button" onClick={() => onNavigate('Register')}>Create an account <span>→</span></button></div></article></main>
}

function PrivacyPage({ onNavigate, supportEmail }: { onNavigate: (page: string) => void; supportEmail: string }) {
  const sections = [
    { title: '1. Who this policy covers', body: 'This policy explains how Biz Track handles information when you visit the public site, register a business, or use a workspace. The business that owns a workspace controls the information its team enters and is responsible for providing its team with any notices required by law.' },
    { title: '2. Information processed', body: 'Depending on how the service is used, information may include owner and business contact details, usernames, team member details, assigned access, attendance and payroll records, sales, inventory, deductions, and support requests. The service also processes authentication and session data needed to secure access.' },
    { title: '3. Biometrics and device data', body: 'If a business enables biometric verification, Biz Track uses browser passkeys or a configured scanner integration to verify an action. Biz Track does not receive or store raw fingerprint images through browser passkeys. A separately configured scanner provider may process verification data under its own terms.' },
    { title: '4. How information is used', body: 'Information is used to provide and secure workspaces, apply access permissions, record business activity, administer subscriptions and registrations, respond to support requests, and maintain the service. Biz Track does not sell workspace information.' },
    { title: '5. Storage and service providers', body: 'Workspace and account information is stored in the configured Supabase project. The public site may be delivered through its configured hosting provider. Information is shared only as needed to operate the service, to follow the workspace owner’s instructions, or when required by law.' },
    { title: '6. Access, retention, and requests', body: 'Workspace owners can manage team access and records through the service and are responsible for deciding how long business records should be retained. To ask about information in a workspace, contact that workspace’s owner. For questions about the platform or a registration request, contact Biz Track using the details below.' },
    { title: '7. Security', body: 'Biz Track uses authentication, access controls, and tenant separation to help protect information. No online service can guarantee absolute security. Keep credentials private and notify the workspace owner promptly if an account may have been accessed without permission.' },
    { title: '8. Changes and contact', body: 'This policy may be updated as the service changes. The latest version is published on this page. For privacy questions, contact us at the support address shown below.' },
  ]
  return <main className="terms-page"><header className="register-header"><button className="welcome-brand" onClick={() => onNavigate('Welcome')}><span className="welcome-mark">b</span><span>biz track</span></button><button className="register-back" onClick={() => onNavigate('Welcome')}>Back to welcome</button></header><article className="terms-card"><p className="welcome-kicker">BIZTRACK / PRIVACY</p><h1>Privacy Policy</h1><p className="terms-intro">Last updated: September 29, 2026</p>{sections.map((section) => <section key={section.title}><h2>{section.title}</h2><p>{section.body}</p></section>)}<div className="terms-actions"><a className="privacy-contact-link" href={`mailto:${supportEmail}`}>Contact support</a><button className="primary-button" onClick={() => onNavigate('Welcome')}>Return to welcome</button></div></article></main>
}

function WelcomePage({ onNavigate, hasOwnerAccount, businessName, supportEmail, whatsappNumber }: { onNavigate: (page: string) => void; hasOwnerAccount: boolean; businessName?: string; supportEmail: string; whatsappNumber: string }) {
  useEffect(() => {
    const groups = document.querySelectorAll('.welcome-footer-group')
    const footerBrand = document.querySelector('.welcome-footer-brand')
    const installLink = document.createElement('button')
    installLink.type = 'button'
    installLink.className = 'welcome-install-link'
    installLink.textContent = 'Install the app'
    installLink.addEventListener('click', () => window.dispatchEvent(new Event('biztrack-install-request')))
    footerBrand?.appendChild(installLink)
    const resourceLinks = groups[2]?.querySelectorAll('a')
    const faqLink = resourceLinks?.[0]
    const termsLink = resourceLinks?.[1]
    const privacyLink = resourceLinks?.[2]
    const openFaqs = (event: MouseEvent) => { event.preventDefault(); onNavigate('FAQs') }
    const openTerms = (event: MouseEvent) => { event.preventDefault(); onNavigate('Terms') }
    const openPrivacy = (event: MouseEvent) => { event.preventDefault(); onNavigate('Privacy') }
    if (faqLink) faqLink.href = pagePaths.FAQs
    if (termsLink) termsLink.href = pagePaths.Terms
    if (privacyLink) privacyLink.href = pagePaths.Privacy
    faqLink?.addEventListener('click', openFaqs)
    termsLink?.addEventListener('click', openTerms)
    privacyLink?.addEventListener('click', openPrivacy)

    document.querySelectorAll<HTMLAnchorElement>('.welcome-footer a[href^="mailto:"]').forEach((link) => {
      const subject = link.href.includes('?') ? link.href.slice(link.href.indexOf('?')) : ''
      link.href = supportEmail ? `mailto:${supportEmail}${subject}` : '#'
    })
    const contactLinks = groups[3]?.querySelectorAll<HTMLAnchorElement>('a')
    const emailLink = contactLinks?.[0]
    const whatsappLink = contactLinks?.[1]
    const hours = groups[3]?.querySelector('span')
    if (emailLink) emailLink.textContent = supportEmail || 'Support email not set'
    const normalizedWhatsapp = whatsappNumber.replace(/[^0-9]/g, '')
    if (whatsappLink) {
      if (normalizedWhatsapp) {
        whatsappLink.href = `https://wa.me/${normalizedWhatsapp}`
        whatsappLink.textContent = `+${normalizedWhatsapp}`
        whatsappLink.target = '_blank'
        whatsappLink.rel = 'noopener noreferrer'
      } else {
        whatsappLink.remove()
      }
    }
    hours?.remove()
    return () => {
      installLink.remove()
      faqLink?.removeEventListener('click', openFaqs)
      termsLink?.removeEventListener('click', openTerms)
      privacyLink?.removeEventListener('click', openPrivacy)
    }
  }, [onNavigate, supportEmail, whatsappNumber])
  return <div className="welcome-page">
    <header className="welcome-nav"><button className="welcome-brand" onClick={() => onNavigate('Welcome')}><span className="welcome-mark">b</span><span>biz track</span></button><nav><button className="welcome-link" onClick={() => document.querySelector('.welcome-model')?.scrollIntoView({ behavior: 'smooth' })}>How it works</button><button className="welcome-link" onClick={() => document.querySelector('.welcome-model')?.scrollIntoView({ behavior: 'smooth' })}>Features</button><button className="welcome-link" onClick={() => onNavigate('Sign in')}>Sign in</button><button className="welcome-nav-cta" onClick={() => onNavigate('Register')}>Create account <span>↗</span></button></nav></header>
    <main>
      <section className="welcome-hero"><div className="welcome-hero-copy"><p className="welcome-kicker">THE BUSINESS OPERATING DESK</p><h1>Start the day<br /><em>with clarity.</em></h1><p className="welcome-lead">Biz Track brings your people, sales, stock, attendance, and payroll into one calm place to run the business.</p><div className="welcome-actions"><button className="welcome-primary" onClick={() => onNavigate(hasOwnerAccount ? 'Sign in' : 'Register')}>{hasOwnerAccount ? 'Sign in to Biz Track' : 'Attend Tracker'} <span>→</span></button></div><div className="welcome-proof"><span className="proof-avatars"><i>AN</i><i>JO</i><i>SK</i><b>+</b></span><span>One workspace for<br /><strong>the whole team</strong></span></div></div><div className="welcome-hero-art"><div className="hero-orbit hero-orbit-a"></div><div className="hero-orbit hero-orbit-b"></div><div className="hero-sticker"><span>BUILT FOR<br />BUSY DAYS</span><b>✦</b></div><div className="welcome-board"><div className="board-top"><span><i></i> {businessName || 'Your workspace'}</span><small>Today · 09:41</small></div><div className="board-heading"><div><small>GOOD MORNING</small><strong>Today at a glance</strong></div><span>•••</span></div><div className="board-metrics"><div><small>Sales today</small><strong>KES 284.5k</strong><b>↑ 12.8%</b></div><div><small>Team present</small><strong>18 / 21</strong><b className="board-warm">85.7%</b></div></div><div className="board-chart"><span></span><span></span><span></span><span></span><span></span><span></span><span></span><span></span><span></span><span></span></div><div className="board-footer"><span><i className="board-green"></i>Team activity</span><span><i className="board-coral"></i>Sales</span><strong>View dashboard →</strong></div></div><div className="hero-float hero-float-one"><b>18</b><span>people in<br />today</span><i>✓</i></div><div className="hero-float hero-float-two"><b>03</b><span>stock alerts<br />to check</span></div></div></section>
      <section className="welcome-model"><div><p className="welcome-kicker">A SIMPLE MODEL</p><h2>One owner.<br /><em>A stronger team.</em></h2></div><div className="welcome-model-copy"><p>The business owner creates the workspace, then invites the people who keep it moving. Give each person the right role, department, and access so everyone knows what to do next.</p><div className="welcome-steps"><article><b>01</b><strong>Create your workspace</strong><span>Set up the business owner account and start with a clear home base.</span></article><article><b>02</b><strong>Add your people</strong><span>Create subaccounts for managers, cashiers, stock keepers, and workers.</span></article><article><b>03</b><strong>Assign the work</strong><span>Organize departments and control which parts of Biz Track each person can use.</span></article></div></div></section>
      <section className="welcome-product"><div className="welcome-product-intro"><p className="welcome-kicker">A CLEAR VIEW OF YOUR TEAM</p><h2>Every person.<br /><em>Right where you need them.</em></h2><p>Keep departments, contact details, and team access together in one workspace.</p></div><div className="welcome-product-frame" role="img" aria-label="Illustrative Biz Track team directory showing workers, departments, contact details, and access controls"><div className="product-frame-bar"><span><i></i><i></i><i></i></span><strong>Biz Track <b>/</b> People <b>/</b> Team</strong><small>WORKSPACE PREVIEW</small></div><div className="product-frame-body"><aside className="product-frame-sidebar"><strong><span className="welcome-mark">b</span> biz track</strong><span>Overview</span><span>Sales</span><span>Attendance</span><span>Payroll</span><span className="active">Team</span><span>Departments</span><span>Settings</span></aside><div className="product-frame-main"><div className="product-frame-heading"><div><small>PEOPLE / TEAM</small><h3>Your team</h3><p>Manage members and keep everyone connected.</p></div><button type="button">+ Add member</button></div><div className="product-frame-tools"><strong>12 team members</strong><span>All departments⌄</span></div><div className="product-frame-table"><table><thead><tr><th>TEAM MEMBER</th><th>PHONE</th><th>DEPARTMENT</th><th>ACCESS</th></tr></thead><tbody>{[['Amina Njeri', '+254 712 410 652', 'OPERATIONS', '4 pages'], ['Joseph Muli', '+254 768 741 104', 'CASHIER', '3 pages'], ['Faith Wanjiku', '+254 701 224 095', 'SALES', '2 pages'], ['David Otieno', '+254 711 083 746', 'INVENTORY', '3 pages'], ['Mercy Kamau', '+254 722 508 319', 'OPERATIONS', '2 pages']].map(([name, phone, department, pages], index) => <tr key={name}><td><span className={`product-avatar tone-${index}`}>{name.split(' ').map((part) => part[0]).join('')}</span><strong>{name}</strong></td><td>{phone}</td><td>{department}</td><td><span className="product-access-pill">{pages}</span></td></tr>)}</tbody></table></div><div className="product-frame-foot"><span>Showing 1–5 of 12 team members</span><span>‹ &nbsp; 1 &nbsp; 2 &nbsp; 3 &nbsp; ›</span></div></div></div></div><p className="welcome-product-caption">Illustrative workspace preview · Sample team information</p></section>
      <section className="welcome-testimonials"><div className="welcome-testimonials-heading"><p className="welcome-kicker">BUILT AROUND THE WORK</p><h2>Small details.<br /><em>Smoother days.</em></h2><p>Illustrative feedback inspired by the everyday jobs Biz Track brings together.</p></div><div className="welcome-quote-list"><blockquote><span>“</span><p>Attendance and shift handovers feel clearer when the whole team is working from one place.</p><footer>Illustrative sample · Team lead</footer></blockquote><blockquote><span>“</span><p>I can give each person the pages they need without opening up everything else.</p><footer>Illustrative sample · Business owner</footer></blockquote><blockquote><span>“</span><p>Stock, sales, and people are easier to keep in view during a busy day.</p><footer>Illustrative sample · Store manager</footer></blockquote></div></section>
      <section className="welcome-bottom"><p>READY WHEN YOU ARE</p><h2>Run a better business<br />from the first shift.</h2><button onClick={() => onNavigate(hasOwnerAccount ? 'Sign in' : 'Register')}>{hasOwnerAccount ? 'Enter your workspace' : 'Attend Tracker'} <span>↗</span></button></section>
    </main><footer className="welcome-footer"><div className="welcome-footer-brand"><span className="welcome-mark">b</span><strong>biz track</strong><p>People · Performance · Progress</p></div><div className="welcome-footer-group"><strong>Product</strong><button onClick={() => document.querySelector('.welcome-model')?.scrollIntoView({ behavior: 'smooth' })}>How it works</button><button onClick={() => document.querySelector('.welcome-model')?.scrollIntoView({ behavior: 'smooth' })}>Features</button><button onClick={() => document.querySelector('.welcome-bottom')?.scrollIntoView({ behavior: 'smooth' })}>Pricing</button></div><div className="welcome-footer-group"><strong>Account</strong><button onClick={() => onNavigate('Sign in')}>Sign in</button><button onClick={() => onNavigate('Register')}>Attend Tracker</button><button onClick={() => onNavigate(hasOwnerAccount ? 'Sign in' : 'Register')}>Open workspace</button></div><div className="welcome-footer-group"><strong>Resources</strong><a href="mailto:support@biztrack.app?subject=Biz Track FAQ">FAQs</a><a href="mailto:support@biztrack.app?subject=Terms and conditions">Terms and conditions</a><a href="mailto:support@biztrack.app?subject=Privacy policy">Privacy policy</a></div><div className="welcome-footer-group"><strong>Contact</strong><a href="mailto:support@biztrack.app">support@biztrack.app</a><a href="tel:+254700000000">+254 700 000 000</a><span>Mon–Fri, 8:00–17:00</span></div><div className="welcome-footer-bottom"><span>© 2026 Biz Track. All rights reserved.</span><span>Built for businesses that keep moving.</span></div></footer>
  </div>
}

function LegacyLoginPage({ members, accessByMember, setAccessByMember, onLogin }: { members: Member[]; accessByMember: Record<number, AccessArea[]>; setAccessByMember: (value: Record<number, AccessArea[]>) => void; onLogin: (memberId: number) => void }) {
  const [selectedMemberId, setSelectedMemberId] = useState(members[0]?.id || 0)
  const selectedMember = members.find((member) => member.id === selectedMemberId)
  const selectedAccess = accessByMember[selectedMemberId] || []
  const toggleAccess = (area: AccessArea) => setAccessByMember({ ...accessByMember, [selectedMemberId]: selectedAccess.includes(area) ? selectedAccess.filter((item) => item !== area) : [...selectedAccess, area] })
  return <div className="login-shell"><div className="login-card"><div className="brand login-brand"><span className="brand-mark">b</span><span>biz track</span></div><p className="eyebrow">WORKSPACE ACCESS</p><h1>Sign in to your workspace</h1><p className="subheading">Choose your registered worker ID to continue.</p><label className="login-field"><span>Worker ID</span><select value={selectedMemberId} onChange={(event) => setSelectedMemberId(Number(event.target.value))}>{members.map((member) => <option key={member.id} value={member.id}>ID {member.id} · {member.name}</option>)}</select></label><button className="primary-button login-button" onClick={() => selectedMember && onLogin(selectedMember.id)}>Continue</button>{selectedMember && <section className="access-editor"><div><p className="eyebrow">OWNER ACCESS CONTROL</p><h2>Areas for {selectedMember.name}</h2><p>Choose the pages this registered user can open.</p></div><div className="access-grid">{accessAreas.map((area) => <label key={area} className="access-option"><input type="checkbox" checked={selectedAccess.includes(area)} onChange={() => toggleAccess(area)} /><span>{area}</span></label>)}</div></section>}</div></div>
}

function LoginPage({ ownerAccount, setOwnerAccount, members, accessByMember, setAccessByMember, onLogin }: { ownerAccount: OwnerAccount | null; setOwnerAccount: (value: OwnerAccount) => void; members: Member[]; accessByMember: Record<number, AccessArea[]>; setAccessByMember: (value: Record<number, AccessArea[]>) => void; onLogin: (memberId: number) => void }) { const [name, setName] = useState(''); const [username, setUsername] = useState(''); const [password, setPassword] = useState(''); const [error, setError] = useState(''); const isSetup = !ownerAccount; const selectedMember = members.find((member) => member.username.toLowerCase() === username.trim().toLowerCase()); const selectedAccess = selectedMember ? accessByMember[selectedMember.id] || [] : []; const toggleAccess = (area: AccessArea) => { if (!selectedMember) return; setAccessByMember({ ...accessByMember, [selectedMember.id]: selectedAccess.includes(area) ? selectedAccess.filter((item) => item !== area) : [...selectedAccess, area] }) }; const submit = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); if (isSetup) { if (!name.trim() || username.trim().length < 3 || password.length < 6) { setError('Enter an owner name, a username of at least 3 characters, and a password of at least 6 characters.'); return } setOwnerAccount({ name: name.trim(), username: username.trim(), password }); onLogin(-1); return } const ownerMatch = ownerAccount.username.toLowerCase() === username.trim().toLowerCase() && ownerAccount.password === password; const member = members.find((item) => item.username.toLowerCase() === username.trim().toLowerCase() && item.password === password); if (!ownerMatch && !member) { setError('Invalid username or password.'); return } setError(''); onLogin(ownerMatch ? -1 : member.id) }; return <div className="login-shell"><form className="login-card" onSubmit={submit}><div className="brand login-brand"><span className="brand-mark">f</span><span>fielddesk</span></div><p className="eyebrow">NORTHSTAR CAFE WORKSPACE</p><h1>{isSetup ? 'Create the business owner' : 'Sign in to your workspace'}</h1><p className="subheading">{isSetup ? 'The owner account controls this workspace and creates all registered users.' : 'Use your registered username and password to continue.'}</p>{isSetup && <label className="login-field"><span>Owner name</span><input value={name} onChange={(event) => setName(event.target.value)} autoComplete="name" required /></label>}<label className="login-field"><span>Username</span><input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" required /></label><label className="login-field"><span>Password</span><input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete={isSetup ? 'new-password' : 'current-password'} required /></label>{error && <p className="login-error" role="alert">{error}</p>}<button className="primary-button login-button" type="submit">{isSetup ? 'Create owner account' : 'Sign in'}</button>{!isSetup && <section className="access-editor"><p className="eyebrow">OWNER ACCESS CONTROL</p><h2>{selectedMember ? `Areas for ${selectedMember.name}` : 'Registered users'}</h2><p>{selectedMember ? 'Choose the pages this worker can open.' : 'Sign in as the owner to manage user access.'}</p>{selectedMember && <div className="access-grid">{accessAreas.map((area) => <label key={area} className="access-option"><input type="checkbox" checked={selectedAccess.includes(area)} onChange={() => toggleAccess(area)} /><span>{area}</span></label>)}</div>}</section>}</form></div> }

function SignInPage({ ownerAccount, members, siteAdminAccount, onLogin, onAdminLogin, onNavigate }: { ownerAccount: OwnerAccount | null; members: Member[]; siteAdminAccount?: OwnerAccount | null; onLogin: (memberId: number) => void; onAdminLogin?: (success: boolean) => void; onNavigate?: (page: string) => void }) { const [username, setUsername] = useState(''); const [password, setPassword] = useState(''); const [error, setError] = useState(''); const submit = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); const normalizedUser = username.trim().toLowerCase(); const adminMatch = siteAdminAccount && normalizedUser === siteAdminAccount.username.toLowerCase() && password === siteAdminAccount.password; if (adminMatch) { setError(''); onAdminLogin?.(true); return } const ownerMatch = ownerAccount && ownerAccount.username.toLowerCase() === normalizedUser && ownerAccount.password === password; const member = members.find((item) => item.username.toLowerCase() === normalizedUser && item.password === password); if (!ownerMatch && !member) { setError(ownerAccount ? 'Invalid username or password.' : 'Create an account before signing in.'); return } setError(''); onLogin(ownerMatch ? -1 : member!.id) }; return <main className="auth-page"><div className="auth-decoration auth-decoration-one"></div><div className="auth-decoration auth-decoration-two"></div><form className="login-card minimal-login" onSubmit={submit}><div className="auth-brand"><span className="auth-brand-mark">b</span><strong>biz track</strong></div><h1>Welcome back</h1><p className="auth-copy">Use your username and password to sign in. The site admin account also works here.</p><label className="login-field"><span>Username</span><input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" placeholder="admin or owner username" required /></label><label className="login-field"><span>Password</span><input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" placeholder="••••••••" required /></label>{error && <p className="login-error" role="alert">{error}</p>}<div className="form-actions"><button type="button" className="secondary-button" onClick={() => onNavigate ? onNavigate('Register') : window.history.pushState({}, '', '/register/')}>Create account</button><button className="primary-button login-button" type="submit">Sign in <span>→</span></button></div></form></main> }

function SiteAdminRegisterPage({ onRegister, onBack }: { onRegister: (account: OwnerAccount) => void; onBack: () => void }) {
  const [error, setError] = useState('')
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const name = String(form.get('name') || '').trim()
    const username = String(form.get('username') || '').trim()
    const password = String(form.get('password') || '')
    const confirmation = String(form.get('confirmation') || '')
    if (name.length < 2 || username.length < 3) { setError('Enter a name and a username of at least 3 characters.'); return }
    if (password.length < 6) { setError('Password must be at least 6 characters.'); return }
    if (password !== confirmation) { setError('Passwords do not match.'); return }
    onRegister({ name, username, password, business: 'Biz Track HQ' })
  }
  return <main className="auth-page"><div className="auth-decoration auth-decoration-one"></div><div className="auth-decoration auth-decoration-two"></div><form className="login-card minimal-login" onSubmit={submit}><div className="auth-brand"><span className="auth-brand-mark">b</span><strong>biz track</strong></div><h1>Create site admin</h1><p className="auth-copy">Set up the account used to manage businesses, registrations, and platform settings.</p><label className="login-field"><span>Full name</span><input name="name" autoComplete="name" placeholder="Your full name" required /></label><label className="login-field"><span>Username</span><input name="username" autoComplete="username" placeholder="Choose a username" required /></label><label className="login-field"><span>Password</span><input name="password" type="password" autoComplete="new-password" placeholder="At least 6 characters" required /></label><label className="login-field"><span>Confirm password</span><input name="confirmation" type="password" autoComplete="new-password" placeholder="Repeat your password" required /></label>{error && <p className="login-error" role="alert">{error}</p>}<div className="form-actions"><button type="button" className="secondary-button" onClick={onBack}>Back</button><button className="primary-button login-button" type="submit">Create account <span>→</span></button></div></form></main>
}

function AdminSignInPage(props: any) { return <SignInPage {...props} /> }

function WorkerNoPagesPage({ onLogout }: { onLogout: () => void }) { return <main className="access-denied"><section className="panel"><p className="eyebrow">WORKSPACE ACCESS</p><h1>No pages assigned yet</h1><p className="subheading">Your login is active, but the business owner has not assigned any pages to your account. Please contact the owner to request access.</p><button className="primary-button" onClick={onLogout}>Sign out</button></section></main> }
function AccessDeniedPage({ onBack }: { onBack: () => void }) { return <div className="access-denied"><div className="panel"><p className="eyebrow">ACCESS RESTRICTED</p><h1>This area is not assigned to your account.</h1><p className="subheading">Ask the owner to enable this page in access control.</p><button className="primary-button" onClick={onBack}>Return to overview</button></div></div> }
function SubscriptionRequiredPage({ expired, onSignOut }: { expired: boolean; onSignOut: () => void }) { return <div className="access-denied"><div className="panel"><p className="eyebrow">PACKAGE ACCESS</p><h1>{expired ? 'This package has expired.' : 'This business is awaiting activation.'}</h1><p className="subheading">{expired ? 'Ask the site admin to reactivate the package.' : 'The site admin must activate this selected package before the workspace can be used.'}</p><button className="primary-button" onClick={onSignOut}>Sign out</button></div></div> }

function EnhancedSettingsPage({ members, defaultSignIn, defaultSignOut, strictSignIn, setStrictSignIn, categories, setCategories, setDefaultSignIn, setDefaultSignOut, setMembers, onChange }: { members: Member[]; defaultSignIn: string; defaultSignOut: string; strictSignIn: boolean; setStrictSignIn: (value: boolean) => void; categories: string[]; setCategories: (value: string[]) => void; setDefaultSignIn: (value: string) => void; setDefaultSignOut: (value: string) => void; setMembers: (members: Member[]) => void; onChange: () => void }) { const [businessName, setBusinessName] = useState('Northstar Cafe'); const [payrollTime, setPayrollTime] = useState('17:00'); const saveBusinessName = (value: string) => { setBusinessName(value); onChange() }; const savePayrollTime = (value: string) => { setPayrollTime(value); onChange() }; return <><PageHeading eyebrow="WORKSPACE / SETTINGS" title="Settings" subtitle="The owner controls workspace identity, payroll, attendance, inventory, and user accounts." /><section className="settings-stack"><article className="panel member-form"><PanelHeading title="Business workspace" subtitle="These details are used across the workspace." /><div className="form-grid"><label><span>Business name</span><input value={businessName} onChange={(event) => saveBusinessName(event.target.value)} /></label><label><span>Payroll payment time</span><input type="time" value={payrollTime} onChange={(event) => savePayrollTime(event.target.value)} /></label></div></article><article className="panel member-form"><PanelHeading title="Attendance and store rules" subtitle="Set defaults used when creating accounts and recording stock." /><div className="form-grid settings-times"><label><span>Default sign-in time</span><input type="time" value={defaultSignIn} onChange={(event) => { setDefaultSignIn(event.target.value); onChange() }} /></label><label><span>Default sign-out time</span><input type="time" value={defaultSignOut} onChange={(event) => { setDefaultSignOut(event.target.value); onChange() }} /></label><label><span>Strict sign-in checks</span><input type="checkbox" checked={strictSignIn} onChange={(event) => { setStrictSignIn(event.target.checked); onChange() }} /></label><label><span>Store categories</span><input value={categories.join(', ')} onChange={(event) => { const next = event.target.value.split(',').map((item) => item.trim()).filter(Boolean); setCategories(next.length ? next : categories); onChange() }} /></label></div></article><article className="panel team-panel"><PanelHeading title="Create and manage accounts" subtitle="Use Add member to create usernames, passwords, roles, and schedules." action={<a className="primary-button" href={pagePaths['Add member']}>＋ Add account</a>} /><SettingsPage members={members} defaultSignIn={defaultSignIn} defaultSignOut={defaultSignOut} strictSignIn={strictSignIn} setStrictSignIn={setStrictSignIn} categories={categories} setCategories={setCategories} setDefaultSignIn={setDefaultSignIn} setDefaultSignOut={setDefaultSignOut} setMembers={setMembers} onChange={onChange} /></article></section></> }

function BulkAttendancePage({ action, members, entries, allowMultipleDailyShifts = false, onMarkAttendance, onMarkSignOut, onBulkAction, onSuccess }: { action: 'Sign in' | 'Sign out'; members: Member[]; entries: AttendanceEntry[]; allowMultipleDailyShifts?: boolean; onMarkAttendance: (memberId: number, status: 'Present' | 'Absent') => boolean | void | Promise<boolean | void>; onMarkSignOut: (memberId: number) => boolean | Promise<boolean>; onBulkAction?: (memberIds: number[], action: 'Sign in' | 'Sign out') => Promise<number>; onSuccess: (count: number, failures: string[], responses: { message: string; tone: 'success' | 'error'; durationMs?: number }[]) => void }) {
  const [selectedIds, setSelectedIds] = useState<number[]>([])
  const [submitting, setSubmitting] = useState(false)
  const departments = Array.from(new Set(members.map((member) => member.department)))
  const eligibleFor = (department: string) => members.filter((member) => member.department === department).filter((member) => {
    const entry = entries.find((item) => item.memberId === member.id && item.date === today)
    if (action === 'Sign in') {
      if (entry?.status === 'Off') return false
      return !entry || entry.status === 'Absent'
    }
    return (entry?.status === 'Present' || entry?.status === 'Late') && entry.checkOut === '—'
  })
  const toggle = (id: number) => setSelectedIds((current) => current.includes(id) ? current.filter((item) => item !== id) : [...current, id])
  const toggleDepartment = (department: string) => { const ids = eligibleFor(department).map((member) => member.id); setSelectedIds((current) => ids.every((id) => current.includes(id)) ? current.filter((id) => !ids.includes(id)) : Array.from(new Set([...current, ...ids]))) }
  const submit = async () => {
    if (submitting || !selectedIds.length) return
    setSubmitting(true)
    const failures: string[] = []
    const responses: { id: number; message: string; tone: 'success' | 'error'; durationMs?: number }[] = []
    const attendanceWindow = window as any
    attendanceWindow.__bulkAttendanceInProgress = true
    attendanceWindow.__bulkAttendanceFailures = failures
    attendanceWindow.__bulkAttendanceResponses = responses
    let successful = 0
    try {
      if (onBulkAction) successful = await onBulkAction(selectedIds, action)
      else successful = await runBulkAttendanceAction(selectedIds, action, async (memberId) => {
          const failureCount = failures.length
          const result = action === 'Sign in' ? await onMarkAttendance(memberId, 'Present') : await onMarkSignOut(memberId)
          if (result === false && failures.length === failureCount) {
            const memberName = members.find((member) => member.id === memberId)?.name || `Worker ${memberId}`
            const message = `${memberName}: could not ${action === 'Sign in' ? 'sign in' : 'sign out'}; please try again.`
            failures.push(message)
            responses.push({ id: 0, message, tone: 'error', durationMs: 1200 })
          }
          return result
        })
    } catch (error) {
      const message = error instanceof Error ? `Bulk action failed: ${error.message}` : 'Bulk action failed unexpectedly.'
      failures.push(message)
      responses.push({ id: 0, message, tone: 'error', durationMs: 1200 })
    } finally {
      attendanceWindow.__bulkAttendanceInProgress = false
      delete attendanceWindow.__bulkAttendanceFailures
      delete attendanceWindow.__bulkAttendanceResponses
      setSubmitting(false)
    }
    onSuccess(successful, failures, responses)
  }
  return <><PageHeading eyebrow={`PEOPLE / BULK ${action.toUpperCase()}`} title={`Bulk worker ${action.toLowerCase()}`} subtitle={`Choose departments and their eligible members, then ${action.toLowerCase()} everyone selected in one action.`} /><article className="panel member-form bulk-attendance-panel" aria-busy={submitting}><PanelHeading title={`Department roster`} subtitle={`${selectedIds.length} worker${selectedIds.length === 1 ? '' : 's'} selected for this bulk action.`} /><div className="bulk-department-list">{departments.map((department) => { const eligible = eligibleFor(department); const selectedCount = eligible.filter((member) => selectedIds.includes(member.id)).length; return <section className="bulk-department-section" key={department}><header><div><span className="bulk-department-icon">▦</span><span><strong>{department}</strong><small>{eligible.length} eligible member{eligible.length === 1 ? '' : 's'}</small></span></div><button type="button" className="bulk-select-all" disabled={submitting || !eligible.length} onClick={() => toggleDepartment(department)}>{selectedCount === eligible.length && eligible.length ? 'Clear department' : 'Select department'}</button></header>{eligible.length ? <div className="bulk-worker-list">{eligible.map((member) => <label className={`bulk-worker ${selectedIds.includes(member.id) ? 'selected' : ''}`} key={member.id}><input type="checkbox" disabled={submitting} checked={selectedIds.includes(member.id)} onChange={() => toggle(member.id)} /><span className={`avatar avatar-${member.color}`}>{member.initials}</span><span><strong>{member.name}</strong><small>{member.role} · ID {member.id}</small></span><b>{selectedIds.includes(member.id) ? 'Selected' : 'Choose'}</b></label>)}</div> : <p className="bulk-empty">No eligible workers in this department today.</p>}</section> })}</div><div className="form-actions"><button className="secondary-button" disabled={submitting} onClick={() => window.history.back()}>Back</button><button className="primary-button" disabled={submitting || !selectedIds.length} onClick={() => void submit()}>{submitting ? 'Processing...' : action === 'Sign in' ? 'Sign in selected' : 'Sign out selected'} <span>→</span></button></div></article></>
}

function CurrentWorkerSignInPage({ members, entries, strictSignIn, defaultSignIn, allowMultipleDailyShifts, onAttendance, onMarkAttendance, onBulkAction, onSuccess }: { members: Member[]; entries: AttendanceEntry[]; strictSignIn: boolean; defaultSignIn: string; allowMultipleDailyShifts: boolean; onAttendance: () => void; onMarkAttendance: (memberId: number, status: 'Present' | 'Absent') => boolean | void | Promise<boolean | void>; onBulkAction?: (memberIds: number[], action: 'Sign in' | 'Sign out') => Promise<number>; onSuccess?: (count: number, failures?: string[], responses?: { message: string; tone: 'success' | 'error'; durationMs?: number }[]) => void }) {
  const [selectedDepartment, setSelectedDepartment] = useState('')
  const [selectedMemberId, setSelectedMemberId] = useState<number | ''>('')
  if (new URLSearchParams(window.location.search).get('mode') === 'bulk') return <BulkAttendancePage action="Sign in" members={members} entries={entries} allowMultipleDailyShifts={allowMultipleDailyShifts} onMarkAttendance={onMarkAttendance} onMarkSignOut={() => false} onBulkAction={onBulkAction} onSuccess={(count, failures, responses) => onSuccess?.(count, failures, responses)} />
  const departments = Array.from(new Set(members.map((member) => member.department)))
  const visibleMembers = selectedDepartment ? members.filter((member) => member.department === selectedDepartment) : []
  const selectedMember = visibleMembers.find((member) => member.id === selectedMemberId)
  const selectedEntry = selectedMember ? entries.find((entry) => entry.memberId === selectedMember.id && entry.date === today) : undefined
  const isUnavailable = selectedEntry?.status === 'Off' || selectedEntry?.status === 'Present' || selectedEntry?.status === 'Late'
  const submit = async (status: 'Present' | 'Absent') => {
    if (!selectedMember || (status === 'Present' && isUnavailable)) return
    const success = await onMarkAttendance(selectedMember.id, status)
    if (status === 'Present' && success !== false) onSuccess?.(1)
  }
  return <><PageHeading eyebrow="PEOPLE / ROLL" title="Sign in a worker" subtitle={strictSignIn ? 'Strict sign-in checks are enabled for hourly staff.' : 'Record the start of a worker\'s shift.'} /><article className="panel member-form worker-attendance-form sign-in-panel"><PanelHeading title="Choose a worker" subtitle="Select a department, then choose a team member to record today’s attendance." /><div className="form-grid"><label><span>Department</span><select value={selectedDepartment} onChange={(event) => { setSelectedDepartment(event.target.value); setSelectedMemberId('') }}><option value="">Select department</option>{departments.map((department) => <option key={department}>{department}</option>)}</select></label><label><span>Worker</span><select value={selectedMemberId} disabled={!selectedDepartment} onChange={(event) => setSelectedMemberId(Number(event.target.value) || '')}><option value="">{selectedDepartment ? 'Select worker (ID)' : 'Choose a department first'}</option>{visibleMembers.map((member) => <option key={member.id} value={member.id}>{member.name} (ID: {member.id})</option>)}</select></label></div>{selectedMember && <div className="sign-in-summary"><div><span>Scheduled sign-in</span><strong>{selectedMember.signInTime || defaultSignIn}</strong></div><div><span>Today’s status</span><strong>{selectedEntry?.status || 'Not recorded'}</strong></div></div>}<div className="form-actions"><button type="button" className="secondary-button" disabled={!selectedMember || isUnavailable} onClick={() => submit('Absent')}>Mark absent</button><button type="button" className="primary-button" disabled={!selectedMember || isUnavailable} onClick={() => submit('Present')}>Sign in worker</button></div></article></>
}

function WorkerSignInPage({ members, entries, strictSignIn, defaultSignIn, allowMultipleDailyShifts, onAttendance, onMarkAttendance, onBulkAction, onSuccess }: { members: Member[]; entries: AttendanceEntry[]; strictSignIn: boolean; defaultSignIn: string; allowMultipleDailyShifts: boolean; onAttendance: () => void; onMarkAttendance: (memberId: number, status: 'Present' | 'Absent') => boolean | void; onBulkAction?: (memberIds: number[], action: 'Sign in' | 'Sign out') => Promise<number>; onSuccess?: (count: number, failures?: string[], responses?: { message: string; tone: 'success' | 'error'; durationMs?: number }[]) => void }) { return <CurrentWorkerSignInPage members={members} entries={entries} strictSignIn={strictSignIn} defaultSignIn={defaultSignIn} allowMultipleDailyShifts={allowMultipleDailyShifts} onAttendance={onAttendance} onMarkAttendance={onMarkAttendance} onBulkAction={onBulkAction} onSuccess={onSuccess} /> }

function RollPage({ onOpenSignIn, onOpenSignOut }: { onOpenSignIn: (mode: 'individual' | 'bulk') => void; onOpenSignOut: (mode: 'individual' | 'bulk') => void }) {
  const [choice, setChoice] = useState<'Sign in' | 'Sign out' | null>(null)
  const choose = (mode: 'individual' | 'bulk') => {
    if (choice === 'Sign in') onOpenSignIn(mode)
    if (choice === 'Sign out') onOpenSignOut(mode)
    setChoice(null)
  }
  return <><PageHeading eyebrow="PEOPLE / ROLL" title="ROLL" subtitle="Choose a worker action to record today’s attendance." /><section className="roll-grid"><button className="roll-card" onClick={() => setChoice('Sign in')}><span className="roll-card-icon">↗</span><span><strong>Sign in</strong><small>Record when a worker starts their shift.</small></span><b>→</b></button><button className="roll-card" onClick={() => setChoice('Sign out')}><span className="roll-card-icon">↘</span><span><strong>Sign out</strong><small>Complete a worker’s shift at the end of the day.</small></span><b>→</b></button></section>{choice && <AttendanceChoiceModal action={choice} onClose={() => setChoice(null)} onChoose={(_, mode) => choose(mode)} />}</>
}

function AttendanceChoiceModal({ action, onClose, onChoose }: { action: 'Sign in' | 'Sign out'; onClose: () => void; onChoose: (action: 'Sign in' | 'Sign out', mode: 'individual' | 'bulk') => void }) {
  useEffect(() => {
    const handleEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose() }
    document.addEventListener('keydown', handleEscape)
    return () => document.removeEventListener('keydown', handleEscape)
  }, [onClose])
  return <div className="attendance-choice-backdrop" role="dialog" aria-modal="true" aria-labelledby="attendance-choice-title"><section className="attendance-choice"><button className="choice-close" aria-label="Close" onClick={onClose}>×</button><p className="eyebrow">WORKER ATTENDANCE</p><h2 id="attendance-choice-title">How would you like to {action.toLowerCase()}?</h2><p>Choose one worker or manage several workers together.</p><div className="attendance-choice-actions"><button className="choice-card" onClick={() => onChoose(action, 'individual')}><strong>Individual</strong><span>Select one worker and record the action.</span><b>→</b></button><button className="choice-card choice-card-accent" onClick={() => onChoose(action, 'bulk')}><strong>Bulk</strong><span>Select workers by department and process them together.</span><b>→</b></button></div></section></div>
}

function WorkerSignOutPage({ members, entries, onMarkSignOut, onBulkAction, onSuccess }: { members: Member[]; entries: AttendanceEntry[]; onMarkSignOut: (memberId: number) => boolean | Promise<boolean>; onBulkAction?: (memberIds: number[], action: 'Sign in' | 'Sign out') => Promise<number>; onSuccess?: (count: number, failures?: string[], responses?: { message: string; tone: 'success' | 'error'; durationMs?: number }[]) => void }) { if (new URLSearchParams(window.location.search).get('mode') === 'bulk') return <BulkAttendancePage action="Sign out" members={members} entries={entries} onMarkAttendance={() => undefined} onMarkSignOut={onMarkSignOut} onBulkAction={onBulkAction} onSuccess={onSuccess || (() => undefined)} />; const [selectedDepartment, setSelectedDepartment] = useState(''); const [selectedWorkerId, setSelectedWorkerId] = useState<number | ''>(''); const departments = Array.from(new Set(members.map((member) => member.department))); const visibleMembers = selectedDepartment ? members.filter((member) => member.department === selectedDepartment) : []; const selectedMember = visibleMembers.find((member) => member.id === selectedWorkerId); const entry = selectedMember ? entries.find((item) => item.memberId === selectedMember.id && item.date === today) : undefined; const isOff = entry?.status === 'Off'; const isSignedIn = entry?.status === 'Present' || entry?.status === 'Late'; return <><PageHeading eyebrow="PEOPLE / WORKER CHECKOUT" title="Worker checkout" subtitle="Record the successful sign-out and complete the worker's shift." /><article className="panel member-form"><PanelHeading title="Complete a shift" subtitle="Only workers with a successful sign-in can be checked out." /><div className="form-grid"><label><span>Department</span><select value={selectedDepartment} onChange={(event) => { setSelectedDepartment(event.target.value); setSelectedWorkerId('') }}><option value="">Select department</option>{departments.map((department) => <option key={department}>{department}</option>)}</select></label><label><span>Worker</span><select value={selectedWorkerId} disabled={!selectedDepartment} onChange={(event) => setSelectedWorkerId(Number(event.target.value) || '')}><option value="">Select worker</option>{visibleMembers.map((member) => <option key={member.id} value={member.id}>{member.name} (ID: {member.id})</option>)}</select></label></div>{selectedMember && <div className="signout-card"><p className="eyebrow">SELECTED WORKER</p><h2>{selectedMember.name}</h2><p>{isOff ? 'Off today. Sign-out is unavailable.' : isSignedIn ? `Expected sign-out: ${selectedMember.signOutTime}` : 'No active sign-in recorded for today.'}</p><button className="primary-button" disabled={!isSignedIn || isOff || entry?.checkOut !== '—'} onClick={async () => { if (await onMarkSignOut(selectedMember.id)) onSuccess?.(1) }}>{entry?.checkOut && entry.checkOut !== '—' ? `Shift completed at ${entry.checkOut}` : 'Record worker checkout'}</button></div>}</article></> }

  function LiveWorkspaceOverview({ businessName, memberName, memberRole, members, attendance, entries, sales, salesHistory, casualEarnings, deductions, inventory, categoryThresholds, onAttendance }: { businessName: string; memberName: string; memberRole: string; members: Member[]; attendance: AttendanceEntry[]; entries: AttendanceEntry[]; sales: Sale[]; salesHistory: Sale[]; casualEarnings: CasualEarning[]; deductions: Deduction[]; inventory: InventoryItem[]; categoryThresholds: Record<string, number>; onAttendance: () => void }) {
  const [now, setNow] = useState(new Date())
  const [selectedSalesDate, setSelectedSalesDate] = useState(today)
  useEffect(() => { const timer = window.setInterval(() => setNow(new Date()), 60000); return () => window.clearInterval(timer) }, [])
  useEffect(() => {
    const metricGrid = document.querySelector('.app-shell .page-content > .metric-grid')
    if (!metricGrid) return
    const filter = document.createElement('div')
    filter.className = 'overview-sales-date-filter'
    const label = document.createElement('label')
    const caption = document.createElement('span')
    caption.textContent = 'Sales date'
    const input = document.createElement('input')
    input.type = 'date'
    input.max = today
    input.value = selectedSalesDate
    input.setAttribute('aria-label', 'Sales date')
    input.addEventListener('change', () => setSelectedSalesDate(input.value || today))
    label.append(caption, input)
    filter.appendChild(label)
    metricGrid.before(filter)
    return () => filter.remove()
  }, [])
  const greeting = now.getHours() < 12 ? 'Good morning' : now.getHours() < 18 ? 'Good afternoon' : now.getHours() < 22 ? 'Good evening' : 'Good night'
  const dateLabel = formatDate(now.toISOString())
  const timeLabel = now.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
  const selectedDateLabel = formatDate(selectedSalesDate)
  const attendanceForSelectedDate = members.map((member) => selectedSalesDate === today
    ? attendance.find((entry) => entry.memberId === member.id) || { memberId: member.id, date: selectedSalesDate, status: 'Absent' as AttendanceStatus, checkIn: '—', checkOut: '—' }
    : entries.find((entry) => entry.memberId === member.id && entry.date === selectedSalesDate) || { memberId: member.id, date: selectedSalesDate, status: 'Absent' as AttendanceStatus, checkIn: '—', checkOut: '—' })
  const present = attendanceForSelectedDate.filter((entry) => entry.status === 'Present').length
  const late = attendanceForSelectedDate.filter((entry) => entry.status === 'Late').length
  const off = attendanceForSelectedDate.filter((entry) => entry.status === 'Off').length
  const coverage = members.length ? Math.round(((present + late) / members.length) * 100) : 0
  const salesForSelectedDate = [...sales, ...salesHistory].filter((sale) => !sale.archived && sale.date === selectedSalesDate)
  const salesTotal = salesForSelectedDate.reduce((sum, sale) => sum + (Number(sale.amount) || 0), 0)
  const completedEntries = entries.filter((entry) => {
    if (entry.date !== selectedSalesDate || entry.checkOut === '—') return false
    const member = members.find((item) => item.id === entry.memberId)
    const termsAtShift = entry.workerPayTerms || (member?.payTermsSince && entry.date < member.payTermsSince ? 'Per shift' : member?.payTerms || 'Per shift')
    return termsAtShift !== 'Casual'
  })
  const casualEarningsForDate = casualEarnings.filter((earning) => earning.date === selectedSalesDate)
  const selectedDateDeductions = deductions.filter((deduction) => !deduction.archived && deduction.date === selectedSalesDate)
  const shiftPayroll = completedEntries.reduce((sum, entry) => sum + (entry.payRate ?? members.find((member) => member.id === entry.memberId)?.payRate ?? 0), 0)
  const casualPayroll = casualEarningsForDate.reduce((sum, earning) => sum + earning.amount, 0)
  const payrollTotal = shiftPayroll + casualPayroll - selectedDateDeductions.reduce((sum, deduction) => sum + deduction.amount, 0)
  const lowStock = inventory.filter((item) => item.quantity <= (categoryThresholds[item.category] ?? item.reorderAt)).length
  return <><PageHeading eyebrow={`${businessName.toUpperCase()} / ${memberRole.toUpperCase()} · ${selectedDateLabel} · ${timeLabel}`} title={`${greeting}, ${memberName} ✦`} subtitle={`Here’s what’s happening across ${businessName} on ${selectedDateLabel}.`} action={<button className="primary-button" onClick={onAttendance}>View attendance <span>→</span></button>} /><section className="metric-grid"><Metric title={selectedSalesDate === today ? 'Today’s sales' : 'Sales on selected date'} value={`KES ${salesTotal.toLocaleString()}`} detail={`${salesForSelectedDate.length} record${salesForSelectedDate.length === 1 ? '' : 's'} · ${selectedDateLabel}`} accent="coral" /><Metric title="Team attendance" value={`${present + late} / ${members.length}`} detail={`${coverage}% present · ${selectedDateLabel}`} accent="teal" /><Metric title={selectedSalesDate === today ? 'Payroll today' : 'Payroll on selected date'} value={`KES ${payrollTotal.toLocaleString()}`} detail={`${completedEntries.length} shift${completedEntries.length === 1 ? '' : 's'} · ${casualEarningsForDate.length} casual earning${casualEarningsForDate.length === 1 ? '' : 's'}`} accent="yellow" /><Metric title="Stock alerts" value={String(lowStock).padStart(2, '0')} detail={lowStock ? 'Needs attention' : 'Stock is healthy'} accent="lilac" /></section><section className="dashboard-grid"><article className="panel attendance-panel"><PanelHeading title={`Attendance · ${selectedDateLabel}`} subtitle={`Team sign-ins for ${selectedDateLabel}`} action={<button className="text-button" onClick={onAttendance}>View all <span>→</span></button>} /><div className="attendance-summary"><div><strong>{present}</strong><span>Present</span></div><div><strong>{String(late).padStart(2, '0')}</strong><span>Late</span></div><div><strong>{String(off).padStart(2, '0')}</strong><span>Off</span></div><div className="attendance-ring"><div><strong>{coverage}%</strong><span>of team</span></div></div></div><div className="table-wrap"><table><thead><tr><th>TEAM MEMBER</th><th>DEPARTMENT</th><th>STATUS</th><th>CHECK-IN</th></tr></thead><tbody>{members.slice(0, 6).map((member) => { const entry = attendanceForSelectedDate.find((item) => item.memberId === member.id); return <tr key={member.id}><td><div className="person-cell"><span className={`avatar avatar-${member.color}`}>{member.initials}</span><strong>{member.name}</strong></div></td><td>{member.department}</td><td><span className={`status-pill ${(entry?.status || 'Absent').toLowerCase()}`}><i></i>{entry?.status || 'Absent'}</span></td><td>{entry?.checkIn || '—'}</td></tr> })}</tbody></table></div></article></section></>
}

function AdminSidebar({ activeNav, onNavigate, onSignOut }: { activeNav: string; onNavigate: (page: string) => void; onSignOut: () => void }) {
  const [expanded, setExpanded] = useState(false)
  const items = [{ label: 'Dashboard', icon: '◈' }, { label: 'Business', icon: '▦' }, { label: 'Users', icon: '◎' }, { label: 'Register a new business', icon: '+' }, { label: 'Activate business', icon: '✓' }, { label: 'Activation codes', icon: '#' }, { label: 'Packages', icon: 'KES' }, { label: 'Admin settings', icon: '⚙' }]
  const navigateFromSidebar = (page: string) => { setExpanded(false); onNavigate(page) }
  return <><button className="sidebar-toggle" aria-label={expanded ? 'Collapse sidebar' : 'Expand sidebar'} aria-expanded={expanded} onClick={() => setExpanded((value) => !value)}><span>{expanded ? '‹' : '☰'}</span><b>{expanded ? 'Collapse menu' : 'Menu'}</b></button><aside className={`sidebar ${expanded ? 'sidebar-expanded' : ''}`}><button className="brand" onClick={() => navigateFromSidebar('Dashboard')}><span className="brand-mark">b</span><span>BizTrack</span></button><div className="workspace-switcher"><span className="workspace-dot">B</span><span><strong>Site admin</strong><small>Platform workspace</small></span></div><nav aria-label="Site admin navigation"><p className="nav-label">SITE ADMIN</p>{items.map((item) => <button key={item.label} className={`nav-item ${activeNav === item.label || (item.label === 'Dashboard' && activeNav === 'Admin') ? 'active' : ''}`} onClick={() => navigateFromSidebar(item.label)}><span className="nav-icon">{item.icon}</span>{item.label}</button>)}</nav><div className="sidebar-footer"><button className="sidebar-signout" onClick={onSignOut}>↪ Sign out</button></div></aside></>
}

function MaintenancePage({ settings, siteAdminAccount, onAdminLogin, onNavigate }: { settings: PlatformSettings; siteAdminAccount: OwnerAccount | null; onAdminLogin: () => void; onNavigate: (page: string) => void }) {
  const [adminDrawerOpen, setAdminDrawerOpen] = useState(false)
  const maintenanceTarget = Date.parse(settings.maintenanceEndsAt)
  const [countdownNow, setCountdownNow] = useState(Date.now())
  const [serverClockOffset, setServerClockOffset] = useState(0)
  useEffect(() => {
    if (!Number.isFinite(maintenanceTarget) || !supabase) return
    let cancelled = false
    const syncServerClock = async () => {
      try {
        const requestStartedAt = Date.now()
        const { data, error } = await supabase.rpc('get_server_time')
        const responseReceivedAt = Date.now()
        const serverTime = Date.parse(String(data))
        if (cancelled || error || !Number.isFinite(serverTime)) return
        setServerClockOffset(serverTime - (requestStartedAt + responseReceivedAt) / 2)
      } catch {
        return
      }
    }
    void syncServerClock()
    const timer = window.setInterval(() => void syncServerClock(), 60000)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [maintenanceTarget])
  useEffect(() => {
    if (!Number.isFinite(maintenanceTarget)) return
    const syncCountdown = () => setCountdownNow(Date.now() + serverClockOffset)
    syncCountdown()
    let interval = 0
    const timeout = window.setTimeout(() => {
      syncCountdown()
      interval = window.setInterval(syncCountdown, 1000)
    }, 1000 - ((Date.now() + serverClockOffset) % 1000))
    return () => {
      window.clearTimeout(timeout)
      window.clearInterval(interval)
    }
  }, [maintenanceTarget, serverClockOffset])
  const supportNumber = settings.whatsappNumber.replace(/[^0-9]/g, '').replace(/^00/, '').replace(/^0/, '254')
  const supportMessage = encodeURIComponent(`Hello, I need help with ${settings.platformName} while the site is under maintenance.`)
  const supportWhatsappUrl = supportNumber ? `https://wa.me/${supportNumber}?text=${supportMessage}` : `https://wa.me/?text=${supportMessage}`
  const remainingSeconds = Number.isFinite(maintenanceTarget) ? Math.max(0, Math.ceil((maintenanceTarget - countdownNow) / 1000)) : null
  const countdownUnits = remainingSeconds === null ? [] : [
    { label: 'Days', value: Math.floor(remainingSeconds / 86400) },
    { label: 'Hours', value: Math.floor((remainingSeconds % 86400) / 3600) },
    { label: 'Minutes', value: Math.floor((remainingSeconds % 3600) / 60) },
    { label: 'Seconds', value: remainingSeconds % 60 },
  ]
  useEffect(() => {
    if (!adminDrawerOpen) return
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') setAdminDrawerOpen(false) }
    document.addEventListener('keydown', closeOnEscape)
    return () => document.removeEventListener('keydown', closeOnEscape)
  }, [adminDrawerOpen])
  return <main className="maintenance-page">
    <section className="maintenance-copy">
      <p className="eyebrow">{settings.platformName.toUpperCase()} / MAINTENANCE</p>
      <h1>This site is under maintenance.</h1>
      <p>We are preparing to serve you better. Business owners and workers cannot sign in until maintenance is complete.</p>
      <section className="maintenance-countdown" aria-label="Estimated maintenance time remaining">
        <p>Expected completion</p>
        {remainingSeconds === null ? <p className="maintenance-countdown-empty">A completion time has not been set yet.</p> : <>
          <div className="maintenance-countdown-units">{countdownUnits.map(({ label, value }) => <div key={label}><strong key={value}>{String(value).padStart(2, '0')}</strong><span>{label}</span></div>)}</div>
          {remainingSeconds === 0 && <p className="maintenance-countdown-expired">Maintenance is taking longer than expected.</p>}
        </>}
        {Number.isFinite(maintenanceTarget) && <time dateTime={settings.maintenanceEndsAt}>{new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', timeZoneName: 'short' }).format(maintenanceTarget)}</time>}
      </section>
      <a href={supportWhatsappUrl} target="_blank" rel="noopener noreferrer">Contact support</a>
    </section>
    <section className="maintenance-visual"><img src="/maintenance.svg" alt="Two disconnected plugs during maintenance" /></section>
    <button type="button" className="maintenance-lock-tab" aria-label={adminDrawerOpen ? 'Close site admin sign-in' : 'Open site admin sign-in'} aria-expanded={adminDrawerOpen} aria-controls="maintenance-admin-drawer" onClick={() => setAdminDrawerOpen((open) => !open)}><span className="maintenance-lock-icon" aria-hidden="true"><i /></span><span>Site admin</span></button>
    <button type="button" className={`maintenance-drawer-backdrop ${adminDrawerOpen ? 'open' : ''}`} aria-label="Close site admin sign-in" tabIndex={adminDrawerOpen ? 0 : -1} onClick={() => setAdminDrawerOpen(false)} />
    <aside id="maintenance-admin-drawer" className={`maintenance-admin-drawer ${adminDrawerOpen ? 'open' : ''}`} role="dialog" aria-modal="true" aria-label="Site administrator sign-in" aria-hidden={!adminDrawerOpen}>{adminDrawerOpen && <><button type="button" className="admin-modal-close" aria-label="Close site admin sign-in" onClick={() => setAdminDrawerOpen(false)}>×</button><div className="maintenance-drawer-content"><CrossDeviceSignInPage ownerAccount={null} members={[]} businessAccounts={[]} siteAdminAccount={siteAdminAccount} onLogin={() => false} onBusinessLogin={() => false} onAdminLogin={(success) => { if (success) { setAdminDrawerOpen(false); onAdminLogin() } }} onNavigate={() => setAdminDrawerOpen(false)} adminOnly /></div></>}</aside>
  </main>
}

type AdminUser = { id: number; tenantId: string; name: string; username: string; business: string; department: string; rawMembers: Partial<Member>[]; isOwner?: boolean }

function DeleteBusinessPage({ account, onCancel, onDelete }: { account?: BusinessAccount; onCancel: () => void; onDelete: (accountId: number) => Promise<void> | void }) {
  const [confirmations, setConfirmations] = useState(['', '', ''])
  const canDelete = Boolean(account && confirmations.every((value) => value.trim() === account.businessName))
  if (!account) return <main className="access-denied"><div className="panel"><h1>Business not found</h1><button className="primary-button" onClick={onCancel}>Back to businesses</button></div></main>
  return <main className="auth-page delete-business-page"><section className="admin-modal delete-business-card" role="dialog" aria-labelledby="delete-business-title"><p className="eyebrow">DANGER ZONE / DELETE BUSINESS</p><h1 id="delete-business-title">Delete {account.businessName}?</h1><p className="subheading">This permanently removes the business, its owner, workers, permissions, workspace records, and sessions. Type the exact business name three times to continue.</p><div className="delete-business-summary"><strong>{account.businessName}</strong><span>{account.plan} · Owner: {account.ownerName}</span></div><div className="delete-confirm-fields">{confirmations.map((value, index) => <label className="login-field" key={index}><span>Confirmation {index + 1}</span><input value={value} onChange={(event) => setConfirmations((current) => current.map((item, itemIndex) => itemIndex === index ? event.target.value : item))} placeholder={account.businessName} /></label>)}</div><div className="form-actions"><button type="button" className="secondary-button" onClick={onCancel}>Cancel</button><button type="button" className="primary-button delete-confirm-button" disabled={!canDelete} onClick={() => onDelete(account.id)}>Delete permanently</button></div></section></main>
}

function ActivateBusinessPage({ accounts, requests, reviewDecisions, onActivateAccount, onDeclineAccount, onActivateRequest, onDeclineRequest, onSaveReviewDecision, activeNav, onNavigate, onSignOut }: { accounts: BusinessAccount[]; requests: RegistrationRequest[]; reviewDecisions: Record<string, 'Activated' | 'Declined'>; onActivateAccount: (accountId: number) => void; onDeclineAccount: (accountId: number) => void; onActivateRequest: (request: RegistrationRequest) => void; onDeclineRequest: (requestId: number) => void; onSaveReviewDecision: (key: string, decision: 'Activated' | 'Declined') => void; activeNav: string; onNavigate: (page: string) => void; onSignOut: () => void }) {
  const pendingAccounts = accounts.filter((account) => account.status === 'Trial' || businessPackageExpired(account) || reviewDecisions[`account:${account.id}`])
  const accountDecisions = Object.fromEntries(accounts.map((account) => { const savedDecision = reviewDecisions[`account:${account.id}`]; const decision = savedDecision === 'Activated' && account.status === 'Active' || savedDecision === 'Declined' && account.status === 'Paused' ? savedDecision : undefined; return [account.id, decision] }))
  const decisionForAccount = (account: BusinessAccount) => { const savedDecision = accountDecisions[account.id]; return savedDecision === 'Activated' && account.status === 'Active' || savedDecision === 'Declined' && account.status === 'Paused' ? savedDecision : undefined }
  const setAccountDecisions = (update: (current: Record<number, 'Activated' | 'Declined' | undefined>) => Record<number, 'Activated' | 'Declined' | undefined>) => { const next = update(accountDecisions); Object.entries(next).forEach(([accountId, decision]) => { if (decision) onSaveReviewDecision(`account:${accountId}`, decision) }) }
  const reviewRequests = requests
  return <div className="app-shell"><AdminSidebar activeNav={activeNav} onNavigate={onNavigate} onSignOut={onSignOut} /><main className="main-content"><header className="topbar"><div className="breadcrumbs"><span>Site admin</span><b>/</b><strong>Activate business</strong></div></header><div className="page-content"><PageHeading eyebrow="SITE ADMIN / REVIEW" title="Business review" subtitle="Review expired subscriptions and client registrations that need a decision." /><article className="panel team-panel activation-review-panel"><div className="table-wrap"><table className="activation-review-table"><thead><tr><th>BUSINESS</th><th>OWNER / APPLICANT</th><th>REASON</th><th>PLAN</th><th>PACKAGE ENDS</th><th>ACTIONS</th></tr></thead><tbody>{pendingAccounts.map((account) => { const decision = accountDecisions[account.id]; return <tr key={`account-${account.id}`}><td><strong>{account.businessName}</strong><small>{account.email}</small></td><td>{account.ownerName}</td><td>{businessPackageExpired(account) ? 'Subscription expired' : 'Awaiting activation'}</td><td>{account.plan}</td><td>{account.nextBilling || '—'}</td><td><div className="review-actions">{decision ? <strong className={decision === 'Activated' ? 'review-activated' : 'review-declined'}>{decision}</strong> : <><button type="button" className="table-action table-action-view" onClick={() => { onActivateAccount(account.id); setAccountDecisions((current) => ({ ...current, [account.id]: 'Activated' })) }}>Activate</button><button type="button" className="table-action table-action-danger" onClick={() => { onDeclineAccount(account.id); setAccountDecisions((current) => ({ ...current, [account.id]: 'Declined' })) }}>Decline</button></>}</div></td></tr> })}{reviewRequests.map((request) => { const decision = request.reviewStatus; return <tr key={`request-${request.id}`}><td><strong>{request.businessName}</strong><small>{request.email || 'No email supplied'}</small></td><td>{request.applicantName}</td><td>{request.issue}</td><td>{request.plan || 'Not selected'}</td><td>—</td><td><div className="review-actions">{decision ? <strong className={decision === 'Activated' ? 'review-activated' : 'review-declined'}>{decision}</strong> : <><button type="button" className="table-action table-action-view" onClick={() => onActivateRequest(request)}>Activate</button><button type="button" className="table-action table-action-danger" onClick={() => onDeclineRequest(request.id)}>Decline</button></>}</div></td></tr> })}{!pendingAccounts.length && !reviewRequests.length && <tr><td colSpan={6}><div className="permission-empty"><strong>No businesses require review</strong><p>Expired subscriptions and unsuccessful client registrations will appear here.</p></div></td></tr>}</tbody></table></div></article></div></main></div>
}

function AdminUsersPage({ accounts, activeNav, onNavigate, onSignOut }: { accounts: BusinessAccount[]; activeNav: string; onNavigate: (page: string) => void; onSignOut: () => void }) {
  const [selectedUser, setSelectedUser] = useState<AdminUser | null>(null)
  const [users, setUsers] = useState<AdminUser[]>([])
  const [newPassword, setNewPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [error, setError] = useState('')
  useEffect(() => {
    if (!supabase) return
    const loadUsers = async () => {
      const snapshots = await Promise.all(accounts.map(async (account) => ({ account, result: await supabase.from('workspace_snapshots').select('payload').eq('tenant_id', account.tenantId).maybeSingle() })))
      const nextUsers = snapshots.flatMap(({ account, result }) => {
        const snapshot = result.data?.payload as Partial<WorkspaceSnapshot> | undefined
        const rawMembers = snapshot?.members || []
        const access = snapshot?.accessByMember || {}
        const owner = { id: account.id, tenantId: account.tenantId, name: account.ownerName, username: account.username, business: account.businessName, department: 'Owner', rawMembers, isOwner: true }
        const workers = rawMembers.map((rawMember, index) => {
          const member = normalizeMember(rawMember, index, account.tenantId)
          return member.hasAccount && (access[member.id] || []).length ? { id: member.id, tenantId: account.tenantId, name: member.name, username: member.username || '', business: account.businessName, department: member.department, rawMembers } : null
        }).filter((user): user is AdminUser => Boolean(user))
        return [owner, ...workers]
      })
      setUsers(nextUsers)
    }
    void loadUsers()
  }, [accounts])
  const closeModal = () => { setSelectedUser(null); setNewPassword(''); setConfirmation(''); setError('') }
  const resetPassword = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!selectedUser) return
    if (newPassword.length < 6) { setError('New password must be at least 6 characters.'); return }
    if (newPassword !== confirmation) { setError('New password and confirmation do not match.'); return }
    if (!supabase) { setError('Supabase is not connected. The password was not changed.'); return }
    const { error: resetError } = await supabase.rpc('admin_reset_account_password', {
      requested_tenant_id: selectedUser.tenantId,
      requested_member_id: selectedUser.isOwner ? null : selectedUser.id,
      requested_is_owner: Boolean(selectedUser.isOwner),
      requested_new_password: newPassword,
    })
    if (resetError) { setError(`Password was not changed. ${resetError.message}`); return }
    closeModal()
  }
  return <div className="app-shell"><AdminSidebar activeNav={activeNav} onNavigate={onNavigate} onSignOut={onSignOut} /><main className="main-content"><header className="topbar"><div className="breadcrumbs"><span>Site admin</span><b>/</b><strong>Users</strong></div></header><div className="page-content"><PageHeading eyebrow="SITE ADMIN / USERS" title="Users" subtitle="Manage account holders who have been granted workspace access by their business owner." /><article className="panel team-panel"><div className="table-wrap"><table><thead><tr><th>NAME</th><th>USERNAME</th><th>BUSINESS</th><th>DEPARTMENT</th><th>RESET PASSWORD</th></tr></thead><tbody>{users.length ? users.map((user) => <tr key={`${user.tenantId}-${user.id}`}><td><strong>{user.name}</strong></td><td>{user.username || '—'}</td><td>{user.business}</td><td>{user.department}</td><td><button className="secondary-button" type="button" onClick={() => setSelectedUser(user)}>Reset password</button></td></tr>) : <tr><td colSpan={5}><div className="permission-empty"><strong>No users with granted access</strong><p>Users appear here after a business owner creates an account and grants page permissions.</p></div></td></tr>}</tbody></table></div></article></div></main>{selectedUser && <div className="admin-modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) closeModal() }}><section className="admin-modal" role="dialog" aria-modal="true" aria-labelledby="reset-password-title"><button className="admin-modal-close" type="button" aria-label="Close" onClick={closeModal}>×</button><p className="eyebrow">USER ACCESS</p><h2 id="reset-password-title">Reset password</h2><p className="admin-modal-user"><strong>{selectedUser.name}</strong><span>{selectedUser.username || 'No username'} · {selectedUser.department}</span></p><form onSubmit={resetPassword}><label className="login-field"><span>Current password</span><input value="Can not be seen since it is hashed in the database" readOnly /></label><label className="login-field"><span>Username</span><input value={selectedUser.username || 'No username'} readOnly /></label><label className="login-field"><span>New password</span><input type="password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} minLength={6} required /></label><label className="login-field"><span>Confirm new password</span><input type="password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} minLength={6} required /></label>{error && <p className="login-error" role="alert">{error}</p>}<div className="form-actions"><button className="secondary-button" type="button" onClick={closeModal}>Cancel</button><button className="primary-button" type="submit">Update password</button></div></form></section></div>}</div>
}

function AdminDashboardPage({ accounts, activeNav, onNavigate, onCreate, onSignOut }: { accounts: BusinessAccount[]; activeNav: string; onNavigate: (page: string) => void; onCreate: () => void; onSignOut: () => void }) {
  const activeAccounts = accounts.filter((account) => account.status === 'Active').length
  const trialAccounts = accounts.filter((account) => account.status === 'Trial').length
  const monthlyRevenue = accounts.reduce((sum, account) => sum + account.monthlyPrice, 0)
  return <div className="app-shell"><AdminSidebar activeNav={activeNav} onNavigate={onNavigate} onSignOut={onSignOut} /><main className="main-content"><header className="topbar"><div className="breadcrumbs"><span>Site admin</span><b>/</b><strong>Dashboard</strong></div></header><div className="page-content"><PageHeading eyebrow="SITE ADMIN / SUMMARY" title="Dashboard" subtitle="A clear view of the businesses and registration activity across your platform." action={<button className="primary-button" onClick={onCreate}><span>＋</span> Register a business</button>} /><section className="metric-grid"><Metric title="Active businesses" value={String(activeAccounts)} detail="Paying customers" accent="teal" /><Metric title="Trials" value={String(trialAccounts)} detail="Awaiting onboarding" accent="yellow" /><Metric title="Monthly revenue" value={`KES ${monthlyRevenue.toLocaleString()}`} detail="Across all plans" accent="coral" /><Metric title="Businesses" value={String(accounts.length)} detail="In the system" accent="lilac" /></section><article className="panel team-panel"><PanelHeading title="Business activity" subtitle="The latest workspaces created on the platform" /><div className="table-wrap"><table><thead><tr><th>BUSINESS</th><th>OWNER</th><th>PLAN</th><th>STATUS</th></tr></thead><tbody>{accounts.slice(0, 5).map((account) => <tr key={account.id}><td><strong>{account.businessName}</strong><small>{account.email}</small></td><td>{account.ownerName}</td><td>{account.plan}</td><td><span className="status-pill status-pill-teal">{account.status}</span></td></tr>)}</tbody></table></div></article></div></main></div>
}

function RegistrationRequestsPage({ requests, activeNav, onNavigate }: { requests: RegistrationRequest[]; activeNav: string; onNavigate: (page: string) => void }) {
  return <div className="app-shell"><AdminSidebar activeNav={activeNav} onNavigate={onNavigate} onSignOut={() => onNavigate('Welcome')} /><main className="main-content"><header className="topbar"><div className="breadcrumbs"><span>Site admin</span><b>/</b><strong>Registration requests</strong></div></header><div className="page-content"><PageHeading eyebrow="SITE ADMIN / REVIEW" title="Registration requests" subtitle="Review registrations that stopped before a business account was created." /><article className="panel team-panel">{requests.length ? <div className="table-wrap"><table><thead><tr><th>APPLICANT</th><th>BUSINESS</th><th>ISSUE</th><th>DATE</th></tr></thead><tbody>{requests.map((request) => <tr key={request.id}><td><strong>{request.applicantName}</strong></td><td>{request.businessName}</td><td>{request.issue}</td><td>{request.submittedAt}</td></tr>)}</tbody></table></div> : <div className="permission-empty"><strong>No registration requests</strong><p>Incomplete or unsuccessful registrations will appear here for review.</p></div>}</article></div></main></div>
}

function LegacyAdminDashboardPage({ accounts, onCreate, onViewBusinessAccounts, onViewSubscriptions, onOpenSettings, onSignOut }: { accounts: BusinessAccount[]; onCreate: () => void; onViewBusinessAccounts: () => void; onViewSubscriptions: () => void; onOpenSettings: () => void; onSignOut: () => void }) {
  const activeAccounts = accounts.filter((account) => account.status === 'Active').length
  const trialAccounts = accounts.filter((account) => account.status === 'Trial').length
  const monthlyRevenue = accounts.reduce((sum, account) => sum + account.monthlyPrice, 0)
  const recentAccounts = accounts.slice(0, 4)
  return <div className="app-shell"><aside className="sidebar"><button className="brand" onClick={onViewBusinessAccounts}><span className="brand-mark">b</span><span>biz track admin</span></button><nav aria-label="Admin navigation"><p className="nav-label">ADMIN</p><button className="nav-item active" onClick={onViewBusinessAccounts}><span className="nav-icon">◈</span>Business accounts</button><button className="nav-item" onClick={onViewSubscriptions}><span className="nav-icon">KES</span>Subscriptions</button><button className="nav-item" onClick={onOpenSettings}><span className="nav-icon">⚙</span>Platform settings</button><button className="nav-item" onClick={onSignOut}><span className="nav-icon">↪</span>Sign out</button></nav></aside><main className="main-content"><header className="topbar"><div className="breadcrumbs"><span>Admin portal</span><b>/</b><strong>Overview</strong></div></header><div className="page-content"><PageHeading eyebrow="SITE ADMIN / CONTROL" title="Platform overview" subtitle="Manage every business workspace, subscription, and the base app configuration." action={<button className="primary-button" onClick={onCreate}><span>＋</span> Create business account</button>} /><section className="metric-grid"><Metric title="Active businesses" value={String(activeAccounts)} detail="Paying customers" accent="teal" /><Metric title="Trials" value={String(trialAccounts)} detail="Awaiting onboarding" accent="yellow" /><Metric title="Monthly revenue" value={`KES ${monthlyRevenue.toLocaleString()}`} detail="Across all plans" accent="coral" /><Metric title="Accounts" value={String(accounts.length)} detail="In the system" accent="lilac" /></section><section className="dashboard-grid"><article className="panel team-panel"><PanelHeading title="Recent business accounts" subtitle="Newest workspaces created in the platform" /><div className="table-wrap"><table><thead><tr><th>BUSINESS</th><th>OWNER</th><th>PLAN</th><th>STATUS</th></tr></thead><tbody>{recentAccounts.map((account) => <tr key={account.id}><td>{account.businessName}</td><td>{account.ownerName}</td><td>{account.plan}</td><td><span className="status-pill status-pill-teal">{account.status}</span></td></tr>)}</tbody></table></div></article><article className="panel member-form"><PanelHeading title="Quick actions" subtitle="Keep the platform and customer accounts moving." /><div className="form-grid single-field"><button type="button" className="primary-button" onClick={onCreate}>Create a new business account</button><button type="button" className="secondary-button" onClick={onViewBusinessAccounts}>View all businesses</button><button type="button" className="secondary-button" onClick={onViewSubscriptions}>Manage subscriptions</button><button type="button" className="secondary-button" onClick={onOpenSettings}>App settings</button></div></article></section></div></main></div>
}

function ActivationCodesPage({ codes, packages, onCreate, activeNav, onNavigate, onSignOut }: { codes: ActivationCode[]; packages: PackageConfig[]; onCreate: (packageName: SubscriptionPlan) => string; activeNav: string; onNavigate: (page: string) => void; onSignOut: () => void }) {
  const [packageName, setPackageName] = useState<SubscriptionPlan>('Starter')
  const [newCode, setNewCode] = useState('')
  const availablePackages = (packages || []).filter((item): item is PackageConfig => Boolean(item?.name && item.active))
  const create = () => setNewCode(onCreate(packageName))
  return <div className="app-shell"><AdminSidebar activeNav={activeNav} onNavigate={onNavigate} onSignOut={onSignOut} /><main className="main-content"><header className="topbar"><div className="breadcrumbs"><span>Site admin</span><b>/</b><strong>Activation codes</strong></div></header><div className="page-content"><PageHeading eyebrow="SITE ADMIN / ACCESS" title="Activation codes" subtitle="Create package-specific codes for business registration." /><article className="panel member-form"><PanelHeading title="Create a code" subtitle="Codes can be used once during business registration." /><div className="form-grid"><label><span>Package</span><select value={packageName} onChange={(event) => setPackageName(event.target.value as SubscriptionPlan)}>{availablePackages.map((item) => <option key={item.name}>{item.name}</option>)}</select></label><div className="form-actions"><button className="primary-button" type="button" onClick={create} disabled={!availablePackages.length}>＋ Create activation code</button>{newCode && <strong>{newCode}</strong>}</div></div></article><article className="panel team-panel"><PanelHeading title="Code inventory" subtitle={`${codes.filter((code) => code.status === 'Available').length} available codes`} /><div className="table-wrap"><table><thead><tr><th>CODE</th><th>PACKAGE</th><th>STATUS</th><th>CREATED</th><th>USED BY</th></tr></thead><tbody>{codes.map((code) => <tr key={code.id}><td><strong>{code.code}</strong></td><td>{code.packageName}</td><td>{code.status}</td><td>{code.createdAt}</td><td>{code.usedBy || '—'}</td></tr>)}</tbody></table></div></article></div></main></div>
}

function ConfiguredPackagesPage({ packages, onUpdate, onSave, activeNav, onNavigate, onSignOut }: { packages: PackageConfig[]; onUpdate: (name: SubscriptionPlan, updates: Partial<PackageConfig>) => void; onSave: () => void; activeNav: string; onNavigate: (page: string) => void; onSignOut: () => void }) {
  const updateDurationUnit = (name: string, value: string) => onUpdate(name, { durationUnit: value as PackageConfig['durationUnit'] })
  useEffect(() => {
    const stack = document.querySelector('.page-content .settings-stack')
    if (!stack || stack.querySelector('.package-save-button')) return
    const actions = document.createElement('div')
    actions.className = 'form-actions'
    const button = document.createElement('button')
    button.type = 'button'
    button.className = 'primary-button package-save-button'
    button.textContent = 'Save changes'
    button.addEventListener('click', onSave)
    actions.appendChild(button)
    stack.appendChild(actions)
    return () => actions.remove()
  }, [onSave, packages])
  return <div className="app-shell"><AdminSidebar activeNav={activeNav} onNavigate={onNavigate} onSignOut={onSignOut} /><main className="main-content"><header className="topbar"><div className="breadcrumbs"><span>Site admin</span><b>/</b><strong>Packages</strong></div></header><div className="page-content"><PageHeading eyebrow="SITE ADMIN / PACKAGES" title="Package management" subtitle="Set the package name, amount, duration, seats, and included capabilities." /><section className="settings-stack">{packages.map((item) => <article className="panel member-form" key={item.name}><PanelHeading title={item.name} subtitle="Changes apply to new activation codes and registrations." /><div className="form-grid"><label><span>Package name</span><input value={item.name} onChange={(event) => onUpdate(item.name, { name: event.target.value || 'Package' })} /></label><label><span>Amount</span><input type="number" min="0" value={item.price} onChange={(event) => onUpdate(item.name, { price: Number(event.target.value) || 0 })} /></label><label><span>Duration</span><input type="number" min="1" value={item.duration} onChange={(event) => onUpdate(item.name, { duration: Number(event.target.value) || 1 })} /></label><label><span>Duration unit</span><select value={item.durationUnit} onChange={(event) => updateDurationUnit(item.name, event.target.value)}><option value="day">Day(s)</option><option value="week">Week(s)</option><option value="month">Month(s)</option><option value="year">Year(s)</option></select></label><label><span>Seats</span><input type="number" min="1" value={item.seats} onChange={(event) => onUpdate(item.name, { seats: Number(event.target.value) || 1 })} /></label><label><span>Description</span><input value={item.description} onChange={(event) => onUpdate(item.name, { description: event.target.value })} /></label></div><div className="settings-choice-group"><strong>Included features</strong><small>Check every capability included with this package.</small><div className="settings-choice-grid">{packageFeatures.map((feature) => <label key={feature} className={item.features.includes(feature) ? 'settings-choice enabled' : 'settings-choice'}><input type="checkbox" checked={item.features.includes(feature)} onChange={(event) => onUpdate(item.name, { features: event.target.checked ? [...item.features, feature] : item.features.filter((value) => value !== feature) })} /><span>{feature}</span></label>)}</div></div><label className="settings-choice enabled"><input type="checkbox" checked={item.active} onChange={(event) => onUpdate(item.name, { active: event.target.checked })} /><span>Available for registration</span></label></article>)}</section></div></main></div>
}

function PackagesPage({ packages, onUpdate, activeNav, onNavigate, onSignOut }: { packages: PackageConfig[]; onUpdate: (name: SubscriptionPlan, updates: Partial<PackageConfig>) => void; activeNav: string; onNavigate: (page: string) => void; onSignOut: () => void }) {
  return <div className="app-shell"><AdminSidebar activeNav={activeNav} onNavigate={onNavigate} onSignOut={onSignOut} /><main className="main-content"><header className="topbar"><div className="breadcrumbs"><span>Site admin</span><b>/</b><strong>Packages</strong></div></header><div className="page-content"><PageHeading eyebrow="SITE ADMIN / PACKAGES" title="Package management" subtitle="Set the package name, billing amount, duration, seats, and included capabilities." /><section className="settings-stack">{packages.map((item) => <article className="panel member-form" key={item.name}><PanelHeading title={item.name} subtitle="Changes apply to new activation codes and registrations." /><div className="form-grid"><label><span>Package name</span><input value={item.name} onChange={(event) => onUpdate(item.name, { name: event.target.value || 'Package' })} /></label><label><span>Amount</span><input type="number" min="0" value={item.price} onChange={(event) => onUpdate(item.name, { price: Number(event.target.value) || 0 })} /></label><label><span>Duration</span><input type="number" min="1" value={item.duration} onChange={(event) => onUpdate(item.name, { duration: Number(event.target.value) || 1 })} /></label><label><span>Duration unit</span><select value={item.durationUnit} onChange={(event) => onUpdate(item.name, { durationUnit: event.target.value as PackageConfig['durationUnit'] })}><option value="month">Month(s)</option><option value="year">Year(s)</option></select></label><label><span>Seats</span><input type="number" min="1" value={item.seats} onChange={(event) => onUpdate(item.name, { seats: Number(event.target.value) || 1 })} /></label><label><span>Description</span><input value={item.description} onChange={(event) => onUpdate(item.name, { description: event.target.value })} /></label></div><div className="settings-choice-group"><strong>Included features</strong><small>Check every capability included with this package.</small><div className="settings-choice-grid">{packageFeatures.map((feature) => <label key={feature} className={item.features.includes(feature) ? 'settings-choice enabled' : 'settings-choice'}><input type="checkbox" checked={item.features.includes(feature)} onChange={(event) => onUpdate(item.name, { features: event.target.checked ? [...item.features, feature] : item.features.filter((value) => value !== feature) })} /><span>{feature}</span></label>)}</div></div><label className="settings-choice enabled"><input type="checkbox" checked={item.active} onChange={(event) => onUpdate(item.name, { active: event.target.checked })} /><span>Available for registration</span></label></article>)}</section></div></main></div>
}

function AdminBusinessRegistrationPage({ onNavigate, onCreate, onBack }: { onNavigate: (page: string) => void; onCreate: (account: { businessName: string; ownerName: string; email: string; username: string; password: string; industry: string; plan: SubscriptionPlan }) => void; onBack: () => void }) {
  return <RegisterPage packages={[]} onNavigate={onNavigate} onRequestIssue={() => undefined} onComplete={(account) => onCreate({ businessName: account.business || 'New business', ownerName: account.name, email: `${account.username}@biztrack.app`, username: account.username, password: account.password, industry: account.industry || 'General', plan: account.plan || 'Starter' })} />
}

function AdminBusinessRegistrationWizard({ packages, defaultPlan, onNavigate, onCreate, onBack }: { packages: PackageConfig[]; defaultPlan: SubscriptionPlan; onNavigate: (page: string) => void; onCreate: (account: { businessName: string; ownerName: string; email: string; username: string; password: string; industry: string; plan: SubscriptionPlan }, activationCode: string) => boolean | Promise<boolean>; onBack: () => void }) {
  const [step, setStep] = useState(1)
  const [details, setDetails] = useState({ name: '', phone: '', email: '', username: '', password: '', business: '', industry: '', plan: defaultPlan, code: '' })
  const [accepted, setAccepted] = useState(false)
  const [error, setError] = useState('')
  const availablePackages = (packages || []).filter((item): item is PackageConfig => Boolean(item?.name && item.active))
  const update = (event: FormEvent<HTMLInputElement | HTMLSelectElement>) => { const { name, value } = event.currentTarget; setDetails((current) => ({ ...current, [name]: value })) }
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setError('')
    if (step === 1 && (!details.name.trim() || !details.phone.trim() || !details.email.trim() || details.username.trim().length < 3 || details.password.length < 6)) { setError('Complete the owner name, phone, email, username, and password.'); return }
    if (step === 2 && (!details.business.trim() || !details.industry.trim())) { setError('Enter the business name and industry.'); return }
    if (step === 3 && !accepted) { setError('Accept the terms and conditions to continue.'); return }
    if (step === 4) {
      if (!details.code.trim()) { setError('Enter an activation code.'); return }
      const created = await onCreate({ businessName: details.business.trim(), ownerName: details.name.trim(), email: details.email.trim(), username: details.username.trim(), password: details.password, industry: details.industry.trim(), plan: details.plan }, details.code)
      if (!created) { setError('Account was not created. Check the activation code and the account credential message.'); return }
      return
    }
    setStep((current) => current + 1)
  }
  const titles = ['Owner particulars', 'Business details', 'Package and terms', 'Activation code']
  return <div className="register-page"><header className="register-header"><button className="welcome-brand" onClick={onBack}><span className="welcome-mark">b</span><span>biz track admin</span></button><button className="register-back" onClick={onBack}>Back to dashboard</button></header><main className="register-layout"><section className="register-card"><div className="register-progress">{titles.map((title, index) => <div key={title} className={index + 1 <= step ? 'complete' : ''}><b>0{index + 1}</b><span>{title}</span></div>)}</div><form onSubmit={submit}><p className="eyebrow">STEP 0{step} OF 04</p><h2>{titles[step - 1]}</h2>{error && <p className="login-error" role="alert">{error}</p>}{step === 1 && <div className="form-grid register-fields"><label><span>Full name *</span><input name="name" value={details.name} onChange={update} required /></label><label><span>Phone number *</span><input name="phone" value={details.phone} onChange={update} required /></label><label><span>Email address *</span><input name="email" type="email" value={details.email} onChange={update} required /></label><label><span>Username *</span><input name="username" value={details.username} onChange={update} required /></label><label><span>Temporary password *</span><input name="password" type="password" value={details.password} onChange={update} required /></label></div>}{step === 2 && <div className="form-grid register-fields"><label><span>Business name *</span><input name="business" value={details.business} onChange={update} required /></label><label><span>Industry *</span><input name="industry" value={details.industry} onChange={update} placeholder="Retail, hospitality..." required /></label></div>}{step === 3 && <div className="form-grid register-fields"><label><span>Preferred package *</span><select name="plan" value={details.plan} onChange={update}>{availablePackages.map((item) => <option key={item.name} value={item.name}>{item.name} · KES {item.price}/month · {item.seats} seats</option>)}</select></label><label className="settings-choice enabled"><input type="checkbox" checked={accepted} onChange={(event) => setAccepted(event.target.checked)} /><span>I accept the terms and conditions.</span></label></div>}{step === 4 && <div className="form-grid register-fields"><label><span>Activation code *</span><input name="code" value={details.code} onChange={update} placeholder="e.g. BT-ABC123" autoFocus required /></label><p className="register-help">Enter a code created for the selected {details.plan} package.</p></div>}<div className="form-actions"><button type="button" className="secondary-button" onClick={() => step === 1 ? onBack() : setStep((current) => current - 1)}>Back</button><button className="primary-button" type="submit">{step === 4 ? 'Create business' : 'Continue'} <span>→</span></button></div></form></section></main></div>
}

function CreateBusinessAccountPage({ activeNav, onNavigate, onCreate, onBack, onSignOut }: { activeNav: string; onNavigate: (page: string) => void; onCreate: (account: { businessName: string; ownerName: string; email: string; username: string; password: string; industry: string; plan: SubscriptionPlan }) => void; onBack: () => void; onSignOut: () => void }) {
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget)
    const account = {
      businessName: String(form.get('businessName') || '').trim(),
      ownerName: String(form.get('ownerName') || '').trim(),
      email: String(form.get('email') || '').trim(),
      username: String(form.get('username') || '').trim(),
      password: String(form.get('password') || '').trim(),
      industry: String(form.get('industry') || '').trim(),
      plan: String(form.get('plan') || 'Starter') as SubscriptionPlan,
    }
    if (!account.businessName || !account.ownerName || !account.email || !account.username || account.password.length < 6 || !account.industry) return
    onCreate(account)
    event.currentTarget.reset()
  }
  return <div className="app-shell"><AdminSidebar activeNav={activeNav} onNavigate={onNavigate} onSignOut={onSignOut} /><main className="main-content"><header className="topbar"><div className="breadcrumbs"><span>Site admin</span><b>/</b><strong>Register a new business</strong></div></header><div className="page-content"><PageHeading eyebrow="SITE ADMIN / REGISTRATION" title="Register a new business" subtitle="Follow the same registration steps to create a business workspace." /><form className="panel member-form" onSubmit={submit}><div className="form-grid"><label><span>Business name</span><input name="businessName" placeholder="e.g. Bluefield Foods" required /></label><label><span>Owner name</span><input name="ownerName" placeholder="e.g. Ada Okafor" required /></label><label><span>Owner email</span><input name="email" type="email" placeholder="owner@business.com" required /></label><label><span>Owner username</span><input name="username" placeholder="owner username" required /></label><label><span>Password</span><input name="password" type="password" placeholder="At least 6 characters" required /></label><label><span>Industry</span><input name="industry" placeholder="Retail, Hospitality, Logistics..." required /></label><label><span>Plan</span><select name="plan" defaultValue="Starter"><option>Starter</option><option>Growth</option><option>Scale</option></select></label></div><div className="form-actions"><button type="button" className="secondary-button" onClick={onBack}>Back</button><button type="submit" className="primary-button"><span>＋</span> Create account</button></div></form></div></main></div>
}

function BusinessAccountsPage({ accounts, activeNav, onNavigate, onCreate, onSignOut, onBack, onUpdateStatus, onDelete }: { accounts: BusinessAccount[]; activeNav: string; onNavigate: (page: string) => void; onCreate: () => void; onSignOut: () => void; onBack?: () => void; onUpdateStatus?: (accountId: number, updates: Partial<Pick<BusinessAccount, 'status'>>) => void; onDelete?: (accountId: number) => void }) {
  if (onNavigate) return <AdminBusinessAccountsPage accounts={accounts} activeNav={activeNav} onNavigate={onNavigate} onCreate={onCreate} onSignOut={onSignOut} onUpdateStatus={onUpdateStatus || (() => undefined)} onDelete={onDelete || (() => undefined)} />
  return <div className="app-shell"><aside className="sidebar"><button className="brand" onClick={onBack}><span className="brand-mark">b</span><span>biz track admin</span></button><nav aria-label="Admin navigation"><p className="nav-label">ADMIN</p><button className="nav-item" onClick={onBack}><span className="nav-icon">◈</span>Overview</button><button className="nav-item active" onClick={() => undefined}><span className="nav-icon">◈</span>Business accounts</button><button className="nav-item" onClick={() => window.history.pushState({}, '', '/admin/subscriptions/')}><span className="nav-icon">KES</span>Subscriptions</button><button className="nav-item" onClick={() => window.history.pushState({}, '', '/admin/settings/')}><span className="nav-icon">⚙</span>Platform settings</button><button className="nav-item" onClick={() => window.history.pushState({}, '', '/signin/')}><span className="nav-icon">↪</span>Sign out</button></nav></aside><main className="main-content"><header className="topbar"><div className="breadcrumbs"><span>Admin portal</span><b>/</b><strong>Business accounts</strong></div></header><div className="page-content"><PageHeading eyebrow="SITE ADMIN / BUSINESS" title="Business accounts" subtitle="Track every workspace and the owner assigned to each one." action={<button className="primary-button" onClick={onCreate}><span>＋</span> New account</button>} /><article className="panel team-panel"><div className="table-wrap"><table><thead><tr><th>BUSINESS</th><th>OWNER</th><th>INDUSTRY</th><th>PLAN</th><th>STATUS</th><th>SEATS</th></tr></thead><tbody>{accounts.map((account) => <tr key={account.id}><td><strong>{account.businessName}</strong><small>{account.email}</small></td><td>{account.ownerName}</td><td>{account.industry}</td><td>{account.plan}</td><td><span className="status-pill status-pill-teal">{account.status}</span></td><td>{account.seats}</td></tr>)}</tbody></table></div></article><div className="form-actions"><button type="button" className="secondary-button" onClick={onBack}>Back</button></div></div></main></div>
}

function AdminBusinessAccountsPage({ accounts, activeNav, onNavigate, onCreate, onSignOut, onUpdateStatus, onDelete }: { accounts: BusinessAccount[]; activeNav: string; onNavigate: (page: string) => void; onCreate: () => void; onSignOut: () => void; onUpdateStatus: (accountId: number, updates: Partial<Pick<BusinessAccount, 'status'>>) => void; onDelete: (accountId: number) => void }) {
  const [viewAccount, setViewAccount] = useState<BusinessAccount | null>(null)
  const [suspendAccount, setSuspendAccount] = useState<BusinessAccount | null>(null)
  return <div className="app-shell"><AdminSidebar activeNav={activeNav} onNavigate={onNavigate} onSignOut={onSignOut} /><main className="main-content"><header className="topbar"><div className="breadcrumbs"><span>Site admin</span><b>/</b><strong>Business accounts</strong></div></header><div className="page-content"><PageHeading eyebrow="SITE ADMIN / BUSINESS" title="Business accounts" subtitle="Track every workspace, subscription, and owner from one place." action={<button className="primary-button" onClick={onCreate}><span>＋</span> New account</button>} /><article className="panel team-panel business-accounts-panel"><div className="table-wrap"><table className="business-accounts-table"><thead><tr><th>BUSINESS</th><th>OWNER</th><th>INDUSTRY</th><th>PLAN</th><th>STATUS</th><th>SEATS</th><th>ACTIONS</th></tr></thead><tbody>{accounts.map((account) => <tr key={account.id}><td><strong>{account.businessName}</strong><small>{account.email}</small></td><td><strong>{account.ownerName}</strong><small>{account.username}</small></td><td>{account.industry}</td><td><strong>{account.plan}</strong><small>Ends {account.nextBilling || 'not set'}</small></td><td><span className={`status-pill ${account.status === 'Active' ? 'status-pill-teal' : account.status === 'Paused' ? 'status-pill-coral' : 'status-pill-yellow'}`}>{account.status}</span></td><td>{account.seats}</td><td><div className="business-account-actions"><button type="button" className="table-action table-action-view" onClick={() => setViewAccount(account)}>View</button><button type="button" className="table-action" onClick={() => onUpdateStatus(account.id, { status: account.status === 'Paused' ? 'Active' : 'Paused' })}>{account.status === 'Paused' ? 'Reactivate' : 'Suspend'}</button><button type="button" className="table-action table-action-danger" onClick={() => onDelete(account.id)}>Delete</button></div></td></tr>)}</tbody></table></div></article></div></main>{viewAccount && <div className="admin-modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) setViewAccount(null) }}><section className="admin-modal" role="dialog" aria-modal="true" aria-labelledby="business-view-title"><button className="admin-modal-close" type="button" aria-label="Close" onClick={() => setViewAccount(null)}>×</button><p className="eyebrow">BUSINESS ACCOUNT</p><h2 id="business-view-title">{viewAccount.businessName}</h2><p className="admin-modal-user"><strong>{viewAccount.ownerName}</strong><span>{viewAccount.email} · {viewAccount.industry}</span></p><div className="business-account-detail-grid"><div><span>Plan</span><strong>{viewAccount.plan}</strong></div><div><span>Status</span><strong>{viewAccount.status}</strong></div><div><span>Seats</span><strong>{viewAccount.seats}</strong></div><div><span>Package ends</span><strong>{viewAccount.nextBilling || 'Not set'}</strong></div></div><div className="form-actions"><button type="button" className="secondary-button" onClick={() => setViewAccount(null)}>Close</button></div></section></div>}</div>
}

function SubscriptionPage({ accounts, onUpdate, onBack }: { accounts: BusinessAccount[]; onUpdate: (accountId: number, updates: Partial<Pick<BusinessAccount, 'status' | 'plan' | 'seats' | 'nextBilling'>>) => void; onBack: () => void }) {
  return <div className="app-shell"><aside className="sidebar"><button className="brand" onClick={onBack}><span className="brand-mark">b</span><span>biz track admin</span></button><nav aria-label="Admin navigation"><p className="nav-label">ADMIN</p><button className="nav-item" onClick={onBack}><span className="nav-icon">◈</span>Overview</button><button className="nav-item" onClick={() => window.history.pushState({}, '', '/admin/businesses/')}><span className="nav-icon">◈</span>Business accounts</button><button className="nav-item active" onClick={() => undefined}><span className="nav-icon">KES</span>Subscriptions</button><button className="nav-item" onClick={() => window.history.pushState({}, '', '/admin/settings/')}><span className="nav-icon">⚙</span>Platform settings</button><button className="nav-item" onClick={() => window.history.pushState({}, '', '/signin/')}><span className="nav-icon">↪</span>Sign out</button></nav></aside><main className="main-content"><header className="topbar"><div className="breadcrumbs"><span>Admin portal</span><b>/</b><strong>Subscriptions</strong></div></header><div className="page-content"><PageHeading eyebrow="SITE ADMIN / BILLING" title="Subscription management" subtitle="Update the plan, seats, billing date, and account status for each workspace." /><article className="panel team-panel"><div className="table-wrap"><table><thead><tr><th>BUSINESS</th><th>PLAN</th><th>SEATS</th><th>NEXT BILLING</th><th>STATUS</th><th>ACTION</th></tr></thead><tbody>{accounts.map((account) => <tr key={account.id}><td><strong>{account.businessName}</strong><small>{account.ownerName}</small></td><td><select value={account.plan} onChange={(event) => onUpdate(account.id, { plan: event.target.value as SubscriptionPlan })}><option>Starter</option><option>Growth</option><option>Scale</option></select></td><td><input type="number" min="1" value={account.seats} onChange={(event) => onUpdate(account.id, { seats: Number(event.target.value) || account.seats })} /></td><td><input type="date" value={account.nextBilling} onChange={(event) => onUpdate(account.id, { nextBilling: event.target.value })} /></td><td><select value={account.status} onChange={(event) => onUpdate(account.id, { status: event.target.value as SubscriptionStatus })}><option>Trial</option><option>Active</option><option>Paused</option><option>Canceled</option></select></td><td><button type="button" className="secondary-button" onClick={() => onUpdate(account.id, { status: 'Active', plan: account.plan })}>Apply</button></td></tr>)}</tbody></table></div></article><div className="form-actions"><button type="button" className="secondary-button" onClick={onBack}>Back</button></div></div></main></div>
}

function AdminPlatformSettingsShell({ activeNav, onNavigate, onSignOut, settings, onSave }: { activeNav: string; onNavigate: (page: string) => void; onSignOut: () => void; settings: PlatformSettings; onSave: (settings: PlatformSettings) => Promise<void> }) {
  return <PlatformSettingsPageLayout key={JSON.stringify(settings)} activeNav={activeNav} onNavigate={onNavigate} onSignOut={onSignOut} settings={settings} onSave={onSave} />
}

function PlatformSettingsPage({ activeNav, onNavigate, onBack, settings, siteAdminAccount, onSave }: { activeNav: string; onNavigate: (page: string) => void; onBack?: () => void; settings: PlatformSettings; siteAdminAccount: OwnerAccount | null; onSave: (settings: PlatformSettings) => Promise<void> }) {
  const [platformName, setPlatformName] = useState(settings.platformName)
  const [supportEmail, setSupportEmail] = useState(settings.supportEmail)
  const [whatsappNumber, setWhatsappNumber] = useState(settings.whatsappNumber)
  const [defaultPlan, setDefaultPlan] = useState(settings.defaultPlan)
  const [maintenanceMode, setMaintenanceMode] = useState(settings.maintenanceMode)
  const [maintenanceEndsAt, setMaintenanceEndsAt] = useState(settings.maintenanceEndsAt)
  const [scheduleOpen, setScheduleOpen] = useState(false)
  const [scheduleDate, setScheduleDate] = useState('')
  const [scheduleTime, setScheduleTime] = useState('')
  const [saving, setSaving] = useState(false)
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const save = async () => {
    const nextSettings = { platformName, supportEmail, whatsappNumber: whatsappNumber.replace(/[^0-9]/g, ''), defaultPlan, maintenanceMode, maintenanceEndsAt }
    setSaving(true)
    try { await onSave(nextSettings) } catch (saveError) { showBusinessAlert('Site admin', saveError instanceof Error ? saveError.message : 'Could not save platform settings.', 'Could not save settings') } finally { setSaving(false) }
  }
  const openSchedule = () => {
    const localValue = toDateTimeLocalValue(maintenanceEndsAt)
    setScheduleDate(localValue.slice(0, 10))
    setScheduleTime(localValue.slice(11, 16) || '12:00')
    setScheduleOpen(true)
  }
  const applySchedule = () => {
    if (!scheduleDate || !scheduleTime) return
    const target = new Date(`${scheduleDate}T${scheduleTime}`)
    if (!Number.isFinite(target.getTime())) return
    setMaintenanceEndsAt(target.toISOString())
    setScheduleOpen(false)
  }
  return <>
    <button type="button" className="legacy-sidebar-toggle" aria-label={sidebarOpen ? 'Close admin menu' : 'Open admin menu'} aria-expanded={sidebarOpen} onClick={() => setSidebarOpen((open) => !open)}>{sidebarOpen ? '‹' : '☰'}</button>
    <div className="app-shell"><aside className="sidebar"><button className="brand" onClick={onBack}><span className="brand-mark">b</span><span>biz track admin</span></button><nav aria-label="Admin navigation"><p className="nav-label">ADMIN</p><button className="nav-item" onClick={onBack}><span className="nav-icon">◈</span>Overview</button><button className="nav-item" onClick={() => window.history.pushState({}, '', '/admin/businesses/')}><span className="nav-icon">◈</span>Business accounts</button><button className="nav-item" onClick={() => window.history.pushState({}, '', '/admin/subscriptions/')}><span className="nav-icon">KES</span>Subscriptions</button><button className="nav-item active" onClick={() => undefined}><span className="nav-icon">⚙</span>Platform settings</button><button className="nav-item" onClick={() => window.history.pushState({}, '', '/signin/')}><span className="nav-icon">↪</span>Sign out</button></nav></aside><main className="main-content"><header className="topbar"><div className="breadcrumbs"><span>Admin portal</span><b>/</b><strong>Platform settings</strong></div></header><div className="page-content"><PageHeading eyebrow="SITE ADMIN / SETTINGS" title="App configuration" subtitle="Set the public platform identity and default account setup rules." /><article className="panel member-form"><div className="form-grid"><label><span>Platform name</span><input value={platformName} onChange={(event) => setPlatformName(event.target.value)} /></label><label><span>Support email</span><input type="email" value={supportEmail} onChange={(event) => setSupportEmail(event.target.value)} /></label><label><span>Default plan</span><select value={defaultPlan} onChange={(event) => setDefaultPlan(event.target.value)}><option>Starter</option><option>Growth</option><option>Scale</option></select></label><label className="maintenance-mode-field"><span>Maintenance mode</span><input type="checkbox" checked={maintenanceMode} onChange={(event) => setMaintenanceMode(event.target.checked)} /></label><label className="whatsapp-support-field"><span>WhatsApp support number</span><input type="tel" value={whatsappNumber} onChange={(event) => setWhatsappNumber(event.target.value)} placeholder="e.g. 254712345678" /><small>Use the full international number without the plus sign.</small></label><label className="maintenance-countdown-field"><span>Expected maintenance completion</span><button type="button" className="maintenance-schedule-trigger" onClick={openSchedule}>{Number.isFinite(Date.parse(maintenanceEndsAt)) ? new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(Date.parse(maintenanceEndsAt)) : 'Choose date and time'}</button><small>Visitors will see a countdown to this date and time.</small></label></div><div className="form-actions"><button type="button" className="secondary-button" onClick={onBack}>Back</button><button type="button" className="primary-button" onClick={save} disabled={saving}>{saving ? 'Saving...' : 'Save settings'}</button></div></article></div></main></div>
    {scheduleOpen && <div className="maintenance-schedule-backdrop"><section className="maintenance-schedule-dialog" role="dialog" aria-modal="true" aria-labelledby="maintenance-schedule-title"><button type="button" className="maintenance-schedule-close" aria-label="Close completion time dialog" onClick={() => setScheduleOpen(false)}>×</button><p className="eyebrow">MAINTENANCE</p><h2 id="maintenance-schedule-title">Set completion time</h2><p className="maintenance-schedule-copy">Choose when visitors should expect the site to be available.</p><div className="maintenance-schedule-fields"><label><span>Date</span><input type="date" required value={scheduleDate} onChange={(event) => setScheduleDate(event.target.value)} /></label><label><span>Time</span><input type="time" required value={scheduleTime} onChange={(event) => setScheduleTime(event.target.value)} /></label></div><div className="maintenance-schedule-actions"><button type="button" className="secondary-button" onClick={() => setScheduleOpen(false)}>Cancel</button><button type="button" className="primary-button" onClick={applySchedule} disabled={!scheduleDate || !scheduleTime}>Apply time</button></div></section></div>}
  </>
}

function PlatformSettingsPageLayout({ activeNav, onNavigate, onSignOut, settings, onSave }: { activeNav: string; onNavigate: (page: string) => void; onSignOut: () => void; settings: PlatformSettings; onSave: (settings: PlatformSettings) => Promise<void> }) {
  const [draft, setDraft] = useState(settings)
  const [saving, setSaving] = useState(false)
  const [scheduleOpen, setScheduleOpen] = useState(false)
  const [scheduleDate, setScheduleDate] = useState('')
  const [scheduleTime, setScheduleTime] = useState('')
  const openSchedule = () => {
    const localValue = toDateTimeLocalValue(draft.maintenanceEndsAt)
    setScheduleDate(localValue.slice(0, 10))
    setScheduleTime(localValue.slice(11, 19) || '12:00:00')
    setScheduleOpen(true)
  }
  const applySchedule = () => {
    if (!scheduleDate || !scheduleTime) return
    const target = new Date(`${scheduleDate}T${scheduleTime}`)
    if (!Number.isFinite(target.getTime())) return
    setDraft((current) => ({ ...current, maintenanceEndsAt: target.toISOString() }))
    setScheduleOpen(false)
  }
  const save = async () => {
    setSaving(true)
    try {
      await onSave({ ...draft, whatsappNumber: draft.whatsappNumber.replace(/[^0-9]/g, '') })
    } catch (error) {
      showBusinessAlert('Site admin', error instanceof Error ? error.message : 'Could not save platform settings.', 'Could not save settings')
    } finally {
      setSaving(false)
    }
  }

  return <><div className="app-shell">
    <AdminSidebar activeNav={activeNav} onNavigate={onNavigate} onSignOut={onSignOut} />
    <main className="main-content">
      <header className="topbar"><div className="breadcrumbs"><span>Site admin</span><b>/</b><strong>Platform settings</strong></div></header>
      <div className="page-content">
        <PageHeading eyebrow="SITE ADMIN / SETTINGS" title="Platform settings" subtitle="Configure platform-wide identity, support, and default account setup." />
        <article className="panel member-form">
          <div className="form-grid">
            <label><span>Platform name</span><input value={draft.platformName} onChange={(event) => setDraft((current) => ({ ...current, platformName: event.target.value }))} /></label>
            <label><span>Support email</span><input type="email" value={draft.supportEmail} onChange={(event) => setDraft((current) => ({ ...current, supportEmail: event.target.value }))} /></label>
            <label><span>Default plan</span><select value={draft.defaultPlan} onChange={(event) => setDraft((current) => ({ ...current, defaultPlan: event.target.value as SubscriptionPlan }))}><option>Starter</option><option>Growth</option><option>Scale</option></select></label>
            <label className="maintenance-mode-field"><span>Maintenance mode</span><input type="checkbox" checked={draft.maintenanceMode} onChange={(event) => setDraft((current) => ({ ...current, maintenanceMode: event.target.checked }))} /></label>
            <label><span>WhatsApp support number</span><input type="tel" value={draft.whatsappNumber} onChange={(event) => setDraft((current) => ({ ...current, whatsappNumber: event.target.value }))} /><small>Use the full international number without the plus sign.</small></label>
            <div className="maintenance-countdown-field"><span>Expected maintenance completion</span><button type="button" className="maintenance-schedule-trigger" onClick={openSchedule}>{Number.isFinite(Date.parse(draft.maintenanceEndsAt)) ? new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', second: '2-digit' }).format(new Date(draft.maintenanceEndsAt)) : 'Choose date and time'}</button><small>Visitors see a countdown to this date and time.</small></div>
          </div>
          <div className="form-actions"><button type="button" className="secondary-button" onClick={() => onNavigate('Dashboard')}>Back</button><button type="button" className="primary-button" disabled={saving} onClick={() => void save()}>{saving ? 'Saving...' : 'Save settings'}</button></div>
        </article>
      </div>
    </main>
  </div>{scheduleOpen && <div className="maintenance-schedule-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) setScheduleOpen(false) }}><section className="maintenance-schedule-dialog" role="dialog" aria-modal="true" aria-labelledby="maintenance-schedule-title"><button type="button" className="maintenance-schedule-close" aria-label="Close completion time dialog" onClick={() => setScheduleOpen(false)}>×</button><p className="eyebrow">MAINTENANCE</p><h2 id="maintenance-schedule-title">Set completion time</h2><p className="maintenance-schedule-copy">Choose the date and time visitors should expect the site to be available.</p><div className="maintenance-schedule-fields"><label><span>Date</span><input type="date" required value={scheduleDate} onChange={(event) => setScheduleDate(event.target.value)} /></label><label><span>Time</span><input type="time" step="1" required value={scheduleTime} onChange={(event) => setScheduleTime(event.target.value)} /></label></div><div className="maintenance-schedule-actions"><button type="button" className="secondary-button" onClick={() => setScheduleOpen(false)}>Cancel</button><button type="button" className="primary-button" onClick={applySchedule} disabled={!scheduleDate || !scheduleTime}>Apply time</button></div></section></div>}</>
}

export default App