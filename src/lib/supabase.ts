import { createClient } from '@supabase/supabase-js'

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY

const normaliseSupabaseUrl = (value: string | undefined) => {
  if (!value) return ''
  return value.trim().replace(/\/+$/, '')
}

const fetchWithTimeout: typeof fetch = async (input, init) => {
  const controller = new AbortController()
  const requestSignal = init?.signal ?? (input instanceof Request ? input.signal : undefined)
  const abortFromRequest = () => controller.abort(requestSignal?.reason)
  if (requestSignal?.aborted) abortFromRequest()
  else requestSignal?.addEventListener('abort', abortFromRequest, { once: true })
  const timeout = window.setTimeout(() => controller.abort(new Error('Supabase request timed out after 10 seconds.')), 10_000)
  try {
    return await fetch(input, { ...init, signal: controller.signal })
  } finally {
    window.clearTimeout(timeout)
    requestSignal?.removeEventListener('abort', abortFromRequest)
  }
}

const hasValidSupabaseUrl = typeof supabaseUrl === 'string' && /^https:\/\/[^/]+\.supabase\.(co|com)$/.test(normaliseSupabaseUrl(supabaseUrl))
export const isSupabaseConfigured = Boolean(hasValidSupabaseUrl && supabaseAnonKey)
export const supabase = isSupabaseConfigured ? createClient(normaliseSupabaseUrl(supabaseUrl), supabaseAnonKey, {
	auth: {
		persistSession: true,
		autoRefreshToken: true,
		detectSessionInUrl: false,
	},
	global: {
		fetch: fetchWithTimeout,
		headers: {
			'x-app-name': 'biztrack',
		},
	},
	db: {
		schema: 'public',
	},
}) : null

export const isSupabaseHealthy = async () => {
  if (!supabase) return false
  try {
    const { error } = await supabase.from('platform_settings').select('id').limit(1).maybeSingle()
    return !error
  } catch {
    return false
  }
}
