import axios from 'axios'

const TOKEN_KEY = 'efp_role_token'

// Role access token for servers that enable ROLE_TOKENS. sessionStorage (tab-lifetime), never localStorage.
export const roleToken = {
  get() { try { return sessionStorage.getItem(TOKEN_KEY) || '' } catch { return '' } },
  set(value) { try { if (value) sessionStorage.setItem(TOKEN_KEY, value); else sessionStorage.removeItem(TOKEN_KEY) } catch { /* storage blocked */ } }
}

const api = axios.create({
  baseURL: '/api',
  timeout: 90000,
  headers: {
    'X-Requested-With': 'Email-Threat-Detection'
  }
})

api.interceptors.request.use(config => {
  const token = roleToken.get()
  const already = config.headers?.get ? config.headers.get('Authorization') : config.headers?.Authorization
  if (token && !already) {
    if (config.headers.set) config.headers.set('Authorization', `Bearer ${token}`)
    else config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(response => response, error => {
  // Gmail endpoints carry their own dedicated tokens; a 401 there is not a role-session problem.
  if (error.response?.status === 401 && !String(error.config?.url || '').startsWith('/gmail/')) {
    window.dispatchEvent(new Event('efp-auth-required'))
  }
  return Promise.reject(error)
})

export default api
