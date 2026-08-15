export const getStoredBackendUrl = () => {
  if (typeof window !== 'undefined') {
    return window.localStorage.getItem('cybersec_backend_url') || ''
  }
  return ''
}

export const setStoredBackendUrl = (url) => {
  if (typeof window !== 'undefined') {
    if (url) {
      window.localStorage.setItem('cybersec_backend_url', url.replace(/\/+$/, ''))
    } else {
      window.localStorage.removeItem('cybersec_backend_url')
    }
  }
}

export const getApiUrl = (path) => {
  const stored = getStoredBackendUrl()
  if (stored) {
    return `${stored}${path}`
  }
  const envUrl = import.meta.env.VITE_API_URL
  if (envUrl) {
    return `${envUrl.replace(/\/+$/, '')}${path}`
  }
  if (typeof window !== 'undefined' && window.location.hostname === 'localhost') {
    return `http://localhost:8080${path}`
  }
  return `https://cybersecia-api.onrender.com${path}`
}

export const getWsUrl = () => {
  const envWs = import.meta.env.VITE_WS_URL
  if (envWs) {
    return envWs
  }
  
  let baseUrl = getStoredBackendUrl()
  if (!baseUrl) {
    const envApi = import.meta.env.VITE_API_URL
    if (envApi) {
      baseUrl = envApi
    } else if (typeof window !== 'undefined' && window.location.hostname === 'localhost') {
      baseUrl = 'http://localhost:8080'
    } else {
      baseUrl = 'https://cybersecia-api.onrender.com'
    }
  }

  const cleanUrl = baseUrl.replace(/\/+$/, '')
  if (cleanUrl.startsWith('https://')) {
    return cleanUrl.replace('https://', 'wss://') + '/ws'
  } else if (cleanUrl.startsWith('http://')) {
    return cleanUrl.replace('http://', 'ws://') + '/ws'
  }
  
  return `wss://${cleanUrl}/ws`
}
