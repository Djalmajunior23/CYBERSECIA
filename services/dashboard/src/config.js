export const getApiUrl = (path) => {
  const baseUrl = import.meta.env.VITE_API_URL || (window.location.hostname === 'localhost' ? 'http://localhost:8080' : '')
  return `${baseUrl}${path}`
}

export const getWsUrl = () => {
  if (import.meta.env.VITE_WS_URL) {
    return import.meta.env.VITE_WS_URL
  }
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = window.location.hostname === 'localhost' ? 'localhost:8080' : window.location.host
  return `${protocol}//${host}/ws`
}
