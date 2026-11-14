const CACHE_NAME = 'biztrack-shell-v4'
const APP_SHELL = ['/', '/index.html', '/manifest.webmanifest', '/pwa-icon.svg', '/biztrack-favicon.svg']

const isNavigationRequest = (request) => request.mode === 'navigate' || request.destination === 'document'
const isStaticAsset = (request) => ['style', 'script', 'font', 'image', 'manifest'].includes(request.destination)
const isApiRequest = (url) => url.origin !== self.location.origin || url.pathname.startsWith('/api/')

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(APP_SHELL))
      .catch((error) => {
        console.warn('Could not cache the complete app shell:', error)
      })
  )
  self.skipWaiting()
})

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(
      keys
        .filter((key) => key.startsWith('biztrack-shell-') && key !== CACHE_NAME)
        .map((key) => caches.delete(key))
    ))
  )
  self.clients.claim()
})

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return

  const requestUrl = new URL(event.request.url)

  if (isApiRequest(requestUrl)) return

  if (isNavigationRequest(event.request)) {
    event.respondWith(
      fetch(event.request, { cache: 'no-store' })
        .then((response) => response.ok
          ? response
          : caches.match('/index.html').then((cached) => cached || response))
        .catch(() => caches.match('/index.html').then((cached) => cached || Response.error()))
    )
    return
  }

  if (isStaticAsset(event.request)) {
    const cachedResponse = caches.match(event.request)
    const networkResponse = fetch(event.request, { cache: 'no-store' })
      .then(async (response) => {
        if (response.ok) {
          const copy = response.clone()
          await caches.open(CACHE_NAME)
            .then((cache) => cache.put(event.request, copy))
            .catch((error) => console.warn('Could not cache a static app asset:', error))
        }
        return response
      })
      .catch(() => null)
    event.respondWith(
      cachedResponse.then((cached) => cached || networkResponse).then((response) => response || Response.error())
    )
    event.waitUntil(networkResponse.then(() => undefined))
  }
})
