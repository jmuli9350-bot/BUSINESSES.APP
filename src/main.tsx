import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App, { MobileInstallLink, SiteCalendarPopups } from './App.tsx'

const preventBrowserZoom = (event: Event) => event.preventDefault()

document.addEventListener('wheel', (event) => {
  if (event.ctrlKey || event.metaKey) preventBrowserZoom(event)
}, { capture: true, passive: false })

document.addEventListener('keydown', (event) => {
  if ((event.ctrlKey || event.metaKey) && ['+', '-', '=', '_', '0'].includes(event.key)) {
    preventBrowserZoom(event)
  }
}, true)

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    void navigator.serviceWorker
      .register('/sw.js', { scope: '/', updateViaCache: 'none' })
      .catch((error) => console.warn('Service worker registration failed:', error))
  })
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <>
      <App />
      <MobileInstallLink />
      <SiteCalendarPopups />
    </>
  </StrictMode>,
)
