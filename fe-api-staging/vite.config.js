import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { readFileSync } from 'node:fs'

const apiTarget = process.env.PORTAL_API_TARGET || 'http://127.0.0.1:8000'

async function consoleAccess() {
  if (process.env.PORTAL_SESSION_AUTH === 'true') return false
  try {
    const response = await fetch(
      new URL('/api/v1/portal/access-mode', apiTarget),
      {
        redirect: 'error',
        signal: AbortSignal.timeout(1500),
      }
    )
    if (!response.ok) return false
    const { data } = await response.json()
    if (data?.mode !== 'OBSERVATION' || data.console_proxy_allowed !== true)
      return false
    // Vite proxies only when bypass returns undefined.
  } catch {
    return false
  }
}


function portalLiveExtensions() {
  const manifest = JSON.parse(
    readFileSync(new URL('./portal-extensions.json', import.meta.url), 'utf8')
  )
  return {
    name: 'portal-live-extensions',
    transformIndexHtml: {
      order: 'post',
      handler(html) {
        const additions = manifest.tags.map((entry) => entry.tag).join('\n')
        return html.replace(
          '</head>',
          '<!-- N91 LIVE EXTENSIONS: keep manifest order -->\n' +
            additions +
            '\n</head>'
        )
      },
    },
  }
}

export default defineConfig({
  plugins: [react(), portalLiveExtensions()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': { target: apiTarget, changeOrigin: true },
      '/console-ws': {
        target: process.env.PORTAL_NOVNC_TARGET || 'http://100.100.10.10:6080',
        ws: true,
        changeOrigin: true,
        rewriteWsOrigin: true,
        bypass: consoleAccess,
        rewrite: (path) => path.replace(/^\/console-ws/, ''),
      },
    },
  },
})
