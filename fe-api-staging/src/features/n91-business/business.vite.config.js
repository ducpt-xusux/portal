// Scope all QA build/cache writes to D delivery. No shared Vite/package changes.
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath } from 'node:url'
const entry = fileURLToPath(new URL('./business-qa.html', import.meta.url))
const delivery = fileURLToPath(
  new URL('../../../../delivery-n91/D-business/', import.meta.url)
)
export default defineConfig({
  plugins: [react()],
  cacheDir: `${delivery}vite-cache`,
  build: {
    outDir: `${delivery}ui-build`,
    emptyOutDir: false,
    rollupOptions: { input: entry },
  },
})
