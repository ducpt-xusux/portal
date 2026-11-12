import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath } from 'node:url'

// Dedicated build, no shared Vite config/package.json or runtime changes.
export default defineConfig({
  root: fileURLToPath(new URL('.', import.meta.url)),
  plugins: [react()],
  build: {
    outDir: fileURLToPath(
      new URL(
        '../../../../delivery-n91/C-investigation/feature-build',
        import.meta.url
      )
    ),
    emptyOutDir: false,
    rollupOptions: {
      input: fileURLToPath(
        new URL('./investigation-preview.html', import.meta.url)
      ),
    },
  },
})
