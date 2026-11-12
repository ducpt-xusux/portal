// Build proposed shared FE changes in memory; never write/apply to shared source.
import { defineConfig, normalizePath } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath } from 'node:url'
import { readFileSync } from 'node:fs'
const workspace = fileURLToPath(new URL('../../../../', import.meta.url))
const delivery = `${workspace}delivery-n91/D-business/`
const entries = JSON.parse(
  readFileSync(`${delivery}integration-base-hashes.json`, 'utf8')
)
const candidates = new Map(
  entries
    .filter((x) => x.path.startsWith('fe-api-staging/src/'))
    .map((x) => [
      normalizePath(workspace + x.path),
      readFileSync(delivery + x.candidate, 'utf8'),
    ])
)
export default defineConfig({
  plugins: [
    {
      name: 'd-unapplied-proposal',
      enforce: 'pre',
      load(id) {
        return candidates.get(normalizePath(id.split('?')[0]))
      },
    },
    react(),
  ],
  cacheDir: `${delivery}vite-cache-proposal`,
  build: { outDir: `${delivery}proposal-build`, emptyOutDir: false },
})
