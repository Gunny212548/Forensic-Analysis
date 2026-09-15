import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Build output goes straight into ../static, which app/main.py already serves:
// index.html at "/" and everything else through the /static mount. `base` has
// to match that mount or the bundle's own <script src> 404s.
//
// Nothing is fetched from a CDN at runtime - Vite inlines/emits every asset
// locally, which is what keeps a case workable air-gapped (CLAUDE.md gotcha
// #17). Dependencies are pinned exactly for the same reason: the output of
// this tool is evidence, so the build has to be repeatable.
export default defineConfig({
  plugins: [react()],
  base: '/static/',
  build: {
    outDir: '../static',
    emptyOutDir: true,
    // One chunk. The whole app is ~1500 lines and an analyst opens it over a
    // LAN or an air-gapped host - a dozen small requests buy nothing here,
    // and a single file is easier to reason about when the page has to work.
    rollupOptions: {
      output: {
        manualChunks: undefined,
        entryFileNames: 'assets/app-[hash].js',
        chunkFileNames: 'assets/app-[hash].js',
        assetFileNames: 'assets/app-[hash][extname]',
      },
    },
  },
  server: {
    // `npm run dev` proxies the API to the container so the UI can be worked
    // on with hot reload against real cases.
    proxy: {
      '/api': 'http://localhost:8091',
    },
  },
})
