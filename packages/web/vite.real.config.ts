import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"

/**
 * Config Vite dédiée aux tests e2e « condition réelle » (voir
 * `playwright.real.config.ts`). Sert l'app sur :5274 et proxifie vers l'API
 * isolée :4100 — sans toucher au stack de dev standard (:5273 -> :4000).
 */
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5274,
    strictPort: true,
    proxy: {
      "/api": { target: "http://127.0.0.1:4100", changeOrigin: true },
      "/ws": { target: "http://127.0.0.1:4100", ws: true },
    },
  },
})
