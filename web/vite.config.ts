import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The build goes straight into the Go package that embeds it (internal/panel/dist).
// `npm run dev` proxies the API to a panel started with --panel-listen (see README).
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: { outDir: "../internal/panel/dist", emptyOutDir: true, chunkSizeWarningLimit: 900 },
  server: {
    proxy: {
      "/api": { target: process.env.MAHAN_PANEL || "https://127.0.0.1:8443", secure: false, changeOrigin: true },
      "/panel/api": { target: process.env.MAHAN_PANEL || "https://127.0.0.1:8443", secure: false, changeOrigin: true },
    },
  },
});
