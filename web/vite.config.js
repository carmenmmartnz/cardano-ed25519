import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  // The crate is the parent directory, so allow Vite to serve `pkg/` from it.
  server: { fs: { allow: [".."] } },
});
