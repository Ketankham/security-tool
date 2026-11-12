// Optional URL prefix the dashboard is served under (e.g. "/security" when it
// sits behind the shared Hetzner reverse proxy next to another app). Empty in
// local dev. Inlined at build time — set it as a Docker build arg, not at runtime.
const basePath = (process.env.NEXT_PUBLIC_BASE_PATH || "").replace(/\/$/, "");

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Standalone output keeps the production Docker image small (only the
  // traced server + its deps ship, not the whole node_modules tree).
  output: "standalone",
  // next/link, router.push and /_next assets pick this up automatically; only
  // raw window.location / <a href> usages need BASE_PATH from lib/api.ts.
  basePath,
};

export default nextConfig;
