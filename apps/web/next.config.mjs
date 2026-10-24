/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Standalone output keeps the production Docker image small (only the
  // traced server + its deps ship, not the whole node_modules tree).
  output: "standalone",
};

export default nextConfig;
