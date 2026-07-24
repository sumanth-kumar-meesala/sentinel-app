import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // puppeteer bundles a native chromium; keep it out of the server bundle.
  serverExternalPackages: ["puppeteer"],
};

export default nextConfig;
