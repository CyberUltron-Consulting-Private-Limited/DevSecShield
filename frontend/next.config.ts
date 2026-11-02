import type { NextConfig } from "next";
import path from "path";

const frontendRoot = path.join(__dirname);

const nextConfig: NextConfig = {
  output: "standalone",
  outputFileTracingRoot: frontendRoot,
  // Read only by `next dev` (cross-origin access to dev-server assets); a production build ignores it. Staging and
  // production serve the `next build` standalone image (deploy/staging), never `next dev`.
  allowedDevOrigins: [
    "127.0.0.1",
    "localhost",
    "13.234.69.238",
    "devsec-staging.zeroshield.ai",
  ],
  turbopack: {
    root: frontendRoot,
  },
};

export default nextConfig;
