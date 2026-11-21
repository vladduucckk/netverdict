import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // README and tests open the app on 127.0.0.1. Next treats that as a
  // different host from localhost and otherwise blocks the dev client.
  allowedDevOrigins: ["127.0.0.1"],
};

export default nextConfig;
