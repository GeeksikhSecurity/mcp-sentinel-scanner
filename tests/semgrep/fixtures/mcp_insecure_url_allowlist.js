function isAllowedFetchTarget(context, targetUrl) {
  // ruleid: mcp-insecure-url-allowlist
  return targetUrl.startsWith("https://allowed.com");
}

function isAllowedHost(context, targetUrl) {
  // ruleid: mcp-insecure-url-allowlist
  return targetUrl.includes("allowed.com");
}

const ALLOWED = new Set(["allowed.com"]);
function isAllowedHostname(context, targetUrl) {
  const hostname = new URL(targetUrl).hostname;
  // ok: mcp-insecure-url-allowlist
  return ALLOWED.has(hostname);
}
