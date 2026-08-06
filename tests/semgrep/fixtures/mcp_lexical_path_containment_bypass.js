const path = require('path');
const fs = require('fs');

function readFileSafe1(base, userPath) {
  let resolved = path.join(base, userPath);
  // ruleid: mcp-lexical-path-containment-bypass
  return resolved.startsWith(base);
}

function readFileSafe2(base, userPath) {
  let resolved = path.join(base, userPath);
  resolved = fs.realpathSync(resolved);
  // ok: mcp-lexical-path-containment-bypass
  return resolved.startsWith(base);
}

async function readFileSafe3(base, userPath) {
  let resolved = path.join(base, userPath);
  resolved = await fs.promises.realpath(resolved);
  // ok: mcp-lexical-path-containment-bypass
  return resolved.startsWith(base);
}
