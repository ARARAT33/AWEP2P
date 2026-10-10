const fs = require("node:fs");
const assert = require("node:assert/strict");

const root = process.cwd();
const read = (p) => fs.readFileSync(root + "/" + p, "utf8");
const html = read("apps/awe-desktop/ui/index.html");
const app = read("apps/awe-desktop/ui/app.js");
const onecoin = read("apps/awe-desktop/ui/onecoin.js");
const backend = read("apps/awe-node/src/main.rs");

function collectIds(source) {
  const ids = new Set();
  for (const match of source.matchAll(/\bid=\\?["']([^"'\\\s]+)\\?["']/g)) ids.add(match[1]);
  for (const match of source.matchAll(/(?:^|[.;])id\s*=\s*["']([^"']+)["']/g)) ids.add(match[1]);
  return ids;
}
const ids = new Set([...collectIds(html), ...collectIds(app), ...collectIds(onecoin)]);
const staticRefs = (source) => [...source.matchAll(/getElementById\(\s*["']([^"']+)["']\s*\)/g)]
  .map((m) => m[1])
  .filter((id) => id && !id.endsWith("-"));
const missing = [...new Set([...staticRefs(app), ...staticRefs(onecoin)])]
  .filter((id) => !ids.has(id) && id !== "menuScrim");
assert.deepEqual(missing, [], "UI references missing DOM IDs: " + missing.join(", "));

const pagesMatch = app.match(/const pages=\{([\s\S]*?)\};/);
assert.ok(pagesMatch, "Desktop page registry is missing");
const pages = new Set([...pagesMatch[1].matchAll(/(?:^|,)\s*([A-Za-z][\w]*)\s*:\s*\[/g)].map((m) => m[1]));
const navViews = new Set([...html.matchAll(/data-view=["']([^"']+)["']/g)].map((m) => m[1]));
const specialViews = new Set(["onecoin"]);
const missingViews = [...navViews].filter((view) => !pages.has(view) && !specialViews.has(view));
assert.deepEqual(missingViews, [], "Navigation points to unimplemented UI pages: " + missingViews.join(", "));

const uiPaths = new Set();
for (const source of [app, onecoin]) {
  for (const match of source.matchAll(/(?:api|get|post)\(\s*["'](\/api\/[A-Za-z0-9_/-]+)/g)) uiPaths.add(match[1]);
}
const missingApi = [...uiPaths].filter((path) => !backend.includes(path));
assert.deepEqual(missingApi, [], "UI calls API routes absent from the node backend: " + missingApi.join(", "));
assert.match(onecoin, /hostname===["']tauri\.localhost["']/, "ONECOIN must route API calls to the local node in Tauri");
console.log("UI contract checks passed: DOM IDs, navigation routes, and backend API paths.");
