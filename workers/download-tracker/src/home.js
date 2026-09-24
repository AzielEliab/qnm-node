/**
 * qnm-node landing page.
 * Author: Aziel Eliab only. Apache-2.0. Forks welcome.
 * No DOI is invented here. No public score is shown.
 */

import {
  AUTHOR,
  DEFAULT_ASSET,
  DESCRIPTION,
  GITHUB_REPO,
  HOST,
  LICENSE,
  LICENSE_URL,
  LOCAL_DOOR,
  VERSION,
} from "./product.js";

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, HEAD, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Accept, User-Agent",
  };
}

function escapeHtml(value) {
  return String(value == null ? "" : value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function citePayload() {
  return {
    author: AUTHOR,
    title: "qnm-node",
    version: VERSION,
    homepage: HOST + "/",
    github: GITHUB_REPO,
    download: HOST + "/download",
    asset: DEFAULT_ASSET,
    install: HOST + "/install.sh",
    openapi: HOST + "/openapi.json",
    skill: HOST + "/v1/skill",
    mcp: HOST + "/mcp",
    local_door: LOCAL_DOOR,
    license: LICENSE,
    license_url: LICENSE_URL,
    one_line: DESCRIPTION,
    how_to_cite:
      "Eliab, Aziel. (2026). QNM-BUILD-1.0 Quantum Node Mesh local node [Software]. Apache-2.0. https://github.com/AzielEliab/qnm-node",
    apa: `Eliab, A. (2026). qnm-node (Version ${VERSION}) [Computer software]. https://github.com/AzielEliab/qnm-node`,
    zenodo_status: "no_doi_published",
    note: "No DOI is published. Cite GitHub. Identity is Aziel Eliab only. Forks are welcome. The Worker serves the source archive packed from the repository; it does not execute the local node.",
    identity: "Aziel Eliab only",
    forks: "welcome and always allowed",
    github_release: "none published",
  };
}

export function jsonLd() {
  return {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    name: "qnm-node",
    applicationCategory: "DeveloperApplication",
    operatingSystem: "Linux, macOS, Windows",
    softwareVersion: VERSION,
    author: { "@type": "Person", name: AUTHOR, url: "https://github.com/AzielEliab" },
    codeRepository: GITHUB_REPO,
    downloadUrl: HOST + "/download",
    installUrl: HOST + "/install.sh",
    license: LICENSE_URL,
    url: HOST + "/",
    description: DESCRIPTION,
    isAccessibleForFree: true,
    offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
  };
}

function sitemapXml() {
  const paths = ["/", "/download", "/install.sh", "/v1/skill", "/openapi.json", "/mcp", "/cite.json", "/llms.txt", "/count"];
  const urls = paths.map((p) => `  <url><loc>${HOST}${p === "/" ? "/" : p}</loc></url>`).join("\n");
  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls}
  <url><loc>${GITHUB_REPO}</loc></url>
</urlset>
`;
}

function robotsTxt() {
  return `User-agent: *
Allow: /

Sitemap: ${HOST}/sitemap.xml
`;
}

function llmsTxt() {
  return `# qnm-node

Author: Aziel Eliab
Version: ${VERSION}
One-line: ${DESCRIPTION}
GitHub: ${GITHUB_REPO}
Homepage: ${HOST}/
Download: ${HOST}/download
Asset: ${DEFAULT_ASSET} (source archive packed from the repository; no GitHub release is published)
Install: ${HOST}/install.sh
OpenAPI: ${HOST}/openapi.json
Skill: ${HOST}/v1/skill
MCP: ${HOST}/mcp
Local door: ${LOCAL_DOOR} via \`python -m qnm serve\`
Cite: ${HOST}/cite.json
License: Apache-2.0
Forks: welcome and always allowed
DOI: none published

This Worker serves the archive and counts downloads by owner, repo, branch, and fork.
It does not execute the node. GET does not enable radios. FragGate remains the suite door on aziel-runtime.
The local API contract is the route table in the repository README.
`;
}

export function handleSeoRoutes(request, url) {
  if (request.method !== "GET" && request.method !== "HEAD") return null;
  const headers = { ...corsHeaders(), "Cache-Control": "private, no-store" };
  if (url.pathname === "/cite.json") {
    return new Response(JSON.stringify(citePayload(), null, 2), {
      status: 200,
      headers: { "Content-Type": "application/json; charset=utf-8", ...headers },
    });
  }
  if (url.pathname === "/sitemap.xml") {
    return new Response(sitemapXml(), {
      status: 200,
      headers: { "Content-Type": "application/xml; charset=utf-8", ...headers },
    });
  }
  if (url.pathname === "/robots.txt") {
    return new Response(robotsTxt(), {
      status: 200,
      headers: { "Content-Type": "text/plain; charset=utf-8", ...headers },
    });
  }
  if (url.pathname === "/llms.txt" || url.pathname === "/ai.txt") {
    return new Response(llmsTxt(), {
      status: 200,
      headers: { "Content-Type": "text/plain; charset=utf-8", ...headers },
    });
  }
  return null;
}

function countLabel(stats) {
  if (!stats || stats.counter === false) return "Counter not bound";
  const downloads = Number(stats.downloads);
  const views = Number(stats.views);
  const d = Number.isFinite(downloads) && downloads >= 0 ? downloads : 0;
  const v = Number.isFinite(views) && views >= 0 ? views : 0;
  return `${d.toLocaleString("en-US")} downloads · ${v.toLocaleString("en-US")} page views`;
}

export function renderHome(stats) {
  const counted = countLabel(stats);
  const ld = JSON.stringify(jsonLd()).replaceAll("<", "\\u003c");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>qnm-node — Aziel Eliab</title>
<meta name="description" content="${escapeHtml(DESCRIPTION)}">
<meta name="author" content="${AUTHOR}">
<meta name="color-scheme" content="light dark">
<meta name="theme-color" media="(prefers-color-scheme: light)" content="#f6f3ec">
<meta name="theme-color" media="(prefers-color-scheme: dark)" content="#12110e">
<link rel="canonical" href="${HOST}/">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<meta property="og:title" content="qnm-node">
<meta property="og:description" content="${escapeHtml(DESCRIPTION)}">
<meta property="og:url" content="${HOST}/">
<meta property="og:type" content="website">
<script type="application/ld+json">${ld}</script>
<style>
  :root {
    color-scheme: light;
    --bg: #f6f3ec;
    --ink: #1c1915;
    --muted: #4e4942;
    --line: #d5ccbe;
    --gold: #5c4300;
    --panel: #fffdf8;
    --btn: #1c1915;
    --btn-ink: #f6f3ec;
    --focus: #1c1915;
    --code: #efeae1;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      color-scheme: dark;
      --bg: #12110e;
      --ink: #f4efe6;
      --muted: #c8bfb0;
      --line: #3a342c;
      --gold: #e4c36a;
      --panel: #1c1a16;
      --btn: #f4efe6;
      --btn-ink: #12110e;
      --focus: #f4efe6;
      --code: #0e0d0b;
    }
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--ink);
    font: 16px/1.5 system-ui, "Segoe UI", sans-serif;
  }
  a { color: var(--gold); }
  a:hover { text-decoration-thickness: 2px; }
  .skip {
    position: absolute;
    left: 0.75rem;
    top: 0.75rem;
    transform: translateY(-150%);
    background: var(--btn);
    color: var(--btn-ink);
    padding: 0.6rem 0.9rem;
    border-radius: 8px;
    z-index: 2;
  }
  .skip:focus { transform: none; outline: 3px solid var(--focus); outline-offset: 3px; }
  .wrap { width: min(100%, 52rem); margin: 0 auto; padding: 1.25rem 1rem 2.5rem; }
  .stamp {
    margin: 0 0 0.35rem;
    color: var(--gold);
    font: 650 0.78rem/1.2 ui-monospace, Menlo, Consolas, monospace;
    letter-spacing: 0.04em;
  }
  .kicker {
    margin: 0;
    color: var(--muted);
    font: 600 0.75rem/1.2 ui-monospace, Menlo, Consolas, monospace;
    letter-spacing: 0.12em;
    text-transform: uppercase;
  }
  h1 {
    margin: 0.2rem 0 0.6rem;
    font-size: clamp(2.1rem, 8vw, 3.4rem);
    line-height: 1.05;
    letter-spacing: -0.03em;
    font-weight: 700;
  }
  .lede { margin: 0 0 1.25rem; max-width: 38rem; font-size: 1.125rem; color: var(--ink); }
  .hero-actions { margin: 0 0 0.25rem; }
  a.btn {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 100%;
    max-width: 22rem;
    min-height: 3.25rem;
    padding: 0.9rem 1.4rem;
    border-radius: 12px;
    background: var(--btn);
    color: var(--btn-ink);
    text-decoration: none;
    font-weight: 700;
    font-size: 1.15rem;
    border: 2px solid var(--btn);
  }
  a.btn:hover { filter: brightness(1.08); }
  a:focus-visible, .btn:focus-visible {
    outline: 3px solid var(--focus);
    outline-offset: 3px;
  }
  .asset { margin: 0.75rem 0 0; color: var(--muted); }
  .asset strong { color: var(--ink); font-weight: 650; }
  code, pre { font-family: ui-monospace, Menlo, Consolas, monospace; }
  h2 { font-size: 1.15rem; margin: 0 0 0.75rem; letter-spacing: -0.01em; }
  .features {
    display: grid;
    grid-template-columns: 1fr;
    gap: 0.75rem;
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .features li {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 14px;
    padding: 0.95rem 1rem;
  }
  .features h3 { margin: 0 0 0.3rem; font-size: 1rem; }
  .features p { margin: 0; color: var(--muted); }
  .section { margin-top: 1.75rem; }
  pre {
    margin: 0;
    padding: 0.9rem 1rem;
    background: var(--code);
    border: 1px solid var(--line);
    border-radius: 12px;
    overflow-x: auto;
    font-size: 0.92rem;
    line-height: 1.45;
    max-width: 100%;
  }
  .quiet { color: var(--muted); margin: 0.75rem 0 0; }
  footer {
    color: var(--muted);
    font-size: 0.95rem;
    border-top: 1px solid var(--line);
    margin-top: 0.5rem;
  }
  footer p { margin: 0.35rem 0; }
  footer a { color: var(--gold); }
  @media (min-width: 720px) {
    .wrap { padding: 2.5rem 1.5rem 3.5rem; }
    a.btn { width: auto; min-width: 16rem; }
    .features { grid-template-columns: 1fr 1fr; }
  }
  @media (forced-colors: active) {
    a.btn { border: 2px solid ButtonText; }
  }
  @media (prefers-reduced-motion: reduce) {
    * { scroll-behavior: auto; }
  }
</style>
</head>
<body>
  <a class="skip" href="#download">Skip to download</a>
  <header class="wrap">
    <p class="stamp">Aziel Eliab</p>
    <p class="kicker">Quantum Node Mesh</p>
    <h1>qnm-node</h1>
    <p class="lede">${escapeHtml(DESCRIPTION)}</p>
    <div class="hero-actions">
      <a class="btn" id="download" href="/download" aria-describedby="asset-note">Download</a>
      <p class="asset" id="asset-note">Version <strong>${escapeHtml(VERSION)}</strong> source archive · <strong>${escapeHtml(DEFAULT_ASSET)}</strong></p>
      <p class="asset">Python 3.10 or newer. One archive for Linux, macOS, and Windows.</p>
    </div>
  </header>
  <main class="wrap">
    <section class="section" aria-labelledby="features-title">
      <h2 id="features-title">What you get</h2>
      <ul class="features">
        <li>
          <h3>Local door</h3>
          <p><code>python -m qnm serve</code> binds ${escapeHtml(LOCAL_DOOR)}. APG checks every ingress.</p>
        </li>
        <li>
          <h3>Photon packets</h3>
          <p>qnsd carries QNS1 version 1.3. The walker moves to the next via class in the same program.</p>
        </li>
        <li>
          <h3>Pair-ids</h3>
          <p>A pair-id is the SHA-256 of both roots and nonces. It stays in both Memorials when a bearer drops.</p>
        </li>
        <li>
          <h3>Disk trail</h3>
          <p>Receipts, the chain, and the outbox are files. Cold copies use named hosts.</p>
        </li>
      </ul>
    </section>
    <section class="section" aria-labelledby="start-title">
      <h2 id="start-title">Start</h2>
      <pre>python -m venv .venv
source .venv/bin/activate
pip install -e .
python -m qnm doctor
python -m qnm serve
python -m qnsd doctor</pre>
      <p class="quiet">On Windows, activate with <code>.venv\\Scripts\\activate</code>. The counted install script is <a href="/install.sh">install.sh</a>. Source and docs: <a href="${GITHUB_REPO}">GitHub</a>.</p>
    </section>
  </main>
  <footer class="wrap">
    <p>Aziel Eliab · <a href="${LICENSE_URL}">Apache-2.0</a> · September 2026 · v${escapeHtml(VERSION)}</p>
    <p>${escapeHtml(counted)}. Branches and forks are included. <a href="/count">Count</a></p>
    <p>The archive is packed from the repository. No GitHub release is published. The node runs on your machine at ${escapeHtml(LOCAL_DOOR)}.</p>
  </footer>
</body>
</html>
`;
}
