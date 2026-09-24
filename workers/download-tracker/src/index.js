/**
 * qnm-node download tracker.
 *
 * GET /            landing (counts a page view)
 * GET /download    serves qnm-node-<version>.tar.gz and counts the download
 * GET /count       {project, views, downloads, total} — total is downloads
 * GET /stats       totals plus per-repo, per-branch, and fork breakdown
 * POST /event      a fork reports a download {owner, repo, branch, fork}
 *
 * KV keys: project|owner|repo|branch|fork
 * /v1, /mcp, and cite routes do not increment.
 * This Worker does not execute the local node and does not enable radios.
 * Author: Aziel Eliab only.
 */

import { classifyRequest, readBotManagement } from "./classify.js";
import { handleSeoRoutes, renderHome } from "./home.js";
import {
  AUTHOR,
  DEFAULT_ASSET,
  DEFAULT_BRANCH,
  DEFAULT_OWNER,
  DEFAULT_REPO,
  DESCRIPTION,
  GITHUB_REPO,
  HOST,
  LICENSE,
  LOCAL_DOOR,
  PROJECT,
  VERSION,
} from "./product.js";
import {
  isolatedKeys,
  isReservedCounterKey,
  shapeCountBody,
  shapeHumanBotFields,
} from "./stats-shape.js";

const KEYS = isolatedKeys(PROJECT);

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, HEAD, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Accept, User-Agent, MCP-Protocol-Version, mcp-session-id",
  };
}

function json(body, status = 200, extra = {}) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "private, no-store",
      ...corsHeaders(),
      ...extra,
    },
  });
}

function splitOwnerRepo(value, fallbackOwner, fallbackRepo) {
  if (typeof value === "string" && value.includes("/")) {
    const [o, r] = value.split("/").filter(Boolean);
    if (o && r) return { owner: o, repo: r };
  }
  return { owner: fallbackOwner, repo: fallbackRepo };
}

export function parseDims(src) {
  const get = (k) => {
    if (src == null) return null;
    if (typeof src.get === "function") {
      const v = src.get(k);
      return v == null || v === "" ? null : v;
    }
    const v = src[k];
    return v == null || v === "" ? null : v;
  };

  let owner = get("owner") || DEFAULT_OWNER;
  let repo = get("repo") || DEFAULT_REPO;
  if (typeof repo === "string" && repo.includes("/")) {
    const split = splitOwnerRepo(repo, owner, DEFAULT_REPO);
    owner = split.owner;
    repo = split.repo;
  }

  const branch = String(get("branch") || DEFAULT_BRANCH);
  const tag = get("tag") || "latest";
  const asset = get("asset") || "";

  const forkRaw = get("fork");
  let fork = "0";
  if (forkRaw === 1 || forkRaw === true || forkRaw === "1" || forkRaw === "true") {
    fork = "1";
  } else if (typeof forkRaw === "string" && forkRaw.includes("/")) {
    const split = splitOwnerRepo(forkRaw, owner, repo);
    owner = split.owner;
    repo = split.repo;
    fork = "1";
  } else if (forkRaw != null && forkRaw !== 0 && forkRaw !== false && forkRaw !== "0" && forkRaw !== "false") {
    fork = "1";
  }

  if (`${owner}/${repo}`.toLowerCase() !== `${DEFAULT_OWNER}/${DEFAULT_REPO}`.toLowerCase()) {
    fork = "1";
  }

  return { project: PROJECT, owner: String(owner), repo: String(repo), branch, fork, tag: String(tag), asset: String(asset) };
}

export function kvKey(dims) {
  return `${dims.project}|${dims.owner}|${dims.repo}|${dims.branch}|${dims.fork}`;
}

function safeAssetName(name) {
  if (name == null || name === "") return DEFAULT_ASSET;
  const asset = String(name);
  if (asset !== DEFAULT_ASSET) return null;
  return asset;
}

async function bump(kv, key) {
  const raw = parseInt((await kv.get(key)) || "0", 10);
  const n = (Number.isFinite(raw) && raw >= 0 ? raw : 0) + 1;
  await kv.put(key, String(n));
  return n;
}

async function incrementSplit(kv, request, humanKey, botKey) {
  const cls = classifyRequest(request);
  const splitKey = cls.bucket === "human" ? humanKey : botKey;
  await bump(kv, splitKey);
  return cls;
}

async function incrementDownload(kv, dims, request) {
  const n = await bump(kv, kvKey(dims));
  if (request) await incrementSplit(kv, request, KEYS.downloads_human, KEYS.downloads_bot);
  return n;
}

async function incrementViews(kv, request) {
  const n = await bump(kv, KEYS.views);
  if (request) await incrementSplit(kv, request, KEYS.views_human, KEYS.views_bot);
  return n;
}

async function listAllKeys(kv) {
  const keys = [];
  let cursor;
  do {
    const page = await kv.list(cursor ? { cursor } : {});
    keys.push(...(page.keys || []));
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return keys;
}

async function readSplit(kv, request, views, downloads) {
  const viewsHuman = parseInt((await kv.get(KEYS.views_human)) || "0", 10) || 0;
  const downloadsHuman = parseInt((await kv.get(KEYS.downloads_human)) || "0", 10) || 0;
  const botManagementAvailable = request ? readBotManagement(request).available : false;
  return shapeHumanBotFields({
    views,
    downloads,
    views_human: viewsHuman,
    downloads_human: downloadsHuman,
    botManagementAvailable,
  });
}

async function collectStats(kv, request) {
  const keys = await listAllKeys(kv);
  let summed = 0;
  const by_repo = {};
  const by_branch = {};
  const by_fork = { "0": 0, "1": 0 };
  const breakdown = [];

  for (const k of keys) {
    const name = k.name;
    if (isReservedCounterKey(name, PROJECT)) continue;
    const n = parseInt((await kv.get(name)) || "0", 10);
    if (!Number.isFinite(n) || n <= 0) continue;
    const parts = name.split("|");
    if (parts.length < 5 || parts[0] !== PROJECT) continue;
    const [, owner, repo, branch, fork] = parts;
    summed += n;
    const repoId = `${owner}/${repo}`;
    by_repo[repoId] = (by_repo[repoId] || 0) + n;
    by_branch[branch] = (by_branch[branch] || 0) + n;
    const forkFlag = fork === "1" ? "1" : "0";
    by_fork[forkFlag] = (by_fork[forkFlag] || 0) + n;
    breakdown.push({ project: PROJECT, owner, repo, branch, fork: forkFlag, count: n });
  }

  const views = parseInt((await kv.get(KEYS.views)) || "0", 10) || 0;
  const split = await readSplit(kv, request, views, summed);
  return {
    project: PROJECT,
    version: VERSION,
    counter: true,
    total: summed,
    views,
    downloads: summed,
    by_repo,
    by_branch,
    by_fork,
    breakdown,
    ...split,
    note: "Forks are owner/repo pairs other than AzielEliab/qnm-node, or fork=1. Key layout: project|owner|repo|branch|fork. Views are separate from downloads. /v1 and /mcp do not increment. total is downloads.",
  };
}

async function githubStats(kv) {
  const cached = await kv.get(KEYS.github);
  if (cached) {
    try {
      const obj = JSON.parse(cached);
      if (obj && obj.fetched_at && Date.now() - obj.fetched_at < 5 * 60 * 1000) return obj;
    } catch {
      /* ignore broken cache */
    }
  }
  const headers = {
    "User-Agent": "Mozilla/5.0 qnm-node-download-tracker",
    Accept: "application/vnd.github+json",
  };
  let stars = null;
  let forks = null;
  let ok = false;
  try {
    const repoRes = await fetch("https://api.github.com/repos/AzielEliab/qnm-node", { headers });
    if (repoRes.ok) {
      const repo = await repoRes.json();
      stars = Number(repo.stargazers_count) || 0;
      forks = Number(repo.forks_count) || 0;
      ok = true;
    }
  } catch {
    ok = false;
  }
  const out = {
    ok,
    stars,
    forks,
    release_download_count: null,
    releases_published: false,
    fetched_at: Date.now(),
  };
  try {
    await kv.put(KEYS.github, JSON.stringify(out));
  } catch {
    /* cache is optional */
  }
  return out;
}

function installScript() {
  return `#!/usr/bin/env bash
# qnm-node one-click install. The download is counted by this Worker.
# Version ${VERSION}. Author: Aziel Eliab. Apache-2.0.
set -euo pipefail
HOST="${HOST}"
ASSET="${DEFAULT_ASSET}"
WORKDIR="\${QNM_HOME:-\$HOME/qnm-node}"
mkdir -p "\$WORKDIR"
cd "\$WORKDIR"
echo "Downloading \${ASSET} from \${HOST}/download"
curl -fsSL -A 'Mozilla/5.0' "\${HOST}/download?asset=\${ASSET}" -o "\${ASSET}"
tar -xzf "\${ASSET}"
DIR="\$(find . -maxdepth 1 -type d -name 'qnm-node-*' | head -n 1)"
if [ -n "\${DIR}" ]; then
  cd "\${DIR}"
fi
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -U pip
python -m pip install -e .
echo
echo "Installed qnm-node ${VERSION}."
echo "Run:  python -m qnm doctor"
echo "Then: python -m qnm serve"
echo "Local door: ${LOCAL_DOOR}"
echo "Author: Aziel Eliab."
`;
}

function skillMarkdown() {
  return `# qnm-node skill

Author: ${AUTHOR}
Version: ${VERSION}
License: ${LICENSE}

${DESCRIPTION}

## Install

\`\`\`bash
curl -fsSL ${HOST}/install.sh | bash
\`\`\`

Or download ${DEFAULT_ASSET} from ${HOST}/download and \`pip install -e .\`.

Python 3.10 or newer. One source archive for Linux, macOS, and Windows.
No GitHub release is published. The archive is packed from ${GITHUB_REPO} at version ${VERSION}.

## Local door

\`\`\`bash
python -m qnm doctor
python -m qnm serve
\`\`\`

The door binds ${LOCAL_DOOR}. GET does not enable radios. \`python -m qnsd serve\` needs \`--operator-extra-door\` and stays on loopback.

The route table in the repository README is the local API contract. This Worker does not execute those routes.

## This Worker

- GET / download landing
- GET /download serves ${DEFAULT_ASSET} and counts owner, repo, branch, and fork
- GET /count and GET /stats read counters
- POST /event lets a fork report a download
- GET /mcp and POST /mcp describe the local door. They do not execute tools.

Suite FragGate stays at https://aziel-runtime.vibelock.workers.dev . This Worker is not that door.
`;
}

function openApi() {
  return {
    openapi: "3.1.0",
    info: {
      title: "qnm-node download tracker",
      version: VERSION,
      description: `${DESCRIPTION} This document covers the Worker. The node API is ${LOCAL_DOOR} after python -m qnm serve, and is not executed here.`,
      license: { name: LICENSE, url: "https://www.apache.org/licenses/LICENSE-2.0" },
      contact: { name: AUTHOR, url: GITHUB_REPO },
    },
    servers: [{ url: HOST, description: "Download tracker" }],
    paths: {
      "/": { get: { summary: "Landing page", responses: { "200": { description: "HTML" } } } },
      "/download": {
        get: {
          summary: "Counted source archive",
          parameters: [
            { name: "branch", in: "query", schema: { type: "string" } },
            { name: "repo", in: "query", schema: { type: "string" } },
            { name: "owner", in: "query", schema: { type: "string" } },
            { name: "fork", in: "query", schema: { type: "string" } },
            { name: "asset", in: "query", schema: { type: "string", enum: [DEFAULT_ASSET] } },
          ],
          responses: {
            "200": { description: "gzip tar archive", content: { "application/gzip": {} } },
            "404": { description: "Unknown asset" },
          },
        },
      },
      "/count": { get: { summary: "View and download totals", responses: { "200": { description: "JSON" } } } },
      "/stats": { get: { summary: "Totals by repo, branch, and fork", responses: { "200": { description: "JSON" } } } },
      "/install.sh": { get: { summary: "Install script", responses: { "200": { description: "shell" } } } },
      "/v1/skill": { get: { summary: "Skill markdown", responses: { "200": { description: "markdown" } } } },
      "/mcp": {
        get: { summary: "MCP description. Does not execute.", responses: { "200": { description: "JSON" } } },
        post: { summary: "JSON-RPC. tools/list is empty. tools/call is refused.", responses: { "200": { description: "JSON-RPC" } } },
      },
    },
    "x-local-door": {
      bind: LOCAL_DOOR,
      start: "python -m qnm serve",
      note: "Implemented in the archive. Not executed by this Worker. The README route table is the contract. GET does not enable radios.",
    },
  };
}

function mcpGet() {
  return {
    protocol: "mcp",
    executable: false,
    name: PROJECT,
    version: VERSION,
    author: AUTHOR,
    instructions: `qnm-node ${VERSION} runs on ${LOCAL_DOOR} after python -m qnm serve. This Worker does not execute tools. Suite FragGate stays at https://aziel-runtime.vibelock.workers.dev/mcp . Skill: ${HOST}/v1/skill`,
    local_door: LOCAL_DOOR,
    skill: HOST + "/v1/skill",
    download: HOST + "/download",
  };
}

async function mcpPost(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "JSON body required" } }, 400);
  }
  const id = body && Object.prototype.hasOwnProperty.call(body, "id") ? body.id : null;
  const method = body && body.method;
  if (method === "initialize") {
    return json({
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: "2025-06-18",
        capabilities: { tools: {} },
        serverInfo: { name: PROJECT, version: VERSION },
        instructions: mcpGet().instructions,
      },
    });
  }
  if (method === "tools/list") {
    return json({
      jsonrpc: "2.0",
      id,
      result: {
        tools: [],
        instructions: mcpGet().instructions,
      },
    });
  }
  if (method === "tools/call") {
    return json({
      jsonrpc: "2.0",
      id,
      error: {
        code: -32601,
        message: `This Worker does not execute tools. Run python -m qnm serve on ${LOCAL_DOOR}. Suite FragGate stays on aziel-runtime.`,
      },
    });
  }
  return json({
    jsonrpc: "2.0",
    id,
    error: {
      code: -32601,
      message: "Method not executed here. The local door is python -m qnm serve on 127.0.0.1:8891.",
    },
  });
}

function plain(body, contentType) {
  return new Response(body, {
    status: 200,
    headers: {
      "Content-Type": contentType,
      "Cache-Control": "private, no-store",
      ...corsHeaders(),
    },
  });
}

async function handleDownload(request, env, url) {
  const dims = parseDims(url.searchParams);
  if (!dims.asset && url.pathname.startsWith("/download/")) {
    dims.asset = decodeURIComponent(url.pathname.slice("/download/".length));
  }
  if (url.pathname === `/${DEFAULT_ASSET}`) dims.asset = DEFAULT_ASSET;
  const asset = safeAssetName(dims.asset);
  if (!asset) {
    return json({ error: "unknown asset", asset: dims.asset || null, served: DEFAULT_ASSET }, 404);
  }
  if (!env.ASSETS) {
    return json({ error: "archive is not bound on this Worker", asset }, 500);
  }
  const probe = await env.ASSETS.fetch(new Request(new URL("/" + asset, request.url), { method: "GET" }));
  if (!probe.ok) {
    return json({ error: "archive missing", asset, status: probe.status }, 404);
  }
  if (request.method === "GET") {
    if (!env.DOWNLOADS) {
      return json({ error: "DOWNLOADS binding missing; archive was not counted", asset }, 503);
    }
    await incrementDownload(env.DOWNLOADS, { ...dims, asset }, request);
  }
  const headers = new Headers();
  headers.set("Content-Type", "application/gzip");
  headers.set("Content-Disposition", `attachment; filename="${asset}"`);
  headers.set("Cache-Control", "private, no-store");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Qnm-Version", VERSION);
  const len = probe.headers.get("Content-Length");
  if (len) headers.set("Content-Length", len);
  for (const [k, v] of Object.entries(corsHeaders())) headers.set(k, v);
  if (request.method === "HEAD") return new Response(null, { status: 200, headers });
  return new Response(probe.body, { status: 200, headers });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    const seo = handleSeoRoutes(request, url);
    if (seo) return seo;

    if ((url.pathname === "/install.sh" || url.pathname === "/install.sh/") && request.method === "GET") {
      return plain(installScript(), "text/x-shellscript; charset=utf-8");
    }

    if (url.pathname === "/openapi.json" && request.method === "GET") {
      return json(openApi());
    }

    if ((url.pathname === "/mcp" || url.pathname === "/mcp/") && request.method === "GET") {
      return json(mcpGet());
    }
    if ((url.pathname === "/mcp" || url.pathname === "/mcp/") && request.method === "POST") {
      return mcpPost(request);
    }

    if (url.pathname === "/v1/skill" && request.method === "GET") {
      return plain(skillMarkdown(), "text/markdown; charset=utf-8");
    }

    if (url.pathname === "/v1/mesh" || url.pathname.startsWith("/v1/mesh/")) {
      if (request.method === "GET" || request.method === "HEAD") {
        return json({
          product: PROJECT,
          version: VERSION,
          get_enables: false,
          local_door: LOCAL_DOOR,
          suite_mesh: "https://aziel-runtime.vibelock.workers.dev/v1/mesh",
          note: "GET does not enable radios. This Worker does not join a mesh and does not proxy qnsd. The local node stays on 127.0.0.1.",
        });
      }
      return json(
        {
          error: "refused",
          reason: "This Worker does not enable the mesh. GET does not enable radios. Start the local node with python -m qnm serve.",
        },
        405,
      );
    }

    if (url.pathname === "/" && request.method === "GET") {
      let stats = { counter: false, views: null, downloads: null };
      if (env.DOWNLOADS) {
        await incrementViews(env.DOWNLOADS, request);
        stats = await collectStats(env.DOWNLOADS, request);
      }
      return new Response(renderHome(stats), {
        status: 200,
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "private, no-store",
          ...corsHeaders(),
        },
      });
    }

    if (url.pathname === "/count" && request.method === "GET") {
      if (!env.DOWNLOADS) return json({ error: "DOWNLOADS binding missing" }, 503);
      const stats = await collectStats(env.DOWNLOADS, request);
      return json(
        shapeCountBody({
          project: PROJECT,
          views: stats.views || 0,
          downloads: stats.downloads || 0,
          total: stats.total || 0,
          views_human: stats.views_human,
          downloads_human: stats.downloads_human,
          botManagementAvailable: readBotManagement(request).available,
        }),
      );
    }

    if (url.pathname === "/stats" && request.method === "GET") {
      if (!env.DOWNLOADS) return json({ error: "DOWNLOADS binding missing" }, 503);
      const stats = await collectStats(env.DOWNLOADS, request);
      const github = await githubStats(env.DOWNLOADS);
      return json({ ...stats, github, description: DESCRIPTION, author: AUTHOR });
    }

    if (url.pathname === "/event" && request.method === "POST") {
      if (!env.DOWNLOADS) return json({ error: "DOWNLOADS binding missing" }, 503);
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ error: "JSON body required" }, 400);
      }
      const dims = parseDims(body || {});
      const count = await incrementDownload(env.DOWNLOADS, dims, request);
      return json({
        ok: true,
        key: kvKey(dims),
        count,
        owner: dims.owner,
        repo: dims.repo,
        branch: dims.branch,
        fork: dims.fork,
        asset: DEFAULT_ASSET,
      });
    }

    const downloadPath =
      url.pathname === "/download" ||
      url.pathname.startsWith("/download/") ||
      url.pathname === "/go" ||
      url.pathname === `/${DEFAULT_ASSET}`;
    if (downloadPath && (request.method === "GET" || request.method === "HEAD")) {
      return handleDownload(request, env, url);
    }

    return json({ error: "not found", product: PROJECT, version: VERSION }, 404);
  },
};
