import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import worker, { parseDims } from "../src/index.js";
import { DEFAULT_ASSET, VERSION } from "../src/product.js";
import { invariantHolds } from "../src/stats-shape.js";

const realFetch = globalThis.fetch;
before(() => {
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ stargazers_count: 1, forks_count: 2 }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
});
after(() => {
  globalThis.fetch = realFetch;
});

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const ARCHIVE = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "../public", DEFAULT_ASSET));

function memoryKv() {
  const store = new Map();
  return {
    store,
    async get(key) {
      return store.has(key) ? store.get(key) : null;
    },
    async put(key, value) {
      store.set(key, String(value));
    },
    async list() {
      return {
        keys: [...store.keys()].map((name) => ({ name })),
        list_complete: true,
      };
    },
  };
}

function assets() {
  return {
    async fetch(request) {
      const path = decodeURIComponent(new URL(request.url).pathname.slice(1));
      if (path !== DEFAULT_ASSET) return new Response("missing", { status: 404 });
      return new Response(ARCHIVE, {
        status: 200,
        headers: { "Content-Length": String(ARCHIVE.length) },
      });
    },
  };
}

function env() {
  return { DOWNLOADS: memoryKv(), ASSETS: assets() };
}

function req(path, { method = "GET", headers = {}, body } = {}) {
  return new Request("https://qnm-node-download-tracker.vibelock.workers.dev" + path, {
    method,
    headers: { "User-Agent": "Mozilla/5.0", ...headers },
    body,
  });
}

test("version matches pyproject.toml and qnm.__version__", () => {
  const py = readFileSync(resolve(ROOT, "pyproject.toml"), "utf8");
  const init = readFileSync(resolve(ROOT, "qnm/__init__.py"), "utf8");
  assert.match(py, new RegExp(`^version = "${VERSION}"$`, "m"));
  assert.match(init, new RegExp(`__version__ = "${VERSION}"`));
});

test("landing is a counted page with one download link", async () => {
  const e = env();
  const res = await worker.fetch(req("/"), e);
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.match(html, /href="\/download"/);
  assert.match(html, new RegExp(VERSION));
  assert.match(html, /prefers-color-scheme:\s*dark/);
  assert.match(html, /:focus-visible/);
  assert.doesNotMatch(html, /THIS IS NOT/i);
  assert.doesNotMatch(html, /identity-lock/i);
  assert.doesNotMatch(html, /fielded_score|architecture_score|public score/i);
  assert.match(html, /1 downloads · 0 page views|0 downloads · 1 page views/);
  const count = await (await worker.fetch(req("/count"), e)).json();
  assert.equal(count.views, 1);
  assert.equal(count.downloads, 0);
  assert.equal(count.total, 0);
  assert.equal(invariantHolds(count), true);
});

test("GET /download serves the archive and counts branch and fork", async () => {
  const e = env();
  const res = await worker.fetch(req("/download"), e);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("Content-Type"), "application/gzip");
  assert.match(res.headers.get("Content-Disposition") || "", new RegExp(DEFAULT_ASSET));
  const buf = new Uint8Array(await res.arrayBuffer());
  assert.equal(buf.length, ARCHIVE.length);
  assert.equal(buf[0], ARCHIVE[0]);
  assert.equal(buf[1], ARCHIVE[1]);

  const fork = await worker.fetch(
    req("/download?owner=someone&repo=qnm-node&branch=feature"),
    e,
  );
  assert.equal(fork.status, 200);
  await fork.arrayBuffer();

  const dev = await worker.fetch(req("/download?branch=dev"), e);
  assert.equal(dev.status, 200);
  await dev.arrayBuffer();

  const stats = await (await worker.fetch(req("/stats"), e)).json();
  assert.equal(stats.downloads, 3);
  assert.equal(stats.total, 3);
  assert.equal(stats.by_fork["0"], 2);
  assert.equal(stats.by_fork["1"], 1);
  assert.equal(stats.by_branch.main, 1);
  assert.equal(stats.by_branch.feature, 1);
  assert.equal(stats.by_branch.dev, 1);
  assert.equal(stats.by_repo["AzielEliab/qnm-node"], 2);
  assert.equal(stats.by_repo["someone/qnm-node"], 1);
  assert.equal(stats.github.ok, true);
  assert.equal(stats.github.releases_published, false);
  assert.equal(stats.github.release_download_count, null);
  assert.equal(invariantHolds(stats), true);
});

test("HEAD and unknown assets do not count", async () => {
  const e = env();
  const head = await worker.fetch(req("/download", { method: "HEAD" }), e);
  assert.equal(head.status, 200);
  const missing = await worker.fetch(req("/download?asset=other.tar.gz"), e);
  assert.equal(missing.status, 404);
  const slip = await worker.fetch(req("/download?asset=../../pyproject.toml"), e);
  assert.equal(slip.status, 404);
  const count = await (await worker.fetch(req("/count"), e)).json();
  assert.equal(count.downloads, 0);
  assert.equal(count.views, 0);
});

test("POST /event counts a fork without serving a file", async () => {
  const e = env();
  const res = await worker.fetch(
    req("/event", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ owner: "forker", repo: "qnm-node", branch: "patch-1", fork: true }),
    }),
    e,
  );
  assert.equal(res.status, 200);
  const stats = await (await worker.fetch(req("/stats"), e)).json();
  assert.equal(stats.by_fork["1"], 1);
  assert.equal(stats.by_branch["patch-1"], 1);
  assert.equal(stats.downloads, 1);
});

test("skill, mcp, and cite routes do not increment", async () => {
  const e = env();
  const skill = await worker.fetch(req("/v1/skill"), e);
  assert.equal(skill.status, 200);
  assert.match(await skill.text(), /python -m qnm serve/);
  const mcp = await worker.fetch(req("/mcp"), e);
  const mcpBody = await mcp.json();
  assert.equal(mcpBody.executable, false);
  const listed = await worker.fetch(
    req("/mcp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    }),
    e,
  );
  const tools = await listed.json();
  assert.deepEqual(tools.result.tools, []);
  const call = await worker.fetch(
    req("/mcp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "mesh_enable" } }),
    }),
    e,
  );
  const refused = await call.json();
  assert.equal(refused.error.code, -32601);
  const mesh = await (await worker.fetch(req("/v1/mesh"), e)).json();
  assert.equal(mesh.get_enables, false);
  const enable = await worker.fetch(req("/v1/mesh/enable", { method: "POST" }), e);
  assert.equal(enable.status, 405);
  const cite = await worker.fetch(req("/cite.json"), e);
  assert.equal((await cite.json()).version, VERSION);
  const count = await (await worker.fetch(req("/count"), e)).json();
  assert.equal(count.downloads, 0);
  assert.equal(count.views, 0);
});

test("install.sh points at the counted archive", async () => {
  const res = await worker.fetch(req("/install.sh"), env());
  const text = await res.text();
  assert.match(text, new RegExp(DEFAULT_ASSET));
  assert.match(text, /\/download/);
  assert.match(text, /python -m qnm serve/);
});

test("a different owner is always a fork", () => {
  const dims = parseDims({ repo: "Other/qnm-node", branch: "main", fork: "0" });
  assert.equal(dims.fork, "1");
  assert.equal(dims.owner, "Other");
});

test("curl is counted as a bot download and the invariant holds", async () => {
  const e = env();
  const res = await worker.fetch(req("/download", { headers: { "User-Agent": "curl/8.0" } }), e);
  assert.equal(res.status, 200);
  await res.arrayBuffer();
  const body = await (await worker.fetch(req("/count"), e)).json();
  assert.equal(body.downloads, 1);
  assert.equal(body.downloads_human, 0);
  assert.equal(body.downloads_bot, 1);
  assert.equal(invariantHolds(body), true);
});
