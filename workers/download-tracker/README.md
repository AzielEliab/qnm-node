# qnm-node download tracker

Worker name: `qnm-node-download-tracker`

Route after deploy: https://qnm-node-download-tracker.vibelock.workers.dev/

This repository does not deploy the Worker. A teammate deploys it after merge.

The landing is `GET /`. `GET /download` returns `qnm-node-1.6.0.tar.gz` (the source archive packed from this repository at the version in `pyproject.toml`) and counts that download by owner, repo, branch, and fork. `GET /count` returns `{project, views, downloads, total}` where `total` is downloads. `POST /event` records a fork download.

No GitHub release is published. The archive is not a GitHub release asset.

The Worker does not execute the local node. `python -m qnm serve` stays on `127.0.0.1:8891`. GET does not enable radios. FragGate stays on aziel-runtime.

## Deploy

1. From this directory, create a dedicated KV namespace. Do not reuse another product's id.

   ```bash
   npx wrangler kv namespace create QNM_NODE_DOWNLOADS
   ```

2. Replace the placeholder ids in `wrangler.toml` (`00000000000000000000000000000000`) with the new namespace id. The placeholder is not a live namespace.

3. Rebuild the archive if the tree changed:

   ```bash
   python3 scripts/pack-archive.py
   ```

4. Deploy:

   ```bash
   npx wrangler deploy
   ```

Account `ac575a9b822bea2bed97d0ab73aed238` is the same account as the other `*.vibelock.workers.dev` trackers. `workers_dev = true` publishes the workers.dev route above. Do not attach a custom domain from this tree.

Local preview (no deploy):

```bash
npx wrangler dev
```

Author: Aziel Eliab. Apache-2.0.
