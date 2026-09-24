/**
 * Additive human/bot stats shaping for isolated download-tracker Workers.
 *
 * Copy this file into other product trackers together with classify.js.
 * Public identity: Aziel Eliab only.
 *
 * Legacy policy (strategy b — display remainder, safer for honesty):
 *   Keep existing KV totals for views / downloads / total unchanged.
 *   New keys views_human, views_bot, downloads_human, downloads_bot start at 0.
 *   Every new counted increment updates BOTH the total AND one bucket.
 *   On read, display:
 *     views_bot     = views − views_human
 *     downloads_bot = downloads − downloads_human
 *   so the invariant holds without rewriting KV history.
 *   Pre-split remainder is shown as bot until proven human.
 *   Never inflate. Never sample. Never reset existing counters.
 */

import {
  BOT_SCORE_THRESHOLD,
  classificationMethod,
} from "./classify.js";

export const LEGACY_STRATEGY = "b";

export const CLASSIFICATION_NOTE =
  "views = views_human + views_bot; same for downloads. Verified bots and score<=threshold → bot. Health-check UAs → bot (counted, not skipped). Legacy: pre-split totals remain in views/downloads; human/bot keys start at 0 until new classified traffic (do NOT reset existing counters; do NOT invent scores). Display strategy (b): views_bot = views - views_human and downloads_bot = downloads - downloads_human so the invariant holds without rewriting KV history. Pre-split remainder is shown as bot until proven human. Never inflate. Never sample.";

export const CLASSIFICATION_LEGACY =
  "display remainder: views_bot = views - views_human; downloads_bot = downloads - downloads_human. Pre-split totals shown as bot until proven. KV history not rewritten.";

/** Isolated WHITESTONE_DOWNLOADS-style keys. PROJECT is the first segment. */
export function isolatedKeys(project) {
  const p = String(project == null ? "" : project).trim();
  return {
    views: `${p}|__views__`,
    views_human: `${p}|__views_human__`,
    views_bot: `${p}|__views_bot__`,
    total: `${p}|__total__`,
    downloads_human: `${p}|__downloads_human__`,
    downloads_bot: `${p}|__downloads_bot__`,
    github: `${p}|__github__`,
  };
}

export function reservedKeyNames(project) {
  return Object.values(isolatedKeys(project));
}

export function isReservedCounterKey(name, project) {
  return reservedKeyNames(project).includes(name);
}

export function asCount(value) {
  const n = typeof value === "number" ? value : parseInt(value, 10);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.floor(n);
}

/**
 * Strategy (b): human is the stored classified-human count (capped at total).
 * bot is the remainder so total === human + bot always.
 */
export function displayRemainder(total, humanStored) {
  const all = asCount(total);
  let human = asCount(humanStored);
  if (human > all) human = all;
  return { human, bot: all - human };
}

export function classificationBlock({ botManagementAvailable } = {}) {
  return {
    method: classificationMethod(!!botManagementAvailable),
    bot_score_threshold: BOT_SCORE_THRESHOLD,
    note: CLASSIFICATION_NOTE,
    legacy: CLASSIFICATION_LEGACY,
  };
}

/**
 * Additive human/bot fields. Existing views / downloads / total stay the caller's job.
 * Invariant: views === views_human + views_bot (same for downloads).
 */
export function shapeHumanBotFields({
  views,
  downloads,
  views_human,
  downloads_human,
  botManagementAvailable,
} = {}) {
  const v = displayRemainder(views, views_human);
  const d = displayRemainder(downloads, downloads_human);
  return {
    views_human: v.human,
    views_bot: v.bot,
    downloads_human: d.human,
    downloads_bot: d.bot,
    human: { views: v.human, downloads: d.human },
    bot: { views: v.bot, downloads: d.bot },
    classification: classificationBlock({ botManagementAvailable }),
  };
}

export function invariantHolds(body) {
  if (!body || typeof body !== "object") return false;
  const views = asCount(body.views);
  const downloads = asCount(body.downloads);
  return (
    views === asCount(body.views_human) + asCount(body.views_bot) &&
    downloads === asCount(body.downloads_human) + asCount(body.downloads_bot)
  );
}

export function shapeCountBody({
  project,
  views,
  downloads,
  total,
  views_human,
  downloads_human,
  botManagementAvailable,
} = {}) {
  const v = asCount(views);
  const d = asCount(downloads);
  const t = asCount(total != null ? total : downloads);
  return {
    project,
    views: v,
    downloads: d,
    total: t,
    ...shapeHumanBotFields({
      views: v,
      downloads: d,
      views_human,
      downloads_human,
      botManagementAvailable,
    }),
  };
}
