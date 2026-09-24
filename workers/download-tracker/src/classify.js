/**
 * Edge human/bot classification for isolated download-tracker Workers.
 *
 * Copy this file into other product trackers. Do not invent bot scores.
 * Do not sample. Public identity: Aziel Eliab only.
 *
 * Order on each counted GET:
 *   1. Health-check / uptime UA → bot (counted; documented)
 *   2. Cloudflare request.cf.botManagement when available:
 *        verifiedBot === true OR score <= BOT_SCORE_THRESHOLD → bot
 *      Score 0 means "not computed" — ignore it; never invent a score.
 *   3. UA denylist → bot
 *   4. Empty / missing UA → bot (not a proven human)
 *   5. Else → human
 *
 * If botManagement is missing or unusable: steps 1, 3, 4, 5 only.
 * classification.method then omits the score clause.
 */

export const BOT_SCORE_THRESHOLD = 30;

export const METHOD_WITH_BOT_MANAGEMENT =
  "cf.botManagement.score + ua_denylist + healthcheck_ua";

export const METHOD_UA_ONLY = "ua_denylist + healthcheck_ua";

/** Health-check / uptime probes. Counted in the bot bucket (not skipped). */
export const HEALTHCHECK_UA_NEEDLES = Object.freeze([
  "cf-healthchecks",
  "cloudflare-healthchecks",
  "cloudflare healthchecks",
  "uptimerobot",
  "pingdom",
  "betteruptime",
  "better uptime",
  "betterstack",
  "healthcheck",
  "health-check",
  "health_check",
  "kube-probe",
  "googlehc",
  "amazon-route53-health-check",
  "aws-healthcheck",
  "elb-healthchecker",
  "statuscake",
  "site24x7",
  "freshping",
  "uptime-kuma",
  "uptime kuma",
  "newrelicsynthetics",
  "datadog/synthetics",
  "smokeping",
  "nodeping",
  "paessler",
  "prtg",
]);

/**
 * Known crawlers, SEO bots, AI scrapers, and default CLI/library agents.
 * Matched case-insensitively as substrings of User-Agent.
 */
export const DENYLIST_UA_NEEDLES = Object.freeze([
  "googlebot",
  "google-inspectiontool",
  "adsbot-google",
  "apis-google",
  "mediapartners-google",
  "storebot-google",
  "bingbot",
  "bingpreview",
  "msnbot",
  "duckduckbot",
  "baiduspider",
  "yandexbot",
  "yandex.com/bots",
  "yandex",
  "gptbot",
  "chatgpt-user",
  "oai-searchbot",
  "claudebot",
  "anthropic-ai",
  "claude-web",
  "bytespider",
  "petalbot",
  "semrushbot",
  "semrush",
  "ahrefsbot",
  "ahrefssiteaudit",
  "ahrefs",
  "dotbot",
  "mj12bot",
  "ccbot",
  "applebot",
  "facebookexternalhit",
  "meta-externalagent",
  "facebot",
  "twitterbot",
  "linkedinbot",
  "slackbot",
  "discordbot",
  "telegrambot",
  "whatsapp",
  "redditbot",
  "pinterestbot",
  "embedly",
  "quora link preview",
  "outbrain",
  "ia_archiver",
  "archive.org_bot",
  "sogou",
  "exabot",
  "seznambot",
  "qwantify",
  "screaming frog",
  "serpstatbot",
  "dataforseo",
  "seokicks",
  "megaindex",
  "zoominfobot",
  "scrapy",
  "phantomjs",
  "headlesschrome",
  "lighthouse",
  "pagespeed",
  "gtmetrix",
  "curl/",
  "wget/",
  "python-requests",
  "python-urllib",
  "aiohttp/",
  "httpx/",
  "go-http-client",
  "java/",
  "libwww-perl",
  "okhttp",
  "node-fetch",
  "undici",
  "axios/",
  "postmanruntime",
  "insomnia/",
]);

function asLower(value) {
  return String(value == null ? "" : value).toLowerCase();
}

function matchesNeedle(haystack, needles) {
  const ua = asLower(haystack);
  if (!ua) return false;
  for (const needle of needles) {
    if (ua.includes(needle)) return true;
  }
  return false;
}

export function readUserAgent(request) {
  if (!request || !request.headers || typeof request.headers.get !== "function") {
    return "";
  }
  return String(request.headers.get("User-Agent") || request.headers.get("user-agent") || "");
}

/**
 * Read Cloudflare Bot Management without inventing scores.
 * available=false when the object is missing or has no usable score/verifiedBot.
 * score is null when missing, non-finite, or 0 (not computed).
 */
export function readBotManagement(request) {
  const cf = request && request.cf;
  if (!cf || typeof cf !== "object") {
    return { available: false, score: null, verifiedBot: null };
  }
  const bm = cf.botManagement;
  if (!bm || typeof bm !== "object") {
    return { available: false, score: null, verifiedBot: null };
  }
  const verifiedPresent = typeof bm.verifiedBot === "boolean";
  const verifiedBot = verifiedPresent ? bm.verifiedBot : null;
  const raw = bm.score;
  const score =
    typeof raw === "number" && Number.isFinite(raw) && raw > 0 ? Math.floor(raw) : null;
  const available = score != null || verifiedPresent;
  return { available, score, verifiedBot };
}

export function isHealthCheckUa(ua) {
  return matchesNeedle(ua, HEALTHCHECK_UA_NEEDLES);
}

export function isDenylistUa(ua) {
  return matchesNeedle(ua, DENYLIST_UA_NEEDLES);
}

export function classificationMethod(botManagementAvailable) {
  return botManagementAvailable ? METHOD_WITH_BOT_MANAGEMENT : METHOD_UA_ONLY;
}

/**
 * Classify one incoming request.
 * @returns {{
 *   bucket: "human"|"bot",
 *   reason: string,
 *   botManagementAvailable: boolean,
 *   score: number|null,
 *   verifiedBot: boolean|null,
 *   method: string
 * }}
 */
export function classifyRequest(request) {
  if (!request) {
    return {
      bucket: "bot",
      reason: "missing_request",
      botManagementAvailable: false,
      score: null,
      verifiedBot: null,
      method: METHOD_UA_ONLY,
    };
  }

  const ua = readUserAgent(request);
  const bm = readBotManagement(request);
  const method = classificationMethod(bm.available);
  const base = {
    botManagementAvailable: bm.available,
    score: bm.score,
    verifiedBot: bm.verifiedBot,
    method,
  };

  if (isHealthCheckUa(ua)) {
    return { bucket: "bot", reason: "healthcheck_ua", ...base };
  }

  if (bm.available) {
    if (bm.verifiedBot === true) {
      return { bucket: "bot", reason: "verified_bot", ...base };
    }
    if (bm.score != null && bm.score <= BOT_SCORE_THRESHOLD) {
      return { bucket: "bot", reason: "bot_score", ...base };
    }
  }

  if (isDenylistUa(ua)) {
    return { bucket: "bot", reason: "ua_denylist", ...base };
  }

  if (!ua.trim()) {
    return { bucket: "bot", reason: "empty_ua", ...base };
  }

  return { bucket: "human", reason: "default", ...base };
}
