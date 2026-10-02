/**
 * background.js
 * --------------
 * Manifest V3 service worker. Runs the phishing check automatically
 * whenever a tab finishes loading or becomes active, and keeps the
 * toolbar badge (color + short text) in sync with the verdict for
 * whichever tab the user is currently looking at.
 *
 * The popup (popup.js) reads results from here via chrome.runtime
 * messages rather than re-running the check itself, so opening the
 * popup is instant.
 */

// Base API URL (Default local; can be updated to your deployed Render/Vercel URL)
let API_BASE = "http://127.0.0.1:5000";

// Load custom API URL from extension storage if set
if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.sync) {
  chrome.storage.sync.get(["customApiUrl"], (data) => {
    if (data.customApiUrl) {
      API_BASE = data.customApiUrl.replace(/\/$/, "");
    }
  });
}


// In-memory cache: tabId -> { url, status: 'loading'|'done'|'error', result }
// Service workers can be killed/restarted by Chrome at any time, so this
// cache is best-effort — a fresh check is cheap (<1s) if it's lost.
const tabResults = new Map();

const BADGE_COLORS = {
  phishing: "#D65C4F",
  legitimate: "#4FA88F",
  loading: "#5B6478",
  error: "#8B93A7",
};

function isCheckableUrl(url) {
  return typeof url === "string" && (url.startsWith("http://") || url.startsWith("https://"));
}

async function setBadge(tabId, state, text) {
  try {
    await chrome.action.setBadgeText({ tabId, text });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS[state] || BADGE_COLORS.error });
  } catch (e) {
    // Tab may have closed mid-request — safe to ignore.
  }
}

async function clearBadge(tabId) {
  try {
    await chrome.action.setBadgeText({ tabId, text: "" });
  } catch (e) {
    /* ignore */
  }
}

async function checkUrl(url) {
  const res = await fetch(`${API_BASE}/api/check`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  const data = await res.json();
  if (!res.ok || data.error) {
    throw new Error(data.error || `Request failed with status ${res.status}`);
  }
  return data;
}

async function runCheck(tabId, url) {
  if (!isCheckableUrl(url)) {
    tabResults.delete(tabId);
    await clearBadge(tabId);
    return;
  }

  tabResults.set(tabId, { url, status: "loading", result: null });
  await setBadge(tabId, "loading", "…");

  try {
    const result = await checkUrl(url);
    tabResults.set(tabId, { url, status: "done", result });
    const badgeText = result.verdict === "phishing" ? "!" : "OK";
    await setBadge(tabId, result.verdict, badgeText);
  } catch (e) {
    tabResults.set(tabId, { url, status: "error", result: null, error: e.message });
    await setBadge(tabId, "error", "?");
  }
}

// Re-check when a tab finishes loading a new page.
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    runCheck(tabId, tab.url);
  }
});

// When switching to a tab we haven't checked yet (e.g. extension was
// just installed, or the service worker restarted and lost its cache),
// check it so the badge isn't blank.
chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  if (!tabResults.has(tabId)) {
    try {
      const tab = await chrome.tabs.get(tabId);
      if (tab.url) runCheck(tabId, tab.url);
    } catch (e) {
      /* tab may have closed */
    }
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabResults.delete(tabId);
});

// Messages from popup.js
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_STATUS") {
    sendResponse(tabResults.get(message.tabId) || null);
    return false;
  }

  if (message.type === "RECHECK") {
    runCheck(message.tabId, message.url).then(() => {
      sendResponse(tabResults.get(message.tabId) || null);
    });
    return true; // keep the message channel open for the async response
  }

  return false;
});
