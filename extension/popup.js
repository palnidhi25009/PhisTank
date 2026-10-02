/**
 * popup.js
 * --------
 * Reads the cached check result for the current tab from background.js
 * and renders it. Never runs the check itself on load — that keeps the
 * popup instant, since background.js already checked the page when it
 * finished loading.
 */

const contentEl = document.getElementById("content");
const recheckBtn = document.getElementById("recheck-btn");

let currentTab = null;

function renderNotCheckable() {
  contentEl.innerHTML = `<div class="not-checkable">This type of page can't be checked (only http/https pages are supported).</div>`;
  recheckBtn.disabled = true;
}

function renderLoading() {
  contentEl.innerHTML = `<div class="loading">Checking this page…</div>`;
}

function renderError(message) {
  contentEl.innerHTML = `<div class="error-box">${message || "Couldn't reach the PhishCheck server. Is app.py running on port 5000?"}</div>`;
}

function renderResult(url, result) {
  const pctRaw = result.confidence !== null && result.confidence !== undefined
    ? Math.round(result.confidence * 100)
    : null;
  const pct = result.verdict === "phishing" ? pctRaw : (pctRaw !== null ? 100 - pctRaw : null);

  const flagsHtml = result.flags && result.flags.length
    ? `<ul>${result.flags.map((f) => `<li>${f}</li>`).join("")}</ul>`
    : `<p class="none">No specific red flags detected.</p>`;

  const allowlistNote = result.method === "allowlist"
    ? `<div class="confidence"><span style="color:var(--safe); font-size:12px;">✓ Verified trusted domain — not scored by the ML model</span></div>`
    : "";

  contentEl.innerHTML = `
    <div class="panel">
      <div class="verdict-row">
        <div class="verdict-label ${result.verdict}">${result.verdict === "phishing" ? "Likely phishing" : "Looks legitimate"}</div>
        <div class="checked-url">${url}</div>
      </div>
      ${pct !== null ? `
      <div class="confidence">
        <div class="confidence-row">
          <span>Model confidence</span>
          <span>${pct}%</span>
        </div>
        <div class="bar-track">
          <div class="bar-fill ${result.verdict}" style="width:${pct}%"></div>
        </div>
      </div>` : ""}
      ${allowlistNote}
      <div class="signals">
        <div class="signals-title">Signals considered</div>
        ${flagsHtml}
      </div>
    </div>
  `;
}

function render(status) {
  if (!status) {
    renderLoading();
    return;
  }
  if (status.status === "loading") {
    renderLoading();
  } else if (status.status === "error") {
    renderError(status.error);
  } else if (status.status === "done") {
    renderResult(status.url, status.result);
  }
}

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentTab = tab;

  if (!tab || !tab.url || !(tab.url.startsWith("http://") || tab.url.startsWith("https://"))) {
    renderNotCheckable();
    return;
  }

  const status = await chrome.runtime.sendMessage({ type: "GET_STATUS", tabId: tab.id });
  render(status);

  // If background hasn't checked this tab yet (e.g. service worker was
  // just restarted), trigger a check now instead of leaving it blank.
  if (!status) {
    const fresh = await chrome.runtime.sendMessage({ type: "RECHECK", tabId: tab.id, url: tab.url });
    render(fresh);
  }
}

recheckBtn.addEventListener("click", async () => {
  if (!currentTab) return;
  recheckBtn.disabled = true;
  renderLoading();
  const fresh = await chrome.runtime.sendMessage({ type: "RECHECK", tabId: currentTab.id, url: currentTab.url });
  render(fresh);
  recheckBtn.disabled = false;
});

init();
