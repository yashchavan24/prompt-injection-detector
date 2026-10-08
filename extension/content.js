/**
 * Prompt Injection Guard -- content script.
 *
 * Behavior on supported AI chat sites (ChatGPT, Claude, Gemini, ...):
 *  1. Scans the chat box automatically while you type (debounced) and shows
 *     a live verdict banner (ALLOW / FLAG / BLOCK + injection score).
 *  2. Intercepts the actual send (Enter key, send button, form submit):
 *     - last verdict BLOCK  -> the prompt is NOT sent; banner stays up.
 *     - last verdict FLAG   -> prompt is sent, warning banner stays up.
 *     - ALLOW / not scanned -> prompt is sent untouched (fail-open), and a
 *       background scan still runs to keep the banner accurate.
 *
 * A floating "Check for injection" button remains for manual checks.
 */
(async function () {
  const DEFAULT_API = "https://prompt-injection-detector-nine.vercel.app";
  let API_BASE = DEFAULT_API;
  let AUTO_CHECK = true; // scan automatically by default; popup can disable

  try {
    const cfg = await chrome.storage.sync.get({ apiUrl: DEFAULT_API, autoCheck: true });
    API_BASE = (cfg.apiUrl || DEFAULT_API).replace(/\/+$/, "");
    AUTO_CHECK = cfg.autoCheck !== false;
  } catch (e) { /* storage unavailable */ }

  const BANNER_ID = "pig-verdict-banner";
  const BTN_ID = "pig-check-btn";
  let checking = false;
  let lastScan = { text: null, verdict: null, prob: null }; // cached verdict
  let debounceTimer = null;

  function findInputBox() {
    // ChatGPT / Qwen / DeepSeek / Mistral use contenteditable divs or textareas
    const candidates = [
      ...document.querySelectorAll(
        'textarea, div[contenteditable="true"], [role="textbox"]'
      ),
    ].filter(el => el.offsetParent !== null || el.isContentEditable);
    // pick the largest visible one (chat input is usually the biggest)
    return candidates.sort((a, b) => {
      const ra = a.getBoundingClientRect();
      const rb = b.getBoundingClientRect();
      return rb.width * rb.height - ra.width * ra.height;
    })[0] || null;
  }

  function getText(box) {
    if (!box) return "";
    return box.value !== undefined && box.value !== ""
      ? box.value
      : (box.innerText || box.textContent || "");
  }

  function getOrCreateBanner() {
    let banner = document.getElementById(BANNER_ID);
    if (!banner) {
      banner = document.createElement("div");
      banner.id = BANNER_ID;
      document.body.appendChild(banner);
    }
    return banner;
  }

  function showBanner(verdict, prob, detail) {
    const banner = getOrCreateBanner();
    const cls = (verdict || "ERROR").toLowerCase();
    banner.className = "pig-banner " + cls;
    banner.innerHTML =
      '<span class="pig-badge">' + verdict + "</span>" +
      '<span class="pig-score">injection score: ' + prob + "%</span>" +
      (detail ? '<span class="pig-detail">' + detail + "</span>" : "") +
      '<button class="pig-close" title="dismiss">&times;</button>';
    banner.querySelector(".pig-close").onclick = () => banner.remove();
    clearTimeout(banner._hideTimer);
    if (cls !== "block") {
      banner._hideTimer = setTimeout(() => banner.remove(), 8000);
    }
  }

  function parseSignals(data) {
    if (!data.signals) return "";
    return Object.entries(data.signals)
      .filter(([k, v]) => v === true)
      .map(([k]) => k.replace(/_/g, " "))
      .slice(0, 4)
      .join(", ");
  }

  /** Ask the detector API about `text`; caches the verdict for send gating. */
  async function scanText(text) {
    const res = await fetch(API_BASE + "/api/guard-check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    const data = await res.json();
    const pct = (data.injection_probability * 100).toFixed(1);
    lastScan = { text, verdict: data.verdict, prob: pct };
    return { data, pct };
  }

  async function checkCurrentPrompt() {
    if (checking) return;
    const box = findInputBox();
    if (!box) {
      showBanner("ERROR", "--", "Could not find the chat input box on this page.");
      return;
    }
    const text = getText(box).trim();
    if (!text) {
      showBanner("ERROR", "--", "Type something in the chat box first.");
      return;
    }
    checking = true;
    btn.textContent = "Checking...";
    try {
      const { data, pct } = await scanText(text);
      showBanner(data.verdict, pct, parseSignals(data));
    } catch (e) {
      showBanner("ERROR", "--", "Could not reach detector API at " + API_BASE);
    }
    checking = false;
    btn.textContent = "\u26d4 Check for injection";
  }

  // ---- floating button (manual check) ----
  const btn = document.createElement("button");
  btn.id = BTN_ID;
  btn.textContent = "\u26d4 Check for injection";
  btn.onclick = checkCurrentPrompt;
  document.body.appendChild(btn);

  if (!AUTO_CHECK) return;

  // ---- 1. live scan while typing (debounced) ----
  document.addEventListener("input", (e) => {
    const box = findInputBox();
    if (!box || !(e.target === box || box.contains(e.target))) return;
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(async () => {
      const text = getText(box).trim();
      if (!text || text === lastScan.text) return;
      try {
        const { data, pct } = await scanText(text);
        // don't clobber a BLOCK banner that still matches the current text
        const banner = document.getElementById(BANNER_ID);
        const boxNow = findInputBox();
        if (banner && banner.className.includes("block") &&
            boxNow && freshBlockVerdict(boxNow)) return;
        showBanner(data.verdict, pct, parseSignals(data));
      } catch (e) { /* offline: fail open, button still works manually */ }
    }, 600);
  }, true);

  // ---- 2. send interception ----
  // Fresh only if the box text is exactly what we last scanned.
  function freshBlockVerdict(box) {
    const text = getText(box).trim();
    if (!text || text !== lastScan.text) return false;
    return (lastScan.verdict || "").toUpperCase() === "BLOCK";
  }

  function stopSend(e, box) {
    e.stopImmediatePropagation();
    e.preventDefault();
    const pct = lastScan.prob || "--";
    showBanner("BLOCKED", pct,
      "PromptShield stopped this prompt before it reached the AI. " +
      "Edit or clear the prompt to continue.");
  }

  // Enter key inside the chat box
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" || e.shiftKey || e.isComposing) return;
    const box = findInputBox();
    if (!box || !(e.target === box || box.contains(e.target))) return;
    if (getText(box).trim() && freshBlockVerdict(box)) stopSend(e, box);
  }, true);

  // Send button click (labelled "send" or inside the input's form).
  // Both pointerdown and click are intercepted: stopping pointerdown alone
  // does not cancel the separate click event that actually triggers the send.
  function interceptSendClick(e) {
    const box = findInputBox();
    if (!box || !getText(box).trim()) return;
    const btnEl = e.target.closest('button, [role="button"]');
    if (!btnEl) return;
    const label = (btnEl.getAttribute("aria-label") || btnEl.title ||
                   btnEl.textContent || "").toLowerCase();
    const form = box.closest("form");
    const isSend = /send|submit/.test(label) || (form && form.contains(btnEl));
    if (isSend && freshBlockVerdict(box)) stopSend(e, box);
  }
  document.addEventListener("pointerdown", interceptSendClick, true);
  document.addEventListener("click", interceptSendClick, true);

  // Form submit (some sites wrap the input in a form)
  document.addEventListener("submit", (e) => {
    const box = findInputBox();
    if (!box || !e.target.contains(box)) return;
    if (getText(box).trim() && freshBlockVerdict(box)) stopSend(e, box);
  }, true);
})();
