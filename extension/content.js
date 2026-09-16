/**
 * Prompt Injection Guard -- content script.
 * Injects a "Check for injection" button + verdict banner into AI chat sites:
 * ChatGPT, Claude, Gemini, Qwen, DeepSeek, Copilot, Mistral, Grok, AI Studio.
 */
(async function () {
  const DEFAULT_API = "https://prompt-injection-detector-nine.vercel.app";
  let API_BASE = DEFAULT_API;

  try {
    const cfg = await chrome.storage.sync.get({ apiUrl: DEFAULT_API, autoCheck: false });
    API_BASE = (cfg.apiUrl || DEFAULT_API).replace(/\/+$/, "");
    var AUTO_CHECK = !!cfg.autoCheck;
  } catch (e) { /* storage unavailable */ }

  const BANNER_ID = "pig-verdict-banner";
  const BTN_ID = "pig-check-btn";
  let checking = false;

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
      banner._hideTimer = setTimeout(() => banner.remove(), 6000);
    }
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
      const res = await fetch(API_BASE + "/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });
      const data = await res.json();
      const pct = (data.injection_probability * 100).toFixed(1);
      const sigs = (data.signals ? Object.entries(data.signals)
        .filter(([k, v]) => v === true)
        .map(([k]) => k.replace(/_/g, " "))
        .slice(0, 4).join(", ")) || "";
      showBanner(data.verdict, pct, sigs);
    } catch (e) {
      showBanner("ERROR", "--", "Could not reach detector API at " + API_BASE);
    }
    checking = false;
    btn.textContent = "\u26d4 Check for injection";
  }

  // floating button
  const btn = document.createElement("button");
  btn.id = BTN_ID;
  btn.textContent = "\u26d4 Check for injection";
  btn.onclick = checkCurrentPrompt;
  document.body.appendChild(btn);

  // optional: auto-check right before the prompt is sent
  if (AUTO_CHECK) {
    document.addEventListener("keydown", (e) => {
      if (e.key !== "Enter" || e.shiftKey || checking) return;
      const box = findInputBox();
      if (box && (e.target === box || box.contains(e.target))) {
        const text = getText(box).trim();
        if (!text) return;
        e.stopImmediatePropagation();
        e.preventDefault();
        checkCurrentPrompt().then(() => {
          if (!document.getElementById(BANNER_ID) ||
              document.getElementById(BANNER_ID).className.includes("allow")) {
            // ALLOW: dispatch a fresh Enter keypress to actually send
            box.focus();
            const ev = new KeyboardEvent("keydown", {
              key: "Enter", code: "Enter", bubbles: true, cancelable: true,
            });
            box.dispatchEvent(ev);
          }
        });
      }
    }, true);
  }
})();
