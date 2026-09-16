const DEFAULT_API = "https://prompt-injection-detector-nine.vercel.app";

// ---- settings ----
const settingsDiv = document.getElementById("settings");
document.getElementById("toggleSettings").addEventListener("click", () => {
  settingsDiv.classList.toggle("open");
});

chrome.storage.sync.get({ apiUrl: DEFAULT_API, autoCheck: false }, (cfg) => {
  document.getElementById("apiUrl").value = cfg.apiUrl || DEFAULT_API;
  document.getElementById("autoCheck").checked = !!cfg.autoCheck;
});

document.getElementById("saveBtn").addEventListener("click", () => {
  const apiUrl = document.getElementById("apiUrl").value.trim() || DEFAULT_API;
  const autoCheck = document.getElementById("autoCheck").checked;
  chrome.storage.sync.set({ apiUrl, autoCheck }, () => {
    const msg = document.getElementById("savedMsg");
    msg.style.display = "block";
    setTimeout(() => (msg.style.display = "none"), 2500);
  });
});

// ---- prompt check ----
document.getElementById("checkBtn").addEventListener("click", async () => {
  const text = document.getElementById("inputText").value.trim();
  const resultDiv = document.getElementById("result");
  if (!text) return;

  const cfg = await chrome.storage.sync.get({ apiUrl: DEFAULT_API });
  const base = (cfg.apiUrl || DEFAULT_API).replace(/\/+$/, "");

  resultDiv.className = "";
  resultDiv.style.display = "none";
  resultDiv.textContent = "Checking...";

  try {
    const res = await fetch(base + "/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    const data = await res.json();
    const verdict = (data.verdict || "ERROR").toLowerCase();
    const pct = (data.injection_probability * 100).toFixed(1);
    const sigs = data.signals
      ? Object.entries(data.signals)
          .filter(([k, v]) => v === true)
          .map(([k]) => k.replace(/_/g, " "))
          .slice(0, 4)
          .join(", ")
      : "";
    resultDiv.className = verdict;
    resultDiv.textContent =
      data.verdict + " -- injection score: " + pct + "%" + (sigs ? "\n" + sigs : "");
    resultDiv.style.display = "block";
  } catch (e) {
    resultDiv.className = "block";
    resultDiv.textContent = "Could not reach detector API at " + base;
    resultDiv.style.display = "block";
  }
});
