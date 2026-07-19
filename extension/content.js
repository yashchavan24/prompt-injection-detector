(function() {
  function findInputBox() {
    return document.querySelector("textarea") ||
           document.querySelector("div[contenteditable=" + String.fromCharCode(34) + "true" + String.fromCharCode(34) + "]");
  }

  function createButton() {
    const btn = document.createElement("button");
    btn.id = "pig-check-btn";
    btn.textContent = "Check for injection";
    btn.onclick = async () => {
      const box = findInputBox();
      if (!box) {
        alert("Could not find the chat input box on this page.");
        return;
      }
      const text = box.value || box.innerText || "";
      if (!text.trim()) {
        alert("Type something in the chat box first.");
        return;
      }

      btn.textContent = "Checking...";
      try {
        const res = await fetch("http://127.0.0.1:8000/check", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text: text })
        });
        const data = await res.json();
        alert("Verdict: " + data.verdict + "\nInjection probability: " + (data.injection_probability * 100).toFixed(1) + "%");
      } catch (e) {
        alert("Could not reach the detector API. Make sure the FastAPI server is running on port 8000.");
      }
      btn.textContent = "Check for injection";
    };
    return btn;
  }

  const btn = createButton();
  document.body.appendChild(btn);
})();
