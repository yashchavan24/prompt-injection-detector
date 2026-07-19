document.getElementById("checkBtn").addEventListener("click", async () => {
  const text = document.getElementById("inputText").value.trim();
  const resultDiv = document.getElementById("result");
  if (!text) return;

  resultDiv.className = "";
  resultDiv.style.display = "none";

  try {
    const res = await fetch("http://127.0.0.1:8000/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: text })
    });
    const data = await res.json();
    const verdict = data.verdict.toLowerCase();
    resultDiv.className = verdict;
    resultDiv.textContent = data.verdict + " -- injection probability: " + (data.injection_probability * 100).toFixed(1) + "%";
    resultDiv.style.display = "block";
  } catch (e) {
    resultDiv.className = "block";
    resultDiv.textContent = "Could not reach detector API. Is the FastAPI server running on port 8000?";
    resultDiv.style.display = "block";
  }
});
