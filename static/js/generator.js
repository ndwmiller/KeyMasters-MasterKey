const btn = document.getElementById("generator-btn");
const lengthInput = document.getElementById("generator-length");
const lengthLabel = document.getElementById("generator-length-label");
const passwordField = document.querySelector('input[name="password"]');

if (lengthInput && lengthLabel) {
  const syncLabel = () => { lengthLabel.textContent = lengthInput.value; };
  lengthInput.addEventListener("input", syncLabel);
  syncLabel();
}

if (btn && passwordField) {
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    try {
      const length = lengthInput ? parseInt(lengthInput.value, 10) : 20;
      const res = await fetch("/credentials/generate", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ length }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      passwordField.value = data.password;
      passwordField.dispatchEvent(new Event("input", { bubbles: true })); // triggers strength meter
    } catch (e) {
      console.error("Password generation failed:", e);
    } finally {
      btn.disabled = false;
    }
  });
}
