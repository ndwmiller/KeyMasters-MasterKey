function entropyBits(pw) {
  if (!pw) return 0;
  let classes = 0;
  if (/[a-z]/.test(pw)) classes += 26;
  if (/[A-Z]/.test(pw)) classes += 26;
  if (/[0-9]/.test(pw)) classes += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) classes += 32;
  return classes === 0 ? 0 : Math.round(pw.length * Math.log2(classes));
}

function levelFor(bits) {
  if (bits < 50) return { text: "Weak", pct: Math.min(35, bits * 0.7), color: "bg-destructive" };
  if (bits < 80) return { text: "Moderate", pct: 55, color: "bg-amber-500" };
  if (bits < 120) return { text: "Strong", pct: 80, color: "bg-primary" };
  return { text: "Excellent", pct: 100, color: "bg-primary" };
}

function attachMeter(inputEl, barEl, labelEl) {
  if (!inputEl || !barEl || !labelEl) return;
  inputEl.addEventListener("input", () => {
    const { text, pct, color } = levelFor(entropyBits(inputEl.value));
    barEl.style.width = pct + "%";
    // Replace bg-* classes without clobbering layout classes.
    barEl.className = barEl.className.replace(/bg-\S+/g, "").trim() + " " + color;
    labelEl.textContent = text.toUpperCase();
  });
}

function attachMatch(passEl, confirmEl, hintEl) {
  if (!passEl || !confirmEl || !hintEl) return;
  const check = () => {
    if (!confirmEl.value) {
      hintEl.textContent = "";
      confirmEl.setCustomValidity("");
      return;
    }
    const ok = passEl.value === confirmEl.value;
    hintEl.textContent = ok ? "" : "Passwords do not match";
    confirmEl.setCustomValidity(ok ? "" : "Passwords do not match");
  };
  passEl.addEventListener("input", check);
  confirmEl.addEventListener("input", check);
}

const pass =
  document.querySelector('input[name="master_password"]') ||
  document.querySelector('input[name="password"]');
const confirm = document.querySelector('input[name="confirm_password"]');
attachMeter(pass, document.getElementById("strength-bar"), document.getElementById("strength-label"));
attachMatch(pass, confirm, document.getElementById("match-hint"));
