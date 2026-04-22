export function requireFilled(formEl, fieldNames, messageEl) {
  if (!formEl || !messageEl) return;
  formEl.addEventListener("submit", (e) => {
    const missing = fieldNames.filter((n) => {
      const el = formEl.elements.namedItem(n);
      return !el || !el.value || !el.value.trim();
    });
    if (missing.length) {
      e.preventDefault();
      messageEl.textContent = `Please fill in: ${missing.join(", ")}`;
    } else {
      messageEl.textContent = "";
    }
  });
}

export function requireMatch(primaryEl, confirmEl, messageEl) {
  if (!primaryEl || !confirmEl || !messageEl) return;
  const check = () => {
    if (!confirmEl.value) {
      messageEl.textContent = "";
      confirmEl.setCustomValidity("");
      return;
    }
    const ok = primaryEl.value === confirmEl.value;
    messageEl.textContent = ok ? "" : "Passwords do not match";
    confirmEl.setCustomValidity(ok ? "" : "Passwords do not match");
  };
  primaryEl.addEventListener("input", check);
  confirmEl.addEventListener("input", check);
}
