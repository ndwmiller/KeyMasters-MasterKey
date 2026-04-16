async function copyAndAutoClear(text, ms = 30000) {
  try {
    await navigator.clipboard.writeText(text);
    window.setTimeout(async () => {
      try {
        await navigator.clipboard.writeText("");
      } catch (_) {
        /* best-effort; browsers may block background writes */
      }
    }, ms);
    return true;
  } catch (e) {
    console.error("Clipboard copy failed:", e);
    return false;
  }
}

document.querySelectorAll("[data-copy-target]").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const id = btn.getAttribute("data-copy-target");
    const source = document.getElementById(id);
    if (!source) return;
    const value = source.value ?? source.textContent ?? "";
    const ok = await copyAndAutoClear(value);
    if (ok) {
      const original = btn.getAttribute("aria-label") ?? "";
      btn.setAttribute("aria-label", "Copied!");
      window.setTimeout(() => btn.setAttribute("aria-label", original), 2000);
    }
  });
});
