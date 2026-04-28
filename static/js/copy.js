// Copy a credential field's value to the clipboard. We previously also
// scheduled a clipboard wipe after 30s, but browsers require a fresh user
// gesture (and a focused document) for background writeText calls — neither
// of which holds once the user has clicked away to paste — so the clear
// silently failed in practice. Removed rather than leaving a false promise.

document.querySelectorAll("[data-copy-target]").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const id = btn.getAttribute("data-copy-target");
    const source = document.getElementById(id);
    if (!source) return;
    const value = source.value ?? source.textContent ?? "";
    try {
      await navigator.clipboard.writeText(value);
      const original = btn.getAttribute("aria-label") ?? "";
      btn.setAttribute("aria-label", "Copied!");
      window.setTimeout(() => btn.setAttribute("aria-label", original), 2000);
    } catch (e) {
      console.error("Clipboard copy failed:", e);
    }
  });
});
