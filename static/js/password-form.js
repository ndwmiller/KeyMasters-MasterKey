// Shared wiring for password-entry forms (new.html, edit.html).
//
// Two behaviours, both CSP-safe (no inline handlers, no inline <script>):
//   1. Buttons with [data-reveal-target="<input-id>"] toggle the target
//      <input>'s type between "password" and "text" and swap the icon
//      between "visibility" and "visibility_off".
//   2. Buttons with [data-regen-trigger] delegate to the sidebar generator
//      by clicking #generator-btn. Keeps one source of truth for generation.
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("button[data-reveal-target]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-reveal-target");
      if (!targetId) return;
      const input = document.getElementById(targetId);
      if (!input) return;
      const icon = btn.querySelector(".material-symbols-outlined");
      if (input.type === "password") {
        input.type = "text";
        if (icon) icon.textContent = "visibility_off";
        btn.setAttribute("aria-label", "Hide password");
      } else {
        input.type = "password";
        if (icon) icon.textContent = "visibility";
        btn.setAttribute("aria-label", "Show password");
      }
    });
  });

  const genBtn = document.getElementById("generator-btn");
  if (genBtn) {
    document.querySelectorAll("button[data-regen-trigger]").forEach((btn) => {
      btn.addEventListener("click", () => genBtn.click());
    });
  }
});
