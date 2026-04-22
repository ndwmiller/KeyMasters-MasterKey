document.querySelectorAll("[data-reveal-target]").forEach((btn) => {
  btn.addEventListener("click", () => {
    const id = btn.getAttribute("data-reveal-target");
    const input = document.getElementById(id);
    if (!input) return;
    input.type = input.type === "password" ? "text" : "password";
    const icon = btn.querySelector(".material-symbols-outlined");
    if (icon) icon.textContent = input.type === "password" ? "visibility" : "visibility_off";
    btn.setAttribute(
      "aria-label",
      input.type === "password" ? "Show password" : "Hide password",
    );
  });
});
