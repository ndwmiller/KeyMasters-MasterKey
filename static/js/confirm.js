// CSP-safe replacement for onsubmit="return confirm(...)".
// Any <form data-confirm="..."> prompts the user before submitting;
// cancelling stops the submission.
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (e) => {
      const message = form.getAttribute("data-confirm");
      if (!window.confirm(message)) {
        e.preventDefault();
      }
    });
  });
});
