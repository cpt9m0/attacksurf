// Alpine components. The CSP build of Alpine only runs components registered here
// (no inline expressions are evaluated), so all client-side behavior lives in this file.
document.addEventListener("alpine:init", function () {
  "use strict";

  window.Alpine.data("themeToggle", function () {
    var root = document.documentElement;
    return {
      // "true"/"false" string for aria-pressed: screen readers announce the current theme.
      pressed: root.getAttribute("data-theme") === "dark" ? "true" : "false",
      toggle: function () {
        var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
        root.setAttribute("data-theme", next);
        this.pressed = next === "dark" ? "true" : "false";
        try {
          window.localStorage.setItem("theme", next);
        } catch (e) {
          // Not persisted; the choice still applies to this page.
        }
      },
    };
  });
});
