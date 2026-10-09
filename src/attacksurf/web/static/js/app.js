// Alpine components. The CSP build of Alpine only runs components registered here
// (no inline expressions are evaluated), so all client-side behavior lives in this file.
document.addEventListener("alpine:init", function () {
  "use strict";

  window.Alpine.data("themeToggle", function () {
    return {
      toggle: function () {
        var root = document.documentElement;
        var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
        root.setAttribute("data-theme", next);
        try {
          window.localStorage.setItem("theme", next);
        } catch (e) {
          // Not persisted; the choice still applies to this page.
        }
      },
    };
  });
});
