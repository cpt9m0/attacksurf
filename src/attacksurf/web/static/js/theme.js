// Runs in <head> (blocking, tiny) so the saved theme applies before first paint.
// External file, not inline: the CSP forbids inline scripts.
(function () {
  "use strict";
  var saved = null;
  try {
    saved = window.localStorage.getItem("theme");
  } catch (e) {
    // Storage blocked (private mode, policy): fall back to the OS preference.
  }
  var prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  var theme = saved === "light" || saved === "dark" ? saved : prefersDark ? "dark" : "light";
  document.documentElement.setAttribute("data-theme", theme);
})();
