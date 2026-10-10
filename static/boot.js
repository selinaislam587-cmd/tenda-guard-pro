/* =============================================================================
   Tenda Guard Pro - static/boot.js
   Applies the saved theme before first paint. Kept as a separate file because
   the Content-Security-Policy does not allow inline scripts.
   ============================================================================= */
(function () {
  "use strict";
  try {
    var saved = localStorage.getItem("tgp-theme");
    var dark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    document.documentElement.setAttribute("data-theme", saved || (dark ? "dark" : "light"));
  } catch (e) {
    document.documentElement.setAttribute("data-theme", "light");
  }
})();
