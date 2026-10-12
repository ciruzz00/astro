// astro web UI helpers. Event delegation only: no inline handlers, so the
// Content-Security-Policy can forbid inline scripts.
(function () {
  "use strict";

  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-copy]");
    if (btn) {
      ev.preventDefault();
      var text = btn.getAttribute("data-copy");
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function () {
          var label = btn.textContent;
          btn.classList.add("copied");
          btn.textContent = "Copied";
          setTimeout(function () { btn.classList.remove("copied"); btn.textContent = label; }, 1200);
        });
      }
      return;
    }
    // Close open dropdown menus when clicking elsewhere.
    document.querySelectorAll(".dropdown details[open]").forEach(function (d) {
      if (!d.contains(ev.target)) { d.removeAttribute("open"); }
    });
  });

  // "/" focuses the quick search, as in most consoles.
  document.addEventListener("keydown", function (ev) {
    if (ev.key !== "/" || ev.ctrlKey || ev.metaKey || ev.altKey) { return; }
    var t = ev.target;
    if (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName)) { return; }
    var q = document.querySelector("[data-quick]");
    if (q) { ev.preventDefault(); q.focus(); }
  });

  // Log uploads: browsers do not send file dates, and syslog lines have no
  // year (astro infers it from the file date). Send the dates alongside.
  document.addEventListener("submit", function (ev) {
    var form = ev.target;
    if (!form.matches || !form.matches("form[data-upload-dates]")) { return; }
    var dates = {};
    form.querySelectorAll('input[type="file"]').forEach(function (input) {
      Array.prototype.forEach.call(input.files || [], function (f) {
        dates[f.webkitRelativePath || f.name] = f.lastModified;
      });
    });
    var field = form.querySelector('input[name="dates"]');
    if (field) { field.value = JSON.stringify(dates); }
  });

  // "Select all" checkboxes: data-check-all="<name of the item checkboxes>".
  document.addEventListener("change", function (ev) {
    var all = ev.target.closest("[data-check-all]");
    if (!all) { return; }
    var form = all.closest("form");
    var name = all.getAttribute("data-check-all");
    form.querySelectorAll('input[type="checkbox"][name="' + name + '"]').forEach(function (c) {
      c.checked = all.checked;
    });
  });
})();
