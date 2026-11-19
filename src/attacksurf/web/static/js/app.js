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

  // components/confirm.html: a native modal <dialog> (focus trap, Escape and backdrop inertness
  // come from the browser).
  window.Alpine.data("confirmDialog", function () {
    return {
      open: function () {
        this.$refs.dialog.showModal();
      },
      close: function () {
        this.$refs.dialog.close();
      },
    };
  });

  // components/verification.html: copy the TXT record into the owner's DNS provider. The
  // Clipboard API needs a secure context; elsewhere the field stays selectable by hand.
  // The template binds to these properties (no inline expressions, like themeToggle).
  window.Alpine.data("copyField", function () {
    return {
      copied: false,
      get label() {
        return this.copied ? "Copied" : "Copy record";
      },
      get pressed() {
        return this.copied ? "true" : "false";
      },
      copy: function () {
        var self = this;
        var text = this.$refs.value.textContent;
        if (!navigator.clipboard) return;
        navigator.clipboard.writeText(text).then(function () {
          self.copied = true;
          window.setTimeout(function () {
            self.copied = false;
          }, 2000);
        });
      },
    };
  });

  // pages/_ai_settings_form.html: confirm before overwriting an existing saved API key.
  window.Alpine.data("aiSettingsForm", function () {
    return {
      confirmed: false,
      init: function () {
        var self = this;
        this.$el.addEventListener("htmx:confirm", function (event) {
          if (self.needsConfirm()) {
            event.preventDefault();
            self.openReplaceDialog();
          }
        });
      },
      needsConfirm: function () {
        if (this.confirmed) return false;
        if (this.$el.dataset.hasKey !== "true") return false;
        var input = this.$el.querySelector('input[name="api_key"]');
        return Boolean(input && input.value.trim().length > 0);
      },
      openReplaceDialog: function () {
        if (this.$refs.replaceDialog && !this.$refs.replaceDialog.open) {
          this.$refs.replaceDialog.showModal();
        }
      },
      onSubmit: function (event) {
        if (this.needsConfirm()) {
          event.preventDefault();
          this.openReplaceDialog();
        }
      },
      cancelReplace: function () {
        if (this.$refs.replaceDialog) {
          this.$refs.replaceDialog.close();
        }
      },
      confirmReplace: function () {
        var self = this;
        this.confirmed = true;
        if (this.$refs.replaceDialog) {
          this.$refs.replaceDialog.close();
        }
        this.$el.requestSubmit();
        window.setTimeout(function () {
          self.confirmed = false;
        }, 0);
      },
    };
  });
});

// pages/_finding_results.html: bulk selection count and "select all". This is deliberately
// plain DOM code, not an Alpine component: the strict CSP build does not reliably run event
// handlers on the re-rendered table, and selection is only a progressive enhancement (the server
// owns the cap, the required comment and all-or-nothing application).
document.addEventListener("change", function (event) {
  "use strict";
  var target = event.target;
  if (!(target instanceof HTMLInputElement) || target.type !== "checkbox") return;
  var form = target.closest(".bulk-form");
  if (!form) return;
  var items = form.querySelectorAll("input[data-bulk-item]");
  if (target.matches("[data-bulk-all]")) {
    for (var i = 0; i < items.length; i++) {
      items[i].checked = target.checked;
    }
  }
  var selected = form.querySelectorAll("input[data-bulk-item]:checked").length;
  var count = form.querySelector("[data-bulk-count]");
  if (count) {
    count.textContent =
      selected === 0
        ? "None selected"
        : selected + (selected === 1 ? " finding selected" : " findings selected");
  }
  var all = form.querySelector("[data-bulk-all]");
  if (all) {
    all.checked = items.length > 0 && selected === items.length;
  }
});
