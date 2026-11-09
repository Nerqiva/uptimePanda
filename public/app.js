// uptimePanda — dashboard behaviour. Served as /public/app.js (CSP:
// script-src 'self'; no inline scripts anywhere). Every block below is
// guarded by element existence so the file can be loaded on any page.
(function () {
  "use strict";

  // ------------------------------------------------------------------
  // Toast region (server-sent OOB fragments and locally created toasts)
  // ------------------------------------------------------------------
  var region = document.getElementById("toast-region");
  function arm(el) {
    window.setTimeout(function () { el.classList.remove("show"); }, 3600);
    window.setTimeout(function () { el.remove(); }, 4000);
  }
  if (region) {
    var mo = new MutationObserver(function (records) {
      for (var i = 0; i < records.length; i++) {
        var nodes = records[i].addedNodes;
        for (var j = 0; j < nodes.length; j++) {
          if (nodes[j].nodeType === 1) {
            window.requestAnimationFrame((function (n) {
              return function () { n.classList.add("show"); };
            })(nodes[j]));
            arm(nodes[j]);
          }
        }
      }
    });
    mo.observe(region, { childList: true });
  }
  window.appToast = function (message, kind) {
    if (!region) return;
    var el = document.createElement("div");
    el.className = "toast " + (kind || "ok");
    el.textContent = message;
    region.appendChild(el);
  };

  // ------------------------------------------------------------------
  // Busy state: flag submitting buttons while their request is in flight
  // ------------------------------------------------------------------
  function actionButtons(elt) {
    if (!elt || !elt.querySelectorAll) return [];
    var trigger = elt.getAttribute && elt.getAttribute("hx-trigger");
    if (trigger && trigger.indexOf("every") !== -1) return [];
    if (elt.matches && elt.matches("button.btn")) return [elt];
    return Array.prototype.slice.call(elt.querySelectorAll("button.btn"));
  }
  function mark(button, busy) {
    button.disabled = busy;
    button.classList.toggle("is-loading", busy);
  }
  document.body.addEventListener("htmx:before:request", function (event) {
    var elt = event.detail && event.detail.ctx && event.detail.ctx.sourceElement;
    actionButtons(elt).forEach(function (b) { mark(b, true); });
  });
  document.body.addEventListener("htmx:after:request", function (event) {
    var elt = event.detail && event.detail.ctx && event.detail.ctx.sourceElement;
    actionButtons(elt).forEach(function (b) { mark(b, false); });
  });

  // ------------------------------------------------------------------
  // CSRF header backstop (hidden csrf_token form fields are the primary path)
  // ------------------------------------------------------------------
  document.body.addEventListener("htmx:config:request", function (event) {
    var meta = document.querySelector('meta[name="csrf-token"]');
    var ctx = event.detail && event.detail.ctx;
    if (meta && meta.content && ctx && ctx.request && ctx.request.headers) {
      ctx.request.headers["X-CSRF-Token"] = meta.content;
    }
  });

  // ------------------------------------------------------------------
  // Shared confirm modal for destructive actions. [data-confirm] buttons
  // are intercepted in the capture phase so htmx never sees the click.
  // ------------------------------------------------------------------
  var pendingConfirm = null;
  function showModal(id) {
    var overlay = document.getElementById(id);
    if (!overlay) return;
    overlay.hidden = false;
    var first = overlay.querySelector("button");
    if (first) first.focus();
  }
  function hideModals() {
    var overlays = document.querySelectorAll(".modal-overlay");
    for (var i = 0; i < overlays.length; i++) overlays[i].hidden = true;
  }
  window.appShowModal = showModal;
  window.appHideModals = hideModals;

  document.body.addEventListener("click", function (event) {
    var open = event.target.closest("[data-modal-open]");
    if (open) {
      event.preventDefault();
      showModal(open.getAttribute("data-modal-open"));
      return;
    }
    if (event.target.closest("[data-modal-close]") || event.target.classList.contains("modal-overlay")) {
      hideModals();
      return;
    }
    var cfm = event.target.closest("[data-confirm]");
    if (cfm && !cfm.hasAttribute("data-confirmed")) {
      event.preventDefault();
      event.stopImmediatePropagation();
      pendingConfirm = cfm;
      var title = document.getElementById("confirm-modal-title");
      var ok = document.getElementById("confirm-ok");
      var parts = String(cfm.getAttribute("data-confirm") || "|").split("|");
      if (title) title.textContent = parts[0] || "Confirm";
      if (ok) ok.textContent = parts[1] || "Confirm";
      showModal("confirm-modal");
    }
  }, true);

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") hideModals();
  });

  document.body.addEventListener("click", function (event) {
    if (event.target.id !== "confirm-ok") return;
    if (!pendingConfirm) { hideModals(); return; }
    var btn = pendingConfirm;
    pendingConfirm = null;
    btn.setAttribute("data-confirmed", "1");
    hideModals();
    btn.click();
    btn.removeAttribute("data-confirmed");
  });

  // ------------------------------------------------------------------
  // Rail toggle (left navigation; hamburger overlay on <= 719px)
  // ------------------------------------------------------------------
  var railBtn = document.getElementById("rail-toggle");
  var railOverlay = document.getElementById("rail-overlay");
  if (railBtn && railOverlay) {
    var railBody = document.body;
    function setRail(open) {
      railBody.classList.toggle("rail-open", open);
      railBtn.setAttribute("aria-expanded", String(open));
    }
    var isMobile = window.matchMedia("(max-width: 719px)").matches;
    var stored = null;
    try { stored = window.localStorage.getItem("rail-open"); } catch (_e) { stored = null; }
    setRail(isMobile ? false : stored !== "0");

    railBtn.addEventListener("click", function () {
      setRail(!railBody.classList.contains("rail-open"));
      try {
        window.localStorage.setItem("rail-open", railBody.classList.contains("rail-open") ? "1" : "0");
      } catch (_e) { /* storage unavailable; rail state just won't persist */ }
    });
    railOverlay.addEventListener("click", function () {
      setRail(false);
    });
  }

  // ------------------------------------------------------------------
  // Websites page: close modals on submit; fill the edit form from
  // [data-id][data-name] buttons.
  // ------------------------------------------------------------------
  var websiteEditForm = document.getElementById("website-edit-form");
  if (websiteEditForm) {
    var siteForms = document.querySelectorAll("#website-add-form, #website-edit-form");
    siteForms.forEach(function (f) {
      f.addEventListener("submit", function () { window.appHideModals(); });
    });
    document.body.addEventListener("click", function (event) {
      var btn = event.target.closest("[data-id][data-name]");
      if (!btn) return;
      var id = btn.getAttribute("data-id");
      document.getElementById("website-edit-name").value = btn.getAttribute("data-name") || "";
      document.getElementById("website-edit-url").value = btn.getAttribute("data-url") || "";
      document.getElementById("website-edit-profile").value = btn.getAttribute("data-profile-id") || "";
      document.getElementById("website-edit-mode").value = btn.getAttribute("data-mode") || "basic";
      document.getElementById("website-edit-min-interval").value = btn.getAttribute("data-min-interval") || "480";
      document.getElementById("website-edit-max-interval").value = btn.getAttribute("data-max-interval") || "780";
      document.getElementById("website-edit-min-session").value = btn.getAttribute("data-min-session") || "15";
      document.getElementById("website-edit-max-session").value = btn.getAttribute("data-max-session") || "60";
      document.getElementById("website-edit-enabled").checked = btn.getAttribute("data-enabled") === "true";
      var target = "/websites/" + id;
      websiteEditForm.setAttribute("hx-patch", target);
      websiteEditForm.setAttribute("action", target);
    });
  }

  // ------------------------------------------------------------------
  // Profiles page: close modals on submit; fill the edit form from
  // [data-profile-id] buttons.
  // ------------------------------------------------------------------
  var profileEditForm = document.getElementById("profile-edit-form");
  if (profileEditForm) {
    var profileForms = document.querySelectorAll("#profile-add-form, #profile-edit-form");
    profileForms.forEach(function (f) {
      f.addEventListener("submit", function () { window.appHideModals(); });
    });
    document.body.addEventListener("click", function (event) {
      var btn = event.target.closest("[data-profile-id]");
      if (!btn) return;
      var id = btn.getAttribute("data-profile-id");
      document.getElementById("profile-edit-name").value = btn.getAttribute("data-name") || "";
      document.getElementById("profile-edit-description").value = btn.getAttribute("data-description") || "";
      document.getElementById("profile-edit-preset").value = btn.getAttribute("data-ua-preset") || "";
      document.getElementById("profile-edit-ua").value = btn.getAttribute("data-ua") || "";
      document.getElementById("profile-edit-enabled").checked = btn.getAttribute("data-enabled") === "true";
      var target = "/profiles/" + id;
      profileEditForm.setAttribute("hx-patch", target);
      profileEditForm.setAttribute("action", target);
    });
  }

  // ------------------------------------------------------------------
  // Interactions editor: snippet palette + format button
  // ------------------------------------------------------------------
  var interactionTa = document.getElementById("interaction-json");
  var interactionPalette = document.getElementById("interaction-palette");
  if (interactionTa && interactionPalette) {
    var SNIPPETS = {
      navigate: { type: "navigate", url: "https://example.com/" },
      wait_duration: { type: "wait_duration", ms: 1500, jitter_pct: 20 },
      wait_selector: { type: "wait_selector", selector: "main", timeout_ms: 8000 },
      wait_js: { type: "wait_js", condition: "document.readyState === 'complete'", timeout_ms: 8000 },
      scroll: { type: "scroll", direction: "vertical", distance_px: 600, operations: 3, delay_ms: 400 },
      click: { type: "click", selector: "a.read-more", wait_after_ms: 1000 },
      end_session: { type: "end_session" }
    };
    function parseCurrent() {
      var raw = interactionTa.value.trim();
      if (!raw) return { actions: [], on_error: "abort" };
      var seq = JSON.parse(raw);
      if (!seq || typeof seq !== "object" || !Array.isArray(seq.actions)) {
        throw new Error('expected {"actions": [...]} at the top level');
      }
      return seq;
    }
    function write(seq) { interactionTa.value = JSON.stringify(seq, null, 2); }
    interactionPalette.addEventListener("click", function (event) {
      var btn = event.target.closest("button[data-snippet]");
      if (!btn) return;
      try {
        var seq = parseCurrent();
        seq.actions.push(JSON.parse(JSON.stringify(SNIPPETS[btn.getAttribute("data-snippet")])));
        write(seq);
      } catch (err) {
        window.appToast("Current JSON is invalid: " + err.message, "err");
      }
    });
    var formatBtn = document.getElementById("interaction-format");
    if (formatBtn) {
      formatBtn.addEventListener("click", function () {
        try { write(parseCurrent()); } catch (err) { window.appToast("Current JSON is invalid: " + err.message, "err"); }
      });
    }
  }

  // ------------------------------------------------------------------
  // System page: raw backup restore upload (fetch, octet-stream ≤ 64 MB)
  // ------------------------------------------------------------------
  var restoreSubmit = document.getElementById("restore-submit");
  var restoreFile = document.getElementById("restore-file");
  var restoreResult = document.getElementById("restore-result");
  if (restoreSubmit && restoreFile && restoreResult) {
    restoreSubmit.addEventListener("click", function () {
      var file = restoreFile.files && restoreFile.files[0];
      if (!file) { restoreResult.textContent = "Choose a backup file first."; restoreResult.className = "note err"; return; }
      var meta = document.querySelector('meta[name="csrf-token"]');
      var headers = { "content-type": "application/octet-stream" };
      if (meta && meta.content) headers["x-csrf-token"] = meta.content;
      restoreResult.textContent = "Uploading…";
      restoreResult.className = "note";
      fetch("/backup/restore", { method: "POST", headers: headers, body: file })
        .then(function (res) { return res.text().then(function (body) { return { status: res.status, body: body }; }); })
        .then(function (out) {
          if (out.status === 200) {
            restoreResult.className = "note";
            restoreResult.innerHTML = out.body;
          } else {
            restoreResult.className = "note err";
            restoreResult.textContent = "Restore failed (" + out.status + ")";
          }
        })
        .catch(function () {
          restoreResult.className = "note err";
          restoreResult.textContent = "Restore failed: network error";
        });
    });
  }
})();
