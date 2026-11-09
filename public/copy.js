/* Copy and incremental-refresh helpers for the logs and errors pages.
 * No dependencies, safe to run on every page. */
(function () {
  "use strict";

  /* Copy/select helpers rely on window.appToast (injected by the page shell). */
  function toast(message, kind) {
    if (typeof window.appToast === "function") window.appToast(message, kind);
  }

  function isSecureContext() {
    try {
      return window.isSecureContext === true;
    } catch (_) {
      return false;
    }
  }

  async function copyText(text) {
    if (isSecureContext() && navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    // Plain-HTTP fallback (self-hosted LAN deployments).
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    ta.style.top = "0";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    ta.setSelectionRange(0, ta.value.length);
    var ok = false;
    try {
      ok = document.execCommand("copy");
    } finally {
      ta.remove();
    }
    if (!ok) throw new Error("clipboard unavailable");
  }

  async function fetchText(url) {
    var response = await fetch(url, {
      credentials: "same-origin",
      cache: "no-store",
    });
    if (!response.ok) throw new Error("HTTP " + response.status);
    return response.text();
  }

  function tableAsText(selector) {
    var container = document.querySelector(selector);
    if (!container) return "";
    var cards = container.querySelectorAll(".error-card");
    if (cards.length === 0) return "";
    var lines = ["archive\tkind\tlast update"];
    cards.forEach(function (card) {
      var name = card.querySelector(".error-name");
      var pill = card.querySelector(".pill");
      var muted = card.querySelector(".error-card-foot .muted");
      lines.push(
        [
          (name ? name.textContent : "").trim(),
          (pill ? pill.textContent : "").trim(),
          (muted ? muted.getAttribute("title") || muted.textContent : "").trim(),
        ].join("\t"),
      );
    });
    return lines.join("\n");
  }

  async function handleCopyUrl(button) {
    var url = button.getAttribute("data-copy-url");
    if (!url) return;
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
    try {
      var text = await fetchText(url);
      await copyText(text);
      toast("Copied " + text.split("\n").length + " line(s)");
    } catch (err) {
      toast("Copy failed: " + (err && err.message ? err.message : String(err)), "err");
    } finally {
      button.disabled = false;
      button.removeAttribute("aria-busy");
    }
  }

  async function handleCopyTable(button) {
    var selector = button.getAttribute("data-copy-table");
    var text = tableAsText(selector);
    if (!text.trim()) {
      toast("No rows to copy", "err");
      return;
    }
    try {
      await copyText(text);
      toast("Copied " + (text.split("\n").length - 1) + " error(s)");
    } catch (err) {
      toast("Copy failed", "err");
    }
  }

  document.addEventListener("click", function (event) {
    var target = event.target;
    if (!(target instanceof Element)) return;

    var urlBtn = target.closest("[data-copy-url]");
    if (urlBtn) {
      event.preventDefault();
      void handleCopyUrl(urlBtn);
      return;
    }
    var tableBtn = target.closest("[data-copy-table]");
    if (tableBtn) {
      event.preventDefault();
      void handleCopyTable(tableBtn);
      return;
    }
  });

  /* ---- log filter chips ---- */
  document.addEventListener("click", function (event) {
    var target = event.target;
    if (!(target instanceof Element)) return;
    var chip = target.closest(".filter-chip");
    if (!chip) return;
    var viewer = document.getElementById("logViewer");
    if (!viewer) return;
    var chips = viewer.parentElement ? viewer.parentElement.querySelectorAll(".filter-chip") : [];
    chips.forEach(function (c) { c.classList.remove("active"); });
    chip.classList.add("active");
    var mode = chip.getAttribute("data-filter");
    if (mode === "warnerr") {
      viewer.classList.add("filter-warnerr");
    } else {
      viewer.classList.remove("filter-warnerr");
    }
  });

  /* ---- live log viewer ---- */

  var viewer = document.getElementById("logViewer");
  if (viewer && viewer.dataset.live === "1") {
    var runId = Number(viewer.dataset.run);
    var kind = viewer.dataset.kind;
    var lastId = Number(viewer.dataset.lastId || "0");

    function appendEntries(htmlStrings) {
      if (!htmlStrings || !htmlStrings.length) return;
      var nearBottom =
        viewer.scrollHeight - viewer.scrollTop - viewer.clientHeight < 80;
      var current = viewer.children.length;
      // Cap at ~1500 entries
      if (current + htmlStrings.length > 1500) {
        var remove = current + htmlStrings.length - 1500;
        for (var i = 0; i < remove && viewer.firstChild; i++) {
          viewer.removeChild(viewer.firstChild);
        }
      }
      var frag = document.createDocumentFragment();
      htmlStrings.forEach(function (html) {
        var wrap = document.createElement("div");
        wrap.innerHTML = html;
        while (wrap.firstChild) frag.appendChild(wrap.firstChild);
      });
      viewer.appendChild(frag);
      if (nearBottom) viewer.scrollTop = viewer.scrollHeight;
    }

    function markFinished() {
      viewer.dataset.live = "0";
      var pill = document.getElementById("livePill");
      if (pill) {
        pill.className = "pill ok";
        pill.textContent = "Finished";
      }
      var note = document.getElementById("liveNote");
      if (note) note.textContent = "session finished \u2014 polling stopped";
      window.clearInterval(timer);
    }

    function poll() {
      if (document.hidden) return;
      var url =
        "/logs/fragment?run=" +
        runId +
        "&kind=" +
        kind +
        "&after=" +
        lastId;
      fetch(url, { credentials: "same-origin", cache: "no-store" })
        .then(function (response) {
          if (!response.ok) return;
          return response.json().then(function (data) {
            if (data.entries && data.entries.length) {
              appendEntries(data.entries);
            }
            if (typeof data.lastId === "number" && data.lastId > 0) {
              lastId = data.lastId;
            }
            if (data.finishedAt) markFinished();
          });
        })
        .catch(function () {
          /* transient network error; retry on the next tick */
        });
    }

    var timer = window.setInterval(poll, 2000);
    poll();
  }

  /* ---- live errors cards ---- */

  var errorCards = document.getElementById("errorCards");
  if (errorCards && errorCards.dataset.live === "1") {
    var pollErrors = function () {
      if (document.hidden) return;
      fetch("/errors/fragment", {
        credentials: "same-origin",
        cache: "no-store",
      })
        .then(function (response) {
          if (!response.ok) return;
          var live = response.headers.get("X-Engine-Live") !== "0";
          return response.text().then(function (html) {
            errorCards.innerHTML = html;
            if (!live) {
              window.clearInterval(errorsTimer);
              errorCards.dataset.live = "0";
              var pill = document.getElementById("livePill");
              if (pill) {
                pill.className = "pill ok";
                pill.textContent = "finished";
              }
            }
          });
        })
        .catch(function () {
          /* transient network error; retry on the next tick */
        });
    };
    var errorsTimer = window.setInterval(pollErrors, 3000);
  }
})();
