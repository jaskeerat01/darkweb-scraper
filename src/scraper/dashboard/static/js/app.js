(function () {
  "use strict";

  const body = document.body;
  const latestTs = Number(body.dataset.latestTs || "0");
  const pollSeconds = Math.max(5, Number(body.dataset.pollSeconds || "15"));

  function pad(value) {
    return String(value).padStart(2, "0");
  }

  function relative(ts) {
    const now = Math.floor(Date.now() / 1000);
    const delta = Math.max(0, now - ts);
    if (delta < 60) return delta + "s ago";
    if (delta < 3600) return Math.floor(delta / 60) + "m ago";
    if (delta < 86400) return Math.floor(delta / 3600) + "h ago";
    return Math.floor(delta / 86400) + "d ago";
  }

  function refreshRelativeTimes() {
    document.querySelectorAll("time[data-ts]").forEach(function (node) {
      const ts = Number(node.dataset.ts || "0");
      if (ts > 0) node.textContent = relative(ts);
    });
  }

  function copyText(value) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(value);
    }
    return new Promise(function (resolve, reject) {
      const area = document.createElement("textarea");
      area.value = value;
      area.setAttribute("readonly", "");
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      try {
        document.execCommand("copy");
        resolve();
      } catch (error) {
        reject(error);
      } finally {
        document.body.removeChild(area);
      }
    });
  }

  function bindCopyButtons() {
    document.querySelectorAll("[data-copy-target], [data-copy-value]").forEach(function (button) {
      button.addEventListener("click", function () {
        let value = button.dataset.copyValue;
        if (!value && button.dataset.copyTarget) {
          const target = document.getElementById(button.dataset.copyTarget);
          value = target ? target.textContent : "";
        }
        if (!value) return;
        const original = button.textContent;
        copyText(value).then(function () {
          button.textContent = "copied";
          window.setTimeout(function () {
            button.textContent = original;
          }, 1400);
        }).catch(function () {
          button.textContent = "failed";
          window.setTimeout(function () {
            button.textContent = original;
          }, 1400);
        });
      });
    });
  }

  function bindKeyboard() {
    document.addEventListener("keydown", function (event) {
      const target = event.target;
      const typing = target && (
        target.tagName === "INPUT" ||
        target.tagName === "TEXTAREA" ||
        target.tagName === "SELECT" ||
        target.isContentEditable
      );
      if (event.key === "/" && !typing) {
        const search = document.querySelector('input[type="search"]');
        if (search) {
          event.preventDefault();
          search.focus();
        }
      }
      if (event.key === "Escape" && typing) {
        target.blur();
      }
    });
  }

  function bindPolling() {
    const banner = document.getElementById("new-alerts");
    const label = document.getElementById("new-alerts-text");
    const refresh = document.getElementById("new-alerts-refresh");
    if (!banner || !label || !refresh) return;
    if (body.dataset.poll !== "on") return;

    let inFlight = false;
    let latest = latestTs || 0;
    let pending = 0;

    refresh.addEventListener("click", function () {
      window.location.reload();
    });

    function poll() {
      if (document.hidden || inFlight) return;
      inFlight = true;

      const params = new URLSearchParams(window.location.search);
      params.delete("cursor");
      params.delete("since");
      params.set("since", String(latest || 0));

      fetch("/api/alerts?" + params.toString(), {
        headers: { Accept: "application/json" },
        credentials: "same-origin"
      })
        .then(function (response) {
          if (!response.ok) return null;
          return response.json();
        })
        .then(function (data) {
          if (!data || !Array.isArray(data.alerts) || data.alerts.length === 0) return;
          pending += data.alerts.length;
          if (data.latest) latest = Math.max(latest, Number(data.latest));
          label.textContent = pending + (pending === 1 ? " new alert" : " new alerts") + " available";
          banner.hidden = false;
        })
        .catch(function () {
          // The dashboard is read-only; polling failures are non-fatal.
        })
        .finally(function () {
          inFlight = false;
        });
    }

    window.setInterval(poll, pollSeconds * 1000);
    document.addEventListener("visibilitychange", function () {
      if (!document.hidden) poll();
    });
  }

  function init() {
    refreshRelativeTimes();
    window.setInterval(refreshRelativeTimes, 30000);
    bindCopyButtons();
    bindKeyboard();
    bindPolling();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
