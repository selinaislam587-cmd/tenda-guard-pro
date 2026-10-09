/* =============================================================================
   Tenda Guard Pro - static/app.js
   Vanilla JS frontend. All dynamic text is inserted with textContent, so device
   names coming from the network can never inject markup.
   ============================================================================= */
(function () {
  "use strict";

  var POLL_MS = 5000;
  var SVG_NS = "http://www.w3.org/2000/svg";

  var state = {
    data: null,
    tab: "connected",
    search: "",
    durations: {},
    signature: "",
    trustTarget: null,
    confirmAction: null
  };

  var PRESETS = [
    { label: "1K", preset: "1k", kbps: 1 },
    { label: "512K", preset: "512k", kbps: 512 },
    { label: "1M", preset: "1m", kbps: 1024 },
    { label: "Max", preset: "max", kbps: 0 }
  ];

  function $(id) { return document.getElementById(id); }

  /* ---------- DOM helpers ---------- */
  function icon(name) {
    var svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("class", "i");
    var use = document.createElementNS(SVG_NS, "use");
    use.setAttribute("href", "#i-" + name);
    svg.appendChild(use);
    return svg;
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text !== undefined && text !== null) { node.textContent = text; }
    return node;
  }

  function badge(text, kind, iconName) {
    var node = el("span", "badge" + (kind ? " " + kind : ""));
    if (iconName) { node.appendChild(icon(iconName)); }
    node.appendChild(document.createTextNode(text));
    return node;
  }

  function button(label, className, onClick, iconName) {
    var node = el("button", className);
    node.type = "button";
    if (iconName) { node.appendChild(icon(iconName)); }
    node.appendChild(document.createTextNode(label));
    node.addEventListener("click", onClick);
    return node;
  }

  /* ---------- Formatting ---------- */
  function speedLabel(kbps) {
    if (kbps === null || kbps === undefined || kbps === 0) { return "Unlimited"; }
    if (kbps >= 1024) { return (kbps / 1024) + " Mbps"; }
    return kbps + " Kbps";
  }

  function timeLeft(seconds) {
    if (seconds <= 0) { return "Expired"; }
    var days = Math.floor(seconds / 86400);
    var hours = Math.floor((seconds % 86400) / 3600);
    var minutes = Math.floor((seconds % 3600) / 60);
    if (days > 0) { return days + "d " + hours + "h left"; }
    if (hours > 0) { return hours + "h " + minutes + "m left"; }
    if (minutes > 0) { return minutes + "m left"; }
    return "Under 1m left";
  }

  function clock(epoch) {
    if (!epoch) { return "Not updated yet"; }
    var date = new Date(epoch * 1000);
    return "Updated " + date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }

  /* ---------- API ---------- */
  function api(path, method, payload) {
    var options = { method: method || "GET", headers: {} };
    if (payload !== undefined) {
      options.headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(payload);
    } else if (options.method !== "GET") {
      options.headers["Content-Type"] = "application/json";
      options.body = "{}";
    }
    return fetch(path, options).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (json) {
        if (!response.ok || json.ok === false) {
          throw new Error(json.error || "Request failed (" + response.status + ")");
        }
        return json;
      });
    });
  }

  /* ---------- Toasts ---------- */
  function toast(message, isError) {
    var node = el("div", "toast" + (isError ? " error" : ""), message);
    $("toastHost").appendChild(node);
    setTimeout(function () {
      if (node.parentNode) { node.parentNode.removeChild(node); }
    }, isError ? 5000 : 2800);
  }

  function fail(error) { toast(error.message || "Something went wrong.", true); }

  /* ---------- Modals ---------- */
  function openModal(id) {
    var modal = $(id);
    modal.hidden = false;
    var first = modal.querySelector("input, select, button.btn-filled");
    if (first) { first.focus(); }
  }

  function closeModal(id) { $(id).hidden = true; }

  function confirmDialog(title, text, okLabel, action) {
    $("confirmTitle").textContent = title;
    $("confirmText").textContent = text;
    $("confirmOk").textContent = okLabel;
    state.confirmAction = action;
    openModal("confirmModal");
  }

  /* ---------- Rendering ---------- */
  function signatureOf(data) {
    var devices = data.devices.map(function (d) {
      return [d.mac, d.name, d.ip, d.limit_kbps, d.trusted, d.expires_at].join("|");
    });
    var trusted = data.trusted.map(function (t) {
      return [t.mac, t.name, t.expires_at, t.online].join("|");
    });
    return JSON.stringify([devices, trusted, state.search, state.tab]);
  }

  function renderStatus(data) {
    $("routerIpLabel").textContent = "Tenda F3 at " + data.router_ip;
    $("statConnected").textContent = data.metrics.connected;
    $("statTrustedFoot").textContent = data.metrics.trusted + " trusted";
    $("statThrottled").textContent = data.metrics.throttled;
    $("statPendingFoot").textContent = data.metrics.pending + " waiting for the router";
    $("autoToggle").checked = data.auto_throttle;
    $("autoLabel").textContent = data.auto_throttle ? "On" : "Off";
    var pill = $("routerPill");
    pill.textContent = data.router_online ? "Online" : "Unreachable";
    pill.className = "pill " + (data.router_online ? "ok" : "bad");
    $("lastPollFoot").textContent = clock(data.last_poll);
    $("countConnected").textContent = data.metrics.connected;
    $("countTrusted").textContent = data.metrics.trusted;

    var banner = $("alertBanner");
    var message = "";
    if (!data.router_online) {
      message = "The router at " + data.router_ip + " is not responding. Check that this device is on the router's network.";
    } else if (data.mail_error) {
      message = "Email alerts are failing: " + data.mail_error;
    }
    banner.hidden = !message;
    $("alertText").textContent = message;
  }

  function matchesSearch(device) {
    if (!state.search) { return true; }
    var haystack = (device.name + " " + device.hostname + " " + device.mac + " " + device.ip).toLowerCase();
    return haystack.indexOf(state.search) !== -1;
  }

  function deviceCard(device) {
    var card = el("article", "device" + (device.trusted ? " is-trusted" : (device.throttled ? " is-limited" : "")));

    var top = el("div", "device-top");
    var info = el("div");
    info.appendChild(el("div", "device-name", device.name));
    var meta = el("div", "device-meta");
    meta.appendChild(badge(device.mac, "mac"));
    meta.appendChild(badge(device.ip || "No IP", ""));
    info.appendChild(meta);
    top.appendChild(info);

    var speedBadge = badge(speedLabel(device.limit_kbps), device.throttled ? "limited" : "free", "gauge");
    top.appendChild(speedBadge);
    card.appendChild(top);

    var chips = el("div", "chips");
    chips.setAttribute("role", "group");
    chips.setAttribute("aria-label", "Speed limit for " + device.name);
    PRESETS.forEach(function (item) {
      var selected = device.limit_kbps === item.kbps || (item.kbps === 0 && (device.limit_kbps === null || device.limit_kbps === undefined));
      var chip = button(item.label, "chip" + (selected ? " is-selected" : ""), function () {
        api("/api/set-speed", "POST", { mac: device.mac, preset: item.preset })
          .then(function () { toast(device.name + " set to " + speedLabel(item.kbps)); return load(); })
          .catch(fail);
      });
      chip.setAttribute("aria-pressed", selected ? "true" : "false");
      chips.appendChild(chip);
    });
    card.appendChild(chips);

    var row = el("div", "trust-row");
    if (device.trusted) {
      var until = el("span", "badge trusted");
      until.appendChild(icon("shield"));
      var untilText = el("span");
      if (device.expires_at) {
        untilText.setAttribute("data-expires", device.expires_at);
        untilText.textContent = "Trusted, " + timeLeft(device.expires_at - Date.now() / 1000);
      } else {
        untilText.textContent = "Trusted, no expiry";
      }
      until.appendChild(untilText);
      row.appendChild(until);
      row.appendChild(button("Remove trust", "btn btn-outline btn-small", function () { askUntrust(device.mac, device.name); }, "close"));
    } else {
      var select = el("select");
      select.setAttribute("aria-label", "Trust duration for " + device.name);
      [["1", "1 day"], ["7", "7 days"], ["30", "30 days"], ["unlimited", "Unlimited"]].forEach(function (pair) {
        var option = el("option", null, pair[1]);
        option.value = pair[0];
        select.appendChild(option);
      });
      select.value = state.durations[device.mac] || "7";
      select.addEventListener("change", function () { state.durations[device.mac] = select.value; });
      row.appendChild(select);
      row.appendChild(button("Trust", "btn btn-tonal btn-small", function () { openTrust(device); }, "check"));
    }
    card.appendChild(row);
    return card;
  }

  function trustedCard(item) {
    var card = el("article", "device is-trusted");
    var top = el("div", "device-top");
    var info = el("div");
    info.appendChild(el("div", "device-name", item.name));
    var meta = el("div", "device-meta");
    meta.appendChild(badge(item.mac, "mac"));
    meta.appendChild(badge(item.online ? "Connected" : "Offline", item.online ? "free" : ""));
    info.appendChild(meta);
    top.appendChild(info);
    card.appendChild(top);

    var row = el("div", "trust-row");
    var expiry = el("span", "badge " + (item.expires_at ? "warn" : "trusted"));
    expiry.appendChild(icon("clock"));
    var text = el("span");
    if (item.expires_at) {
      text.setAttribute("data-expires", item.expires_at);
      text.textContent = timeLeft(item.expires_at - Date.now() / 1000);
    } else {
      text.textContent = "No expiry";
    }
    expiry.appendChild(text);
    row.appendChild(expiry);
    row.appendChild(button("Remove trust", "btn btn-outline btn-small", function () { askUntrust(item.mac, item.name); }, "trash"));
    card.appendChild(row);
    return card;
  }

  function emptyState(message) { return el("div", "empty", message); }

  function renderLists(data) {
    var list = $("deviceList");
    list.textContent = "";
    var shown = data.devices.filter(matchesSearch);
    if (!shown.length) {
      list.appendChild(emptyState(data.devices.length
        ? "No devices match your search."
        : (data.router_online ? "No devices are connected right now." : "Device list unavailable while the router is unreachable.")));
    }
    shown.forEach(function (device) { list.appendChild(deviceCard(device)); });

    var trustedList = $("trustedList");
    trustedList.textContent = "";
    if (!data.trusted.length) {
      trustedList.appendChild(emptyState("No trusted devices yet. Open Connected and tap Trust on a device you recognize."));
    }
    data.trusted.forEach(function (item) { trustedList.appendChild(trustedCard(item)); });
  }

  function render(data) {
    state.data = data;
    renderStatus(data);
    var signature = signatureOf(data);
    var active = document.activeElement;
    var interacting = active && active.tagName === "SELECT" && $("deviceList").contains(active);
    if (signature !== state.signature && !interacting) {
      state.signature = signature;
      renderLists(data);
    }
  }

  function tickCountdowns() {
    var nodes = document.querySelectorAll("[data-expires]");
    var now = Date.now() / 1000;
    for (var index = 0; index < nodes.length; index++) {
      var node = nodes[index];
      var left = Number(node.getAttribute("data-expires")) - now;
      var prefix = node.textContent.indexOf("Trusted, ") === 0 ? "Trusted, " : "";
      node.textContent = prefix + timeLeft(left);
    }
  }

  /* ---------- Actions ---------- */
  function load() {
    return api("/api/data").then(render).catch(function () {
      $("routerPill").textContent = "App offline";
      $("routerPill").className = "pill bad";
    });
  }

  function openTrust(device) {
    state.trustTarget = device;
    $("trustMacLabel").textContent = device.mac + (device.ip ? "  |  " + device.ip : "");
    $("trustName").value = device.hostname && device.hostname !== "Unknown device" ? device.hostname : "";
    $("trustDuration").value = state.durations[device.mac] || "7";
    openModal("trustModal");
  }

  function askUntrust(mac, name) {
    confirmDialog(
      "Remove trust?",
      name + " will be limited to 1 Kbps right away.",
      "Remove trust",
      function () {
        return api("/api/untrust-device", "POST", { mac: mac })
          .then(function (result) {
            toast(result.throttled_now ? name + " is now throttled." : name + " will be throttled when the router responds.");
            return load();
          });
      }
    );
  }

  function bindEvents() {
    document.addEventListener("click", function (event) {
      var closer = event.target.closest("[data-close]");
      if (closer) { closeModal(closer.getAttribute("data-close")); return; }
      if (event.target.classList && event.target.classList.contains("scrim")) {
        event.target.hidden = true;
      }
    });

    document.addEventListener("keydown", function (event) {
      if (event.key !== "Escape") { return; }
      ["trustModal", "confirmModal", "settingsModal"].forEach(closeModal);
    });

    $("themeBtn").addEventListener("click", function () {
      var next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      try { localStorage.setItem("tgp-theme", next); } catch (e) { /* storage unavailable */ }
      syncThemeIcon();
    });

    Array.prototype.forEach.call(document.querySelectorAll(".tab"), function (tab) {
      tab.addEventListener("click", function () {
        state.tab = tab.getAttribute("data-tab");
        Array.prototype.forEach.call(document.querySelectorAll(".tab"), function (other) {
          var active = other === tab;
          other.classList.toggle("is-active", active);
          other.setAttribute("aria-selected", active ? "true" : "false");
        });
        $("panelConnected").hidden = state.tab !== "connected";
        $("panelTrusted").hidden = state.tab !== "trusted";
      });
    });

    $("searchInput").addEventListener("input", function (event) {
      state.search = event.target.value.trim().toLowerCase();
      if (state.data) { state.signature = ""; render(state.data); }
    });

    $("autoToggle").addEventListener("change", function (event) {
      var wanted = event.target.checked;
      api("/api/toggle-autothrottle", "POST", { enabled: wanted })
        .then(function (result) {
          $("autoLabel").textContent = result.auto_throttle ? "On" : "Off";
          toast(result.auto_throttle ? "Auto-throttle is on." : "Auto-throttle is off.");
        })
        .catch(function (error) { event.target.checked = !wanted; fail(error); });
    });

    $("refreshBtn").addEventListener("click", function () {
      var btn = $("refreshBtn");
      btn.disabled = true;
      api("/api/refresh", "POST")
        .then(function (data) { render(data); toast("Device list refreshed."); })
        .catch(fail)
        .then(function () { btn.disabled = false; });
    });

    $("panicBtn").addEventListener("click", function () {
      confirmDialog(
        "Lock down the network?",
        "Every device that is not on your trusted list will be limited to 1 Kbps.",
        "Panic lock",
        function () {
          return api("/api/panic-lock", "POST").then(function (result) {
            toast(result.throttled + " device(s) throttled.");
            return load();
          });
        }
      );
    });

    $("rebootBtn").addEventListener("click", function () {
      confirmDialog(
        "Reboot the router?",
        "Everyone on the network will be disconnected for a minute or two.",
        "Reboot router",
        function () {
          return api("/api/reboot", "POST").then(function () {
            toast("Reboot command sent. The router will be back shortly.");
            return load();
          });
        }
      );
    });

    $("confirmOk").addEventListener("click", function () {
      var action = state.confirmAction;
      state.confirmAction = null;
      closeModal("confirmModal");
      if (action) { action().catch(fail); }
    });

    $("trustConfirm").addEventListener("click", function () {
      var device = state.trustTarget;
      if (!device) { return; }
      var name = $("trustName").value.trim();
      if (!name) { toast("Enter a name for this device.", true); $("trustName").focus(); return; }
      var duration = $("trustDuration").value;
      var btn = $("trustConfirm");
      btn.disabled = true;
      api("/api/trust-device", "POST", { mac: device.mac, name: name, duration: duration })
        .then(function () {
          state.durations[device.mac] = duration;
          closeModal("trustModal");
          toast(name + " is now trusted.");
          return load();
        })
        .catch(fail)
        .then(function () { btn.disabled = false; });
    });

    $("settingsBtn").addEventListener("click", function () {
      api("/api/settings").then(function (settings) {
        $("setSender").value = settings.sender;
        $("setTarget").value = settings.target;
        $("setRouterIp").value = settings.router_ip;
        $("setPassword").value = "";
        $("setRouterPassword").value = "";
        $("setPassword").placeholder = settings.password_set ? "Saved. Leave blank to keep it" : "16-character app password";
        $("setRouterPassword").placeholder = settings.router_password_set ? "Saved. Leave blank to keep it" : "Leave blank if none";
        openModal("settingsModal");
      }).catch(fail);
    });

    function settingsPayload() {
      return {
        sender: $("setSender").value,
        target: $("setTarget").value,
        app_password: $("setPassword").value,
        router_ip: $("setRouterIp").value,
        router_password: $("setRouterPassword").value
      };
    }

    $("saveSettingsBtn").addEventListener("click", function () {
      api("/api/settings", "POST", settingsPayload())
        .then(function () { closeModal("settingsModal"); toast("Settings saved."); return load(); })
        .catch(fail);
    });

    $("testEmailBtn").addEventListener("click", function () {
      var btn = $("testEmailBtn");
      btn.disabled = true;
      api("/api/settings", "POST", settingsPayload())
        .then(function () { return api("/api/test-email", "POST"); })
        .then(function () { toast("Test email sent."); })
        .catch(fail)
        .then(function () { btn.disabled = false; });
    });
  }

  function syncThemeIcon() {
    var dark = document.documentElement.getAttribute("data-theme") === "dark";
    $("themeIcon").firstElementChild.setAttribute("href", dark ? "#i-sun" : "#i-moon");
    $("themeBtn").setAttribute("aria-label", dark ? "Switch to light theme" : "Switch to dark theme");
  }

  syncThemeIcon();
  bindEvents();
  load();
  setInterval(load, POLL_MS);
  setInterval(tickCountdowns, 1000);
})();
