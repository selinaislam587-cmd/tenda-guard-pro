/* =============================================================================
   Tenda Guard Pro - static/app.js  (v2)
   - Live updates through Server-Sent Events (EventSource) with automatic
     reconnect, a stall watchdog and a polling fallback.
   - Persistence: the last snapshot and your UI choices are kept in
     localStorage, so a reload paints instantly and never shows an empty list
     while the first update is on its way.
   - A snapshot with zero devices never replaces a non-empty list while the
     router is unreachable.
   All dynamic text is inserted with textContent, so device names coming from
   the network cannot inject markup.
   ============================================================================= */
(function () {
  "use strict";

  var SVG_NS = "http://www.w3.org/2000/svg";
  var CACHE_KEY = "tgp-cache";
  var UI_KEY = "tgp-ui";
  var STALL_MS = 16000;

  var csrfMeta = document.querySelector('meta[name="csrf-token"]');
  var csrfToken = csrfMeta ? csrfMeta.getAttribute("content") : "";

  var state = {
    data: null,
    tab: "connected",
    search: "",
    durations: {},
    signature: "",
    trustTarget: null,
    confirmAction: null
  };

  var stream = { source: null, lastMessage: 0, fallbackTimer: null, reconnectTimer: null };

  var PRESETS = [
    { label: "1K", preset: "1k", kbps: 1 },
    { label: "512K", preset: "512k", kbps: 512 },
    { label: "1M", preset: "1m", kbps: 1024 },
    { label: "Max", preset: "max", kbps: 0 }
  ];

  function $(id) { return document.getElementById(id); }

  /* ---------- Storage (never throws) ---------- */
  function readStore(key) {
    try {
      var raw = localStorage.getItem(key);
      return raw ? JSON.parse(raw) : null;
    } catch (e) { return null; }
  }

  function writeStore(key, value) {
    try { localStorage.setItem(key, JSON.stringify(value)); } catch (e) { /* storage full or blocked */ }
  }

  function saveUi() {
    writeStore(UI_KEY, { tab: state.tab, search: state.search, durations: state.durations });
  }

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
  function goToLogin() { window.location.href = "/login"; }

  function api(path, method, payload) {
    var verb = method || "GET";
    var headers = {};
    var options = { method: verb, headers: headers, credentials: "same-origin" };
    if (verb !== "GET") {
      headers["Content-Type"] = "application/json";
      headers["X-CSRF-Token"] = csrfToken;
      options.body = JSON.stringify(payload === undefined ? {} : payload);
    }
    var controller = window.AbortController ? new AbortController() : null;
    var timer = null;
    if (controller) {
      options.signal = controller.signal;
      timer = setTimeout(function () { controller.abort(); }, 15000);
    }
    return fetch(path, options).then(function (response) {
      if (timer) { clearTimeout(timer); }
      if (response.status === 401) { goToLogin(); throw new Error("Signed out. Redirecting to sign in."); }
      return response.json().catch(function () { return {}; }).then(function (json) {
        if (!response.ok || json.ok === false) {
          throw new Error(json.error || "Request failed (" + response.status + ")");
        }
        return json;
      });
    }, function (error) {
      if (timer) { clearTimeout(timer); }
      throw new Error(error && error.name === "AbortError" ? "The request timed out." : "Network error. Check your connection.");
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

  function setLive(kind) {
    var labels = { live: "Live", retry: "Reconnecting", cached: "Saved data", connecting: "Connecting" };
    $("liveBadge").setAttribute("data-state", kind);
    $("liveText").textContent = labels[kind] || "Connecting";
  }

  function bannerMessage(data) {
    if (data.auth_error) {
      return (data.last_error || "The router login failed.") + (data.devices.length ? " Showing the last known devices." : "");
    }
    if (!data.router_online) {
      return "The router at " + data.router_ip + " is not responding." + (data.devices.length ? " Showing the last known devices." : " Check that this phone is on the router's network.");
    }
    if (data.last_error) { return data.last_error; }
    if (data.mail_error) { return "Email alerts are failing: " + data.mail_error; }
    return "";
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
    if (data.auth_error) {
      pill.textContent = "Login failed";
      pill.className = "pill bad";
    } else if (!data.router_online) {
      pill.textContent = "Unreachable";
      pill.className = "pill bad";
    } else {
      pill.textContent = "Online";
      pill.className = "pill ok";
    }
    $("lastPollFoot").textContent = clock(data.last_poll);
    $("countConnected").textContent = data.metrics.connected;
    $("countTrusted").textContent = data.metrics.trusted;

    var message = bannerMessage(data);
    $("alertBanner").hidden = !message;
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
    top.appendChild(badge(speedLabel(device.limit_kbps), device.throttled ? "limited" : "free", "gauge"));
    card.appendChild(top);

    var chips = el("div", "chips");
    chips.setAttribute("role", "group");
    chips.setAttribute("aria-label", "Speed limit for " + device.name);
    PRESETS.forEach(function (item) {
      var selected = device.limit_kbps === item.kbps || (item.kbps === 0 && (device.limit_kbps === null || device.limit_kbps === undefined));
      var chip = button(item.label, "chip" + (selected ? " is-selected" : ""), function () {
        api("/api/set-speed", "POST", { mac: device.mac, preset: item.preset })
          .then(function () { toast(device.name + " set to " + speedLabel(item.kbps)); return refreshNow(); })
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
        untilText.setAttribute("data-prefix", "Trusted, ");
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
      select.addEventListener("change", function () { state.durations[device.mac] = select.value; saveUi(); });
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
      text.setAttribute("data-prefix", "");
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
        : (data.router_online ? "No devices are connected right now." : "Waiting for the router. Devices will appear here once it responds.")));
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
      node.textContent = (node.getAttribute("data-prefix") || "") + timeLeft(left);
    }
  }

  /* ---------- Snapshot handling ---------- */
  function acceptSnapshot(data) {
    var previous = state.data;
    if (previous && previous.devices.length > 0 && data.devices.length === 0 && (data.stale || !data.router_online)) {
      data.devices = previous.devices;
      data.metrics.connected = previous.metrics.connected;
      data.metrics.throttled = previous.metrics.throttled;
    }
    state.data = data;
    writeStore(CACHE_KEY, data);
    render(data);
  }

  function load() {
    return api("/api/data").then(function (data) {
      acceptSnapshot(data);
      return data;
    });
  }

  function refreshNow() {
    return load().catch(function () { /* the stream will catch up */ });
  }

  /* ---------- Live stream ---------- */
  function startFallback() {
    if (stream.fallbackTimer) { return; }
    stream.fallbackTimer = setInterval(function () { load().catch(function () { setLive("retry"); }); }, 5000);
  }

  function stopFallback() {
    if (stream.fallbackTimer) { clearInterval(stream.fallbackTimer); stream.fallbackTimer = null; }
  }

  function closeStream() {
    if (stream.source) { stream.source.close(); stream.source = null; }
    if (stream.reconnectTimer) { clearTimeout(stream.reconnectTimer); stream.reconnectTimer = null; }
  }

  function scheduleReconnect(delay) {
    if (stream.reconnectTimer) { return; }
    stream.reconnectTimer = setTimeout(function () {
      stream.reconnectTimer = null;
      connectStream();
    }, delay);
  }

  function connectStream() {
    closeStream();
    if (!window.EventSource) {
      setLive("retry");
      startFallback();
      return;
    }
    var source = new EventSource("/stream");
    stream.source = source;
    source.addEventListener("snapshot", function (event) {
      var data;
      try { data = JSON.parse(event.data); } catch (e) { return; }
      stream.lastMessage = Date.now();
      stopFallback();
      setLive("live");
      acceptSnapshot(data);
    });
    source.onerror = function () {
      setLive("retry");
      startFallback();
      if (source.readyState === 2) {
        scheduleReconnect(5000);
      }
    };
  }

  function watchdog() {
    if (stream.source && stream.lastMessage && Date.now() - stream.lastMessage > STALL_MS) {
      stream.lastMessage = 0;
      setLive("retry");
      startFallback();
      connectStream();
    }
  }

  /* ---------- Actions ---------- */
  function setTab(name) {
    state.tab = name;
    Array.prototype.forEach.call(document.querySelectorAll(".tab"), function (tab) {
      var active = tab.getAttribute("data-tab") === name;
      tab.classList.toggle("is-active", active);
      tab.setAttribute("aria-selected", active ? "true" : "false");
    });
    $("panelConnected").hidden = name !== "connected";
    $("panelTrusted").hidden = name !== "trusted";
    saveUi();
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
            return refreshNow();
          });
      }
    );
  }

  function settingsPayload() {
    return {
      sender: $("setSender").value,
      target: $("setTarget").value,
      app_password: $("setPassword").value,
      router_ip: $("setRouterIp").value,
      router_password: $("setRouterPassword").value
    };
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
      ["trustModal", "confirmModal", "settingsModal", "diagModal"].forEach(closeModal);
    });

    document.addEventListener("visibilitychange", function () {
      if (!document.hidden) {
        refreshNow();
        if (!stream.source || stream.source.readyState === 2) { connectStream(); }
      }
    });

    window.addEventListener("online", function () { connectStream(); refreshNow(); });

    $("themeBtn").addEventListener("click", function () {
      var next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      try { localStorage.setItem("tgp-theme", next); } catch (e) { /* storage unavailable */ }
      syncThemeIcon();
    });

    $("logoutBtn").addEventListener("click", function () {
      closeStream();
      api("/logout", "POST").catch(function () { /* ignore */ }).then(function () {
        try { localStorage.removeItem(CACHE_KEY); } catch (e) { /* ignore */ }
        goToLogin();
      });
    });

    Array.prototype.forEach.call(document.querySelectorAll(".tab"), function (tab) {
      tab.addEventListener("click", function () { setTab(tab.getAttribute("data-tab")); });
    });

    $("searchInput").addEventListener("input", function (event) {
      state.search = event.target.value.trim().toLowerCase();
      saveUi();
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
        .then(function (data) { acceptSnapshot(data); toast("Device list refreshed."); })
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
            return refreshNow();
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
            return refreshNow();
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
          saveUi();
          closeModal("trustModal");
          toast(name + " is now trusted.");
          return refreshNow();
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
        $("pwCurrent").value = "";
        $("pwNew").value = "";
        $("setPassword").placeholder = settings.password_set ? "Saved. Leave blank to keep it" : "16-character app password";
        $("setRouterPassword").placeholder = settings.router_password_set ? "Saved. Leave blank to keep it" : "Enter the router admin password";
        openModal("settingsModal");
      }).catch(fail);
    });

    $("saveSettingsBtn").addEventListener("click", function () {
      api("/api/settings", "POST", settingsPayload())
        .then(function () { closeModal("settingsModal"); toast("Settings saved."); })
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

    $("diagnoseBtn").addEventListener("click", function () {
      var btn = $("diagnoseBtn");
      btn.disabled = true;
      $("diagOutput").textContent = "Running test. This can take up to a minute...";
      openModal("diagModal");
      api("/api/settings", "POST", settingsPayload())
        .then(function () { return api("/api/diagnose", "POST"); })
        .then(function (result) { $("diagOutput").textContent = result.lines.join("\n"); })
        .catch(function (error) { $("diagOutput").textContent = "Test failed: " + error.message; })
        .then(function () { btn.disabled = false; });
    });

    $("diagCopy").addEventListener("click", function () {
      var text = $("diagOutput").textContent;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function () { toast("Report copied."); }, function () { toast("Copy failed. Select the text manually.", true); });
      } else {
        toast("Select the text and copy it manually.", true);
      }
    });

    $("changePwBtn").addEventListener("click", function () {
      var btn = $("changePwBtn");
      btn.disabled = true;
      api("/api/change-password", "POST", { current: $("pwCurrent").value, "new": $("pwNew").value })
        .then(function (result) {
          if (result.csrf) { csrfToken = result.csrf; }
          $("pwCurrent").value = "";
          $("pwNew").value = "";
          toast("Password changed. Other devices were signed out.");
        })
        .catch(fail)
        .then(function () { btn.disabled = false; });
    });
  }

  function syncThemeIcon() {
    var dark = document.documentElement.getAttribute("data-theme") === "dark";
    $("themeIcon").firstElementChild.setAttribute("href", dark ? "#i-sun" : "#i-moon");
    $("themeBtn").setAttribute("aria-label", dark ? "Switch to light theme" : "Switch to dark theme");
  }

  /* ---------- Startup ---------- */
  function restore() {
    var ui = readStore(UI_KEY);
    if (ui) {
      state.search = typeof ui.search === "string" ? ui.search : "";
      state.durations = ui.durations && typeof ui.durations === "object" ? ui.durations : {};
      $("searchInput").value = state.search;
      setTab(ui.tab === "trusted" ? "trusted" : "connected");
    }
    var cached = readStore(CACHE_KEY);
    if (cached && Array.isArray(cached.devices) && Array.isArray(cached.trusted) && cached.metrics) {
      state.data = cached;
      render(cached);
      setLive("cached");
    }
  }

  syncThemeIcon();
  bindEvents();
  restore();
  connectStream();
  load().catch(function () { /* the stream or fallback will retry */ });
  setInterval(tickCountdowns, 1000);
  setInterval(watchdog, 5000);
})();
