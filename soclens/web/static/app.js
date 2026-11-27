(function () {
  "use strict";

  const API = window.SOCLensAPI;
  const Tiling = window.SOCLensTiling;
  const Tiles = window.SOCLensTiles;

  let tilingManager = null;
  let tileHandlers = {};
  let tileRegistry = new Map();
  let killSwitchActive = false;

  function setStatusMsg(text) {
    const el = document.getElementById("sl-status-msg");
    if (el) el.textContent = text;
  }

  function applyStatusPayload(status) {
    if (!status) return;
    const verEl = document.getElementById("sl-version-badge");
    const adminEl = document.getElementById("sl-admin-badge");
    const dialectEl = document.getElementById("sl-dialect-badge");
    const lockEl = document.getElementById("sl-lock-badge");
    const ksBtn = document.getElementById("sl-btn-killswitch");

    if (verEl && status.version) verEl.textContent = "v" + status.version;
    if (adminEl) adminEl.classList.toggle("sl-hidden", !status.admin_enabled);
    if (dialectEl && status.dialect) dialectEl.textContent = status.dialect;
    if (lockEl) lockEl.classList.toggle("sl-hidden", !status.settings_locked);

    killSwitchActive = Boolean(status.ai_kill_switch_active);
    if (ksBtn) {
      ksBtn.textContent = killSwitchActive ? "AI: HALTED" : "AI: Active";
      ksBtn.className = "sl-btn " + (killSwitchActive ? "sl-btn-danger" : "sl-btn-warn");
    }
  }

  function syncWorkspaceButtons() {
    if (!tilingManager) return;
    const cur = String(tilingManager.activeWorkspace);
    for (const btn of document.querySelectorAll(".sl-ws-btn")) {
      btn.classList.toggle("active", btn.dataset.ws === cur);
    }
    const activeTile = tilingManager.getFocusedTileId();
    for (const pill of document.querySelectorAll(".sl-tile-pill")) {
      pill.classList.toggle("active", pill.dataset.tileId === activeTile);
    }
  }

  function pivotTo(targetTile, payload) {
    if (tilingManager) {
      tilingManager.openOrFocusTile(targetTile);
    }
    const fn = tileHandlers[targetTile];
    if (typeof fn === "function") {
      fn(payload || {});
    }
    API.broadcastSync("pivot", { targetTile: targetTile, payload: payload || {} });
    setStatusMsg("Pivoted to " + targetTile);
  }

  function setupPivotContextMenu() {
    const menu = document.getElementById("sl-pivot-menu");
    if (!menu) return;

    function hideMenu() {
      menu.classList.add("sl-hidden");
      menu.innerHTML = "";
    }

    document.addEventListener("click", hideMenu);
    document.addEventListener("contextmenu", function (ev) {
      const targetEl = ev.target;
      let indicator = "";
      let fieldLabel = "Selection";

      if (targetEl && targetEl.dataset && targetEl.dataset.pivotValue) {
        indicator = String(targetEl.dataset.pivotValue).trim();
        fieldLabel = String(targetEl.dataset.pivotField || "Field");
      } else if (window.getSelection) {
        indicator = String(window.getSelection().toString() || "").trim();
      }
      if (!indicator || indicator === "-" || indicator.length > 180) {
        hideMenu();
        return;
      }

      ev.preventDefault();
      menu.innerHTML = "";
      const actions = [
        { label: "Research (" + fieldLabel + ")", tile: "research", payload: { indicator: indicator } },
        { label: "Search RF Intel", tile: "rf-intel", payload: { indicator: indicator } },
        { label: "Search Splunk (SPL)", tile: "splunk-search", payload: { indicator: indicator } },
        { label: "AI: Ask about event", tile: "ai-analyst", payload: { indicator: indicator, mode: "ask_only", title: fieldLabel + ": " + indicator } },
        { label: "AI: Full investigation", tile: "ai-analyst", payload: { indicator: indicator, mode: "full_investigation", title: fieldLabel + ": " + indicator } },
        { label: "Learn from This", tile: "ai-analyst", payload: { indicator: indicator, openTeach: true, title: indicator } },
      ];
      for (const act of actions) {
        const item = document.createElement("button");
        item.className = "sl-context-item";
        item.textContent = act.label;
        item.addEventListener("click", function (clickEv) {
          clickEv.stopPropagation();
          hideMenu();
          pivotTo(act.tile, act.payload);
        });
        menu.appendChild(item);
      }

      menu.style.left = Math.min(ev.clientX, window.innerWidth - 230) + "px";
      menu.style.top = Math.min(ev.clientY, window.innerHeight - 200) + "px";
      menu.classList.remove("sl-hidden");
    });
  }

  function setupCommandPalette() {
    const backdrop = document.getElementById("sl-palette-backdrop");
    const input = document.getElementById("sl-palette-input");
    const listEl = document.getElementById("sl-palette-list");
    const closeBtn = document.getElementById("sl-palette-close");
    if (!backdrop || !input || !listEl) return;

    function close() {
      backdrop.classList.add("sl-hidden");
    }

    function buildCommands() {
      const cmds = [];
      for (const [id, meta] of tileRegistry.entries()) {
        cmds.push({
          label: "Open Tile: " + meta.title,
          hint: id,
          run: function () {
            if (tilingManager) tilingManager.openOrFocusTile(id);
          },
        });
      }
      cmds.push({
        label: "Layout: Split Right (Alt+v)",
        hint: "horizontal",
        run: function () { if (tilingManager) tilingManager.splitFocused("horizontal"); },
      });
      cmds.push({
        label: "Layout: Split Down (Alt+s)",
        hint: "vertical",
        run: function () { if (tilingManager) tilingManager.splitFocused("vertical"); },
      });
      cmds.push({
        label: "Layout: Toggle Zoom (Alt+z)",
        hint: "zoom",
        run: function () { if (tilingManager) tilingManager.toggleZoom(); },
      });
      cmds.push({
        label: "Layout: Close Focused Tile (Alt+q)",
        hint: "close",
        run: function () { if (tilingManager) tilingManager.closeFocused(); },
      });
      for (const ws of ["1", "2", "3", "4", "5"]) {
        cmds.push({
          label: "Workspace: Switch to " + ws + " (Alt+" + ws + ")",
          hint: "ws-" + ws,
          run: function () { if (tilingManager) tilingManager.switchWorkspace(ws); },
        });
      }
      return cmds;
    }

    function renderList() {
      const q = input.value.trim().toLowerCase();
      listEl.innerHTML = "";
      const cmds = buildCommands().filter(function (c) {
        return !q || c.label.toLowerCase().includes(q) || c.hint.toLowerCase().includes(q);
      });
      for (const cmd of cmds) {
        const btn = document.createElement("button");
        btn.className = "sl-palette-item";
        btn.innerHTML = "";
        const lbl = document.createElement("span");
        lbl.textContent = cmd.label;
        const hint = document.createElement("span");
        hint.className = "sl-badge";
        hint.textContent = cmd.hint;
        btn.appendChild(lbl);
        btn.appendChild(hint);
        btn.addEventListener("click", function () {
          close();
          cmd.run();
        });
        listEl.appendChild(btn);
      }
    }

    function open() {
      backdrop.classList.remove("sl-hidden");
      input.value = "";
      renderList();
      input.focus();
    }

    input.addEventListener("input", renderList);
    input.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape") close();
      if (ev.key === "Enter") {
        const first = listEl.querySelector(".sl-palette-item");
        if (first) first.click();
      }
    });
    if (closeBtn) closeBtn.addEventListener("click", close);
    backdrop.addEventListener("click", function (ev) {
      if (ev.target === backdrop) close();
    });
    window.__soclensOpenPalette = open;
  }

  function setupKeyboardShortcuts() {
    window.addEventListener("keydown", function (ev) {
      const key = String(ev.key || "").toLowerCase();
      if ((ev.ctrlKey || ev.metaKey) && key === "k") {
        ev.preventDefault();
        if (typeof window.__soclensOpenPalette === "function") {
          window.__soclensOpenPalette();
        }
        return;
      }
      if (!ev.altKey || !tilingManager) return;

      if (key === "v") {
        ev.preventDefault();
        tilingManager.splitFocused("horizontal");
      } else if (key === "s") {
        ev.preventDefault();
        tilingManager.splitFocused("vertical");
      } else if (key === "z") {
        ev.preventDefault();
        tilingManager.toggleZoom();
      } else if (key === "q") {
        ev.preventDefault();
        tilingManager.closeFocused();
      } else if (key === "h") {
        ev.preventDefault();
        tilingManager.focusDirection("left");
      } else if (key === "j") {
        ev.preventDefault();
        tilingManager.focusDirection("down");
      } else if (key === "k") {
        ev.preventDefault();
        tilingManager.focusDirection("up");
      } else if (key === "l") {
        ev.preventDefault();
        tilingManager.focusDirection("right");
      } else if (key === "1" || key === "2" || key === "3" || key === "4" || key === "5") {
        ev.preventDefault();
        tilingManager.switchWorkspace(key);
      }
    });
  }

  async function bootstrap() {
    try {
      await API.initAuth();
      const status = await API.apiFetch("/api/status");
      applyStatusPayload(status);

      const built = Tiles.buildTileRegistry({
        adminEnabled: Boolean(status.admin_enabled),
        pivotTo: pivotTo,
      });
      tileRegistry = built.registry;
      tileHandlers = built.handlers;

      const pillsHost = document.getElementById("sl-tile-pills");
      if (pillsHost) {
        pillsHost.innerHTML = "";
        for (const [id, meta] of tileRegistry.entries()) {
          const pill = document.createElement("button");
          pill.className = "sl-tile-pill";
          pill.dataset.tileId = id;
          pill.textContent = meta.admin ? "[Admin] " + meta.title : meta.title;
          pill.addEventListener("click", function () {
            if (tilingManager) tilingManager.openOrFocusTile(id);
          });
          pillsHost.appendChild(pill);
        }
      }

      const rootEl = document.getElementById("sl-workspace-root");
      tilingManager = new Tiling.BSPTilingManager(rootEl, tileRegistry, {
        onStateChanged: syncWorkspaceButtons,
      });

      const params = new URLSearchParams(window.location.search);
      const tearoffTile = params.get("tearoff") ? params.get("tile") : "";
      if (tearoffTile && tileRegistry.has(tearoffTile)) {
        tilingManager.workspaces["1"] = {
          type: "leaf",
          id: "tearoff-leaf",
          tabs: [tearoffTile],
          activeTab: tearoffTile,
        };
        tilingManager.focusedLeafId = "tearoff-leaf";
        tilingManager.render();
      } else {
        try {
          const layoutRes = await API.apiFetch("/api/workspace/layout");
          if (layoutRes && layoutRes.state && layoutRes.state.workspaces) {
            tilingManager.importState(layoutRes.state);
          } else {
            tilingManager.render();
          }
        } catch (_ignored) {
          tilingManager.render();
        }
      }

      syncWorkspaceButtons();
      setupPivotContextMenu();
      setupCommandPalette();
      setupKeyboardShortcuts();

      for (const wsBtn of document.querySelectorAll(".sl-ws-btn")) {
        wsBtn.addEventListener("click", function () {
          tilingManager.switchWorkspace(wsBtn.dataset.ws);
        });
      }

      const btnPalette = document.getElementById("sl-btn-palette");
      const btnSplitV = document.getElementById("sl-btn-split-v");
      const btnSplitS = document.getElementById("sl-btn-split-s");
      const btnZoom = document.getElementById("sl-btn-zoom");
      const btnKS = document.getElementById("sl-btn-killswitch");
      const btnShutdown = document.getElementById("sl-btn-shutdown");

      if (btnPalette) btnPalette.addEventListener("click", function () {
        if (typeof window.__soclensOpenPalette === "function") window.__soclensOpenPalette();
      });
      if (btnSplitV) btnSplitV.addEventListener("click", function () { tilingManager.splitFocused("horizontal"); });
      if (btnSplitS) btnSplitS.addEventListener("click", function () { tilingManager.splitFocused("vertical"); });
      if (btnZoom) btnZoom.addEventListener("click", function () { tilingManager.toggleZoom(); });
      if (btnKS) btnKS.addEventListener("click", async function () {
        const res = await API.apiFetch("/api/ai/kill-switch", {
          method: "POST",
          body: { active: !killSwitchActive },
        });
        applyStatusPayload({ ai_kill_switch_active: res.ai_kill_switch_active });
      });
      if (btnShutdown) btnShutdown.addEventListener("click", function () {
        Tiles.showDoubleConfirmModal(
          "Shutdown SOCLens Server",
          "Stop background triage, dispose database connections, and shut down localhost server?",
          async function () {
            await API.apiFetch("/api/shutdown", { method: "POST", body: {} });
            setStatusMsg("Server shutdown requested. You may close this window.");
          }
        );
      });

      API.onStreamEvent("sse_state", function (ev) {
        const dot = document.getElementById("sl-sse-dot");
        const lbl = document.getElementById("sl-sse-label");
        if (dot) dot.className = "sl-dot " + (ev.state === "connected" ? "connected" : ev.state === "error" ? "error" : "");
        if (lbl) lbl.textContent = "SSE: " + ev.state;
      });
      API.onStreamEvent("status", applyStatusPayload);
      API.onStreamEvent("shutdown", function () {
        setStatusMsg("SOCLens local server has shut down.");
      });
      API.onBroadcastSync(function (msg) {
        if (msg.type === "pivot" && msg.payload && msg.payload.targetTile) {
          const fn = tileHandlers[msg.payload.targetTile];
          if (typeof fn === "function") fn(msg.payload.payload || {});
        }
      });

      API.connectEventStream();
      setStatusMsg("SOCLens ready — profile: " + (status.profile_name || "default") + " (" + (status.dialect || "sqlite") + ")");
    } catch (err) {
      setStatusMsg("Authentication / initialization failed: " + err.message);
    }
  }

  document.addEventListener("DOMContentLoaded", bootstrap);
})();
