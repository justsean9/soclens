(function () {
  "use strict";

  let leafCounter = 1;
  function nextLeafId() {
    leafCounter += 1;
    return "leaf-" + leafCounter;
  }

  function makeLeaf(tabs, activeTab) {
    const cleanTabs = Array.isArray(tabs) && tabs.length ? tabs.slice() : ["research"];
    return {
      type: "leaf",
      id: nextLeafId(),
      tabs: cleanTabs,
      activeTab: cleanTabs.includes(activeTab) ? activeTab : cleanTabs[0],
    };
  }

  function makeDefaultWorkspaces() {
    return {
      "1": makeLeaf(["splunk-es", "research", "rf-intel"], "splunk-es"),
      "2": makeLeaf(["ai-analyst", "logs"], "ai-analyst"),
      "3": makeLeaf(["sentinelone", "splunk-search"], "sentinelone"),
      "4": makeLeaf(["rf-intel", "research"], "rf-intel"),
      "5": makeLeaf(["settings", "logs"], "settings"),
    };
  }

  class BSPTilingManager {
    constructor(rootEl, tileRegistry, options) {
      this.rootEl = rootEl;
      this.tileRegistry = tileRegistry;
      this.onStateChanged = (options && options.onStateChanged) || function () {};
      this.onOpenTile = (options && options.onOpenTile) || function () {};
      this.workspaces = makeDefaultWorkspaces();
      this.activeWorkspace = "1";
      this.focusedLeafId = this.workspaces["1"].id;
      this.zoomedLeafId = null;
      this.dragPayload = null;
      this._persistTimer = null;
      this._leafRects = new Map();
      this._tileInstances = new Map();
    }

    get tree() {
      return this.workspaces[this.activeWorkspace] || this.workspaces["1"];
    }

    set tree(node) {
      this.workspaces[this.activeWorkspace] = node;
    }

    collectLeaves(node, out) {
      const list = out || [];
      if (!node) return list;
      if (node.type === "leaf") {
        list.push(node);
        return list;
      }
      this.collectLeaves(node.first, list);
      this.collectLeaves(node.second, list);
      return list;
    }

    findLeaf(leafId, node) {
      const cur = node || this.tree;
      if (!cur) return null;
      if (cur.type === "leaf") {
        return cur.id === leafId ? cur : null;
      }
      return this.findLeaf(leafId, cur.first) || this.findLeaf(leafId, cur.second);
    }

    findLeafWithTile(tileId) {
      const leaves = this.collectLeaves(this.tree);
      for (const leaf of leaves) {
        if (leaf.tabs.includes(tileId)) return leaf;
      }
      return null;
    }

    getFocusedLeaf() {
      const leaves = this.collectLeaves(this.tree);
      const exact = leaves.find(function (l) {
        return l.id === this.focusedLeafId;
      }, this);
      if (exact) return exact;
      if (leaves.length) {
        this.focusedLeafId = leaves[0].id;
        return leaves[0];
      }
      const created = makeLeaf(["research"], "research");
      this.tree = created;
      this.focusedLeafId = created.id;
      return created;
    }

    getFocusedTileId() {
      const leaf = this.getFocusedLeaf();
      return leaf ? leaf.activeTab : null;
    }

    focusLeaf(leafId) {
      const leaf = this.findLeaf(leafId);
      if (!leaf) return;
      this.focusedLeafId = leaf.id;
      this.render();
      this.onStateChanged(this.exportState());
    }

    openOrFocusTile(tileId, options) {
      const opts = options || {};
      if (!this.tileRegistry.has(tileId)) return null;
      const existing = this.findLeafWithTile(tileId);
      if (existing) {
        existing.activeTab = tileId;
        this.focusedLeafId = existing.id;
        this.render();
        this.schedulePersist();
        return existing;
      }
      const focused = this.getFocusedLeaf();
      if (opts.splitDirection && this.collectLeaves(this.tree).length < 6) {
        this.splitLeaf(focused.id, opts.splitDirection, tileId);
        return this.findLeafWithTile(tileId);
      }
      focused.tabs.push(tileId);
      focused.activeTab = tileId;
      this.focusedLeafId = focused.id;
      this.render();
      this.schedulePersist();
      return focused;
    }

    splitFocused(direction, newTileId) {
      const focused = this.getFocusedLeaf();
      if (!focused) return;
      const candidateTile = newTileId || this._pickUnopenedTile(focused.activeTab);
      this.splitLeaf(focused.id, direction, candidateTile);
    }

    _pickUnopenedTile(fallbackTile) {
      const openSet = new Set();
      for (const leaf of this.collectLeaves(this.tree)) {
        for (const t of leaf.tabs) openSet.add(t);
      }
      for (const id of this.tileRegistry.keys()) {
        if (!openSet.has(id)) return id;
      }
      return fallbackTile || "research";
    }

    splitLeaf(leafId, direction, tileId) {
      let targetTile = this.tileRegistry.has(tileId) ? tileId : "research";
      const existing = this.findLeafWithTile(targetTile);
      if (existing) {
        if (existing.tabs.length > 1) {
          existing.tabs = existing.tabs.filter(function (t) {
            return t !== targetTile;
          });
          if (existing.activeTab === targetTile) {
            existing.activeTab = existing.tabs[0];
          }
        } else if (existing.id === leafId) {
          const unopened = this._pickUnopenedTile(null);
          if (!unopened || this.findLeafWithTile(unopened)) {
            return;
          }
          targetTile = unopened;
        } else {
          const pruned = this._removeLeafNode(this.tree, existing.id);
          if (pruned) {
            this.tree = pruned;
          } else {
            this.focusLeaf(existing.id);
            return;
          }
        }
      }
      const newLeaf = makeLeaf([targetTile], targetTile);
      const splitDir = direction === "vertical" ? "vertical" : "horizontal";
      this.tree = this._replaceLeaf(this.tree, leafId, function (leaf) {
        return {
          type: "split",
          direction: splitDir,
          ratio: 0.5,
          first: leaf,
          second: newLeaf,
        };
      });
      this.zoomedLeafId = null;
      this.focusedLeafId = newLeaf.id;
      this.render();
      this.schedulePersist();
    }

    _replaceLeaf(node, leafId, replacer) {
      if (!node) return node;
      if (node.type === "leaf") {
        return node.id === leafId ? replacer(node) : node;
      }
      return {
        type: "split",
        direction: node.direction,
        ratio: node.ratio,
        first: this._replaceLeaf(node.first, leafId, replacer),
        second: this._replaceLeaf(node.second, leafId, replacer),
      };
    }

    _removeLeafNode(node, leafId) {
      if (!node) return null;
      if (node.type === "leaf") {
        return node.id === leafId ? null : node;
      }
      const left = this._removeLeafNode(node.first, leafId);
      const right = this._removeLeafNode(node.second, leafId);
      if (!left && !right) return null;
      if (!left) return right;
      if (!right) return left;
      return {
        type: "split",
        direction: node.direction,
        ratio: node.ratio,
        first: left,
        second: right,
      };
    }

    closeTileOrLeaf(leafId, tileId) {
      const leaf = this.findLeaf(leafId || this.focusedLeafId);
      if (!leaf) return;
      const targetTab = tileId || leaf.activeTab;
      if (leaf.tabs.length > 1) {
        leaf.tabs = leaf.tabs.filter(function (t) {
          return t !== targetTab;
        });
        if (leaf.activeTab === targetTab) {
          leaf.activeTab = leaf.tabs[0];
        }
        this.render();
        this.schedulePersist();
        return;
      }
      const allLeaves = this.collectLeaves(this.tree);
      if (allLeaves.length <= 1) return;
      const pruned = this._removeLeafNode(this.tree, leaf.id);
      if (pruned) {
        this.tree = pruned;
      }
      if (this.zoomedLeafId === leaf.id) {
        this.zoomedLeafId = null;
      }
      const remaining = this.collectLeaves(this.tree);
      this.focusedLeafId = remaining.length ? remaining[0].id : null;
      this.render();
      this.schedulePersist();
    }

    closeFocused() {
      const leaf = this.getFocusedLeaf();
      if (leaf) this.closeTileOrLeaf(leaf.id, leaf.activeTab);
    }

    toggleZoom() {
      const focused = this.getFocusedLeaf();
      if (!focused) return;
      this.zoomedLeafId = this.zoomedLeafId === focused.id ? null : focused.id;
      this.render();
      this.schedulePersist();
    }

    switchWorkspace(wsKey) {
      const key = String(wsKey);
      if (!this.workspaces[key]) {
        this.workspaces[key] = makeLeaf(["research"], "research");
      }
      this.activeWorkspace = key;
      this.zoomedLeafId = null;
      const leaves = this.collectLeaves(this.tree);
      this.focusedLeafId = leaves.length ? leaves[0].id : null;
      this.render();
      this.schedulePersist();
    }

    focusDirection(dir) {
      const leaves = this.collectLeaves(this.tree);
      if (leaves.length <= 1) return;
      const focused = this.getFocusedLeaf();
      const curRect = this._leafRects.get(focused.id);
      if (!curRect) {
        const idx = leaves.indexOf(focused);
        const nextIdx = (idx + (dir === "left" || dir === "up" ? -1 : 1) + leaves.length) % leaves.length;
        this.focusLeaf(leaves[nextIdx].id);
        return;
      }
      const cx = curRect.left + curRect.width / 2;
      const cy = curRect.top + curRect.height / 2;
      let best = null;
      let bestScore = Infinity;

      for (const leaf of leaves) {
        if (leaf.id === focused.id) continue;
        const r = this._leafRects.get(leaf.id);
        if (!r) continue;
        const lx = r.left + r.width / 2;
        const ly = r.top + r.height / 2;
        const dx = lx - cx;
        const dy = ly - cy;
        if (dir === "left" && dx >= -4) continue;
        if (dir === "right" && dx <= 4) continue;
        if (dir === "up" && dy >= -4) continue;
        if (dir === "down" && dy <= 4) continue;
        const primary = dir === "left" || dir === "right" ? Math.abs(dx) : Math.abs(dy);
        const secondary = dir === "left" || dir === "right" ? Math.abs(dy) : Math.abs(dx);
        const score = primary + secondary * 2.2;
        if (score < bestScore) {
          bestScore = score;
          best = leaf;
        }
      }
      if (best) {
        this.focusLeaf(best.id);
      }
    }

    dockOrSplitDrop(sourceLeafId, tileId, targetLeafId, zone) {
      if (!sourceLeafId || !tileId || !targetLeafId) return;
      if (sourceLeafId === targetLeafId && zone === "center") return;

      const srcLeaf = this.findLeaf(sourceLeafId);
      const tgtLeaf = this.findLeaf(targetLeafId);
      if (!srcLeaf || !tgtLeaf) return;

      if (srcLeaf.id === tgtLeaf.id && srcLeaf.tabs.length <= 1) return;

      srcLeaf.tabs = srcLeaf.tabs.filter(function (t) {
        return t !== tileId;
      });
      if (srcLeaf.tabs.length === 0) {
        const pruned = this._removeLeafNode(this.tree, srcLeaf.id);
        if (pruned) this.tree = pruned;
      } else if (srcLeaf.activeTab === tileId) {
        srcLeaf.activeTab = srcLeaf.tabs[0];
      }

      if (zone === "center") {
        if (!tgtLeaf.tabs.includes(tileId)) {
          tgtLeaf.tabs.push(tileId);
        }
        tgtLeaf.activeTab = tileId;
        this.focusedLeafId = tgtLeaf.id;
      } else {
        const newLeaf = makeLeaf([tileId], tileId);
        const isHoriz = zone === "left" || zone === "right";
        const putFirst = zone === "left" || zone === "top";
        this.tree = this._replaceLeaf(this.tree, tgtLeaf.id, function (leaf) {
          return {
            type: "split",
            direction: isHoriz ? "horizontal" : "vertical",
            ratio: 0.5,
            first: putFirst ? newLeaf : leaf,
            second: putFirst ? leaf : newLeaf,
          };
        });
        this.focusedLeafId = newLeaf.id;
      }

      this.zoomedLeafId = null;
      this.render();
      this.schedulePersist();
    }

    tearOutTile(tileId) {
      const url = "/?tearoff=1&tile=" + encodeURIComponent(tileId);
      window.open(url, "soclens_tile_" + tileId, "width=1120,height=780,resizable=yes");
    }

    exportState() {
      return {
        version: 1,
        activeWorkspace: this.activeWorkspace,
        focusedLeafId: this.focusedLeafId,
        zoomedLeafId: this.zoomedLeafId,
        workspaces: this.workspaces,
      };
    }

    importState(raw) {
      if (!raw || typeof raw !== "object") return;
      if (raw.workspaces && typeof raw.workspaces === "object") {
        const loaded = {};
        for (const k of ["1", "2", "3", "4", "5"]) {
          if (raw.workspaces[k]) {
            loaded[k] = this._sanitizeNode(raw.workspaces[k]);
          }
        }
        if (Object.keys(loaded).length) {
          this.workspaces = Object.assign(makeDefaultWorkspaces(), loaded);
        }
      }
      if (raw.activeWorkspace && this.workspaces[String(raw.activeWorkspace)]) {
        this.activeWorkspace = String(raw.activeWorkspace);
      }
      this.zoomedLeafId = raw.zoomedLeafId || null;
      this.focusedLeafId = raw.focusedLeafId || this.getFocusedLeaf().id;
      this.render();
    }

    _sanitizeNode(node) {
      if (!node || typeof node !== "object") {
        return makeLeaf(["research"], "research");
      }
      if (node.type === "split" && node.first && node.second) {
        return {
          type: "split",
          direction: node.direction === "vertical" ? "vertical" : "horizontal",
          ratio: Math.max(0.15, Math.min(0.85, Number(node.ratio || 0.5))),
          first: this._sanitizeNode(node.first),
          second: this._sanitizeNode(node.second),
        };
      }
      const validTabs = Array.isArray(node.tabs)
        ? node.tabs.filter(function (t) {
            return this.tileRegistry.has(t);
          }, this)
        : [];
      const tabs = validTabs.length ? validTabs : ["research"];
      const resolvedId = String(node.id || nextLeafId());
      const idMatch = /^leaf-(\d+)$/.exec(resolvedId);
      if (idMatch) {
        leafCounter = Math.max(leafCounter, Number(idMatch[1]));
      }
      return {
        type: "leaf",
        id: resolvedId,
        tabs: tabs,
        activeTab: tabs.includes(node.activeTab) ? node.activeTab : tabs[0],
      };
    }

    schedulePersist() {
      this.onStateChanged(this.exportState());
      if (this._persistTimer) clearTimeout(this._persistTimer);
      const self = this;
      this._persistTimer = setTimeout(function () {
        if (window.SOCLensAPI && window.SOCLensAPI.isAuthenticated()) {
          window.SOCLensAPI
            .apiFetch("/api/workspace/layout", {
              method: "POST",
              body: { mode: "tiling", state: self.exportState() },
            })
            .catch(function () {});
        }
      }, 300);
    }

    render() {
      if (!this.rootEl) return;
      // Preserve live tile DOM elements by detaching before re-rendering tree
      for (const entry of this._tileInstances.values()) {
        if (entry.el && entry.el.parentNode) {
          entry.el.parentNode.removeChild(entry.el);
        }
      }
      this.rootEl.innerHTML = "";
      this._leafRects.clear();

      const zoomedLeaf = this.zoomedLeafId ? this.findLeaf(this.zoomedLeafId) : null;
      const rootNode = zoomedLeaf || this.tree;
      const dom = this._renderNode(rootNode);
      this.rootEl.appendChild(dom);

      const self = this;
      requestAnimationFrame(function () {
        for (const leaf of self.collectLeaves(rootNode)) {
          const el = self.rootEl.querySelector('[data-leaf-id="' + leaf.id + '"]');
          if (el) self._leafRects.set(leaf.id, el.getBoundingClientRect());
        }
      });
    }

    _renderNode(node) {
      if (node.type === "leaf") {
        return this._renderLeaf(node);
      }
      const splitEl = document.createElement("div");
      const isHoriz = node.direction !== "vertical";
      splitEl.className = "sl-split " + (isHoriz ? "sl-split-row" : "sl-split-col");

      const firstWrap = document.createElement("div");
      firstWrap.className = "sl-split-child";
      firstWrap.style.flex = String(node.ratio) + " 1 0%";

      const gutter = document.createElement("div");
      gutter.className = "sl-gutter " + (isHoriz ? "sl-gutter-row" : "sl-gutter-col");

      const secondWrap = document.createElement("div");
      secondWrap.className = "sl-split-child";
      secondWrap.style.flex = String(1 - node.ratio) + " 1 0%";

      firstWrap.appendChild(this._renderNode(node.first));
      secondWrap.appendChild(this._renderNode(node.second));

      const self = this;
      gutter.addEventListener("mousedown", function (ev) {
        ev.preventDefault();
        gutter.classList.add("dragging");
        const rect = splitEl.getBoundingClientRect();
        function onMove(moveEv) {
          const span = isHoriz ? rect.width : rect.height;
          if (span <= 20) return;
          const pos = isHoriz ? moveEv.clientX - rect.left : moveEv.clientY - rect.top;
          const nextRatio = Math.max(0.15, Math.min(0.85, pos / span));
          node.ratio = nextRatio;
          firstWrap.style.flex = String(nextRatio) + " 1 0%";
          secondWrap.style.flex = String(1 - nextRatio) + " 1 0%";
        }
        function onUp() {
          gutter.classList.remove("dragging");
          window.removeEventListener("mousemove", onMove);
          window.removeEventListener("mouseup", onUp);
          self.schedulePersist();
        }
        window.addEventListener("mousemove", onMove);
        window.addEventListener("mouseup", onUp);
      });

      splitEl.appendChild(firstWrap);
      splitEl.appendChild(gutter);
      splitEl.appendChild(secondWrap);
      return splitEl;
    }

    _renderLeaf(leaf) {
      const self = this;
      const leafEl = document.createElement("section");
      leafEl.className = "sl-leaf" + (leaf.id === this.focusedLeafId ? " focused" : "");
      leafEl.dataset.leafId = leaf.id;
      leafEl.addEventListener("mousedown", function () {
        if (self.focusedLeafId !== leaf.id) {
          self.focusedLeafId = leaf.id;
          for (const node of self.rootEl.querySelectorAll(".sl-leaf")) {
            node.classList.toggle("focused", node.dataset.leafId === leaf.id);
          }
          self.onStateChanged(self.exportState());
        }
      });

      const header = document.createElement("div");
      header.className = "sl-leaf-header";

      const tabsWrap = document.createElement("div");
      tabsWrap.className = "sl-leaf-tabs";

      for (const tabId of leaf.tabs) {
        const meta = this.tileRegistry.get(tabId);
        if (!meta) continue;
        const tabBtn = document.createElement("button");
        tabBtn.className = "sl-leaf-tab" + (leaf.activeTab === tabId ? " active" : "");
        tabBtn.textContent = meta.title;
        tabBtn.draggable = true;
        tabBtn.title = "Drag to dock or split | Click to focus";
        tabBtn.addEventListener("click", function (ev) {
          ev.stopPropagation();
          leaf.activeTab = tabId;
          self.focusedLeafId = leaf.id;
          self.render();
          self.schedulePersist();
        });
        tabBtn.addEventListener("dragstart", function (ev) {
          self.dragPayload = { sourceLeafId: leaf.id, tileId: tabId };
          if (ev.dataTransfer) {
            ev.dataTransfer.setData("text/plain", tabId);
            ev.dataTransfer.effectAllowed = "move";
          }
        });
        tabsWrap.appendChild(tabBtn);
      }

      const controls = document.createElement("div");
      controls.className = "sl-leaf-controls";

      const splitRightBtn = document.createElement("button");
      splitRightBtn.className = "sl-btn-icon";
      splitRightBtn.textContent = "|";
      splitRightBtn.title = "Split Right (Alt+v)";
      splitRightBtn.addEventListener("click", function (ev) {
        ev.stopPropagation();
        self.focusedLeafId = leaf.id;
        self.splitFocused("horizontal");
      });

      const splitDownBtn = document.createElement("button");
      splitDownBtn.className = "sl-btn-icon";
      splitDownBtn.textContent = "-";
      splitDownBtn.title = "Split Down (Alt+s)";
      splitDownBtn.addEventListener("click", function (ev) {
        ev.stopPropagation();
        self.focusedLeafId = leaf.id;
        self.splitFocused("vertical");
      });

      const tearBtn = document.createElement("button");
      tearBtn.className = "sl-btn-icon";
      tearBtn.textContent = "^";
      tearBtn.title = "Tear off into multi-monitor window";
      tearBtn.addEventListener("click", function (ev) {
        ev.stopPropagation();
        self.tearOutTile(leaf.activeTab);
      });

      const zoomBtn = document.createElement("button");
      zoomBtn.className = "sl-btn-icon";
      zoomBtn.textContent = self.zoomedLeafId === leaf.id ? "z*" : "z";
      zoomBtn.title = "Zoom Toggle (Alt+z)";
      zoomBtn.addEventListener("click", function (ev) {
        ev.stopPropagation();
        self.focusedLeafId = leaf.id;
        self.toggleZoom();
      });

      const closeBtn = document.createElement("button");
      closeBtn.className = "sl-btn-icon";
      closeBtn.textContent = "x";
      closeBtn.title = "Close Tab/Tile (Alt+q)";
      closeBtn.addEventListener("click", function (ev) {
        ev.stopPropagation();
        self.closeTileOrLeaf(leaf.id, leaf.activeTab);
      });

      controls.appendChild(splitRightBtn);
      controls.appendChild(splitDownBtn);
      controls.appendChild(tearBtn);
      controls.appendChild(zoomBtn);
      controls.appendChild(closeBtn);

      header.appendChild(tabsWrap);
      header.appendChild(controls);

      const dropOverlay = document.createElement("div");
      dropOverlay.className = "sl-leaf-drop-overlay";

      leafEl.addEventListener("dragover", function (ev) {
        if (!self.dragPayload) return;
        ev.preventDefault();
        leafEl.classList.add("drag-target");
      });
      leafEl.addEventListener("dragleave", function () {
        leafEl.classList.remove("drag-target");
      });
      leafEl.addEventListener("drop", function (ev) {
        ev.preventDefault();
        leafEl.classList.remove("drag-target");
        if (!self.dragPayload) return;
        const rect = leafEl.getBoundingClientRect();
        const relX = (ev.clientX - rect.left) / Math.max(1, rect.width);
        const relY = (ev.clientY - rect.top) / Math.max(1, rect.height);
        let zone = "center";
        if (relX < 0.22) zone = "left";
        else if (relX > 0.78) zone = "right";
        else if (relY < 0.25) zone = "top";
        else if (relY > 0.75) zone = "bottom";
        const payload = self.dragPayload;
        self.dragPayload = null;
        self.dockOrSplitDrop(payload.sourceLeafId, payload.tileId, leaf.id, zone);
      });

      const body = document.createElement("div");
      body.className = "sl-leaf-body";
      const activeTileId = leaf.activeTab;
      let instance = this._tileInstances.get(activeTileId);
      if (!instance) {
        const meta = this.tileRegistry.get(activeTileId);
        const el = document.createElement("div");
        el.className = "sl-tile-container";
        el.dataset.tileId = activeTileId;
        instance = { el: el, mounted: false };
        this._tileInstances.set(activeTileId, instance);
        if (meta && typeof meta.mount === "function") {
          meta.mount(el);
          instance.mounted = true;
        }
      }
      body.appendChild(instance.el);
      this.onOpenTile(activeTileId);

      leafEl.appendChild(header);
      leafEl.appendChild(dropOverlay);
      leafEl.appendChild(body);
      return leafEl;
    }
  }

  window.SOCLensTiling = {
    BSPTilingManager: BSPTilingManager,
  };
})();
