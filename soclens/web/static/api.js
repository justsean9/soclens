(function () {
  "use strict";

  let csrfToken = "";
  let authReady = false;
  let eventSource = null;
  let reconnectTimer = null;
  const eventListeners = new Map();
  let syncChannel = null;

  try {
    if (typeof BroadcastChannel === "function") {
      syncChannel = new BroadcastChannel("soclens-workspace-sync");
    }
  } catch (_err) {
    syncChannel = null;
  }

  function extractBootstrapTokenFromHash() {
    const rawHash = String(window.location.hash || "");
    if (!rawHash) return "";
    const cleaned = rawHash.startsWith("#") ? rawHash.slice(1) : rawHash;
    const params = new URLSearchParams(cleaned);
    const token = params.get("token") || "";
    if (token && window.history && typeof window.history.replaceState === "function") {
      const cleanUrl = window.location.pathname + window.location.search;
      window.history.replaceState(null, "", cleanUrl);
    }
    return token;
  }

  async function initAuth() {
    const fragmentToken = extractBootstrapTokenFromHash();
    if (fragmentToken) {
      const res = await fetch("/api/auth/exchange", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: fragmentToken }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        throw new Error(data.error || "Bootstrap token exchange failed.");
      }
      csrfToken = String(data.csrf_token || "");
      authReady = true;
      return data;
    }

    const res = await fetch("/api/auth/session", {
      method: "GET",
      credentials: "same-origin",
    });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      throw new Error(data.error || "Session authentication required.");
    }
    csrfToken = String(data.csrf_token || "");
    authReady = true;
    return data;
  }

  async function apiFetch(path, options) {
    const opts = Object.assign({ method: "GET", credentials: "same-origin" }, options || {});
    const method = String(opts.method || "GET").toUpperCase();
    const headers = Object.assign({}, opts.headers || {});
    if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") {
      if (csrfToken) {
        headers["X-SOCLens-Token"] = csrfToken;
      }
      if (opts.body && typeof opts.body === "object" && !(opts.body instanceof FormData)) {
        headers["Content-Type"] = "application/json";
        opts.body = JSON.stringify(opts.body);
      }
    }
    opts.headers = headers;
    const res = await fetch(path, opts);
    const contentType = String(res.headers.get("content-type") || "");
    if (contentType.includes("application/json")) {
      const json = await res.json();
      if (!res.ok) {
        const err = new Error(json.error || ("HTTP " + res.status));
        err.status = res.status;
        err.payload = json;
        throw err;
      }
      return json;
    }
    if (!res.ok) {
      throw new Error("HTTP " + res.status);
    }
    return await res.text();
  }

  async function streamSSEPost(path, body, handlers) {
    const cb = handlers || {};
    const headers = { "Content-Type": "application/json" };
    if (csrfToken) {
      headers["X-SOCLens-Token"] = csrfToken;
    }
    const res = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: headers,
      body: JSON.stringify(body || {}),
    });
    if (!res.ok) {
      let msg = "HTTP " + res.status;
      try {
        const errJson = await res.json();
        msg = errJson.error || msg;
      } catch (_ignored) {}
      throw new Error(msg);
    }
    if (!res.body) {
      throw new Error("Streaming response body unavailable.");
    }
    const reader = res.body.getReader();
    const decoder = new TextDecoder("utf-8");
    let buffer = "";

    function dispatchBlock(block) {
      if (!block.trim()) return;
      let evName = "message";
      const dataLines = [];
      for (const line of block.split(/\r?\n/)) {
        if (line.startsWith(":")) continue;
        if (line.startsWith("event:")) {
          evName = line.slice(6).trim();
        } else if (line.startsWith("data:")) {
          dataLines.push(line.slice(5).trimStart());
        }
      }
      if (!dataLines.length) return;
      const rawData = dataLines.join("\n");
      let parsed = rawData;
      try {
        parsed = JSON.parse(rawData);
      } catch (_ignored) {}
      if (typeof cb.onEvent === "function") {
        cb.onEvent(evName, parsed);
      }
      const specific = cb["on_" + evName];
      if (typeof specific === "function") {
        specific(parsed);
      }
    }

    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      buffer += decoder.decode(chunk.value, { stream: true });
      let idx = buffer.indexOf("\n\n");
      while (idx !== -1) {
        const block = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 2);
        dispatchBlock(block);
        idx = buffer.indexOf("\n\n");
      }
    }
    if (buffer.trim()) {
      dispatchBlock(buffer);
    }
  }

  function emitBusEvent(eventName, detail) {
    const handlers = eventListeners.get(eventName);
    if (!handlers) return;
    for (const fn of handlers) {
      try {
        fn(detail);
      } catch (_err) {}
    }
  }

  function onStreamEvent(eventName, callback) {
    if (!eventListeners.has(eventName)) {
      eventListeners.set(eventName, new Set());
    }
    eventListeners.get(eventName).add(callback);
    return function () {
      const set = eventListeners.get(eventName);
      if (set) set.delete(callback);
    };
  }

  function connectEventStream() {
    if (!authReady) return;
    if (eventSource) {
      eventSource.close();
      eventSource = null;
    }
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    const es = new EventSource("/api/events/stream");
    eventSource = es;

    const types = ["status", "log", "triage_update", "ai_token", "tool_event", "ai_policy_updated", "shutdown"];
    es.onopen = function () {
      emitBusEvent("sse_state", { state: "connected" });
    };
    for (const t of types) {
      es.addEventListener(t, function (ev) {
        let parsed = ev.data;
        try {
          parsed = JSON.parse(ev.data);
        } catch (_ignored) {}
        emitBusEvent(t, parsed);
        if (t === "shutdown") {
          es.close();
          emitBusEvent("sse_state", { state: "shutdown" });
        }
      });
    }
    es.onerror = function () {
      emitBusEvent("sse_state", { state: "error" });
      if (es.readyState === EventSource.CLOSED && !reconnectTimer) {
        reconnectTimer = setTimeout(connectEventStream, 3000);
      }
    };
  }

  function broadcastSync(type, payload) {
    if (!syncChannel) return;
    try {
      syncChannel.postMessage({ type: type, payload: payload, ts: Date.now() });
    } catch (_err) {}
  }

  function onBroadcastSync(handler) {
    if (!syncChannel) return function () {};
    const listener = function (ev) {
      if (ev && ev.data) handler(ev.data);
    };
    syncChannel.addEventListener("message", listener);
    return function () {
      syncChannel.removeEventListener("message", listener);
    };
  }

  window.SOCLensAPI = {
    initAuth: initAuth,
    apiFetch: apiFetch,
    streamSSEPost: streamSSEPost,
    connectEventStream: connectEventStream,
    onStreamEvent: onStreamEvent,
    broadcastSync: broadcastSync,
    onBroadcastSync: onBroadcastSync,
    isAuthenticated: function () {
      return authReady;
    },
  };
})();
