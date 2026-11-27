(function () {
  "use strict";

  const API = window.SOCLensAPI;

  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (k === "className") node.className = v;
        else if (k === "textContent") node.textContent = v;
        else if (k.startsWith("on") && typeof v === "function") {
          node.addEventListener(k.slice(2).toLowerCase(), v);
        } else if (v !== null && v !== undefined) {
          node.setAttribute(k, String(v));
        }
      }
    }
    if (Array.isArray(children)) {
      for (const ch of children) {
        if (ch === null || ch === undefined) continue;
        node.appendChild(typeof ch === "string" ? document.createTextNode(ch) : ch);
      }
    } else if (typeof children === "string") {
      node.textContent = children;
    }
    return node;
  }

  function showDoubleConfirmModal(title, description, onConfirmed) {
    const backdrop = document.getElementById("sl-modal-backdrop");
    const titleEl = document.getElementById("sl-modal-title");
    const bodyEl = document.getElementById("sl-modal-body");
    const footerEl = document.getElementById("sl-modal-footer");
    if (!backdrop || !titleEl || !bodyEl || !footerEl) {
      return;
    }

    let step = 1;
    function renderStep() {
      titleEl.textContent = title + " (Step " + step + " of 2)";
      bodyEl.innerHTML = "";
      footerEl.innerHTML = "";

      if (step === 1) {
        bodyEl.appendChild(el("p", { textContent: description }));
        bodyEl.appendChild(
          el("p", {
            className: "sl-badge sl-badge-warn",
            textContent: "Double Confirmation Required: Review action before proceeding.",
          })
        );
        footerEl.appendChild(
          el("button", {
            className: "sl-btn",
            textContent: "Cancel",
            onClick: closeModal,
          })
        );
        footerEl.appendChild(
          el("button", {
            className: "sl-btn sl-btn-warn",
            textContent: "Continue to Final Confirm (1/2)",
            onClick: function () {
              step = 2;
              renderStep();
            },
          })
        );
      } else {
        bodyEl.appendChild(
          el("p", { textContent: "Final Confirmation: Execute '" + title + "'?" })
        );
        footerEl.appendChild(
          el("button", {
            className: "sl-btn",
            textContent: "Back",
            onClick: function () {
              step = 1;
              renderStep();
            },
          })
        );
        footerEl.appendChild(
          el("button", {
            className: "sl-btn sl-btn-danger",
            textContent: "Confirm & Execute (2/2)",
            onClick: function () {
              closeModal();
              onConfirmed();
            },
          })
        );
      }
    }

    function closeModal() {
      backdrop.classList.add("sl-hidden");
    }

    const closeBtn = document.getElementById("sl-modal-close");
    if (closeBtn) closeBtn.onclick = closeModal;
    backdrop.classList.remove("sl-hidden");
    renderStep();
  }

  function showTeachModal(prefillTitle, prefillContent, onSaved) {
    const backdrop = document.getElementById("sl-modal-backdrop");
    const titleEl = document.getElementById("sl-modal-title");
    const bodyEl = document.getElementById("sl-modal-body");
    const footerEl = document.getElementById("sl-modal-footer");
    if (!backdrop || !titleEl || !bodyEl || !footerEl) return;

    titleEl.textContent = "Teach / Learn from This";
    bodyEl.innerHTML = "";
    footerEl.innerHTML = "";

    const titleInput = el("input", { className: "sl-input", value: prefillTitle || "" });
    const catSelect = el("select", { className: "sl-select" }, [
      el("option", { value: "environment_fact", textContent: "Environment Fact" }),
      el("option", { value: "playbook", textContent: "Playbook" }),
      el("option", { value: "escalation_rule", textContent: "Escalation Rule" }),
      el("option", { value: "benign_tool", textContent: "Known Benign Tool" }),
      el("option", { value: "watchlist", textContent: "Watchlist Context" }),
      el("option", { value: "takeaway", textContent: "Analyst Takeaway" }),
    ]);
    const contentArea = el("textarea", { className: "sl-textarea" });
    contentArea.value = prefillContent || "";
    const statusLine = el("div", { className: "sl-badge sl-hidden" });

    bodyEl.appendChild(el("label", { textContent: "Title" }));
    bodyEl.appendChild(titleInput);
    bodyEl.appendChild(el("label", { textContent: "Category" }));
    bodyEl.appendChild(catSelect);
    bodyEl.appendChild(el("label", { textContent: "Knowledge Content (scanned by security guards)" }));
    bodyEl.appendChild(contentArea);
    bodyEl.appendChild(statusLine);

    function close() {
      backdrop.classList.add("sl-hidden");
    }

    footerEl.appendChild(el("button", { className: "sl-btn", textContent: "Cancel", onClick: close }));
    footerEl.appendChild(
      el("button", {
        className: "sl-btn sl-btn-primary",
        textContent: "Save Active Learning",
        onClick: async function () {
          try {
            const res = await API.apiFetch("/api/knowledge/learn", {
              method: "POST",
              body: {
                title: titleInput.value.trim(),
                content: contentArea.value.trim(),
                category: catSelect.value,
              },
            });
            close();
            if (typeof onSaved === "function") onSaved(res.entry);
          } catch (err) {
            statusLine.textContent = err.message;
            statusLine.className = "sl-badge sl-badge-danger";
          }
        },
      })
    );

    const closeBtn = document.getElementById("sl-modal-close");
    if (closeBtn) closeBtn.onclick = close;
    backdrop.classList.remove("sl-hidden");
  }

  function renderFormattedTable(rows, columns, opts) {
    const options = opts || {};
    const wrap = el("div", { className: "sl-table-wrap" });
    const table = el("table", { className: "sl-table" });
    const thead = el("thead");
    const headRow = el("tr");
    for (const col of columns) {
      headRow.appendChild(el("th", { textContent: col.label }));
    }
    if (options.actions) {
      headRow.appendChild(el("th", { textContent: "Actions" }));
    }
    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = el("tbody");
    if (!rows || !rows.length) {
      const emptyTr = el("tr");
      const emptyTd = el("td", {
        colspan: String(columns.length + (options.actions ? 1 : 0)),
        textContent: options.emptyText || "No records found.",
      });
      emptyTr.appendChild(emptyTd);
      tbody.appendChild(emptyTr);
    } else {
      for (const row of rows) {
        const tr = el("tr");
        for (const col of columns) {
          const rawVal = typeof col.get === "function" ? col.get(row) : row[col.key];
          const text = rawVal === null || rawVal === undefined ? "-" : String(rawVal);
          const td = el("td");
          if (col.pivot && text && text !== "-") {
            const span = el("span", {
              className: "sl-pivotable",
              textContent: text,
              "data-pivot-value": text,
              "data-pivot-field": col.label,
            });
            td.appendChild(span);
          } else {
            td.textContent = text;
          }
          tr.appendChild(td);
        }
        if (options.actions) {
          const tdAct = el("td");
          for (const act of options.actions(row)) {
            tdAct.appendChild(act);
          }
          tr.appendChild(tdAct);
        }
        if (typeof options.onRowClick === "function") {
          tr.style.cursor = "pointer";
          tr.addEventListener("click", function () {
            options.onRowClick(row);
          });
        }
        tbody.appendChild(tr);
      }
    }
    table.appendChild(tbody);
    wrap.appendChild(table);
    return wrap;
  }

  function createRawJsonWrapper() {
    let rawMode = false;
    let lastData = null;
    const toggleBtn = el("button", { className: "sl-btn", textContent: "Raw JSON: OFF" });
    const formattedHost = el("div", { className: "sl-formatted-host" });
    const rawPre = el("pre", { className: "sl-pre-json sl-hidden" });

    toggleBtn.addEventListener("click", function () {
      rawMode = !rawMode;
      toggleBtn.textContent = rawMode ? "Raw JSON: ON" : "Raw JSON: OFF";
      formattedHost.classList.toggle("sl-hidden", rawMode);
      rawPre.classList.toggle("sl-hidden", !rawMode);
    });

    function setData(data, renderFormattedFn) {
      lastData = data;
      rawPre.textContent = JSON.stringify(lastData, null, 2);
      formattedHost.innerHTML = "";
      if (typeof renderFormattedFn === "function") {
        renderFormattedFn(formattedHost, data);
      }
    }

    return { toggleBtn: toggleBtn, formattedHost: formattedHost, rawPre: rawPre, setData: setData };
  }

  function buildTileRegistry(appCtx) {
    const registry = new Map();
    const handlers = {};

    function pivotTo(targetTile, payload) {
      appCtx.pivotTo(targetTile, payload);
    }

    // 1. Splunk ES & Mission Control
    registry.set("splunk-es", {
      id: "splunk-es",
      title: "Splunk ES",
      admin: false,
      mount: function (root) {
        const viewSel = el("select", { className: "sl-select" }, [
          el("option", { value: "notables", textContent: "Notable Events" }),
          el("option", { value: "correlations", textContent: "Correlation Searches" }),
          el("option", { value: "threat_intel", textContent: "Threat Intel" }),
          el("option", { value: "assets_identities", textContent: "Assets & Identities" }),
          el("option", { value: "risk", textContent: "Risk Events (RBA)" }),
        ]);
        const queryInput = el("input", { className: "sl-input", placeholder: "Filter / entity..." });
        const loadBtn = el("button", { className: "sl-btn sl-btn-primary", textContent: "Load Cached" });
        const liveBtn = el("button", { className: "sl-btn", textContent: "Fetch Live ES" });
        const wrapper = createRawJsonWrapper();
        const statusBadge = el("span", { className: "sl-badge", textContent: "Ready" });
        const detailBox = el("div", { className: "sl-card" });

        async function loadES(live) {
          statusBadge.textContent = "Loading...";
          try {
            const url =
              "/api/splunk-es/notables?view=" +
              encodeURIComponent(viewSel.value) +
              "&q=" +
              encodeURIComponent(queryInput.value.trim()) +
              (live ? "&live=1" : "");
            const data = await API.apiFetch(url);
            statusBadge.textContent = (data.items || []).length + " item(s) [" + (data.source || "") + "]";
            wrapper.setData(data, function (host, d) {
              host.appendChild(
                renderFormattedTable(
                  d.items || [],
                  [
                    { key: "rule_name", label: "Rule / Title", get: function (r) { return r.rule_name || r.search_name || r.name || r.title || "-"; } },
                    { key: "urgency", label: "Urgency", get: function (r) { return r.urgency || r.severity || "-"; } },
                    { key: "status_label", label: "Status", get: function (r) { return r.status_label || r.status || "-"; } },
                    { key: "src", label: "Src / Host", pivot: true, get: function (r) { return r.src || r.host || r.dest || "-"; } },
                    { key: "owner", label: "Owner", get: function (r) { return r.owner || "unassigned"; } },
                  ],
                  {
                    onRowClick: function (row) {
                      detailBox.innerHTML = "";
                      detailBox.appendChild(el("div", { className: "sl-card-title", textContent: row.rule_name || row.title || "ES Event" }));
                      detailBox.appendChild(el("div", { textContent: JSON.stringify(row).slice(0, 400) }));
                      const btnRow = el("div", { className: "sl-toolbar" });
                      btnRow.appendChild(
                        el("button", {
                          className: "sl-btn sl-btn-primary",
                          textContent: "AI: Ask Only",
                          onClick: function () {
                            pivotTo("ai-analyst", { mode: "ask_only", event: row, title: row.rule_name || "ES Event" });
                          },
                        })
                      );
                      btnRow.appendChild(
                        el("button", {
                          className: "sl-btn",
                          textContent: "AI: Full Investigate",
                          onClick: function () {
                            pivotTo("ai-analyst", { mode: "full_investigation", event: row, title: row.rule_name || "ES Event" });
                          },
                        })
                      );
                      btnRow.appendChild(
                        el("button", {
                          className: "sl-btn",
                          textContent: "Learn from This",
                          onClick: function () {
                            showTeachModal(row.rule_name || "ES Rule Note", JSON.stringify(row, null, 2));
                          },
                        })
                      );
                      detailBox.appendChild(btnRow);
                    },
                  }
                )
              );
            });
          } catch (err) {
            statusBadge.textContent = err.message;
          }
        }

        loadBtn.addEventListener("click", function () { loadES(false); });
        liveBtn.addEventListener("click", function () { loadES(true); });
        root.appendChild(el("div", { className: "sl-toolbar" }, [viewSel, queryInput, loadBtn, liveBtn, wrapper.toggleBtn, statusBadge]));
        root.appendChild(wrapper.formattedHost);
        root.appendChild(wrapper.rawPre);
        root.appendChild(detailBox);
        loadES(false);
      },
    });

    // 2. Threat Research (RF + 16 OSINT)
    registry.set("research", {
      id: "research",
      title: "Research",
      admin: false,
      mount: function (root) {
        const targetInput = el("input", { className: "sl-input", placeholder: "IP, domain, hash, CVE, URL..." });
        const rfCb = el("input", { type: "checkbox", checked: "checked" });
        const osintCb = el("input", { type: "checkbox", checked: "checked" });
        const runBtn = el("button", { className: "sl-btn sl-btn-primary", textContent: "Research Target" });
        const statusBadge = el("span", { className: "sl-badge", textContent: "RF + 16 Passive OSINT" });
        const wrapper = createRawJsonWrapper();

        async function runResearch(targetVal) {
          const target = (targetVal || targetInput.value).trim();
          if (!target) return;
          targetInput.value = target;
          statusBadge.textContent = "Querying RF + OSINT...";
          try {
            const data = await API.apiFetch("/api/research", {
              method: "POST",
              body: {
                target: target,
                include_rf: rfCb.checked,
                include_osint: osintCb.checked,
              },
            });
            const dossier = data.dossier || {};
            const tgtObj = dossier.target && typeof dossier.target === "object" ? dossier.target : null;
            const tgtDisplay = tgtObj
              ? (tgtObj.raw_query || tgtObj.canonical_name || target)
              : (dossier.target || target);
            statusBadge.textContent = "Target: " + tgtDisplay;
            wrapper.setData(dossier, function (host, d) {
              const tObj = d.target && typeof d.target === "object" ? d.target : null;
              const tDisplay = tObj
                ? (tObj.raw_query || tObj.canonical_name || target)
                : (d.target || target);
              const tType = (tObj && (tObj.detected_kind || tObj.rf_type)) || d.entity_type || "-";
              const verdict = d.unified_verdict && typeof d.unified_verdict === "object" ? d.unified_verdict : {};
              const riskDisplay = d.risk_score !== null && d.risk_score !== undefined
                ? String(d.risk_score) + (d.criticality_label ? " (" + d.criticality_label + ")" : "")
                : (d.risk_string || "-");
              const cards = el("div", { className: "sl-card-grid" });
              const summaryNodes = [
                el("div", { className: "sl-card-title", textContent: "Indicator Summary" }),
                el("div", { textContent: "Target: " + tDisplay }),
                el("div", { textContent: "Type: " + tType }),
                el("div", { textContent: "Risk Score: " + riskDisplay }),
                el("div", {
                  textContent:
                    "Verdict: " +
                    (verdict.label || verdict.level || "-") +
                    (verdict.summary ? " — " + verdict.summary : ""),
                }),
              ];
              if (verdict.rf_sources_ok !== undefined || verdict.osint_sources_ok !== undefined) {
                summaryNodes.push(
                  el("div", {
                    textContent:
                      "Sources OK: RF=" +
                      (verdict.rf_sources_ok ?? 0) +
                      " | OSINT=" +
                      (verdict.osint_sources_ok ?? 0) +
                      (verdict.osint_sources_total ? "/" + verdict.osint_sources_total : ""),
                  })
                );
              }
              if (d.ai_summary) {
                summaryNodes.push(el("div", { textContent: "Summary: " + String(d.ai_summary).slice(0, 240) }));
              }
              cards.appendChild(el("div", { className: "sl-card" }, summaryNodes));

              function formatSectionBody(sec) {
                if (!sec || typeof sec !== "object") return String(sec || "-");
                const parts = [];
                if (sec.message) parts.push(String(sec.message));
                if (sec.data !== null && sec.data !== undefined) {
                  if (typeof sec.data === "string") {
                    parts.push(sec.data);
                  } else if (Array.isArray(sec.data)) {
                    parts.push(sec.data.length + " item(s): " + JSON.stringify(sec.data.slice(0, 3)));
                  } else if (typeof sec.data === "object") {
                    const kv = Object.entries(sec.data)
                      .slice(0, 6)
                      .map(function (entry) {
                        const v = entry[1];
                        const s = typeof v === "object" && v !== null ? JSON.stringify(v) : String(v);
                        return entry[0] + "=" + s;
                      })
                      .join(", ");
                    if (kv) parts.push(kv);
                  } else {
                    parts.push(String(sec.data));
                  }
                }
                const combined = parts.join(" — ").trim();
                return combined ? combined.slice(0, 260) : "Status: " + (sec.status || "ok");
              }

              const sectionsObj = d.sections && typeof d.sections === "object" ? d.sections : null;
              if (sectionsObj) {
                for (const [secKey, sec] of Object.entries(sectionsObj)) {
                  if (!sec || typeof sec !== "object") continue;
                  const grp = sec.source_group ? "[" + String(sec.source_group).toUpperCase() + "] " : "";
                  const cnt = sec.count ? " (" + sec.count + ")" : "";
                  const st = sec.status ? " · " + sec.status : "";
                  cards.appendChild(
                    el("div", { className: "sl-card" }, [
                      el("div", {
                        className: "sl-card-title",
                        textContent: grp + (sec.title || secKey) + cnt + st,
                      }),
                      el("div", { textContent: formatSectionBody(sec) }),
                    ])
                  );
                }
              } else {
                const findings = d.findings || d.osint_results || [];
                if (Array.isArray(findings)) {
                  for (const f of findings.slice(0, 12)) {
                    cards.appendChild(
                      el("div", { className: "sl-card" }, [
                        el("div", { className: "sl-card-title", textContent: f.source || f.module || "Source" }),
                        el("div", { textContent: f.summary || JSON.stringify(f).slice(0, 220) }),
                      ])
                    );
                  }
                }
              }
              host.appendChild(cards);
            });
          } catch (err) {
            statusBadge.textContent = err.message;
          }
        }

        handlers.research = function (payload) {
          if (payload && payload.indicator) runResearch(payload.indicator);
        };

        runBtn.addEventListener("click", function () { runResearch(); });
        root.appendChild(
          el("div", { className: "sl-toolbar" }, [
            targetInput,
            el("label", {}, [rfCb, " RF"]),
            el("label", {}, [osintCb, " OSINT"]),
            runBtn,
            wrapper.toggleBtn,
            statusBadge,
          ])
        );
        root.appendChild(wrapper.formattedHost);
        root.appendChild(wrapper.rawPre);
      },
    });

    // 3. RF Intel & Playbook Alerts (with privacy-blurred PNG screenshots)
    registry.set("rf-intel", {
      id: "rf-intel",
      title: "RF Intel",
      admin: false,
      mount: function (root) {
        const modeSel = el("select", { className: "sl-select" }, [
          el("option", { value: "alerts_v3", textContent: "Alerts v3" }),
          el("option", { value: "playbook", textContent: "Playbook Alerts" }),
          el("option", { value: "cases", textContent: "Cases" }),
        ]);
        const qInput = el("input", { className: "sl-input", placeholder: "Filter alerts..." });
        const loadBtn = el("button", { className: "sl-btn sl-btn-primary", textContent: "Load Alerts" });
        const liveBtn = el("button", { className: "sl-btn", textContent: "Fetch Live" });
        const statusBadge = el("span", { className: "sl-badge", textContent: "Ready" });
        const wrapper = createRawJsonWrapper();
        const mediaArea = el("div", { className: "sl-card-grid" });

        async function loadRF(live) {
          statusBadge.textContent = "Loading...";
          try {
            const data = await API.apiFetch(
              "/api/rf/alerts?mode=" +
                encodeURIComponent(modeSel.value) +
                "&q=" +
                encodeURIComponent(qInput.value.trim()) +
                (live ? "&live=1" : "")
            );
            statusBadge.textContent = (data.items || []).length + " alert(s)";
            mediaArea.innerHTML = "";
            const imageKeys = data.image_keys || {};
            for (const [aid, entries] of Object.entries(imageKeys)) {
              if (!Array.isArray(entries)) continue;
              for (const rec of entries) {
                const imgKey = Array.isArray(rec) ? rec[2] : rec;
                if (!imgKey) continue;
                const img = el("img", {
                  className: "sl-rf-screenshot",
                  src: "/api/alerts/image/" + encodeURIComponent(imgKey),
                  alt: "Playbook screenshot " + aid,
                  title: "Click to toggle privacy blur (filter: blur(14px))",
                });
                img.addEventListener("click", function () {
                  img.classList.toggle("unblurred");
                });
                mediaArea.appendChild(
                  el("div", { className: "sl-card" }, [
                    el("div", { className: "sl-card-title", textContent: "Playbook Screenshot (" + aid + ")" }),
                    img,
                    el("small", { textContent: "Blurred by default — click image to toggle clarity" }),
                  ])
                );
              }
            }

            wrapper.setData(data, function (host, d) {
              host.appendChild(
                renderFormattedTable(d.items || [], [
                  { key: "id", label: "ID", pivot: true, get: function (r) { return r.id || r.alert_id || "-"; } },
                  { key: "title", label: "Title / Rule", get: function (r) { return r.title || r.rule_name || r.category || "-"; } },
                  { key: "priority", label: "Priority", get: function (r) { return r.priority || r.severity || "-"; } },
                  { key: "status", label: "Status", get: function (r) { return r.status || "-"; } },
                  { key: "primary_entity", label: "Entity", pivot: true, get: function (r) { return r.primary_entity || "-"; } },
                ])
              );
            });
          } catch (err) {
            statusBadge.textContent = err.message;
          }
        }

        handlers["rf-intel"] = function (payload) {
          if (payload && payload.indicator) {
            qInput.value = payload.indicator;
            loadRF(false);
          }
        };

        loadBtn.addEventListener("click", function () { loadRF(false); });
        liveBtn.addEventListener("click", function () { loadRF(true); });
        root.appendChild(el("div", { className: "sl-toolbar" }, [modeSel, qInput, loadBtn, liveBtn, wrapper.toggleBtn, statusBadge]));
        root.appendChild(wrapper.formattedHost);
        root.appendChild(wrapper.rawPre);
        root.appendChild(mediaArea);
        loadRF(false);
      },
    });

    // 4. SentinelOne EDR
    registry.set("sentinelone", {
      id: "sentinelone",
      title: "SentinelOne",
      admin: false,
      mount: function (root) {
        const viewSel = el("select", { className: "sl-select" }, [
          el("option", { value: "threats", textContent: "Threats & Alerts" }),
          el("option", { value: "agents", textContent: "Endpoints / Agents" }),
          el("option", { value: "sites", textContent: "Sites" }),
          el("option", { value: "exclusions", textContent: "Exclusions" }),
          el("option", { value: "blocklist", textContent: "Blocklist" }),
        ]);
        const qInput = el("input", { className: "sl-input", placeholder: "Search host, hash, threat..." });
        const loadBtn = el("button", { className: "sl-btn sl-btn-primary", textContent: "Load" });
        const liveBtn = el("button", { className: "sl-btn", textContent: "Fetch Live" });
        const statusBadge = el("span", { className: "sl-badge", textContent: "Ready" });
        const wrapper = createRawJsonWrapper();

        async function loadS1(live) {
          statusBadge.textContent = "Loading...";
          try {
            const view = viewSel.value;
            let url = "/api/sentinelone/threats?q=" + encodeURIComponent(qInput.value.trim()) + (live ? "&live=1" : "");
            if (view === "agents") url = "/api/sentinelone/agents?q=" + encodeURIComponent(qInput.value.trim());
            else if (view !== "threats") url = "/api/sentinelone/" + encodeURIComponent(view);
            const data = await API.apiFetch(url);
            statusBadge.textContent = (data.items || []).length + " record(s)";
            wrapper.setData(data, function (host, d) {
              host.appendChild(
                renderFormattedTable(
                  d.items || [],
                  [
                    { key: "id", label: "ID", get: function (r) { return r.id || (r.threatInfo && r.threatInfo.threatId) || (r.alertInfo && r.alertInfo.alertId) || "-"; } },
                    {
                      key: "name",
                      label: "Threat / Host",
                      pivot: true,
                      get: function (r) {
                        return (
                          r.threatName ||
                          (r.threatInfo && r.threatInfo.threatName) ||
                          (r.ruleInfo && r.ruleInfo.name) ||
                          r.computerName ||
                          (r.agentRealtimeInfo && r.agentRealtimeInfo.agentComputerName) ||
                          (r.agentDetectionInfo && r.agentDetectionInfo.agentDomain) ||
                          r.name ||
                          r.value ||
                          "-"
                        );
                      },
                    },
                    {
                      key: "site",
                      label: "Site",
                      get: function (r) {
                        return (
                          r.siteName ||
                          (r.agentRealtimeInfo && r.agentRealtimeInfo.siteName) ||
                          (r.agentDetectionInfo && r.agentDetectionInfo.siteName) ||
                          r.siteId ||
                          (r.agentRealtimeInfo && r.agentRealtimeInfo.siteId) ||
                          "-"
                        );
                      },
                    },
                    {
                      key: "verdict",
                      label: "Verdict / Status",
                      get: function (r) {
                        return (
                          r.analystVerdict ||
                          (r.threatInfo && r.threatInfo.analystVerdict) ||
                          (r.alertInfo && r.alertInfo.analystVerdict) ||
                          r.incidentStatus ||
                          (r.threatInfo && r.threatInfo.incidentStatus) ||
                          r.mitigationStatus ||
                          (r.threatInfo && r.threatInfo.mitigationStatus) ||
                          r.networkStatus ||
                          "-"
                        );
                      },
                    },
                    {
                      key: "hash",
                      label: "SHA1 / IP",
                      pivot: true,
                      get: function (r) {
                        return (
                          r.sha1 ||
                          (r.threatInfo && (r.threatInfo.sha1 || r.threatInfo.sha256)) ||
                          r.lastIpToMgmt ||
                          (r.agentRealtimeInfo && r.agentRealtimeInfo.agentIpV4) ||
                          (r.agentDetectionInfo && r.agentDetectionInfo.agentIpV4) ||
                          "-"
                        );
                      },
                    },
                  ],
                  {
                    actions: function (row) {
                      const btns = [];
                      if (view === "agents" && row.id) {
                        const compName = row.computerName || (row.agentRealtimeInfo && row.agentRealtimeInfo.agentComputerName) || row.id;
                        btns.push(
                          el("button", {
                            className: "sl-btn sl-btn-danger",
                            textContent: "Isolate",
                            onClick: function (ev) {
                              ev.stopPropagation();
                              showDoubleConfirmModal(
                                "SentinelOne Isolate Endpoint",
                                "Disconnect endpoint " + compName + " from network?",
                                async function () {
                                  await API.apiFetch("/api/sentinelone/action", {
                                    method: "POST",
                                    body: { action: "disconnect", ids: [row.id], double_confirmed: true },
                                  });
                                  loadS1(true);
                                }
                              );
                            },
                          })
                        );
                      }
                      return btns;
                    },
                  }
                )
              );
            });
          } catch (err) {
            statusBadge.textContent = err.message;
          }
        }

        loadBtn.addEventListener("click", function () { loadS1(false); });
        liveBtn.addEventListener("click", function () { loadS1(true); });
        root.appendChild(el("div", { className: "sl-toolbar" }, [viewSel, qInput, loadBtn, liveBtn, wrapper.toggleBtn, statusBadge]));
        root.appendChild(wrapper.formattedHost);
        root.appendChild(wrapper.rawPre);
        loadS1(false);
      },
    });

    // 5. Splunk Search (Read-Only SPL)
    registry.set("splunk-search", {
      id: "splunk-search",
      title: "Splunk Search",
      admin: false,
      mount: function (root) {
        const splArea = el("textarea", {
          className: "sl-textarea",
          placeholder: "index=* earliest=-24h | head 50 (Read-only SPL enforced)",
        });
        splArea.value = "search index=* | head 50";
        const earliestInput = el("input", { className: "sl-input", value: "-24h", style: "width:90px" });
        const latestInput = el("input", { className: "sl-input", value: "now", style: "width:90px" });
        const runBtn = el("button", { className: "sl-btn sl-btn-primary", textContent: "Run Read-Only SPL" });
        const statusBadge = el("span", { className: "sl-badge", textContent: "Read-only SPL" });
        const wrapper = createRawJsonWrapper();

        async function runSpl() {
          statusBadge.textContent = "Searching...";
          try {
            const data = await API.apiFetch("/api/splunk/search", {
              method: "POST",
              body: {
                spl: splArea.value,
                earliest: earliestInput.value.trim() || "-24h",
                latest: latestInput.value.trim() || "now",
              },
            });
            const res = data.result || {};
            const rows = res.results || res.events || [];
            statusBadge.textContent = rows.length + " row(s)";
            wrapper.setData(res, function (host) {
              const cols = rows.length
                ? Object.keys(rows[0]).slice(0, 6).map(function (k) {
                    return { key: k, label: k, pivot: true };
                  })
                : [{ key: "raw", label: "Result" }];
              host.appendChild(renderFormattedTable(rows, cols));
            });
          } catch (err) {
            statusBadge.textContent = err.message;
          }
        }

        handlers["splunk-search"] = function (payload) {
          if (payload && payload.spl) {
            splArea.value = payload.spl;
          } else if (payload && payload.indicator) {
            splArea.value = 'index=* "' + String(payload.indicator).replace(/"/g, '\\"') + '"';
          }
        };

        runBtn.addEventListener("click", runSpl);
        root.appendChild(el("div", { className: "sl-toolbar" }, [earliestInput, latestInput, runBtn, wrapper.toggleBtn, statusBadge]));
        root.appendChild(splArea);
        root.appendChild(wrapper.formattedHost);
        root.appendChild(wrapper.rawPre);
      },
    });

    // 6. AI Analyst & Copilot (Chat SSE, Event Panels, Control Panel, Audit, Knowledge/Self-Learning)
    registry.set("ai-analyst", {
      id: "ai-analyst",
      title: "AI Analyst",
      admin: false,
      mount: function (root) {
        let activeSub = "chat";
        let activeMode = "full_investigation";
        const sessions = new Map([["chat-1", []]]);
        let currentSessionId = "chat-1";
        let attachedContext = "";
        let attachedTitle = "";

        const subBar = el("div", { className: "sl-subtabs" });
        const subBody = el("div", { className: "sl-leaf-body", style: "padding:0;" });

        const subDefs = [
          { id: "chat", label: "AI Chat (SSE)" },
          { id: "panels", label: "Event AI Panels" },
          { id: "policy", label: "AI Control Panel" },
          { id: "audit", label: "Audit Log" },
          { id: "knowledge", label: "Knowledge & Learning" },
        ];
        const subBtns = {};
        for (const sd of subDefs) {
          const btn = el("button", {
            className: "sl-subtab-btn" + (sd.id === activeSub ? " active" : ""),
            textContent: sd.label,
            onClick: function () {
              activeSub = sd.id;
              for (const k of Object.keys(subBtns)) {
                subBtns[k].classList.toggle("active", k === activeSub);
              }
              renderSub();
            },
          });
          subBtns[sd.id] = btn;
          subBar.appendChild(btn);
        }

        function renderChat() {
          subBody.innerHTML = "";
          const sessSel = el("select", { className: "sl-select" });
          for (const sid of sessions.keys()) {
            sessSel.appendChild(el("option", { value: sid, textContent: sid }));
          }
          sessSel.value = currentSessionId;
          sessSel.addEventListener("change", function () {
            currentSessionId = sessSel.value;
            renderChat();
          });

          const newChatBtn = el("button", {
            className: "sl-btn",
            textContent: "+ Chat",
            onClick: function () {
              const nextId = "chat-" + (sessions.size + 1);
              sessions.set(nextId, []);
              currentSessionId = nextId;
              renderChat();
            },
          });

          const modeSel = el("select", { className: "sl-select" }, [
            el("option", { value: "full_investigation", textContent: "Full Investigation (Tools ON)" }),
            el("option", { value: "ask_only", textContent: "Ask About Event Only (No Tools)" }),
          ]);
          modeSel.value = activeMode;
          modeSel.addEventListener("change", function () {
            activeMode = modeSel.value;
          });
          const providerSel = el("select", { className: "sl-select" }, [
            el("option", { value: "", textContent: "Provider: Default" }),
            el("option", { value: "ollama", textContent: "Ollama" }),
            el("option", { value: "openai", textContent: "OpenAI-Compatible" }),
            el("option", { value: "gemini", textContent: "Gemini" }),
            el("option", { value: "m365_copilot", textContent: "M365 Copilot" }),
            el("option", { value: "copilot_studio", textContent: "Copilot Studio" }),
            el("option", { value: "copilot_directline", textContent: "Copilot Direct Line" }),
            el("option", { value: "security_copilot", textContent: "Security Copilot" }),
          ]);
          const teachBtn = el("button", {
            className: "sl-btn",
            textContent: "Teach / Learn",
            onClick: function () {
              showTeachModal("", attachedContext || "", function () {
                activeSub = "knowledge";
                renderSub();
              });
            },
          });

          const transcript = el("div", { className: "sl-chat-transcript" });
          const hist = sessions.get(currentSessionId) || [];
          for (const msg of hist) {
            transcript.appendChild(
              el("div", {
                className: "sl-chat-msg " + (msg.role || "assistant"),
                textContent: (msg.role === "user" ? "You: " : msg.role === "tool" ? "[Tool] " : "AI: ") + msg.content,
              })
            );
          }

          const attachInfo = el("div", {
            className: "sl-badge " + (attachedContext ? "sl-badge-info" : "sl-hidden"),
            textContent: attachedContext ? "Attached: " + (attachedTitle || "Context") : "",
          });

          const promptInput = el("input", {
            className: "sl-input",
            style: "flex:1 1 auto;",
            placeholder: "Ask AI analyst or type /learn <lesson>...",
          });
          const sendBtn = el("button", { className: "sl-btn sl-btn-primary", textContent: "Send (SSE)" });

          async function sendChat() {
            const prompt = promptInput.value.trim();
            if (!prompt && !attachedContext) return;
            promptInput.value = "";
            hist.push({ role: "user", content: prompt || "(Analyze attached context)" });
            const assistantMsg = { role: "assistant", content: "" };
            hist.push(assistantMsg);
            renderChat();

            try {
              await API.streamSSEPost(
                "/api/ai/chat/stream",
                {
                  prompt: prompt,
                  session_id: currentSessionId,
                  mode: modeSel.value,
                  provider: providerSel.value || undefined,
                  attached_context: attachedContext || undefined,
                  attached_title: attachedTitle || undefined,
                  history: hist.slice(0, -2).filter(function (m) {
                    return m.role === "user" || m.role === "assistant";
                  }),
                },
                {
                  on_token: function (ev) {
                    assistantMsg.content += ev.token || "";
                    const nodes = transcript.querySelectorAll(".sl-chat-msg");
                    if (nodes.length) nodes[nodes.length - 1].textContent = "AI: " + assistantMsg.content;
                  },
                  on_tool: function (ev) {
                    hist.splice(hist.length - 1, 0, {
                      role: "tool",
                      content: (ev.tool_name || ev.kind || "tool") + " " + JSON.stringify(ev.args || ev),
                    });
                  },
                  on_learn_preview: function (ev) {
                    assistantMsg.content = "Opening Teach modal for: " + (ev.title || "");
                    showTeachModal(ev.title || "", ev.content || "", function () {
                      activeSub = "knowledge";
                      renderSub();
                    });
                  },
                  on_done: function (ev) {
                    if (!assistantMsg.content && ev.content) {
                      assistantMsg.content = ev.content;
                    }
                    renderChat();
                  },
                  on_error: function (ev) {
                    assistantMsg.content = "Error: " + (ev.error || "Unknown error");
                    renderChat();
                  },
                }
              );
            } catch (err) {
              assistantMsg.content = "Error: " + err.message;
              renderChat();
            }
          }

          sendBtn.addEventListener("click", sendChat);
          promptInput.addEventListener("keydown", function (ev) {
            if (ev.key === "Enter" && !ev.shiftKey) {
              ev.preventDefault();
              sendChat();
            }
          });

          subBody.appendChild(el("div", { className: "sl-toolbar" }, [sessSel, newChatBtn, modeSel, providerSel, teachBtn]));
          subBody.appendChild(attachInfo);
          subBody.appendChild(transcript);
          subBody.appendChild(el("div", { className: "sl-toolbar" }, [promptInput, sendBtn]));
        }

        async function renderPanels() {
          subBody.innerHTML = "<div class='sl-badge'>Loading Event AI Panels...</div>";
          const data = await API.apiFetch("/api/ai/panels");
          subBody.innerHTML = "";
          const rows = data.panels || [];
          subBody.appendChild(
            renderFormattedTable(rows, [
              { key: "event_key", label: "Event Key" },
              { key: "mode", label: "Mode" },
              { key: "provider", label: "Provider" },
              { key: "status", label: "Status" },
              { key: "answer_markdown", label: "Summary", get: function (r) { return String(r.answer_markdown || "").slice(0, 180); } },
            ])
          );
        }

        async function renderPolicy() {
          subBody.innerHTML = "<div class='sl-badge'>Loading AI Policy...</div>";
          const data = await API.apiFetch("/api/ai/policy");
          const pol = data.policy || {};
          subBody.innerHTML = "";

          const learningSel = el("select", { className: "sl-select" }, [
            el("option", { value: "manual", textContent: "manual (Pending Queue default)" }),
            el("option", { value: "auto", textContent: "auto (Auto-promote high confidence)" }),
          ]);
          learningSel.value = pol.learning_mode || "manual";

          const bgCb = el("input", { type: "checkbox" });
          bgCb.checked = Boolean(pol.background_triage_enabled);
          const localDbCb = el("input", { type: "checkbox" });
          localDbCb.checked = Boolean(pol.local_db_enabled);

          const saveBtn = el("button", {
            className: "sl-btn sl-btn-primary",
            textContent: "Save AI Policy",
            onClick: async function () {
              await API.apiFetch("/api/ai/policy", {
                method: "POST",
                body: {
                  learning_mode: learningSel.value,
                  background_triage_enabled: bgCb.checked,
                  local_db_enabled: localDbCb.checked,
                },
              });
              renderPolicy();
            },
          });

          subBody.appendChild(
            el("div", { className: "sl-card" }, [
              el("div", { className: "sl-card-title", textContent: "AI Policy & Learning Mode" }),
              el("label", { textContent: "Self-Learning Mode" }),
              learningSel,
              el("label", {}, [bgCb, " Background Triage Enabled"]),
              el("label", {}, [localDbCb, " Local DB-First Tools Enabled"]),
              saveBtn,
              el("div", {
                className: "sl-badge sl-badge-info",
                textContent: "Registered Read-Only Tools (" + (data.readonly_tools || []).length + "): " + (data.readonly_tools || []).join(", "),
              }),
            ])
          );
        }

        async function renderAudit() {
          subBody.innerHTML = "<div class='sl-badge'>Loading AI Audit Log...</div>";
          const data = await API.apiFetch("/api/audit?limit=150");
          subBody.innerHTML = "";
          subBody.appendChild(
            renderFormattedTable(data.entries || [], [
              { key: "timestamp", label: "Timestamp" },
              { key: "event_type", label: "Type" },
              { key: "tool_name", label: "Tool" },
              { key: "allowed", label: "Allowed" },
              { key: "reason", label: "Reason" },
            ])
          );
        }

        async function renderKnowledge() {
          subBody.innerHTML = "<div class='sl-badge'>Loading SOC Knowledge...</div>";
          const data = await API.apiFetch("/api/knowledge");
          subBody.innerHTML = "";
          const toolbar = el("div", { className: "sl-toolbar" }, [
            el("button", {
              className: "sl-btn sl-btn-primary",
              textContent: "+ Teach Entry",
              onClick: function () {
                showTeachModal("", "", renderKnowledge);
              },
            }),
            el("button", {
              className: "sl-btn",
              textContent: "Reload Base Info",
              onClick: async function () {
                await API.apiFetch("/api/knowledge/reload-base", { method: "POST", body: {} });
                renderKnowledge();
              },
            }),
            el("span", { className: "sl-badge sl-badge-info", textContent: "Mode: " + (data.learning_mode || "manual") }),
          ]);
          subBody.appendChild(toolbar);
          subBody.appendChild(
            renderFormattedTable(
              data.entries || [],
              [
                { key: "status", label: "Status" },
                { key: "source", label: "Source" },
                { key: "category", label: "Category" },
                { key: "title", label: "Title" },
                { key: "pinned", label: "Pinned" },
                { key: "content", label: "Content", get: function (r) { return String(r.content || "").slice(0, 140); } },
              ],
              {
                actions: function (row) {
                  const btns = [];
                  if (row.status === "pending") {
                    btns.push(
                      el("button", {
                        className: "sl-btn sl-btn-primary",
                        textContent: "Approve",
                        onClick: async function () {
                          await API.apiFetch("/api/knowledge/" + encodeURIComponent(row.id) + "/approve", { method: "POST", body: {} });
                          renderKnowledge();
                        },
                      })
                    );
                  }
                  btns.push(
                    el("button", {
                      className: "sl-btn",
                      textContent: row.pinned ? "Unpin" : "Pin",
                      onClick: async function () {
                        await API.apiFetch("/api/knowledge/" + encodeURIComponent(row.id) + "/pin", {
                          method: "POST",
                          body: { pinned: !row.pinned },
                        });
                        renderKnowledge();
                      },
                    })
                  );
                  btns.push(
                    el("button", {
                      className: "sl-btn sl-btn-warn",
                      textContent: "Rollback",
                      onClick: async function () {
                        await API.apiFetch("/api/knowledge/" + encodeURIComponent(row.id) + "/rollback", { method: "POST", body: {} });
                        renderKnowledge();
                      },
                    })
                  );
                  btns.push(
                    el("button", {
                      className: "sl-btn sl-btn-danger",
                      textContent: "Delete",
                      onClick: async function () {
                        await API.apiFetch("/api/knowledge/" + encodeURIComponent(row.id), { method: "DELETE" });
                        renderKnowledge();
                      },
                    })
                  );
                  return btns;
                },
              }
            )
          );
        }

        function renderSub() {
          if (activeSub === "chat") renderChat();
          else if (activeSub === "panels") renderPanels();
          else if (activeSub === "policy") renderPolicy();
          else if (activeSub === "audit") renderAudit();
          else if (activeSub === "knowledge") renderKnowledge();
        }

        handlers["ai-analyst"] = function (payload) {
          if (!payload) return;
          if (payload.openTeach) {
            showTeachModal(payload.title || "Learned Pivot", payload.indicator || "", function () {
              activeSub = "knowledge";
              for (const k of Object.keys(subBtns)) {
                subBtns[k].classList.toggle("active", k === activeSub);
              }
              renderSub();
            });
            return;
          }
          if (payload.mode === "ask_only" || payload.mode === "full_investigation") {
            activeMode = payload.mode;
          }
          if (payload.event || payload.indicator) {
            attachedTitle = payload.title || payload.indicator || "Pivot Context";
            attachedContext = payload.event
              ? JSON.stringify(payload.event, null, 2)
              : "Investigate indicator: " + payload.indicator;
            activeSub = "chat";
            for (const k of Object.keys(subBtns)) {
              subBtns[k].classList.toggle("active", k === activeSub);
            }
            renderSub();
          } else if (payload.mode === "ask_only" || payload.mode === "full_investigation") {
            renderSub();
          }
        };

        root.appendChild(subBar);
        root.appendChild(subBody);
        renderSub();
      },
    });

    // 7. Logs Tile
    registry.set("logs", {
      id: "logs",
      title: "Logs",
      admin: false,
      mount: function (root) {
        const levelSel = el("select", { className: "sl-select" }, [
          el("option", { value: "ALL", textContent: "All Levels" }),
          el("option", { value: "INFO", textContent: "INFO" }),
          el("option", { value: "WARNING", textContent: "WARNING" }),
          el("option", { value: "ERROR", textContent: "ERROR" }),
        ]);
        const qInput = el("input", { className: "sl-input", placeholder: "Filter logs..." });
        const refreshBtn = el("button", { className: "sl-btn sl-btn-primary", textContent: "Refresh" });
        const clearBtn = el("button", { className: "sl-btn sl-btn-danger", textContent: "Clear" });
        const wrapper = createRawJsonWrapper();

        async function loadLogs() {
          const data = await API.apiFetch(
            "/api/logs?level=" + encodeURIComponent(levelSel.value) + "&q=" + encodeURIComponent(qInput.value.trim())
          );
          wrapper.setData(data, function (host, d) {
            host.appendChild(
              renderFormattedTable((d.entries || []).slice().reverse(), [
                { key: "timestamp", label: "Time" },
                { key: "level", label: "Level" },
                { key: "source", label: "Source" },
                { key: "message", label: "Message" },
              ])
            );
          });
        }

        API.onStreamEvent("log", function () {
          loadLogs().catch(function () {});
        });

        refreshBtn.addEventListener("click", loadLogs);
        clearBtn.addEventListener("click", async function () {
          await API.apiFetch("/api/logs/clear", { method: "POST", body: {} });
          loadLogs();
        });
        root.appendChild(el("div", { className: "sl-toolbar" }, [levelSel, qInput, refreshBtn, clearBtn, wrapper.toggleBtn]));
        root.appendChild(wrapper.formattedHost);
        root.appendChild(wrapper.rawPre);
        loadLogs();
      },
    });

    // 8. Settings & Vault Tile
    registry.set("settings", {
      id: "settings",
      title: "Settings",
      admin: false,
      mount: function (root) {
        const statusBadge = el("span", { className: "sl-badge", textContent: "Loading..." });
        const vaultArea = el("div", { className: "sl-toolbar" });
        const dbCard = el("div", { className: "sl-card" });
        const wrapper = createRawJsonWrapper();

        async function loadSettings() {
          const data = await API.apiFetch("/api/settings");
          statusBadge.textContent = (data.locked ? "LOCKED" : "UNLOCKED") + " | Profile: " + (data.active_profile || "default");

          vaultArea.innerHTML = "";
          const passInput = el("input", { className: "sl-input", type: "password", placeholder: "Vault passphrase..." });
          const unlockBtn = el("button", {
            className: "sl-btn sl-btn-primary",
            textContent: "Unlock Vault (Memory Only)",
            onClick: async function () {
              try {
                await API.apiFetch("/api/settings/unlock", {
                  method: "POST",
                  body: { passphrase: passInput.value },
                });
                passInput.value = "";
                loadSettings();
              } catch (err) {
                statusBadge.textContent = err.message;
              }
            },
          });
          const lockBtn = el("button", {
            className: "sl-btn sl-btn-warn",
            textContent: "Lock Vault",
            onClick: async function () {
              await API.apiFetch("/api/settings/lock", { method: "POST", body: {} });
              loadSettings();
            },
          });
          const hydrateBtn = el("button", {
            className: "sl-btn",
            textContent: "Hydrate PAM Secrets",
            onClick: async function () {
              const res = await API.apiFetch("/api/settings/hydrate-secrets", { method: "POST", body: {} });
              statusBadge.textContent = "Hydrated " + (res.count || 0) + " secret(s) in memory";
              loadSettings();
            },
          });
          vaultArea.appendChild(passInput);
          vaultArea.appendChild(unlockBtn);
          vaultArea.appendChild(lockBtn);
          vaultArea.appendChild(hydrateBtn);
          vaultArea.appendChild(wrapper.toggleBtn);
          vaultArea.appendChild(statusBadge);

          const db = data.db_config || {};
          dbCard.innerHTML = "";
          const backendSel = el("select", { className: "sl-select" }, [
            el("option", { value: "sqlite", textContent: "sqlite (Local WAL + FTS5)" }),
            el("option", { value: "postgres", textContent: "postgres (pg8000)" }),
            el("option", { value: "mysql", textContent: "mysql (PyMySQL)" }),
            el("option", { value: "custom", textContent: "custom (SQLAlchemy DSN)" }),
          ]);
          backendSel.value = db.backend || "sqlite";
          const hostIn = el("input", { className: "sl-input", value: db.host || "", placeholder: "DB Host" });
          const portIn = el("input", { className: "sl-input", value: db.port || "", placeholder: "Port" });
          const nameIn = el("input", { className: "sl-input", value: db.name || "", placeholder: "DB Name" });
          const userIn = el("input", { className: "sl-input", value: db.user || "", placeholder: "DB User" });
          const passIn = el("input", { className: "sl-input", type: "password", placeholder: db.password_configured ? "********" : "DB Password" });
          const dbResult = el("span", { className: "sl-badge", textContent: "Dialect: " + (db.dialect || "sqlite") });

          const testDbBtn = el("button", {
            className: "sl-btn",
            textContent: "Test DB Connection",
            onClick: async function () {
              const res = await API.apiFetch("/api/settings/test-db", {
                method: "POST",
                body: {
                  backend: backendSel.value,
                  host: hostIn.value,
                  port: portIn.value || undefined,
                  name: nameIn.value,
                  user: userIn.value,
                  password: passIn.value || undefined,
                },
              });
              dbResult.textContent = res.ok
                ? "DB OK (" + res.dialect + " " + (res.version || "") + ")"
                : "DB Error: " + (res.error || "failed");
              dbResult.className = "sl-badge " + (res.ok ? "sl-badge-ok" : "sl-badge-danger");
            },
          });
          const saveDbBtn = el("button", {
            className: "sl-btn sl-btn-primary",
            textContent: "Save DB Settings",
            onClick: async function () {
              const settingsMap = {
                db_backend: backendSel.value,
                db_host: hostIn.value,
                db_port: portIn.value,
                db_name: nameIn.value,
                db_user: userIn.value,
              };
              if (passIn.value) settingsMap.db_password = passIn.value;
              await API.apiFetch("/api/settings", { method: "POST", body: { settings: settingsMap } });
              loadSettings();
            },
          });

          dbCard.appendChild(el("div", { className: "sl-card-title", textContent: "Database & Storage Configuration" }));
          dbCard.appendChild(el("div", { className: "sl-toolbar" }, [backendSel, hostIn, portIn, nameIn, userIn, passIn, testDbBtn, saveDbBtn, dbResult]));

          wrapper.setData(data, function (host, d) {
            host.appendChild(
              renderFormattedTable(d.settings || [], [
                { key: "category", label: "Category" },
                { key: "key", label: "Key" },
                { key: "value", label: "Value" },
                { key: "source", label: "Source" },
                { key: "configured", label: "Configured" },
              ])
            );
          });
        }

        root.appendChild(vaultArea);
        root.appendChild(dbCard);
        root.appendChild(wrapper.formattedHost);
        root.appendChild(wrapper.rawPre);
        loadSettings();
      },
    });

    // Admin Tiles (9..13)
    if (appCtx.adminEnabled) {
      registry.set("dashboard", {
        id: "dashboard",
        title: "Dashboard",
        admin: true,
        mount: function (root) {
          const wrapper = createRawJsonWrapper();
          const refreshBtn = el("button", { className: "sl-btn sl-btn-primary", textContent: "Refresh Diagnostics" });
          const sslBtn = el("button", {
            className: "sl-btn sl-btn-warn",
            textContent: "Toggle Insecure SSL",
            onClick: function () {
              showDoubleConfirmModal(
                "Toggle SSL Verification",
                "Change TLS certificate verification mode for this web session?",
                async function () {
                  await API.apiFetch("/api/admin/dashboard", {
                    method: "POST",
                    body: { action: "toggle_ssl", insecure: true, double_confirmed: true },
                  });
                  loadDash();
                }
              );
            },
          });

          async function loadDash() {
            const data = await API.apiFetch("/api/admin/dashboard");
            wrapper.setData(data, function (host, d) {
              const diag = d.diagnostics || {};
              host.appendChild(
                el("div", { className: "sl-card" }, [
                  el("div", { className: "sl-card-title", textContent: "Environment Diagnostics" }),
                  el("div", { textContent: "Python: " + diag.python_version + " | Dialect: " + diag.storage_dialect + " | Wheelhouse: " + diag.wheelhouse_wheels + " wheels" }),
                  el("div", { textContent: "SSL: " + diag.ssl_status + " | Proxy: " + diag.proxy_summary }),
                ])
              );
              host.appendChild(
                renderFormattedTable(d.api_surfaces || [], [
                  { key: "family", label: "API Family" },
                  { key: "endpoint", label: "Endpoint" },
                  { key: "auth", label: "Auth" },
                  { key: "surface", label: "Surface" },
                ])
              );
            });
          }

          refreshBtn.addEventListener("click", loadDash);
          root.appendChild(el("div", { className: "sl-toolbar" }, [refreshBtn, sslBtn, wrapper.toggleBtn]));
          root.appendChild(wrapper.formattedHost);
          root.appendChild(wrapper.rawPre);
          loadDash();
        },
      });

      registry.set("watchlists", {
        id: "watchlists",
        title: "Watchlists",
        admin: true,
        mount: function (root) {
          const listIdIn = el("input", { className: "sl-input", placeholder: "Watchlist ID..." });
          const entityIn = el("input", { className: "sl-input", placeholder: "Entity to add/remove..." });
          const loadBtn = el("button", { className: "sl-btn sl-btn-primary", textContent: "Load Watchlists" });
          const addBtn = el("button", {
            className: "sl-btn sl-btn-warn",
            textContent: "Add Entity",
            onClick: function () {
              showDoubleConfirmModal(
                "Add Watchlist Entity",
                "Add '" + entityIn.value + "' to watchlist '" + listIdIn.value + "'?",
                async function () {
                  await API.apiFetch("/api/admin/watchlists", {
                    method: "POST",
                    body: { action: "add_entity", list_id: listIdIn.value, entity: entityIn.value, double_confirmed: true },
                  });
                  loadWL();
                }
              );
            },
          });
          const wrapper = createRawJsonWrapper();

          async function loadWL() {
            const url = "/api/admin/watchlists" + (listIdIn.value.trim() ? "?list_id=" + encodeURIComponent(listIdIn.value.trim()) : "");
            const data = await API.apiFetch(url);
            wrapper.setData(data, function (host, d) {
              const rows = d.entities || d.lists || [];
              host.appendChild(
                renderFormattedTable(rows, [
                  { key: "id", label: "ID" },
                  { key: "name", label: "Name / Entity", pivot: true, get: function (r) { return r.name || (r.entity && r.entity.name) || "-"; } },
                  { key: "type", label: "Type", get: function (r) { return r.type || (r.entity && r.entity.type) || "-"; } },
                ])
              );
            });
          }

          loadBtn.addEventListener("click", loadWL);
          root.appendChild(el("div", { className: "sl-toolbar" }, [listIdIn, entityIn, loadBtn, addBtn, wrapper.toggleBtn]));
          root.appendChild(wrapper.formattedHost);
          root.appendChild(wrapper.rawPre);
          loadWL();
        },
      });

      registry.set("brand-logos", {
        id: "brand-logos",
        title: "Brand Logos",
        admin: true,
        mount: function (root) {
          const listIdIn = el("input", { className: "sl-input", placeholder: "Watchlist ID..." });
          const domainsIn = el("input", { className: "sl-input", placeholder: "Domains (comma-separated)..." });
          const stateBtn = el("button", { className: "sl-btn sl-btn-primary", textContent: "Load State" });
          const syncBtn = el("button", {
            className: "sl-btn sl-btn-danger",
            textContent: "Sync Brand Logos",
            onClick: function () {
              showDoubleConfirmModal(
                "Execute Brand Logo Sync",
                "Run domain brand logo sync against watchlist '" + listIdIn.value + "'?",
                async function () {
                  await API.apiFetch("/api/admin/brand-logos", {
                    method: "POST",
                    body: {
                      action: "sync",
                      list_id: listIdIn.value,
                      domains: domainsIn.value.split(",").map(function (s) { return s.trim(); }).filter(Boolean),
                      double_confirmed: true,
                    },
                  });
                  loadBrandState();
                }
              );
            },
          });
          const wrapper = createRawJsonWrapper();

          async function loadBrandState() {
            const data = await API.apiFetch("/api/admin/brand-logos");
            wrapper.setData(data, function (host, d) {
              const issues = (d.issues && d.issues.issues) || [];
              host.appendChild(
                renderFormattedTable(issues, [
                  { key: "domain", label: "Domain", pivot: true },
                  { key: "kind", label: "Issue" },
                  { key: "detail", label: "Detail" },
                ])
              );
            });
          }

          stateBtn.addEventListener("click", loadBrandState);
          root.appendChild(el("div", { className: "sl-toolbar" }, [listIdIn, domainsIn, stateBtn, syncBtn, wrapper.toggleBtn]));
          root.appendChild(wrapper.formattedHost);
          root.appendChild(wrapper.rawPre);
          loadBrandState();
        },
      });

      registry.set("sigma", {
        id: "sigma",
        title: "Sigma Rules",
        admin: true,
        mount: function (root) {
          const qIn = el("input", { className: "sl-input", placeholder: "Search Sigma rules..." });
          const loadBtn = el("button", { className: "sl-btn sl-btn-primary", textContent: "Load Cached" });
          const wrapper = createRawJsonWrapper();

          async function loadSigma() {
            const data = await API.apiFetch("/api/admin/sigma?q=" + encodeURIComponent(qIn.value.trim()));
            wrapper.setData(data, function (host, d) {
              host.appendChild(
                renderFormattedTable(d.rules || [], [
                  { key: "id", label: "Rule ID" },
                  { key: "title", label: "Title" },
                  { key: "level", label: "Level" },
                  { key: "status", label: "Status" },
                ])
              );
            });
          }

          loadBtn.addEventListener("click", loadSigma);
          root.appendChild(el("div", { className: "sl-toolbar" }, [qIn, loadBtn, wrapper.toggleBtn]));
          root.appendChild(wrapper.formattedHost);
          root.appendChild(wrapper.rawPre);
          loadSigma();
        },
      });

      registry.set("splunk-bundle", {
        id: "splunk-bundle",
        title: "Splunk & Bundle",
        admin: true,
        mount: function (root) {
          const platSel = el("select", { className: "sl-select" }, [
            el("option", { value: "current", textContent: "Current Platform" }),
            el("option", { value: "all", textContent: "All Platforms (Wheelhouse)" }),
            el("option", { value: "win_amd64", textContent: "Windows x64 (win_amd64)" }),
            el("option", { value: "linux_x86_64", textContent: "Linux x64" }),
            el("option", { value: "macosx_arm64", textContent: "macOS ARM64" }),
          ]);
          const whCb = el("input", { type: "checkbox", checked: "checked" });
          const buildBtn = el("button", {
            className: "sl-btn sl-btn-primary",
            textContent: "Build Release ZIP",
            onClick: function () {
              showDoubleConfirmModal(
                "Build Air-Gapped Bundle",
                "Package offline ZIP bundle for platform '" + platSel.value + "'?",
                async function () {
                  const res = await API.apiFetch("/api/admin/splunk-bundle", {
                    method: "POST",
                    body: { action: "build", target_platform: platSel.value, wheelhouse: whCb.checked, double_confirmed: true },
                  });
                  wrapper.setData(res);
                }
              );
            },
          });
          const wrapper = createRawJsonWrapper();
          root.appendChild(el("div", { className: "sl-toolbar" }, [platSel, el("label", {}, [whCb, " Wheelhouse"]), buildBtn, wrapper.toggleBtn]));
          root.appendChild(wrapper.formattedHost);
          root.appendChild(wrapper.rawPre);
        },
      });
    }

    return { registry: registry, handlers: handlers };
  }

  window.SOCLensTiles = {
    buildTileRegistry: buildTileRegistry,
    showDoubleConfirmModal: showDoubleConfirmModal,
    showTeachModal: showTeachModal,
  };
})();
