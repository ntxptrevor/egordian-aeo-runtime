/* eGordian AEO - static operator console (deploy bundle).
 *
 * Read-only by construction:
 *   - a single API base derived from the __PORT_8080__ deployment placeholder;
 *   - one request helper, hard-locked to GET, with an allowlist of endpoints;
 *   - no browser storage of any kind (web storage and cookies are blocked in
 *     sandboxed iframes anyway): the operator token lives in a JS variable for
 *     the lifetime of the tab and nowhere else;
 *   - all page/asset references are relative so the bundle works from any
 *     iframe sub-path such as /computer/a/<id>/index.html.
 */
(function () {
  "use strict";

  // deploy_website rewrites __PORT_8080__ to the proxy path (e.g. "port/8080").
  // Before rewriting, the literal still starts with "__", which selects the
  // local development origin instead.
  var PORT_TOKEN = "__PORT_8080__";
  var API = PORT_TOKEN.indexOf("__") === 0 ? "http://localhost:8080" : PORT_TOKEN;

  // Read-only allowlist. Nothing outside this set can be requested.
  var ENDPOINTS = {
    status: "/api/status",
    operations: "/api/operations",
    tools: "/api/tools",
    audit: "/api/audit",
    exceptions: "/api/exceptions",
    readyz: "/readyz",
    healthz: "/healthz",
    openapi: "/openapi.json",
  };

  var TOKEN = "";
  var $ = function (id) { return document.getElementById(id); };

  function url(key, query) {
    var path = ENDPOINTS[key];
    if (!path) throw new Error("Endpoint not allowlisted: " + key);
    var qs = "";
    if (query) {
      var parts = [];
      Object.keys(query).forEach(function (k) {
        if (query[k] !== undefined && query[k] !== null && query[k] !== "") {
          parts.push(encodeURIComponent(k) + "=" + encodeURIComponent(query[k]));
        }
      });
      if (parts.length) qs = "?" + parts.join("&");
    }
    return API + path + qs;
  }

  // The only network primitive in this bundle. GET only, always through API.
  async function get(key, query) {
    var target = url(key, query);
    var response = await fetch(target, {
      method: "GET",
      credentials: "omit",
      cache: "no-store",
      headers: TOKEN ? { Authorization: "Bearer " + TOKEN } : {},
    });
    if (!response.ok) throw new Error(ENDPOINTS[key] + " -> HTTP " + response.status);
    return response.json();
  }

  var esc = function (value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  };

  function card(label, value, note, chipClass) {
    return '<div class="card"><div class="label">' + esc(label) + "</div>" +
      '<div class="value">' + esc(value) + "</div>" +
      (note ? '<div class="note">' + (chipClass
        ? '<span class="chip ' + chipClass + '">' + esc(note) + "</span>"
        : esc(note)) + "</div>" : "") + "</div>";
  }

  function empty(tbody, message) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty">' + esc(message) + "</td></tr>";
  }

  // --- theme (attribute only; nothing persisted) ---------------------------
  var themeButton = $("theme");
  if (themeButton) {
    themeButton.addEventListener("click", function () {
      var root = document.documentElement;
      var current = root.getAttribute("data-theme");
      var isDark = current === "dark" ||
        (current !== "light" &&
         window.matchMedia("(prefers-color-scheme: dark)").matches);
      root.setAttribute("data-theme", isDark ? "light" : "dark");
    });
  }

  // --- OpenAPI link on the docs page ---------------------------------------
  var openapiLink = $("openapi-link");
  if (openapiLink) {
    openapiLink.setAttribute("href", API + ENDPOINTS.openapi);
    openapiLink.setAttribute("rel", "noopener");
  }

  // Everything below only runs on the console page.
  if (!$("connect")) return;

  // --- renderers -----------------------------------------------------------
  function renderHealth(status) {
    var s = status.service, repo = status.repository;
    $("brand-sub").textContent =
      "MCP " + s.mcp_protocol_version + " \u00b7 " + s.deployment_env + " \u00b7 stateless";
    $("health-cards").innerHTML = [
      card("Service", s.version, "uptime " + Math.round(s.uptime_s) + "s", "ok"),
      card("MCP revision", s.mcp_protocol_version, "no sessions \u00b7 no handshake", "info"),
      card("Repository", repo.backend, repo.ok ? "connected" : "unavailable",
           repo.ok ? "ok" : "err"),
      card("MCP tools", status.mcp.tools,
           Object.keys(status.mcp.tool_categories).map(function (k) {
             return k + " " + status.mcp.tool_categories[k];
           }).join(" \u00b7 ")),
    ].join("");
  }

  function renderCatalogue(status) {
    var c = status.catalogue, counts = c.counts || {}, v = status.versions || {};
    $("catalogue-cards").innerHTML = [
      card("Edition", c.edition || "unavailable",
           c.available ? "sealed \u00b7 immutable" : "missing", c.available ? "ok" : "err"),
      card("Task lines", (counts.tasks || 0).toLocaleString()),
      card("Modifiers", (counts.modifiers || 0).toLocaleString()),
      card("Divisions", counts.divisions || 0, (counts.sections || 0) + " sections"),
    ].join("");
    $("catalogue-provenance").textContent =
      "row-content sha256 " + String(v.catalogue_row_content_sha256 || "").slice(0, 16) +
      "\u2026 \u00b7 registry sha256 " + String(v.operation_registry_sha256 || "").slice(0, 16) +
      "\u2026 \u00b7 stage machine " + String(v.stage_machine_hash || "").slice(0, 16) + "\u2026";
  }

  function renderStages(stages) {
    $("stage-diagram").innerHTML = stages.map(function (stage) {
      return '<div class="stage ' + stage.tier.toLowerCase() + " " +
        (stage.blocked_reason ? "blocked" : "") + '">' +
        '<div class="n">' + stage.index + "</div>" +
        '<div class="name">' + esc(stage.name) + "</div>" +
        '<div class="tier">' + esc(stage.tier) + (stage.gate ? " \u00b7 GATE" : "") + "</div>" +
        (stage.blocked_reason ? '<div class="flag">capability blocked</div>' : "") +
        "</div>";
    }).join("");
  }

  function renderEgordian(status, operations) {
    var e = status.egordian, counts = e.operation_counts || {};
    $("egordian-cards").innerHTML = [
      card("Connection", e.state, e.auth.provider + " provider", e.connected ? "ok" : "warn"),
      card("Documented ops", counts.total, counts.read + " read \u00b7 " + counts.write + " write"),
      card("Writes", e.writes_enabled ? "enabled" : "disabled",
           "mode " + e.write_mode, e.writes_enabled ? "warn" : "ok"),
      card("DELETE / admin", "blocked",
           counts.destructive + " delete \u00b7 " + counts.admin + " admin", "ok"),
    ].join("");

    var body = $("ops-body");
    if (!operations.length) return empty(body, "No operations registered.");
    body.innerHTML = operations.map(function (op) {
      var chip = (op.risk === "read" || op.risk === "auth") ? "ok"
        : (op.risk === "write" ? "warn" : "err");
      return "<tr><td>" + esc(op.section) + "</td>" +
        '<td class="mono">' + esc(op.method) + "</td>" +
        '<td class="mono">' + esc(op.route_template) + "</td>" +
        '<td><span class="chip ' + chip + '">' + esc(op.risk) + "</span></td>" +
        '<td class="mono">' + (op.enabled_by_default ? "yes" : "gated") + "</td></tr>";
    }).join("");
  }

  function renderGaps(gaps) {
    $("gaps").innerHTML = gaps.map(function (gap) {
      return '<div class="gap"><div class="cap">' + esc(gap.capability) + " \u2014 " +
        esc(gap.status) + '</div><div class="why">' + esc(gap.detail || "") + "</div></div>";
    }).join("") || '<div class="empty">No capability gaps recorded.</div>';
  }

  function renderAudit(rows) {
    var body = $("audit-body");
    if (!rows.length) return empty(body, "No audit events yet.");
    body.innerHTML = rows.map(function (row) {
      return "<tr>" +
        '<td class="mono">' + esc(String(row.created_at || "").replace("T", " ").slice(0, 19)) + "</td>" +
        '<td class="mono">' + esc(row.action) + "</td>" +
        "<td>" + esc(row.actor || row.user_id || "\u2014") + "</td>" +
        '<td class="mono">' + esc(row.project_id || "\u2014") + "</td></tr>";
    }).join("");
  }

  function renderExceptions(rows) {
    var body = $("exc-body");
    if (!rows.length) return empty(body, "No open exceptions.");
    body.innerHTML = rows.map(function (row) {
      return "<tr>" +
        '<td class="mono">' + esc(row.project_id) + "</td>" +
        '<td class="mono">' + esc(row.kind) + "</td>" +
        '<td><span class="chip ' + (row.severity === "error" ? "err" : "warn") + '">' +
        esc(row.severity) + "</span></td>" +
        '<td class="mono">' + (row.stage == null ? "\u2014" : row.stage) + "</td></tr>";
    }).join("");
  }

  // --- load ----------------------------------------------------------------
  async function load() {
    TOKEN = $("token").value.trim();
    if (!TOKEN) { window.alert("A bearer token is required."); return; }
    $("connect").textContent = "Loading\u2026";
    try {
      var results = await Promise.all([
        get("status"), get("operations"), get("audit", { limit: 25 }),
      ]);
      $("intro").classList.add("hidden");
      $("app").classList.remove("hidden");
      renderHealth(results[0]);
      renderCatalogue(results[0]);
      renderStages(results[0].aeo.stages);
      renderEgordian(results[0], results[1].operations);
      renderGaps(results[1].capability_gaps);
      renderAudit(results[2].results);
      renderExceptions([]);
    } catch (error) {
      window.alert("Could not load status: " + error.message);
    } finally {
      $("connect").textContent = "Load";
    }
  }

  $("connect").addEventListener("click", load);
  $("token").addEventListener("keydown", function (e) { if (e.key === "Enter") load(); });
  $("load-exc").addEventListener("click", async function () {
    var project = $("project").value.trim();
    if (!project) return;
    try {
      var data = await get("exceptions", { project_id: project });
      renderExceptions(data.results);
    } catch (error) {
      renderExceptions([]);
      $("exc-hint").textContent = error.message;
    }
  });
})();
