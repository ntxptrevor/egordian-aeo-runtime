/* Operator console. Token stays in memory only - never persisted to storage,
   never sent anywhere except this service's own /api endpoints. */
(function () {
  "use strict";

  let TOKEN = "";
  const $ = (id) => document.getElementById(id);

  // --- theme ---------------------------------------------------------------
  const root = document.documentElement;
  $("theme").addEventListener("click", () => {
    const current = root.getAttribute("data-theme");
    const isDark = current === "dark" ||
      (current === "auto" && window.matchMedia("(prefers-color-scheme: dark)").matches);
    root.setAttribute("data-theme", isDark ? "light" : "dark");
  });

  // --- helpers -------------------------------------------------------------
  async function api(path) {
    const response = await fetch(path, { headers: { Authorization: "Bearer " + TOKEN } });
    if (!response.ok) throw new Error(path + " → HTTP " + response.status);
    return response.json();
  }

  const esc = (value) => String(value == null ? "" : value)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

  function card(label, value, note, chipClass) {
    return `<div class="card"><div class="label">${esc(label)}</div>
      <div class="value">${esc(value)}</div>
      ${note ? `<div class="note">${chipClass ? `<span class="chip ${chipClass}">${esc(note)}</span>` : esc(note)}</div>` : ""}
    </div>`;
  }

  function empty(tbody, message) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty">${esc(message)}</td></tr>`;
  }

  // --- renderers -----------------------------------------------------------
  function renderHealth(status) {
    const s = status.service, repo = status.repository;
    $("brand-sub").textContent =
      `MCP ${s.mcp_protocol_version} · ${s.deployment_env} · stateless`;
    $("health-cards").innerHTML = [
      card("Service", s.version, `uptime ${Math.round(s.uptime_s)}s`, "ok"),
      card("MCP revision", s.mcp_protocol_version, "no sessions · no handshake", "info"),
      card("Repository", repo.backend, repo.ok ? "connected" : "unavailable",
           repo.ok ? "ok" : "err"),
      card("MCP tools", status.mcp.tools,
           Object.entries(status.mcp.tool_categories)
             .map(([k, v]) => `${k} ${v}`).join(" · ")),
    ].join("");
  }

  function renderCatalogue(status) {
    const c = status.catalogue, counts = c.counts || {};
    $("catalogue-cards").innerHTML = [
      card("Edition", c.edition || "unavailable", c.available ? "sealed · immutable" : "missing",
           c.available ? "ok" : "err"),
      card("Task lines", (counts.tasks || 0).toLocaleString()),
      card("Modifiers", (counts.modifiers || 0).toLocaleString()),
      card("Divisions", counts.divisions || 0, `${counts.sections || 0} sections`),
    ].join("");
    const v = status.versions || {};
    $("catalogue-provenance").textContent =
      `row-content sha256 ${(v.catalogue_row_content_sha256 || "").slice(0, 16)}… · ` +
      `registry sha256 ${(v.operation_registry_sha256 || "").slice(0, 16)}… · ` +
      `stage machine ${(v.stage_machine_hash || "").slice(0, 16)}…`;
  }

  function renderStages(stages) {
    $("stage-diagram").innerHTML = stages.map((stage) => `
      <div class="stage ${stage.tier.toLowerCase()} ${stage.blocked_reason ? "blocked" : ""}">
        <div class="n">${stage.index}</div>
        <div class="name">${esc(stage.name)}</div>
        <div class="tier">${esc(stage.tier)}${stage.gate ? " · GATE" : ""}</div>
        ${stage.blocked_reason ? `<div class="flag">capability blocked</div>` : ""}
      </div>`).join("");
  }

  function renderEgordian(status, operations) {
    const e = status.egordian, counts = e.operation_counts || {};
    $("egordian-cards").innerHTML = [
      card("Connection", e.state, e.auth.provider + " provider",
           e.connected ? "ok" : "warn"),
      card("Documented ops", counts.total, `${counts.read} read · ${counts.write} write`),
      card("Writes", e.writes_enabled ? "enabled" : "disabled",
           `mode ${e.write_mode}`, e.writes_enabled ? "warn" : "ok"),
      card("DELETE / admin", "blocked",
           `${counts.destructive} delete · ${counts.admin} admin`, "ok"),
    ].join("");

    const body = $("ops-body");
    if (!operations.length) return empty(body, "No operations registered.");
    body.innerHTML = operations.map((op) => `
      <tr>
        <td>${esc(op.section)}</td>
        <td class="mono">${esc(op.method)}</td>
        <td class="mono">${esc(op.route_template)}</td>
        <td><span class="chip ${op.risk === "read" || op.risk === "auth" ? "ok" :
          op.risk === "write" ? "warn" : "err"}">${esc(op.risk)}</span></td>
        <td class="mono">${op.enabled_by_default ? "yes" : "gated"}</td>
      </tr>`).join("");
  }

  function renderGaps(gaps) {
    $("gaps").innerHTML = gaps.map((gap) => `
      <div class="gap">
        <div class="cap">${esc(gap.capability)} — ${esc(gap.status)}</div>
        <div class="why">${esc(gap.detail || "")}</div>
      </div>`).join("") || `<div class="empty">No capability gaps recorded.</div>`;
  }

  function renderAudit(rows) {
    const body = $("audit-body");
    if (!rows.length) return empty(body, "No audit events yet.");
    body.innerHTML = rows.map((row) => `
      <tr>
        <td class="mono">${esc((row.created_at || "").replace("T", " ").slice(0, 19))}</td>
        <td class="mono">${esc(row.action)}</td>
        <td>${esc(row.actor || row.user_id || "—")}</td>
        <td class="mono">${esc(row.project_id || "—")}</td>
      </tr>`).join("");
  }

  function renderExceptions(rows) {
    const body = $("exc-body");
    if (!rows.length) return empty(body, "No open exceptions.");
    body.innerHTML = rows.map((row) => `
      <tr>
        <td class="mono">${esc(row.project_id)}</td>
        <td class="mono">${esc(row.kind)}</td>
        <td><span class="chip ${row.severity === "error" ? "err" : "warn"}">${esc(row.severity)}</span></td>
        <td class="mono">${row.stage == null ? "—" : row.stage}</td>
      </tr>`).join("");
  }

  // --- load ----------------------------------------------------------------
  async function load() {
    TOKEN = $("token").value.trim();
    if (!TOKEN) { alert("A bearer token is required."); return; }
    $("connect").textContent = "Loading…";
    try {
      const [status, operations, audit] = await Promise.all([
        api("/api/status"), api("/api/operations"), api("/api/audit?limit=25"),
      ]);
      $("intro").classList.add("hidden");
      $("app").classList.remove("hidden");
      renderHealth(status);
      renderCatalogue(status);
      renderStages(status.aeo.stages);
      renderEgordian(status, operations.operations);
      renderGaps(operations.capability_gaps);
      renderAudit(audit.results);
      renderExceptions([]);
    } catch (error) {
      alert("Could not load status: " + error.message);
    } finally {
      $("connect").textContent = "Load";
    }
  }

  $("connect").addEventListener("click", load);
  $("token").addEventListener("keydown", (e) => { if (e.key === "Enter") load(); });
  $("load-exc").addEventListener("click", async () => {
    const project = $("project").value.trim();
    if (!project) return;
    try {
      const data = await api("/api/exceptions?project_id=" + encodeURIComponent(project));
      renderExceptions(data.results);
    } catch (error) {
      renderExceptions([]);
      $("exc-hint").textContent = error.message;
    }
  });
})();
