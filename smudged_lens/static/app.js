/* Smudged Lens — UI logic */

"use strict";

/* --------------------------------------------------------------------------
   API layer
   -------------------------------------------------------------------------- */

async function req(path, body) {
  const opts = body
    ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }
    : {};
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

const api = {
  status: () => req("/api/status"),
  log: (limit = 100) => req(`/api/log?limit=${limit}`),
  portsets: () => req("/api/portsets"),
  setup: (enabled, profile, portCount) => req("/api/setup", { enabled, profile, port_count: portCount }),
  osProfile: (profile) => req("/api/os/profile", { profile }),
  clearLog: () => req("/api/log/clear", {}),
};

/* --------------------------------------------------------------------------
   State
   -------------------------------------------------------------------------- */

const state = {
  enabled: false,
  profile: "windows11",
  portCount: 8,
  busy: false,
  profileTouched: false, // user picked a chip — refresh must not clobber it
  portSets: null, // { profile: [[port, banner], ...] } from /api/portsets
};

const $ = (id) => document.getElementById(id);

const OS_PROFILES = [
  { key: "windows11", label: "Windows 11" },
  { key: "windows10", label: "Windows 10" },
  { key: "macos", label: "macOS" },
  { key: "ubuntu", label: "Ubuntu" },
  { key: "centos", label: "CentOS" },
];

const MAX_PORTS = 13;

let toastTimer;
let osRowBuilt = false; // OS chips drawn (skip full rebuild on later refreshes)
let previewKey = "";    // last (profile:count) the port preview was built for

function toast(msg, type = "success") {
  const el = $("toast");
  el.textContent = msg;
  el.className = `toast show ${type}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.className = "toast"), 2600);
}

function formatUptime(s) {
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  return `${Math.floor(s / 3600)}h`;
}

/* --------------------------------------------------------------------------
   Renderers
   -------------------------------------------------------------------------- */

function renderPower() {
  $("powerBtn").className = `power${state.enabled ? " on" : ""}${state.busy ? " busy" : ""}`;
  $("powerLabel").textContent = state.busy
    ? "Applying…"
    : state.enabled
      ? "Defense is on"
      : "Defense is off";
  $("powerLabel").classList.toggle("on", state.enabled);
}

function renderOS() {
  const row = $("osRow");
  // Build the chips once; refreshes only toggle the selection highlight so the
  // entry animation doesn't replay (which made the page look like it reloaded).
  if (!osRowBuilt) {
    row.innerHTML = OS_PROFILES.map(
      (p) => `<button class="chip" data-profile="${p.key}">${p.label}</button>`
    ).join("");
    osRowBuilt = true;
  }
  row.querySelectorAll(".chip").forEach((c) =>
    c.classList.toggle("selected", c.dataset.profile === state.profile)
  );
}

function renderSlider() {
  const slider = $("portCount");
  // Max depends on profile (windows sets have 13, macos/ubuntu have 12)
  const profileMax = state.portSets?.[state.profile]?.length ?? MAX_PORTS;
  slider.max = profileMax;
  // Clamp count if profile changed to one with fewer ports
  if (state.portCount > profileMax) state.portCount = profileMax;
  // state.portCount is the single source of truth (kept in sync on drag) — never
  // overwrite the live value from stale state, which used to snap 12 back to 8.
  slider.value = state.portCount;
  $("portCountValue").textContent = state.portCount;
  const pct = ((state.portCount - slider.min) / (slider.max - slider.min)) * 100;
  slider.style.setProperty("--fill", `${pct}%`);
  renderPortPreview();
}

function renderPortPreview() {
  const el = $("portPreview");
  const sets = state.portSets;
  const profile = state.profile;
  if (!sets || !sets[profile]) {
    if (!el.classList.contains("hidden")) el.classList.add("hidden");
    return;
  }

  const count = state.portCount;
  const list = sets[profile];
  const key = `${profile}:${count}`;
  // Skip the rebuild (and its animations) on the 3s tick when nothing changed.
  if (key === previewKey && !el.classList.contains("hidden")) return;
  previewKey = key;

  el.classList.remove("hidden");
  el.innerHTML =
    `<div class="port-preview-label">Spoofing <b>${count}</b> of <b>${list.length}</b> ports — ` +
    `highlighted ports come up when armed</div>` +
    `<div class="port-chips">${list
      .map(([port, svc], i) => {
        const cls = i < count ? "port-chip armed" : "port-chip";
        return `<span class="${cls}" title="${esc(svc)}">:${esc(String(port))}</span>`;
      })
      .join("")}</div>`;
}

function renderStatus(d) {
  const active = d.port_spoofing_enabled || d.os_spoofing_enabled;
  $("statusBadge").className = `badge ${active ? "active" : ""}`;
  $("statusText").textContent = active ? "Active" : "Idle";

  $("metaProbes").textContent = d.total_log_hits ?? "–";
  $("metaBlocked").textContent = d.rate_limiter?.blocked_ips?.length ?? 0;
  $("metaUptime").textContent = formatUptime(d.uptime ?? 0);

  // Sync local state with what the server reports. The os_profile is the
  // *persisted* value; while defense is off a chip the user just picked has
  // nothing persisted yet, so don't clobber their in-flight selection.
  state.enabled = d.port_spoofing_enabled || false;
  if (!state.profileTouched) state.profile = d.os_profile || state.profile;
}

async function renderLog() {
  try {
    const d = await api.log(100);
    const tbody = $("logBody");

    if (!d.entries?.length) {
      tbody.innerHTML =
        '<tr><td colspan="4" class="empty">Nothing yet — scanners will show up here.</td></tr>';
      return;
    }

    tbody.innerHTML = d.entries
      .map(
        (e) => `
          <tr${e.blocked ? ' class="blocked"' : ""}>
            <td class="time">${esc(e.time)}</td>
            <td>${esc(e.source_ip)}</td>
            <td class="port">:${esc(e.dest_port)}</td>
            <td>${esc(e.service)}${e.blocked ? ' <span class="blocked-tag">blocked</span>' : ""}</td>
          </tr>`
      )
      .join("");
  } catch (err) {
    console.error("log refresh failed:", err);
  }
}

function esc(str) {
  const d = document.createElement("div");
  d.textContent = str;
  return d.innerHTML;
}

/* --------------------------------------------------------------------------
   Actions
   -------------------------------------------------------------------------- */

async function applySetup(enabled) {
  state.busy = true;
  renderPower();
  try {
    await api.setup(enabled, state.profile, state.portCount);
    state.enabled = enabled;
    // After arming, the server now persists this profile, so refresh can sync again.
    if (enabled) state.profileTouched = false;
    toast(enabled ? "Defense enabled" : "Defense disabled");
  } catch (err) {
    toast(err?.message || String(err), "error");
  } finally {
    state.busy = false;
    refresh();
  }
}

/* --------------------------------------------------------------------------
   Refresh loop
   -------------------------------------------------------------------------- */

let refreshing = false;

async function refresh() {
  if (refreshing) return;
  refreshing = true;
  try {
    const d = await api.status();
    renderStatus(d);
    renderPower();
    renderOS();
    renderSlider();
  } catch (err) {
    $("statusBadge").className = "badge error";
    $("statusText").textContent = "Offline";
    console.error("refresh failed:", err);
  } finally {
    refreshing = false;
  }
}

/* --------------------------------------------------------------------------
   Events
   -------------------------------------------------------------------------- */

$("powerBtn").addEventListener("click", () => applySetup(!state.enabled));

$("osRow").addEventListener("click", (e) => {
  const chip = e.target.closest("[data-profile]");
  if (!chip || chip.dataset.profile === state.profile) return;
  state.profile = chip.dataset.profile;
  state.profileTouched = true;
  renderOS();
  renderPortPreview();
  if (state.enabled) {
    applySetup(true); // armed: re-apply live so the change takes effect
  } else {
    persistProfile(); // disarmed: keep the choice server-side so a reload keeps it
  }
});

async function persistProfile() {
  try {
    await api.osProfile(state.profile);
    // Server now persists this profile — refresh can sync against it again.
    state.profileTouched = false;
  } catch (err) {
    toast(err?.message || String(err), "error");
  }
}

$("portCount").addEventListener("input", () => {
  state.portCount = parseInt($("portCount").value, 10) || state.portCount;
  renderSlider();
});

$("portCount").addEventListener("change", () => {
  state.portCount = parseInt($("portCount").value, 10) || state.portCount;
  if (state.enabled) applySetup(true);
});

$("clearLogBtn").addEventListener("click", async () => {
  try {
    await api.clearLog();
    toast("Log cleared");
  } catch (err) {
    toast(err?.message || String(err), "error");
  }
  renderLog();
});

/* --------------------------------------------------------------------------
   Boot
   -------------------------------------------------------------------------- */

refresh();
setInterval(refresh, 3000);
setInterval(renderLog, 3000);

// Concrete per-profile port sets are static for the process lifetime — fetch once so
// the slider can preview exact ports. Non-fatal if the endpoint is unavailable.
api.portsets()
  .then((d) => { state.portSets = d || null; renderPortPreview(); })
  .catch(() => { state.portSets = null; });
