// policy.mjs — structured baseline-override editor: lists the binary-owned
// baseline rules (each with an enable toggle + severity override), the user's
// own rules (allowlist/custom), a raw-JSON advanced view, and the version list.
// Overrides are assembled into a thin File and saved via PUT /api/policy
// (validate-before-write). Baselines come from the binary, so this view is
// always current; the file only stores the deltas.

export const id = "policy";
export const title = "Policy";

const SEVERITIES = ["safe", "low", "medium", "high"];

export function mount(el) {
  el.innerHTML = `
    <section class="panel">
      <h2>Policy</h2>
      <h3>Baseline rules <span class="muted">(from the binary — toggle or re-rank to override)</span></h3>
      <table class="baselines">
        <thead><tr><th>On</th><th>Rule</th><th>Severity</th></tr></thead>
        <tbody id="pol-baselines"></tbody>
      </table>

      <h3>Your rules <span class="muted">(allowlist &amp; custom — preserved on save)</span></h3>
      <ul id="pol-userrules" class="userrules"></ul>

      <div class="form-row">
        <button id="pol-save">Validate &amp; Save</button>
        <span id="pol-status" class="status"></span>
      </div>

      <details class="advanced">
        <summary>Advanced: raw policy JSON (read-only)</summary>
        <textarea id="pol-raw" class="editor" spellcheck="false" readonly></textarea>
      </details>

      <h2>Versions</h2>
      <ul id="pol-versions" class="versions"></ul>
    </section>`;

  const state = { baselines: [], userRules: [] };
  load(el, state);
  el.querySelector("#pol-save").addEventListener("click", () => save(el, state));
}

function load(el, state) {
  Promise.all([
    fetch("/api/policy/effective").then((r) => r.json()),
    fetch("/api/policy").then((r) => r.json()),
  ])
    .then(([eff, pol]) => {
      state.baselines = eff.baselines || [];
      state.userRules = eff.userRules || [];
      renderBaselines(el, state);
      renderUserRules(el, state);
      el.querySelector("#pol-raw").value = pol.json || "";
      renderVersions(el.querySelector("#pol-versions"), pol.versions || [], el.querySelector("#pol-raw"));
    })
    .catch(() => {});
}

function renderBaselines(el, state) {
  const tbody = el.querySelector("#pol-baselines");
  tbody.replaceChildren();
  for (const b of state.baselines) {
    const ov = b.override || {};
    const enabled = ov.enabled !== false;
    const sev = ov.severity || b.defaultSeverity;
    const tr = document.createElement("tr");
    if (b.override) tr.className = "overridden";

    const tdOn = document.createElement("td");
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = enabled;
    cb.dataset.id = b.id;
    cb.className = "b-enabled";
    tdOn.appendChild(cb);

    const tdName = document.createElement("td");
    const code = document.createElement("code");
    code.textContent = b.id;
    const why = document.createElement("div");
    why.className = "muted";
    why.textContent = b.reason || "";
    tdName.append(code, why);

    const tdSev = document.createElement("td");
    const sel = document.createElement("select");
    sel.dataset.id = b.id;
    sel.dataset.default = b.defaultSeverity;
    sel.className = "b-sev";
    for (const s of SEVERITIES) {
      const o = document.createElement("option");
      o.value = s;
      o.textContent = s;
      if (s === sev) o.selected = true;
      sel.appendChild(o);
    }
    tdSev.appendChild(sel);

    tr.append(tdOn, tdName, tdSev);
    tbody.appendChild(tr);
  }
}

function renderUserRules(el, state) {
  const ul = el.querySelector("#pol-userrules");
  ul.replaceChildren();
  if (!state.userRules.length) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = "no user rules";
    ul.appendChild(li);
    return;
  }
  for (const r of state.userRules) {
    const li = document.createElement("li");
    const code = document.createElement("code");
    code.textContent = r.id;
    const meta = document.createElement("span");
    meta.className = "muted";
    meta.textContent = " " + (r.allow ? "allow" : r.severity || "") + " " + (r.reason || "");
    li.append(code, meta);
    ul.appendChild(li);
  }
}

function buildFile(el, state) {
  const overrides = {};
  for (const cb of el.querySelectorAll(".b-enabled")) {
    if (!cb.checked) overrides[cb.dataset.id] = { enabled: false };
  }
  for (const sel of el.querySelectorAll(".b-sev")) {
    if (sel.value !== sel.dataset.default) {
      overrides[sel.dataset.id] = Object.assign(overrides[sel.dataset.id] || {}, { severity: sel.value });
    }
  }
  return { version: 1, overrides, rules: state.userRules };
}

function save(el, state) {
  const status = el.querySelector("#pol-status");
  setStatus(status, "saving…", "");
  fetch("/api/policy", {
    method: "PUT",
    headers: { "Content-Type": "application/json", "X-Argus-CSRF": "1" },
    body: JSON.stringify(buildFile(el, state), null, 2),
  })
    .then(async (r) => {
      const d = await r.json().catch(() => ({}));
      if (!r.ok) {
        setStatus(status, d.error || `save failed (${r.status})`, "err");
        return;
      }
      setStatus(status, `saved as version ${d.version}`, "ok");
      load(el, state);
    })
    .catch((err) => setStatus(status, "save failed: " + err, "err"));
}

function renderVersions(list, metas, raw) {
  list.replaceChildren();
  for (const m of metas) {
    const li = document.createElement("li");
    const btn = document.createElement("button");
    btn.className = "linkish";
    btn.textContent = `v${m.version}`;
    btn.addEventListener("click", () => viewVersion(m.version, raw));
    li.appendChild(btn);
    const meta = document.createElement("span");
    meta.className = "muted";
    meta.textContent = ` ${m.ts || ""} ${m.author || ""} ${m.note || ""}`.replace(/\s+/g, " ");
    li.appendChild(meta);
    list.appendChild(li);
  }
  if (metas.length === 0) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = "no versions recorded yet";
    list.appendChild(li);
  }
}

function viewVersion(v, raw) {
  fetch(`/api/policy/versions/${v}`)
    .then((r) => r.text())
    .then((body) => {
      raw.value = body;
    })
    .catch(() => {});
}

function setStatus(el, msg, kind) {
  el.textContent = msg;
  el.className = "status" + (kind ? " status-" + kind : "");
}
