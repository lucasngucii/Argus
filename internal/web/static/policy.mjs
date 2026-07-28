// policy.mjs — the Policy editor: loads the current policy.json into a textarea,
// saves it via PUT /api/policy (validate-before-write; a 400 shows inline and
// the file is left untouched), and lists recorded versions. Clicking a version
// loads that snapshot into the editor for inspection. Schema autocomplete is
// intentionally out of the no-build editor — validation-on-save is the
// guarantee.

export const id = "policy";
export const title = "Policy";

export function mount(el) {
  el.innerHTML = `
    <section class="panel">
      <h2>Policy</h2>
      <textarea id="pol-text" class="editor" spellcheck="false"></textarea>
      <div class="form-row">
        <button id="pol-save">Validate &amp; Save</button>
        <span id="pol-status" class="status"></span>
      </div>
      <h2>Versions</h2>
      <ul id="pol-versions" class="versions"></ul>
    </section>`;

  const text = el.querySelector("#pol-text");
  const status = el.querySelector("#pol-status");
  const versions = el.querySelector("#pol-versions");

  load(text, versions);
  el.querySelector("#pol-save").addEventListener("click", () => save(text, status, versions));
}

function load(text, versions) {
  fetch("/api/policy")
    .then((r) => r.json())
    .then((d) => {
      text.value = d.json || "";
      renderVersions(versions, d.versions || [], text);
    })
    .catch(() => {});
}

function save(text, status, versions) {
  setStatus(status, "saving…", "");
  fetch("/api/policy", {
    method: "PUT",
    headers: { "Content-Type": "application/json", "X-Argus-CSRF": "1" },
    body: text.value,
  })
    .then(async (r) => {
      const d = await r.json().catch(() => ({}));
      if (!r.ok) {
        setStatus(status, d.error || `save failed (${r.status})`, "err");
        return;
      }
      setStatus(status, `saved as version ${d.version}`, "ok");
      load(text, versions);
    })
    .catch((err) => setStatus(status, "save failed: " + err, "err"));
}

function renderVersions(list, metas, text) {
  list.replaceChildren();
  for (const m of metas) {
    const li = document.createElement("li");
    const btn = document.createElement("button");
    btn.className = "linkish";
    btn.textContent = `v${m.version}`;
    btn.addEventListener("click", () => viewVersion(m.version, text));
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

function viewVersion(v, text) {
  fetch(`/api/policy/versions/${v}`)
    .then((r) => r.text())
    .then((body) => {
      text.value = body;
    })
    .catch(() => {});
}

function setStatus(el, msg, kind) {
  el.textContent = msg;
  el.className = "status" + (kind ? " status-" + kind : "");
}
