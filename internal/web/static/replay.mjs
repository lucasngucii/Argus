// replay.mjs — the Replay simulator: edit a candidate policy (prefilled with the
// current one) and POST it to /api/replay to see which logged decisions would
// change severity/verdict under it. Read-only: replay never writes. It always
// shows the scope caveat that safe (unlogged) decisions are not covered.

export const id = "replay";
export const title = "Replay";

export function mount(el) {
  el.innerHTML = `
    <section class="panel">
      <h2>Replay simulator</h2>
      <p class="muted">Re-score the logged decision history against a candidate policy.
        Safe (unlogged) decisions are not covered.</p>
      <textarea id="rp-text" class="editor" spellcheck="false"></textarea>
      <div class="form-row">
        <button id="rp-run">Run replay</button>
        <span id="rp-status" class="status"></span>
      </div>
      <div id="rp-result" class="result"></div>
    </section>`;

  const text = el.querySelector("#rp-text");
  const status = el.querySelector("#rp-status");
  const result = el.querySelector("#rp-result");

  fetch("/api/policy")
    .then((r) => r.json())
    .then((d) => {
      text.value = d.json || "";
    })
    .catch(() => {});

  el.querySelector("#rp-run").addEventListener("click", () => run(text, status, result));
}

function run(text, status, result) {
  status.textContent = "running…";
  status.className = "status";
  result.replaceChildren();
  fetch("/api/replay", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Argus-CSRF": "1" },
    body: text.value,
  })
    .then(async (r) => {
      const d = await r.json().catch(() => ({}));
      if (!r.ok) {
        status.textContent = d.error || `replay failed (${r.status})`;
        status.className = "status status-err";
        return;
      }
      status.textContent = "";
      renderResult(result, d);
    })
    .catch((err) => {
      status.textContent = "replay failed: " + err;
      status.className = "status status-err";
    });
}

function renderResult(result, d) {
  const changed = d.changed || [];
  const head = document.createElement("p");
  head.appendChild(bold(`${d.total || 0} decisions scored, ${changed.length} changed`));
  result.appendChild(head);

  const summary = d.summary || {};
  const keys = Object.keys(summary).sort();
  if (keys.length) {
    const ul = document.createElement("ul");
    ul.className = "versions";
    for (const k of keys) {
      const li = document.createElement("li");
      li.textContent = `${k}: ${summary[k]}`;
      ul.appendChild(li);
    }
    result.appendChild(ul);
  }

  if (changed.length) {
    const table = document.createElement("table");
    table.className = "rows";
    table.innerHTML = `<thead><tr><th>subject</th><th>old</th><th>new</th></tr></thead>`;
    const tbody = document.createElement("tbody");
    for (const c of changed) {
      const tr = document.createElement("tr");
      tr.appendChild(cell((c.row && (c.row.command || c.row.file)) || "", "subject"));
      tr.appendChild(cell(`${c.oldSeverity}/${c.oldVerdict}`));
      tr.appendChild(cell(`${c.newSeverity}/${c.newVerdict}`));
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    result.appendChild(table);
  }

  if (d.capped) {
    const note = document.createElement("p");
    note.className = "muted";
    note.textContent = "NOTE: history truncated at the replay cap.";
    result.appendChild(note);
  }
}

function cell(text, cls) {
  const td = document.createElement("td");
  if (cls) td.className = cls;
  td.textContent = text;
  return td;
}

function bold(t) {
  const s = document.createElement("strong");
  s.textContent = t;
  return s;
}
