// explain.mjs — the Explain view: a small form (command / tool / mode / file)
// posts to /api/explain and renders why the decision lands where it does. It
// mirrors the CLI `argus explain`: firing rule, severity, verdict, reason, the
// obfuscation flag, and the resolved AST facts.

const SEVERITIES = ["safe", "low", "medium", "high"];

export const id = "explain";
export const title = "Explain";

export function mount(el) {
  el.innerHTML = `
    <section class="panel">
      <h2>Explain a decision</h2>
      <form id="explain-form" class="form">
        <label>command
          <input id="ex-command" type="text" placeholder="sudo rm -rf /" autocomplete="off">
        </label>
        <div class="form-row">
          <label>tool
            <select id="ex-tool">
              <option>Bash</option><option>Write</option><option>Edit</option>
            </select>
          </label>
          <label>mode
            <select id="ex-mode">
              <option>default</option><option>acceptEdits</option><option>plan</option>
            </select>
          </label>
        </div>
        <label>file (for Write/Edit)
          <input id="ex-file" type="text" placeholder="/home/x/.ssh/id_ed25519" autocomplete="off">
        </label>
        <label>args (MCP tool arguments)
          <textarea id="ex-args" placeholder='{"path":"/tmp/x"}'></textarea>
        </label>
        <button type="submit">Explain</button>
      </form>
      <div id="ex-result" class="result"></div>
    </section>`;

  const form = el.querySelector("#explain-form");
  const result = el.querySelector("#ex-result");
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    submit(el, result);
  });
}

function submit(el, result) {
  const body = {
    command: el.querySelector("#ex-command").value,
    tool: el.querySelector("#ex-tool").value,
    mode: el.querySelector("#ex-mode").value,
    file: el.querySelector("#ex-file").value,
    args: el.querySelector("#ex-args").value,
  };
  result.textContent = "…";
  fetch("/api/explain", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Argus-CSRF": "1" },
    body: JSON.stringify(body),
  })
    .then((r) => r.json())
    .then((d) => renderResult(result, d))
    .catch((err) => {
      result.textContent = "explain failed: " + err;
    });
}

function renderResult(result, d) {
  const sev = SEVERITIES.includes(d.severity) ? d.severity : "safe";
  result.replaceChildren();

  const head = document.createElement("div");
  head.className = "result-head";
  const dot = document.createElement("span");
  dot.className = "dot sev-" + sev;
  head.appendChild(dot);
  head.appendChild(strongText(`${sev} → ${d.verdict || "?"}`));
  result.appendChild(head);

  result.appendChild(kv("rule", d.ruleId || "(none)"));
  result.appendChild(kv("reason", d.reason || ""));
  result.appendChild(kv("obfuscated", String(!!d.obfuscated)));
  result.appendChild(kv("commands", (d.commands || []).join(", ") || "(none)"));
  result.appendChild(kv("pipe sinks", (d.pipeSinks || []).join(", ") || "(none)"));
}

function kv(k, v) {
  const row = document.createElement("div");
  row.className = "kv";
  const key = document.createElement("span");
  key.className = "kv-key";
  key.textContent = k;
  const val = document.createElement("span");
  val.className = "kv-val";
  val.textContent = v;
  row.append(key, val);
  return row;
}

function strongText(t) {
  const s = document.createElement("strong");
  s.textContent = t;
  return s;
}
