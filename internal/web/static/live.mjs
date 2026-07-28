// live.mjs — the Live tail. Fills from /api/decisions (newest-first) once, then
// prepends each new decision streamed over /api/stream (SSE). Returns a cleanup
// that closes the EventSource so navigating away can't leak a connection.

const SEVERITIES = ["safe", "low", "medium", "high"];

export const id = "live";
export const title = "Live";

export function mount(el) {
  el.innerHTML = `
    <section class="panel">
      <h2>Live decisions</h2>
      <table class="rows">
        <thead>
          <tr><th>time</th><th>sev</th><th>tool</th><th>subject</th><th>verdict</th></tr>
        </thead>
        <tbody id="live-rows"></tbody>
      </table>
    </section>`;
  const tbody = el.querySelector("#live-rows");

  fetch("/api/decisions?limit=50")
    .then((r) => r.json())
    .then((d) => {
      for (const row of d.rows || []) tbody.appendChild(rowEl(row));
    })
    .catch(() => {});

  const es = new EventSource("/api/stream");
  es.onmessage = (e) => {
    try {
      tbody.prepend(rowEl(JSON.parse(e.data)));
    } catch {
      /* ignore a malformed frame */
    }
  };
  return () => es.close();
}

// rowEl renders one decision row. Severity carries a colored dot AND its text
// name (identity is never color-alone), matching the validated severity palette
// in style.css.
export function rowEl(row) {
  const tr = document.createElement("tr");
  const sev = SEVERITIES.includes(row.severity) ? row.severity : "safe";
  tr.appendChild(td(shortTime(row.ts)));
  tr.appendChild(sevCell(sev));
  tr.appendChild(td(row.tool || ""));
  tr.appendChild(td(row.command || row.file || "", "subject"));
  tr.appendChild(td(row.verdict || ""));
  return tr;
}

function sevCell(sev) {
  const cell = document.createElement("td");
  const dot = document.createElement("span");
  dot.className = "dot sev-" + sev;
  cell.appendChild(dot);
  cell.appendChild(document.createTextNode(sev));
  return cell;
}

function td(text, cls) {
  const cell = document.createElement("td");
  if (cls) cell.className = cls;
  cell.textContent = text;
  return cell;
}

// shortTime trims a stored timestamp to its time-of-day when it looks like an
// ISO/SQL datetime, else returns it verbatim.
function shortTime(ts) {
  if (!ts) return "";
  const m = String(ts).match(/\d{2}:\d{2}:\d{2}/);
  return m ? m[0] : ts;
}
