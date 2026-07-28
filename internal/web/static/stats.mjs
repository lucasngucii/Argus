// stats.mjs — the Stats view: deny/sessions stat tiles + an inline-SVG severity
// bar. The bar is a horizontal magnitude-by-category chart; every bar is
// directly labeled with its severity name and count, so color is never the only
// carrier of identity (the severity palette lives in style.css, validated for
// both light and dark surfaces).

const SEVERITIES = ["safe", "low", "medium", "high"];

export const id = "stats";
export const title = "Stats";

export function mount(el) {
  el.innerHTML = `<section class="panel" id="stats-panel"><p class="muted">loading…</p></section>`;
  const panel = el.querySelector("#stats-panel");
  fetch("/api/stats")
    .then((r) => r.json())
    .then((d) => renderStats(panel, d))
    .catch((err) => {
      panel.innerHTML = `<p class="error">stats unavailable: ${escapeText(String(err))}</p>`;
    });
}

function renderStats(panel, d) {
  const counts = d.counts || {};
  panel.replaceChildren();

  const tiles = document.createElement("div");
  tiles.className = "tiles";
  tiles.appendChild(tile("denied", d.deny ?? 0));
  tiles.appendChild(tile("sessions", d.sessions ?? 0));
  panel.appendChild(tiles);

  const h = document.createElement("h2");
  h.textContent = "By severity";
  panel.appendChild(h);
  panel.appendChild(severityBar(counts));
}

function tile(label, value) {
  const t = document.createElement("div");
  t.className = "tile";
  const v = document.createElement("div");
  v.className = "tile-value";
  v.textContent = String(value);
  const l = document.createElement("div");
  l.className = "tile-label";
  l.textContent = label;
  t.append(v, l);
  return t;
}

// severityBar builds an inline SVG: one thin horizontal bar per severity,
// baseline-anchored at x=0, rounded data-end, a 2px surface gap between bars,
// and a direct `name  count` label. Bars scale to the largest count.
function severityBar(counts) {
  const max = Math.max(1, ...SEVERITIES.map((s) => counts[s] || 0));
  const rowH = 28;
  const barH = 18;
  const gap = rowH - barH; // >= 2px surface gap between fills
  const labelW = 190;
  const chartW = 320;
  const width = labelW + chartW + 40;
  const height = SEVERITIES.length * rowH + 8;

  const svgNS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(svgNS, "svg");
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("width", "100%");
  svg.setAttribute("class", "sev-chart");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "decision counts by severity");

  SEVERITIES.forEach((sev, i) => {
    const n = counts[sev] || 0;
    const y = i * rowH + gap / 2;
    const w = Math.round((n / max) * chartW);

    const label = document.createElementNS(svgNS, "text");
    label.setAttribute("x", "0");
    label.setAttribute("y", y + barH / 2);
    label.setAttribute("dominant-baseline", "central");
    label.setAttribute("class", "sev-chart-label");
    label.textContent = sev;
    svg.appendChild(label);

    const rect = document.createElementNS(svgNS, "rect");
    rect.setAttribute("x", labelW);
    rect.setAttribute("y", y);
    rect.setAttribute("width", Math.max(w, n > 0 ? 3 : 0));
    rect.setAttribute("height", barH);
    rect.setAttribute("rx", "4");
    rect.setAttribute("class", "sev-fill sev-" + sev);
    svg.appendChild(rect);

    const value = document.createElementNS(svgNS, "text");
    value.setAttribute("x", labelW + Math.max(w, 3) + 8);
    value.setAttribute("y", y + barH / 2);
    value.setAttribute("dominant-baseline", "central");
    value.setAttribute("class", "sev-chart-value");
    value.textContent = String(n);
    svg.appendChild(value);
  });

  return svg;
}

function escapeText(s) {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}
