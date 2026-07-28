// app.mjs — the shell: a hash-routed tab bar over per-view ES modules. No
// build step, no framework; each view module exports { id, title, mount(el) }
// and mount may return a cleanup function called on navigation away (Live uses
// it to close its EventSource). New tabs are added by importing the module and
// appending it to `tabs` — Explain/Policy (12b) and Replay (12c) land that way.

import * as live from "/static/live.mjs";
import * as stats from "/static/stats.mjs";
import * as explain from "/static/explain.mjs";
import * as policy from "/static/policy.mjs";

// Replay (Task 12c) appends its module here.
const tabs = [live, stats, explain, policy];

let cleanup = null;

function render() {
  const nav = document.getElementById("tabs");
  const view = document.getElementById("view");
  const current = location.hash.slice(1) || tabs[0].id;

  nav.replaceChildren();
  for (const t of tabs) {
    const a = document.createElement("a");
    a.textContent = t.title;
    a.href = "#" + t.id;
    a.className = "tab" + (t.id === current ? " active" : "");
    nav.appendChild(a);
  }

  if (cleanup) {
    cleanup();
    cleanup = null;
  }
  view.replaceChildren();
  const tab = tabs.find((t) => t.id === current) || tabs[0];
  cleanup = tab.mount(view) || null;
}

window.addEventListener("hashchange", render);
render();
