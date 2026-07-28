# Argus policy packs

Optional rule sets you merge into `~/.argus/policy.json` (via the web **Policy**
tab, or by hand) if they fit your setup. Not baked into the default policy.

## infra.json — cloud / IaC teardown guards

Flags `terraform destroy`/`apply -auto-approve`, `kubectl delete`/`drain`, and
`aws`/`gcloud`/`az` delete/terminate as **medium (ask)**, escalating to **high
(deny)** when the working directory looks like prod (`cwdMatches: "prod"`).

**Caveat (honest):** unlike the built-in floor rules, these severities are
inference from the MITRE ATT&CK Impact/Availability principle, **not** a
directly-cited incident in the verified research set (research §2.4). `terraform
destroy` in a dev workspace is routine — that is why these are opt-in, medium,
and context-escalated, not a hard floor. Known gaps: `-auto-approve=true` (vs the
bare flag) and cloud subcommands beyond delete/terminate/rb aren't matched — tune
as needed.

## Optional: pip install from a URL/VCS ref

Same supply-chain class as npm, but with **no directly-cited incident** in the
research set (so not baked into the default). Add it if you want it:

    { "id": "pip-install-untrusted", "enabled": true, "tool": ["Bash"], "severity": "medium",
      "reason": "pip install from a direct URL/VCS ref bypasses lockfile review",
      "match": { "cmd": ["pip", "pip3"], "argMatches": "install\\s+.*(git\\+|https?://)" } }

Note it can over-fire on `pip install -i https://mirror …` (a private index of a
named package); tighten if that's your workflow.

To apply any pack: copy the `rules` entries into your `policy.json`, then
re-version and save (the web editor bumps the version + snapshots for you).
