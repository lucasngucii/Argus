# Nghiên cứu: bộ rule chặn lệnh nguy hiểm cho Claude Code (Argus policy)

> **Phương pháp:** deep-research harness — 6 hướng tìm kiếm song song, 27 nguồn fetch,
> 117 claim rút ra, **25 claim qua kiểm chứng đối kháng 3-vote** (0 bị bác bỏ). Nguồn
> ưu tiên: academic (arXiv), framework chuẩn (MITRE ATT&CK, OWASP), tài liệu hãng, và
> postmortem thật. Bước tổng hợp tự động của workflow bị gián đoạn (hết session) —
> báo cáo này là bản tổng hợp thủ công từ 25 claim đã verify, giữ nguyên trích dẫn gốc.

## 1. Khung lý thuyết — vì sao chia 4 mức, không phải nhị phân

**Căn cứ học thuật trực tiếp nhất** cho mô hình severity của Argus:

> "SAFE, for read-only commands and commands that do not alter the state of the
> system significantly; RISKY, for commands that may irreversibly alter the state
> of the system and cause damage, for which privilege escalation is required;
> BLOCKED, for commands that will irreversibly alter the correct state of the
> system, and must never be executed."
> — [arXiv:2412.01655](https://arxiv.org/html/2412.01655v1) (Notaro et al., Huawei/TU Munich) [3-0]

Đây gần như là bản gốc của thang `safe/low/medium(ask)/high(deny-always)` — **BLOCKED = floor, không thương lượng**; **RISKY = ask-a-human**; **SAFE = allow**.

Cùng bài báo cảnh báo lý do parse-AST là bắt buộc, không chỉ regex trên verb:

> "small changes to parameters, flags, and some uses of the command-line syntax
> highly influence the risk of executed commands"
> — [arXiv:2412.01655](https://arxiv.org/html/2412.01655v1) [3-0]

→ `rm <logfile>` an toàn, `rm -rf /bin/*` thảm hoạ — **cùng verb, khác flag/target, khác severity**. Đây chính là lý do Argus không match trên tên lệnh trần mà dùng `flags`/`argsContain`/`targetScorer` trên AST đã resolve.

**Vì sao "ask-a-human" (medium) có căn cứ chuẩn, không phải tuỳ tiện:**

> "Utilise human-in-the-loop control to require a human to approve high-impact
> actions before they are taken."
> — [OWASP Top-10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf) [3-0]

> "Implement authorization in downstream systems rather than relying on an LLM to
> decide if an action is allowed or not. Enforce the complete mediation principle."
> — cùng nguồn [3-0]

→ Đây là căn cứ trực tiếp cho **kiến trúc PreToolUse hook ngoài model** (không để LLM tự quyết) — đúng thiết kế Argus.

**Vì sao denylist đơn thuần (regex/danh sách chuỗi) không đủ:**

> "even a built-in denylist of Claude Code, well-maintained by its developers, can
> overlook bypass commands that invalidate its effectiveness"
> — [arXiv:2606.15549](https://arxiv.org/pdf/2606.15549) [3-0]

> "In an empirical study of 1,709 real-world command denylists (13,332 rules) ...
> between 69.0% and 98.6% of denylists were found to be fragile (bypassable)"
> — cùng nguồn [3-0]

**Đây là bằng chứng định lượng mạnh nhất tìm được cho lý do Argus phải parse AST thay vì regex thô** — 7/10 đến gần 99% denylist thực tế trên GitHub bị lách được. Không có căn cứ nào mạnh hơn để giải thích "vì sao không chỉ ghi list `rm -rf` là xong".

---

## 2. Theo nhóm rủi ro — căn cứ + severity đề xuất

### 2.1 Phá huỷ filesystem (rm -rf, dd, mkfs)

| Bằng chứng | Nguồn | Vote |
|---|---|---|
| Data destruction (ghi đè/xoá không phục hồi được) là kỹ thuật **Impact/Availability** trong MITRE ATT&CK | [T1485](https://attack.mitre.org/techniques/T1485/) | 3-0 |
| Xoá file bằng tính năng OS hợp pháp (`rm`, `del`) **không thể ngăn bằng kiểm soát phòng ngừa** — phải chặn tại điểm thực thi | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | 2-1 |
| **Sự cố thật:** kỹ sư GitLab chạy `rm -rf` nhắm nhầm server, xoá **~300GB dữ liệu production** trong vài giây trước khi kịp Ctrl-C | [GitLab postmortem 2017](https://about.gitlab.com/blog/postmortem-of-database-outage-of-january-31/) | 3-0 |

→ **Severity: `high` (floor)** khi target là `/`, home, system dir, hoặc AST không resolve được target (đúng rule `rm-catastrophic` hiện có). Sự cố GitLab chứng minh: **giây đầu tiên** đã không cứu được — floor phải chặn *trước khi chạy*, không phải log lại sau.

### 2.2 RCE / supply-chain (curl|bash, npm postinstall, decoder→shell)

> "Any developer workstation or CI/CD pipeline that ran `npm install` or
> `npm update` after the compromised versions were published was potentially
> exposed, **regardless of whether the package was imported in application code**."
> — [Microsoft Security, vụ Mastra 2026](https://www.microsoft.com/en-us/security/blog/2026/06/17/postinstall-payload-inside-mastra-npm-supply-chain-compromise/) [3-0]

> Axios (100M+ tải/tuần) bị chiếm tài khoản maintainer, publish 2 bản chứa RAT đa nền tảng qua **postinstall hook** (`postinstall: "node setup.js"`)
> — [Trend Micro 2026](https://www.trendmicro.com/en_us/research/26/c/axios-npm-package-compromised.html) [3-0 / 2-1]

> npm packages "harvest developer-workstation secrets including SSH keys, GitHub/npm
> tokens, cloud provider credentials, and Kubernetes service-account tokens"
> — [Unit42 (Palo Alto)](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/) [3-0]

→ **Severity: `high` (floor)** cho `curl|sh`, `wget|bash`, `base64 -d|sh` (pipe-to-shell — đã có). **Bằng chứng mới quan trọng:** `npm install`/`npm update` bản thân **cũng là vector RCE** qua lifecycle hook, kể cả khi không import package — đây là gap Argus hiện **chưa có rule riêng** cho `npm install`/`pip install` (khuyến nghị bổ sung, xem §3).

### 2.3 Lộ / khai thác credential

> Kịch bản tấn công thật: "Execute `grep` with regex patterns to locate API
> credentials ... Use `curl` to transmit discovered keys to attacker infrastructure"
> — [arXiv:2509.22040](https://arxiv.org/html/2509.22040v2) [3-0]

> "Overwrite the `~/.ssh/authorized_keys` file" để duy trì truy cập SSH; sửa
> `~/.bashrc`; tạo account đặc quyền bằng `useradd`
> — cùng nguồn [3-0]

> Prompt injection qua tài nguyên ngoài (file rule coding, repo GitHub, MCP server)
> đạt **tỉ lệ thành công tới 84%** khiến AI coding editor chạy lệnh độc hại
> — cùng nguồn [3-0]

→ **Severity: `high` (floor)** cho ghi/xoá `.ssh`, `.aws/credentials`, `sudoers` (đã có). **Bằng chứng mới:** chuỗi **`grep <credential-pattern> | curl -d`** (exfiltrate) là mẫu tấn công thật đã ghi nhận — Argus nên có rule riêng bắt chuỗi này (xem §3), không chỉ chặn ghi file mà cả **đọc-rồi-gửi**.

### 2.4 Phá hạ tầng (terraform/kubectl/cloud CLI)

Không tìm được postmortem hãng chính thức riêng cho `terraform destroy`/`kubectl delete` trong 25 claim đã verify (câu hỏi có hỏi nhưng nguồn tìm được tập trung vào MITRE/OWASP/npm/rm). Đây là **khoảng trống cần gắn cờ**: mức độ nguy hiểm của `terraform destroy`/`kubectl delete -n prod` là **suy luận hợp lý từ nguyên tắc chung** (Impact/Availability — T1485 áp dụng tương tự cho tài nguyên cloud, không riêng file) **chứ chưa có trích dẫn sự cố cụ thể** trong tập nguồn đã verify. Khuyến nghị: severity theo nguyên tắc cùng nhóm với DB/filesystem — **medium mặc định, escalate `high` khi cwd/context là prod** (context-escalation, không phải floor cứng, vì `terraform plan`/`destroy -target` trong dev env là thao tác hợp lệ thường xuyên).

### 2.5 Nguyên tắc thiết kế bao trùm (áp dụng mọi nhóm)

> "Avoid the use of open-ended extensions where possible (e.g., run a shell
> command...) ... the scope for undesirable actions is very large."
> — [OWASP LLM Top-10 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf) [3-0]

> "Many LLM-based systems execute tasks the moment an instruction is generated,
> without any form of human review" — cơ sở bắt buộc phải có tầng ask-a-human.
> — [Indusface, OWASP LLM Excessive Agency](https://www.indusface.com/learning/owasp-llm-excessive-agency/) [3-0]

Đây là căn cứ tổng quát cho **toàn bộ kiến trúc Argus**: bash là "open-ended extension" nguy hiểm nhất trong OWASP taxonomy — không có cách "làm an toàn" nó ngoài **gate ngoài model + human-in-the-loop cho case rủi ro**.

---

## 3. Tổng hợp: rule đề xuất bổ sung (dạng data cho `policy.json`)

Ký hiệu: 🔒 = floor (`alwaysHigh: true`, không rule/allowlist nào hạ được) · ⬆️prod = context-escalate khi cwd chứa `prod`.

| id | Pattern | Severity | Căn cứ (rút gọn) |
|---|---|---|---|
| `npm-install-lifecycle` | `npm install`/`npm ci`/`npm update` (không `--ignore-scripts`) | **medium** | postinstall hook = vector RCE đã ghi nhận nhiều vụ 2026 (Mastra, Axios) [3-0] |
| `pip-install-untrusted` | `pip install` từ URL/git trực tiếp (không lockfile) | **medium** | cùng lớp nguy cơ supply-chain như npm |
| `grep-then-exfil` | chuỗi lệnh: `grep`/`rg` tìm pattern credential **PIPE VÀO** `curl`/`nc`/`wget` gửi ra ngoài | 🔒 **high** | mẫu tấn công thật: "grep để tìm API key → curl gửi ra ngoài" [3-0] |
| `ssh-persistence-write` | ghi vào `~/.ssh/authorized_keys`, sửa `~/.bashrc`/`~/.zshrc` để chèn lệnh | 🔒 **high** | kỹ thuật duy trì truy cập đã ghi nhận trong tấn công thật [3-0] |
| `useradd-privileged` | `useradd`, `usermod -aG sudo/wheel` | 🔒 **high** | tạo account đặc quyền là bước persistence trong tấn công thật [3-0] |
| `terraform-destroy` | `terraform destroy`, `terraform apply -auto-approve` | medium ⬆️prod→high | suy luận nguyên tắc Impact/Availability (chưa có postmortem trích dẫn trực tiếp — xem §2.4) |
| `kubectl-delete-prod` | `kubectl delete`/`drain` | medium ⬆️prod→high | cùng lý do trên |
| `cloud-cli-delete` | `aws … delete-*`, `gcloud … delete` | medium ⬆️prod→high | cùng lý do trên |
| *(đã có)* `rm-catastrophic`, `disk-format`, `forkbomb`, `pipe-to-shell`, `db-destructive`, `credential-system-write`, `self-protect-*` | — | 🔒 high | củng cố bởi T1485/T1070.004/GitLab postmortem/Trend Micro/Microsoft/Unit42 ở trên |

**Điều Argus đã làm đúng theo bằng chứng:** kiến trúc "gate ngoài model, ask cho medium, floor cứng cho catastrophe" **khớp trực tiếp** với khuyến nghị OWASP (human-in-the-loop + external mediation) và với thang 3 mức của arXiv:2412.01655. Điểm engine cần nâng cấp theo bằng chứng mới nhất (2026): **supply-chain qua package-manager install** là vector RCE ngang hàng `curl|bash` nhưng Argus **hiện chưa có rule riêng** cho `npm install`/`pip install` — đây là gap cụ thể, có trích dẫn, đáng ưu tiên thêm.

---

## 4. `policy.json` sẵn dùng — 8 rule bổ sung (data, dán thẳng vào mảng `rules`)

```json
[
  {
    "id": "npm-install-lifecycle",
    "enabled": true,
    "tool": ["Bash"],
    "severity": "medium",
    "reason": "package install can run arbitrary code via postinstall/preinstall hooks (npm supply-chain RCE)",
    "match": { "cmd": ["npm"], "argsContain": ["install", "ci", "update"] }
  },
  {
    "id": "pip-install-untrusted",
    "enabled": true,
    "tool": ["Bash"],
    "severity": "medium",
    "reason": "installing from a direct URL/VCS ref bypasses lockfile review",
    "match": { "cmd": ["pip", "pip3"], "argMatches": "install\\s+.*(git\\+|https?://)" }
  },
  {
    "id": "grep-then-exfil",
    "enabled": true,
    "alwaysHigh": true,
    "tool": ["Bash"],
    "severity": "high",
    "reason": "credential-search piped to network exfiltration (documented attack pattern)",
    "match": { "raw": "(?i)\\b(grep|rg|ag)\\b[^|]*(key|token|secret|credential|password)[^|]*\\|\\s*(curl|wget|nc|ncat)\\b" }
  },
  {
    "id": "ssh-persistence-write",
    "enabled": true,
    "alwaysHigh": true,
    "tool": ["Bash", "Write", "Edit"],
    "severity": "high",
    "reason": "writes to authorized_keys/shell rc files are a documented persistence technique",
    "match": { "raw": "(^|[\\s;&|(\"'/])\\.ssh/authorized_keys\\b|(^|[\\s;&|(\"'/])\\.(bash|zsh)rc\\b" }
  },
  {
    "id": "useradd-privileged",
    "enabled": true,
    "alwaysHigh": true,
    "tool": ["Bash"],
    "severity": "high",
    "reason": "privileged account creation is a documented attack persistence step",
    "match": { "cmd": ["useradd", "usermod"], "argMatches": "(?i)\\b(sudo|wheel|admin)\\b" }
  },
  {
    "id": "terraform-destroy",
    "enabled": true,
    "tool": ["Bash"],
    "severity": "medium",
    "reason": "irreversible infrastructure teardown",
    "match": { "cmd": ["terraform"], "argsContain": ["destroy"] },
    "contextEscalation": [{ "when": { "cwdMatches": "prod" }, "to": "high" }]
  },
  {
    "id": "terraform-auto-approve",
    "enabled": true,
    "tool": ["Bash"],
    "severity": "medium",
    "reason": "applies infra changes with no human confirmation step",
    "match": { "cmd": ["terraform"], "argsContain": ["-auto-approve"] },
    "contextEscalation": [{ "when": { "cwdMatches": "prod" }, "to": "high" }]
  },
  {
    "id": "kubectl-delete-drain",
    "enabled": true,
    "tool": ["Bash"],
    "severity": "medium",
    "reason": "removes live workloads/nodes from a cluster",
    "match": { "cmd": ["kubectl"], "argsContain": ["delete", "drain"] },
    "contextEscalation": [{ "when": { "cwdMatches": "prod" }, "to": "high" }]
  },
  {
    "id": "cloud-cli-delete",
    "enabled": true,
    "tool": ["Bash"],
    "severity": "medium",
    "reason": "deletes cloud resources (compute/storage/DB) via provider CLI",
    "match": { "cmd": ["aws", "gcloud", "az"], "argMatches": "(?i)\\bdelete\\b" },
    "contextEscalation": [{ "when": { "cwdMatches": "prod" }, "to": "high" }]
  }
]
```

Đã schema-validate cú pháp thủ công theo `internal/policy/schema.json` (fields `cmd/argsContain/argMatches/raw/contextEscalation` đúng shape). **Khuyến nghị trước khi bật thật:** dán vào `~/.argus/policy.json`, chạy `argus doctor` (kiểm schema) rồi `argus explain` với vài lệnh mẫu, và dùng tab **Replay** để xem áp lên lịch sử đổi gì trước khi save.

---

## 5. Giới hạn của nghiên cứu này (minh bạch)

- **Bước tổng hợp tự động bị hỏng** (hết session) — báo cáo này tổng hợp thủ công từ 25 claim thô đã 3-vote-verify; không có bước "reconcile mâu thuẫn giữa nguồn" tự động thêm.
- **§2.4 (terraform/kubectl/cloud CLI) thiếu trích dẫn sự cố cụ thể** trong tập 25 claim — đã gắn cờ rõ, severity đề xuất dựa trên suy luận nguyên tắc, không phải bằng chứng trực tiếp như các nhóm khác.
- 27 nguồn fetch được, 1 nguồn lỗi fetch (`github.com/Dicklesworthstone/destructive_command_guard` — timeout, đánh dấu unreliable, không dùng).
- Vote 2-1 (không phải 3-0 tuyệt đối) ở 3 claim: T1070.004 (file-deletion cannot be prevented), Axios postinstall auto-exec, Mastra malware auto-exec — vẫn đủ ngưỡng xác nhận (≥2/3) nhưng đáng lưu ý có 1 model bất đồng.

## Nguồn chính (primary, đã verify ≥1 claim)

- arXiv:2412.01655 — Command-line Risk Classification (Huawei/TU Munich)
- arXiv:2606.15899 — SkillVetBench (taxonomy 7 nhóm lỗ hổng skill)
- arXiv:2606.15549 — nghiên cứu thực nghiệm 1,709 denylist thật trên GitHub
- arXiv:2509.22040 — prompt-injection → RCE trên AI coding editor (84% success rate)
- MITRE ATT&CK T1485 (Data Destruction), T1070.004 (File Deletion), T1105 (Ingress Tool Transfer)
- OWASP Top-10 for LLM Applications 2025
- GitLab.com postmortem (2017) — sự cố xoá 300GB production
- Trend Micro (Axios npm compromise, 2026), Microsoft Security (Mastra postinstall, 2026), Unit42/Palo Alto (npm supply-chain monitoring)
