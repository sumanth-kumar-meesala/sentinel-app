# 🛡️ Domain Exposure Scanner

Type a domain → click **Get Report** → watch live progress → export a **PDF** and download all raw **evidence**.
Checks whether a domain's passwords, keys, or tokens are exposed, using only free/open-source tools.

Built with **Next.js 16**, **Tailwind v4**, **DaisyUI 5**.

## What it does

| Phase | Tool(s) | Needs |
|-------|---------|-------|
| Domain recon & DNS | node `dns`, GitHub public API | — |
| Breach & infostealer intel | Hudson Rock Cavalier (free API) | — |
| DNS & email security | node `dns` + DoH | — |
| Subdomain enumeration & liveness | `crt.sh` + `subfinder` + `httpx` | subfinder/httpx optional |
| Related-asset discovery | node `dns` (reverse + Cymru ASN) | — |
| Phishing & typosquat domains | `dnstwist` | dnstwist optional |
| Exposed cloud storage | `cloud_enum` | cloud_enum optional |
| Public code & secret leaks | `gh` + `trufflehog` + `gitleaks` | gh authed; trufflehog/gitleaks optional |
| Employee email exposure | `gh` code search | gh authed |
| TLS & HTTP security | node `tls` + `fetch` | optional `tlsx` |
| Active vuln scan | `nuclei` | **domain verification** + nuclei |

Passive phases always run. Any missing tool degrades that phase gracefully (marked *skipped* in the report).

`httpx` is projectdiscovery's — install via `go install github.com/projectdiscovery/httpx/cmd/httpx@latest`
(the app prefers `~/go/bin` on `PATH` so it wins over the Python `httpx`).

## Requirements

- Node 18+
- Optional CLIs on `PATH` for deeper phases:
  ```bash
  brew install subfinder trufflehog gitleaks nuclei dnstwist
  pipx install git+https://github.com/initstring/cloud_enum.git
  go install github.com/projectdiscovery/httpx/cmd/httpx@latest
  # gh: brew install gh && gh auth login
  ```

## Run

```bash
npm install
npm run dev      # http://localhost:3000
# or: npm run build && npm run start
```

## Domain verification (optional)

Unlocks the active vuln scan (which touches live servers, so it's gated).
Open the "Verify domain ownership" section → **Generate token** → add the shown DNS `TXT` record → **Check**.
The token is a deterministic hash of the domain (no database).

## Analytics

Every report includes a weighted **posture score** (0–100, A–F) across five
dimensions (breach, attack surface, DNS/email, TLS, secrets) with the penalty
reasons shown as methodology, a **trend** vs. the previous run of the same
domain, a **prioritized remediation** roadmap, **compound-risk correlations**
(e.g. a stolen credential whose login host is live), and an interactive
**asset graph**. Export findings as CSV at `/api/report/<runId>/csv`.

Optional CLIs `tlsx` (deeper TLS) and `naabu` (port scanning, gated behind
verification) enhance their phases if installed; the tool degrades gracefully
without them.

## Export

- **Download PDF** — browser print-to-PDF of the report only (print CSS hides the UI chrome).
- **Evidence (.zip)** — all raw tool output for the run (`report.json`, breach JSON, subdomains, emails, nuclei JSON…).

Scan output is written to `runs/<runId>/` (gitignored).

## Notes / limits

- The verification token is a deterministic hash of the domain, so no database is needed — fine for a single-user local tool; add per-user nonces if you make this multi-tenant.
- Only scan domains you are authorized to test. Active scanning is opt-in behind verification for that reason.
