# AI Sentinel

Insider-fraud early warning for banks, plus bank-message verification and loan-document verification. One Node.js server (REST API + website) with a SQLite database. No npm dependencies. Requires **Node.js 22.5+**.

## Two modes

| | Demo mode (`SEED_DEMO=1`) | Real-data mode (`SEED_DEMO=0`) |
|---|---|---|
| Starts with | 400 synthetic rows per dataset from `seed/` | **Empty**: no records, no alerts |
| Live event simulator | on (`SIMULATE=1`) | always off |
| "Reset to demo" buttons | work | disabled (they would erase your data) |
| Use for | demos, training | your bank's data |

The files in `seed/` are **synthetic** (placeholder IDs, `example.com` emails, "Synthetic demo data" labels). They are only loaded in demo mode. Never treat them as real data.

## 1. Run locally
    npm start                 # demo mode  -> http://localhost:3000   (login admin / sentinel123, registration key SENTINEL-2026)
    npm run start:real        # real-data mode, empty
    npm test                  # 15 API tests

## 2. Deploy
Copy `.env.example` to `.env` and set `ADMIN_PASSWORD`, `ADMIN_KEY` and `TZ`. `.env.example` is already set for real-data mode.

**Docker (any VPS)**
    docker compose up -d --build                    # http://SERVER:3000
    docker compose --profile https up -d --build    # automatic HTTPS for $DOMAIN (Caddy)
Data lives in the `sentinel-data` volume. The container fixes volume ownership itself, so it also works on Render and Fly.

**Render**: push to GitHub and create a Blueprint from `render.yaml`. The Blueprint uses Render's free plan with synthetic demo data and no persistent disk; the service may spin down when idle, and database changes can be lost when the instance restarts or redeploys. Do not use this free deployment for real data. For real-data mode, use a paid plan with a persistent disk mounted at `/app/data`, and set `SEED_DEMO=0` and `SIMULATE=0`.
**Fly.io**: edit the app name in `fly.toml`, then `fly launch --no-deploy`, `fly volumes create sentinel_data --size 1`, `fly secrets set ADMIN_PASSWORD=... ADMIN_KEY=...`, `fly deploy`.
**Plain Linux server**: copy to `/opt/ai-sentinel`, put settings in `.env`, `chown -R www-data /opt/ai-sentinel/data`, install `deploy/ai-sentinel.service` (systemd) or use `ecosystem.config.js` (pm2), and put nginx (`deploy/nginx.conf` + certbot) or Caddy in front for HTTPS.

Serverless hosts (Vercel, Netlify) will not work. Run **one instance only** (SQLite). Do not expose port 3000 to the internet without HTTPS in front.

## 3. Loading your real data
Sign in, open **Data Import**, choose a dataset, choose your CSV (header row required) and press **Import**. Alerts are raised automatically after each import. Starter headers are in `templates/`.

**Import in this order:** 1) employees, 2) customers, 3) transactions, 4) activity events.

| Dataset | Required | Rules enforced on import |
|---|---|---|
| employees | `EmployeeID` | must look like `EMP0001` (letters EMP + digits) |
| customers | `CustomerID` | must look like `CUS0001` |
| transactions | `TransactionID`, `EmployeeID`, `TransactionDate`, `Amount` | date `2026-10-28 14:30:00`, numeric amount |
| activity events | `EventID`, `EmployeeID`, `EventTimestamp` | timestamp `2026-10-28 14:30:00` |

Rows that break a rule are skipped and listed with their row number. Events and transactions whose `EmployeeID` is not in the employees list are stored but **not scored**, and you are warned. Re-importing the same ID updates that record. **If your core systems use other ID formats (for example `HR-2231`), map them to `EMP####` / `CUS####` in your export first.** Times are read as written, so export them in your bank's local time.

Message and loan verification (Message Verify / Document Verify pages) take their own CSVs with the columns in `templates/message_verification.csv` and `templates/loan_verification.csv`. Message rows need a `Label` starting with *Suspicious* or *Genuine*; loan rows need a `Label` starting with *Review* or *Consistent*.

Large files: one import request is capped at 8 MB (roughly 20,000 rows). Split bigger exports.

## 4. Alert notifications
Set `ALERT_WEBHOOK_URL` to a Slack, Teams or Discord incoming webhook. A message is sent when a **new** alert reaches the threshold in Settings (default 80) and "email alerts" is on. **Settings → Send test email** posts a test message. No email (SMTP) sending is built in. If no webhook is set, the test button says so and nothing is sent.

## 5. Settings (environment variables)
| Variable | Default | Purpose |
|---|---|---|
| NODE_ENV | | `production` enforces ADMIN_PASSWORD and ADMIN_KEY |
| SEED_DEMO | 1 (Docker image: 0) | `0` = real-data mode (starts empty) |
| SIMULATE | on (demo only) | `0` stops the synthetic live-event generator |
| TZ | system | Timezone for off-hours rules and "today" charts, e.g. `Asia/Kolkata` |
| PORT | 3000 | HTTP port |
| ADMIN_PASSWORD | sentinel123 | Password for `admin`, **used only when the database is first created** |
| ADMIN_KEY | SENTINEL-2026 | Access key needed to register users (new users are analysts) |
| SESSION_HOURS | 12 | Login lifetime |
| ALERT_WEBHOOK_URL | | Where high-risk alerts are posted |
| TRUST_PROXY / HTTPS_ONLY | off | `1` behind a reverse proxy / adds HSTS |
| DATA_DIR / DB_FILE | ./data | Database location (mount a volume here) |
| KEEP_BACKUPS | 14 | Backups kept by `npm run backup` |

The login page shows the default credentials only while the server is still using the built-in defaults.

## 6. Backup and restore
    npm run backup                       # consistent copy into data/backups/
    docker compose --profile backup run --rm backup
    crontab deploy/backup.cron           # daily at 02:30
Restore: stop the app, copy a backup over `data/sentinel.db` (delete `sentinel.db-wal` and `-shm`), start the app.
`npm run reset-db` deletes the database, users and alerts. With `SEED_DEMO=0` the next start is empty. **Switching an existing demo database to real data: run `npm run reset-db` first**, otherwise the synthetic records stay.

## 7. Layout
`server.js` server, API, persistence, rate limiting, security headers | `engine.js` detection rules, scoring, honeypot, cases, graph, import validation, webhook | `public/index.html` the interface | `seed/` synthetic demo CSVs | `preview/ai-sentinel-preview.html` standalone copy of the UI that runs in any browser with no server (demo data, resets on refresh) | `templates/` empty CSV headers | `scripts/` backup and reset | `deploy/` Caddy, nginx, systemd, cron | `tests/` API tests

## 8. Known limits (read before using real customer data)
- Detection is rule and model based, tuned on synthetic data. Have your fraud team review thresholds and measure false positives in a pilot before acting on alerts.
- Data is held in memory and scanned in full. Measured: with 100,000 activity events, a 20,000-row import takes under a second and the dashboard statistics about 0.3 s. Not tested beyond 100,000 events; expect slower responses and higher memory use as it grows. One instance only.
- Customer details are stored unencrypted in SQLite. Use an encrypted disk and restrict who can reach the server.
- Only two roles (admin, analyst). The audit screen shows the latest 30 entries.
- There are no live connectors to core banking, HR or log systems. Data arrives by CSV import or the API.
- The message and loan models train in the browser from the records the API serves.
