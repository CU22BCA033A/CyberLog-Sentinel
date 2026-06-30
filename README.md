# CyberLog Sentinel

**SOC-Inspired Linux Log Analysis & Threat Detection Platform**

A production-grade security operations platform that ingests Linux authentication logs, parses them, detects threats with a rule-based detection engine, maps findings to MITRE ATT&CK, and presents results through a professional analyst dashboard.

![CyberLog Sentinel Dashboard](docs/screenshot.png)

---

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌────────────────────┐
│   Next.js App    │────▶│   API Routes      │────▶│   Detection Engine  │
│  (Dashboard UI)  │     │ /api/upload       │     │  15 rule modules    │
│  React + Tailwind│     │ /api/process/[id] │     │  → MITRE mapping    │
└─────────────────┘     │ /api/events        │     └─────────┬──────────┘
         │               │ /api/incidents     │               │
         │               │ /api/reports       │               ▼
         ▼               └──────────┬─────────┘     ┌────────────────────┐
┌─────────────────┐                 │                │   Log Parser       │
│  Supabase Auth   │                 ▼                │  (TypeScript,      │
│ (email/magic-link)│     ┌──────────────────┐         │   no dependencies) │
└─────────────────┘     │  Supabase Postgres │         └────────────────────┘
                          │  (RLS-protected)   │
                          │  log_events         │
                          │  incidents           │
                          │  detections           │
                          │  ssh_sessions          │
                          └──────────────────────┘
```

---

## Features

- **Secure Authentication** — Supabase Auth with email/password and magic-link login, protected routes, audit logging.
- **Drag-and-drop Log Upload** — `.log`, `.txt`, `.gz` up to 100MB, multi-file batch support, real-time progress.
- **Custom Log Parser** — Zero-dependency TypeScript parser handling auth.log, secure, syslog, and journald JSON formats. Never crashes on malformed input.
- **15 Detection Rules** — Brute force, password spray, low-and-slow attacks, root login, privilege escalation, impossible travel, off-hours auth, coordinated attacks, and more — each mapped to a MITRE ATT&CK technique with a confidence score.
- **MITRE ATT&CK Integration** — Local technique database, heatmap visualization, technique detail drawers.
- **Analyst Dashboard** — Animated metric cards, event timeline, severity donut, top attacker bar chart, all built with Recharts.
- **Events Table** — Server-side pagination, filtering, full-text search, expandable rows, CSV export, false-positive marking, analyst notes.
- **Threat Incidents** — Auto-generated incident cards with status workflow (open/investigating/closed/false positive), full evidence timelines.
- **SSH Session Reconstruction** — Sessions rebuilt from `session opened`/`session closed` log pairs, sudo command tracking, active session highlighting.
- **Reports** — PDF, CSV, JSON, and STIX 2.1 threat-intel bundle export.
- **Global Search & Command Palette** — Search IPs, usernames, raw log lines, incidents, and MITRE IDs.
- **Settings** — Detection threshold tuning, IP whitelist/watchlist, webhook alerts, API key management.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 15 (App Router) + TypeScript |
| Styling | Tailwind CSS v4, custom dark SOC theme |
| Charts | Recharts |
| Backend | Next.js API Routes (Node runtime) |
| Database | Supabase (PostgreSQL) with Row Level Security |
| Auth | Supabase Auth (email/password + magic link) |
| Parsing | Custom TypeScript parser (zero external deps) |
| Icons | Lucide React |
| Dates | date-fns |

---

## Prerequisites

- Node.js 18+
- A free [Supabase](https://supabase.com) project
- npm or pnpm

---

## Setup

### 1. Clone & install

```bash
cd cyberlog-sentinel
npm install
```

### 2. Create a Supabase project

1. Go to [supabase.com](https://supabase.com) and create a new project.
2. Copy your project URL, anon key, and service role key from **Project Settings → API**.

### 3. Configure environment variables

```bash
cp .env.local.example .env.local
```

Edit `.env.local`:

```env
NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your-anon-key
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
NEXT_PUBLIC_APP_URL=http://localhost:3000
```

### 4. Run database migrations

Using the Supabase CLI:

```bash
npx supabase login
npx supabase link --project-ref your-project-ref
npx supabase db push
```

Or paste the contents of `supabase/migrations/001_initial_schema.sql` directly into the Supabase SQL Editor and run it.

### 5. Start the dev server

```bash
npm run dev
```

Visit `http://localhost:3000`, register an account, and you're in.

### 6. Try the sample data

A realistic synthetic attack log is included at `supabase/seed-logs/realistic-attack.log`. Upload it from the **Upload Logs** page to see the full detection pipeline in action — it contains a brute force campaign, a password spray, a confirmed root compromise, legitimate sudo usage, and off-hours logins.

---

## Running Tests

```bash
npm test
```

This runs the full parser and detection-engine test suite (40 tests), including an end-to-end check against the bundled seed log that verifies all major attack patterns are correctly detected.

```bash
npm run test:watch   # watch mode
```

---

## MITRE ATT&CK Coverage

| Technique ID | Name | Tactic |
|---|---|---|
| T1110 | Brute Force | Credential Access |
| T1110.001 | Brute Force: Password Guessing | Credential Access |
| T1110.003 | Brute Force: Password Spraying | Credential Access |
| T1078 | Valid Accounts | Initial Access |
| T1078.003 | Valid Accounts: Local Accounts | Privilege Escalation |
| T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | Privilege Escalation |
| T1136 | Create Account | Persistence |
| T1531 | Account Access Removal | Impact |
| T1571 | Non-Standard Port | Command and Control |
| T1021 | Remote Services | Lateral Movement |

---

## Detection Rules Reference

| # | Rule | Logic | Severity | MITRE |
|---|---|---|---|---|
| 1 | SSH Brute Force | ≥5 failures from same IP / 60s | High / Critical (10+) | T1110.001 |
| 2 | Low-and-Slow Brute Force | ≥10 failures / 10min, evasive rate | High | T1110.003 |
| 3 | Password Spray | ≥3 usernames from same IP / 2min | High | T1110.003 |
| 4 | Success After Brute Force | Success from IP with ≥3 prior failures | Critical | T1078 |
| 5 | Root Login | Direct root SSH login | High (internal) / Critical (external) | T1078.003 |
| 6 | Invalid User Enumeration | ≥3 invalid usernames from same IP | Medium | T1110.001 |
| 7 | Sudo Usage | Privileged command execution | Low | T1548.003 |
| 8 | Sudo Shell Escape | `sudo bash`/`sh`/`su`/`-i` | High | T1548.003 |
| 9 | Off-Hours Authentication | Success between 22:00–06:00 | Medium | T1078 |
| 10 | Global Failure Flood | >100 failures across all IPs / 5min | Critical | T1110 |
| 11 | Repeated PAM Failures | ≥3 PAM failures for same user | Medium | T1110 |
| 12 | Non-Standard Source Port | SSH from port < 1024 | Low | T1571 |

---

## Project Structure

```
cyberlog-sentinel/
├── app/
│   ├── (auth)/login/             # Login & registration
│   ├── (dashboard)/              # Sidebar + topbar shell, all analyst pages
│   │   ├── dashboard/            # Main metrics dashboard
│   │   │   ├── events/           # Events table
│   │   │   ├── threats/          # Incidents list + detail
│   │   │   ├── sessions/         # SSH session tracker
│   │   │   ├── search/           # Global search
│   │   │   ├── reports/          # Report export
│   │   │   └── settings/         # Thresholds, watchlist, API keys
│   │   └── upload/               # Upload flow
│   └── api/
│       ├── upload/               # File upload + processing trigger
│       ├── process/[jobId]/      # Job status polling
│       ├── events/                # Paginated events API
│       ├── incidents/             # Incidents CRUD
│       ├── ip-intel/              # IP enrichment
│       └── reports/generate/      # PDF/CSV/JSON/STIX export
├── lib/
│   ├── parser/                   # Log parsing engine
│   ├── detection/rules/          # 12 standalone detection functions
│   ├── mitre/                    # MITRE ATT&CK local database
│   ├── supabase/                 # Client/server Supabase helpers
│   └── utils/                    # IP classification, geo enrichment
├── types/                        # Shared TypeScript types
├── __tests__/                    # Parser, detection, and integration tests
└── supabase/
    ├── migrations/                # SQL schema with RLS
    └── seed-logs/                 # Realistic sample attack log
```

---

## Security Notes

- All Supabase tables use Row Level Security — users can only access data from their own uploads.
- The service role key is never exposed to the client; it's used only in server-side API routes.
- All API routes that mutate data validate the request before writing.

---

## Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/new-detection-rule`)
3. Add tests for any new detection logic
4. Run `npm test` and `npm run lint` before submitting
5. Open a pull request

---

## License

MIT
