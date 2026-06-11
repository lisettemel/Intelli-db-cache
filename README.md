# Intelli-db-cache

Database and cache layer for **intelli-dns** — an intelligent DNS security system that classifies domains as malicious, benign, or unknown using a machine-learning model. This repository contains the PostgreSQL schema, stored functions, Redis cache configuration, Docker Compose deployment, and the whitelist bulk-loader script.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Project Structure](#project-structure)
- [Database — `database/`](#database--database)
  - [`schema.sql` — Tables & Types](#schemasql--tables--types)
  - [`functions.sql` — Stored Functions](#functionssql--stored-functions)
- [Cache — `cache/`](#cache--cache)
  - [`docker-compose.yml` — Services](#docker-composeyml--services)
  - [`redis.conf` — Redis Configuration](#redisconf--redis-configuration)
  - [`load-whitelist.js` — Whitelist Loader](#load-whitelistjs--whitelist-loader)
  - [`package.json` — Node Dependencies](#packagejson--node-dependencies)
  - [`.env.example` — Environment Variables](#envexample--environment-variables)
  - [`data/tranco_top1m_domains.csv` — Domain Whitelist](#datatrancocsv--domain-whitelist)
- [How Redis is Used by the Backend](#how-redis-is-used-by-the-backend)
- [Quick Start](#quick-start)
- [Network Security](#network-security)
- [License](#license)

---

## Architecture Overview

```
┌────────────────┐     ┌──────────────────────────────────────────────┐
│  Browser Ext.  │────▶│  Backend Express (separate repo)             │
│  (intelli-dns) │     │                                              │
└────────────────┘     │  1. Check whitelist in Redis (SET)           │
                       │  2. Check cache in Redis (key-value)         │
                       │  3. If MISS → call ML model → save to DB    │
                       │  4. Log event → return verdict               │
                       └──────────┬──────────────┬────────────────────┘
                                  │              │
                       ┌──────────▼──────┐  ┌────▼─────────────┐
                       │  Redis (cache)  │  │  PostgreSQL (DB) │
                       │  Port 6379      │  │  Port 5432       │
                       │  256 MB RAM     │  │  Persistent      │
                       └─────────────────┘  └──────────────────┘
                       ▲                    ▲
                       │  THIS REPOSITORY   │
                       └────────────────────┘
```

Both PostgreSQL and Redis run on the **same VM** inside Docker containers, connected via a private bridge network (`intellidns_net`). Neither is exposed to the public internet.

---

## Project Structure

```
Intelli-db-cache/
├── .gitignore                  # Files excluded from version control
├── LICENSE                     # MIT License (Lisette Melo Reyes, 2026)
├── README.md                   # This file
│
├── database/                   # PostgreSQL schema & stored functions
│   ├── schema.sql              # Tables, types, and indexes (3NF design)
│   └── functions.sql           # 8 PL/pgSQL functions called by the backend
│
└── cache/                      # Redis cache + Docker orchestration
    ├── .env.example            # Template for environment variables
    ├── README.md               # Detailed cache documentation
    ├── docker-compose.yml      # Defines Postgres + Redis containers
    ├── redis.conf              # Hardened Redis configuration
    ├── load-whitelist.js       # Node.js script to bulk-load whitelist
    ├── package.json            # Node dependencies (ioredis, dotenv)
    ├── package-lock.json       # Locked dependency versions
    └── data/
        └── tranco_top1m_domains.csv  # Top 1M known-safe domains (~22 MB)
```

---

## Database — `database/`

These SQL files are automatically executed by the PostgreSQL container on first startup (mounted to `/docker-entrypoint-initdb.d`).

### `schema.sql` — Tables & Types

Defines the normalized (3NF) database schema. No personal data is stored by design.

#### Enum Types

| Type | Values | Purpose |
|------|--------|---------|
| `verdict_enum` | `malicious`, `benign`, `unknown` | Classification result from the ML model |
| `report_enum` | `false_positive`, `false_negative` | User feedback type |

#### Tables

| Table | Purpose | Key Columns |
|-------|---------|-------------|
| **`users`** | Anonymous user identities | `anon_id` (SHA-256 hash, 64 hex chars) — no personal data |
| **`domains`** | Catalog of all domains seen | `domain` (unique), `verdict`, `confidence`, `last_classified` |
| **`domain_features`** | 6 ML features per domain (1-to-1 with `domains`) | 3 lexical (`lex_length`, `lex_entropy`, `lex_digits`) + 3 DNS (`dns_a_count`, `dns_ttl`, `dns_age_days`) |
| **`check_events`** | Audit log — one row per `/check` API call | `anon_id` → `users`, `domain_id` → `domains`, `was_cached` flag |
| **`reports`** | User-submitted false positive/negative reports | Links `anon_id` + `domain_id` + `report_type`; does **not** auto-change verdicts |

#### Indexes

| Index | On | Purpose |
|-------|----|---------|
| `idx_check_events_anon` | `check_events(anon_id)` | Fast per-user stats lookups |
| `idx_check_events_time` | `check_events(checked_at)` | Time-range queries |
| `idx_check_events_domain` | `check_events(domain_id)` | Domain activity lookups |
| `idx_reports_domain` | `reports(domain_id)` | Reports per domain |

> **Note:** `domains(domain)` is already indexed by its `UNIQUE` constraint.

---

### `functions.sql` — Stored Functions

Eight PL/pgSQL functions consumed by the backend Express API via `SELECT * FROM fn_name(...)`:

| # | Function | Called by | What it does |
|---|----------|-----------|--------------|
| 1 | `fn_register_user(anon_id)` | `POST /register` | Inserts a new anonymous user. Returns `'registered'` or `'collision'` if the ID already exists. |
| 2 | `fn_upsert_domain(domain, verdict, confidence)` | `POST /check` | Inserts a new domain or updates its verdict if it already exists (reclassification). Returns `domain_id`. |
| 3 | `fn_save_features(domain_id, lex_length, lex_entropy, lex_digits, dns_a_count, dns_ttl, dns_age_days)` | `POST /check` | Saves or updates the 6 ML features for a domain (1-to-1 with `domains`). |
| 4 | `fn_log_check(anon_id, domain_id, was_cached)` | `POST /check` | Logs a check event in the audit trail. Returns `event_id`. |
| 5 | `fn_save_report(anon_id, domain_id, report_type)` | `POST /report` | Saves a user report (false positive/negative). Does **not** change the verdict. Returns `report_id`. |
| 6 | `fn_stats_me(anon_id)` | `GET /stats/me` | Returns personal stats: total checked, malicious count, benign count, unknown count, and the date of first check. |
| 7 | `fn_stats_me_history(anon_id, limit, offset)` | `GET /stats/me/history` | Returns paginated check history for a user (domain, verdict, confidence, timestamp). |
| 8 | `fn_stats_global()` | `GET /stats/global` | Returns aggregate stats: total domains, total checks, malicious/benign counts, and detection rate percentage. Cached in Redis for 5 minutes. |

---

## Cache — `cache/`

### `docker-compose.yml` — Services

Defines two Docker containers on a shared bridge network (`intellidns_net`):

| Service | Image | Container Name | Port | Data |
|---------|-------|----------------|------|------|
| **db** (PostgreSQL) | `postgres:16-alpine` | `intellidns_postgres` | `5432` | Persisted in Docker volume `postgres_data` |
| **redis** (Redis) | `redis:7-alpine` | `intellidns_redis` | `6379` | In-memory only (no persistence) |

Key behaviors:
- On first startup, PostgreSQL automatically runs all `.sql` files in `database/` (mounted to `/docker-entrypoint-initdb.d`), creating the schema and functions.
- Both services bind to `127.0.0.1` by default (safe for local development). In production, set `DB_BIND_IP` and `REDIS_BIND_IP` in `.env` to the VM's private IP.
- Both restart automatically unless manually stopped (`restart: unless-stopped`).

---

### `redis.conf` — Redis Configuration

A hardened, cache-optimized configuration:

| Setting | Value | Why |
|---------|-------|-----|
| `bind` | `0.0.0.0` | Listens on all interfaces inside the container (access is restricted by Docker port binding + firewall) |
| `protected-mode` | `yes` | Requires authentication |
| `requirepass` | set in file | Password for Redis connections |
| `save ""` | disabled | **No disk persistence (RDB off)** — avoids competing with PostgreSQL for disk I/O |
| `appendonly` | `no` | **No AOF persistence** — pure in-memory cache |
| `maxmemory` | `256mb` | Hard cap on Redis RAM usage |
| `maxmemory-policy` | `allkeys-lru` | Evicts least-recently-used keys when memory is full |
| `activedefrag` | `yes` | Automatically defragments memory in the background |

Dangerous commands are **renamed to empty** (disabled): `FLUSHDB`, `FLUSHALL`, `CONFIG`, `SHUTDOWN`, `DEBUG`.

---

### `load-whitelist.js` — Whitelist Loader

A Node.js script that bulk-loads the Tranco top 1 million domains into a Redis Set (`whitelist:domains`). This Set is used by the backend to skip ML classification for known-safe domains.

**How it works:**
1. Reads environment variables (`REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`) from `.env`.
2. Opens `data/tranco_top1m_domains.csv` as a stream (CSV format: `rank,domain`).
3. Reads line by line, extracting and lowercasing each domain.
4. Sends domains to Redis in batches of 10,000 using `SADD`.
5. If Redis is not available, falls back to a **simulation mode** that loads domains into an in-memory JavaScript Set (useful for testing on Windows without Redis).

**Usage:**
```bash
cd cache
npm install
node load-whitelist.js
```

> Only needs to be run **once** after deployment, or whenever the CSV is updated.

---

### `package.json` — Node Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| `ioredis` | `^5.11.1` | Redis client for Node.js |
| `dotenv` | `^17.4.2` | Loads `.env` file into `process.env` |

---

### `.env.example` — Environment Variables

Template file — copy to `.env` and fill in real values. **Never commit `.env` to git.**

| Variable | Example Value | Description |
|----------|---------------|-------------|
| `DB_BIND_IP` | `10.0.0.5` | IP address PostgreSQL binds to (use `127.0.0.1` for local dev) |
| `REDIS_BIND_IP` | `10.0.0.5` | IP address Redis binds to (use `127.0.0.1` for local dev) |
| `DB_NAME` | `intellidns` | PostgreSQL database name |
| `DB_USER` | `intellidns_admin` | PostgreSQL username |
| `DB_PASSWORD` | *(your password)* | PostgreSQL password |
| `REDIS_HOST` | `10.0.0.5` | Redis host for the whitelist loader |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_PASSWORD` | *(your password)* | Redis password (must match `requirepass` in `redis.conf`) |

---

### `data/tranco_top1m_domains.csv` — Domain Whitelist

A ~22 MB CSV file containing the **Tranco top 1 million domains** (a well-known research ranking of popular domains). Format:

```csv
1,google.com
2,facebook.com
3,youtube.com
...
```

These domains are loaded into the Redis Set `whitelist:domains` so the backend can instantly skip ML classification for known-safe domains.

> This file is listed in `.gitignore` due to its size. Download it from [Tranco List](https://tranco-list.eu/) if needed.

---

## How Redis is Used by the Backend

Redis stores three types of data in memory:

| What | Redis Key | Type | TTL | Purpose |
|------|-----------|------|-----|---------|
| Known-safe domains | `whitelist:domains` | Set | None (permanent) | Skip ML classification for the top 1M domains |
| Malicious domain cache | `domain:<name>` | String (JSON) | 24 hours | Avoid repeated ML calls for already-classified malicious domains |
| Global statistics | `stats:global` | String (JSON) | 5 minutes | Cache expensive aggregate queries from PostgreSQL |

### Request Flow

```
User visits a domain
        │
        ▼
  ┌─ Is it in whitelist:domains? ──▶ YES → Return "benign" (source: whitelist)
  │     NO
  │     ▼
  ├─ Is it in domain:<name> cache? ──▶ YES → Return cached verdict (source: cache)
  │     NO
  │     ▼
  ├─ Call ML model for classification
  │     │
  │     ▼
  ├─ Save to PostgreSQL (fn_upsert_domain + fn_save_features)
  │     │
  │     ▼
  └─ If malicious → Cache in Redis for 24h
        │
        ▼
    Return verdict (source: model)
```

---

## Quick Start

### 1. Clone and configure

```bash
git clone https://github.com/lisettemel/Intelli-db-cache.git
cd Intelli-db-cache/cache
cp .env.example .env
# Edit .env with your real passwords and IP addresses
```

### 2. Start services

```bash
docker-compose up -d
```

This will:
- Start **PostgreSQL 16** on port `5432` and automatically create the database schema and functions from `database/`.
- Start **Redis 7** on port `6379` with the hardened configuration.

### 3. Load the whitelist (one-time)

```bash
npm install
node load-whitelist.js
```

### 4. Verify

```bash
# Check containers are running
docker ps

# Test PostgreSQL connection
docker exec -it intellidns_postgres psql -U intellidns_admin -d intellidns -c "\dt"

# Test Redis connection
docker exec -it intellidns_redis redis-cli -a <your_redis_password> SCARD whitelist:domains
# Expected output: (integer) 1000000
```

---

## Other Root Files

| File | Description |
|------|-------------|
| `.gitignore` | Excludes `.env` files (real credentials), `node_modules/`, and the large CSV whitelist file from version control |
| `LICENSE` | MIT License — Copyright (c) 2026 Lisette Melo Reyes |

---

## Network Security

In production, the VM should be locked down with UFW firewall rules so only the backend server can reach the database and cache ports:

```bash
sudo ufw default deny incoming
sudo ufw allow 22/tcp                                              # SSH
sudo ufw allow from <BACKEND_PRIVATE_IP> to any port 5432 proto tcp  # PostgreSQL
sudo ufw allow from <BACKEND_PRIVATE_IP> to any port 6379 proto tcp  # Redis
sudo ufw enable
```

---

## License

MIT License — Copyright (c) 2026 Lisette Melo Reyes. See [LICENSE](LICENSE) for details.