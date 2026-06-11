# Intelli-db-cache

Database and cache layer for **intelli-dns** — an intelligent DNS security system that classifies domains as malicious, benign, or unknown using a machine-learning model. This repository contains the PostgreSQL schema, stored functions, Redis cache configuration, and Docker Compose deployment.

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
  - [`package.json` — Node Dependencies](#packagejson--node-dependencies)
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
└────────────────┘     │  1. Check verdict cache in Redis             │
                       │  2. If MISS → call ML model → save to DB    │
                       │  3. Cache verdict in Redis (if not unknown)  │
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
    ├── README.md               # Detailed cache documentation (in Spanish)
    ├── docker-compose.yml      # Defines Postgres + Redis containers
    ├── redis.conf              # Hardened Redis configuration
    ├── package.json            # Node dependencies (ioredis, dotenv)
    ├── package-lock.json       # Locked dependency versions
    └── data/
        └── tranco_top1m_domains.csv  # Top 1M known-safe domains (~22 MB)
```

---

## Database — `database/`

These SQL files are automatically executed by the PostgreSQL container on first startup. Docker Compose mounts them into `/docker-entrypoint-initdb.d/` with explicit ordering:
- `01_schema.sql` ← `schema.sql`
- `02_functions.sql` ← `functions.sql`

### `schema.sql` — Tables & Types

Defines the normalized (3NF) database schema. **No personal data is stored by design.**

#### Enum Types

| Type | Values | Purpose |
|------|--------|---------|
| `verdict_enum` | `malicious`, `benign`, `unknown` | ML classification result |
| `report_enum` | `false_positive`, `false_negative` | User feedback type |

#### Tables

| Table | Purpose | Key Columns |
|-------|---------|-------------|
| **`users`** | Anonymous user identities | `anon_id` (SHA-256 hash, 64 hex chars) — no personal data stored |
| **`domains`** | Catalog of all domains seen | `domain` (unique), `verdict`, `confidence`, `last_classified` |
| **`domain_features`** | 6 ML features per domain (1-to-1 with `domains`) | 3 lexical + 3 DNS (see below) |
| **`check_events`** | Audit log — one row per `/check` API call | `anon_id` → `users`, `domain_id` → `domains`, `was_cached` flag |
| **`reports`** | User-submitted false positive/negative reports | Links `anon_id` + `domain_id` + `report_type`; does **not** auto-change verdicts |

#### Domain Features (6 columns in `domain_features`)

These match exactly the features computed by the ML model (`intelli-dns src/model/features.py`):

| Column | Type | Category | Description |
|--------|------|----------|-------------|
| `domain_length` | `INTEGER` | Lexical | Total length of the domain string |
| `num_dots` | `INTEGER` | Lexical | Number of dots in the domain |
| `has_suspicious_keyword` | `SMALLINT` | Lexical | 0/1 flag — contains suspicious token |
| `num_a_records` | `INTEGER` | DNS | Number of A records (0 for NXDOMAIN) |
| `num_ns_records` | `INTEGER` | DNS | Number of NS records (0 for NXDOMAIN) |
| `has_txt` | `SMALLINT` | DNS | 0/1 flag — has a TXT record |

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
| 2 | `fn_upsert_domain(domain, verdict, confidence)` | `POST /check` | Inserts or updates a domain's verdict. **Special behavior for `unknown`:** does NOT overwrite an existing real verdict — only ensures the domain row exists so the check event can be logged. |
| 3 | `fn_save_features(domain_id, domain_length, num_dots, has_suspicious_keyword, num_a_records, num_ns_records, has_txt)` | `POST /check` | Saves or updates the 6 ML features for a domain (1-to-1 upsert). |
| 4 | `fn_log_check(anon_id, domain_id, was_cached)` | `POST /check` | Logs a check event in the audit trail. Returns `event_id`. |
| 5 | `fn_save_report(anon_id, domain_id, report_type)` | `POST /report` | Saves a user report (false positive/negative). Does **not** change the verdict. Returns `report_id`. |
| 6 | `fn_stats_me(anon_id)` | `GET /stats/me` | Returns personal stats: total checked, malicious count, benign count, unknown count, and date of first check. |
| 7 | `fn_stats_me_history(anon_id, limit, offset)` | `GET /stats/me/history` | Returns paginated check history for a user. Includes `total_count` (via window function) so the client can paginate without a second round-trip. |
| 8 | `fn_stats_global()` | `GET /stats/global` | Returns aggregate stats: total domains, total checks, malicious/benign counts, and detection rate as a **fraction (0–1)**, not a percentage. Cached in Redis for 5 minutes. |

---

## Cache — `cache/`

### `docker-compose.yml` — Services

Defines two Docker containers on a shared bridge network (`intellidns_net`):

| Service | Image | Container Name | Port | Data |
|---------|-------|----------------|------|------|
| **db** (PostgreSQL) | `postgres:16-alpine` | `intellidns_postgres` | `5432` | Persisted in Docker volume `postgres_data` |
| **redis** (Redis) | `redis:7-alpine` | `intellidns_redis` | `6379` | In-memory only (no persistence) |

Key behaviors:
- On first startup, PostgreSQL automatically runs `schema.sql` then `functions.sql` (mounted as `01_schema.sql` and `02_functions.sql` in read-only mode).
- Both services bind to `127.0.0.1` by default (safe for local development). In production, set `DB_BIND_IP` and `REDIS_BIND_IP` in `.env` to the VM's private IP.
- `DB_PASSWORD` and `REDIS_PASSWORD` are **required** — docker-compose will fail if they are missing (uses `${VAR:?}` syntax).
- The Redis password is **not hardcoded** in `redis.conf`. Instead, it is injected at runtime via the `--requirepass` flag in the docker-compose command.
- Both services restart automatically unless manually stopped (`restart: unless-stopped`).

---

### `redis.conf` — Redis Configuration

A hardened, cache-optimized configuration:

| Setting | Value | Why |
|---------|-------|-----|
| `bind` | `0.0.0.0` | Listens on all interfaces inside the container (access restricted by Docker port binding + firewall) |
| `protected-mode` | `yes` | Requires authentication for connections |
| `save ""` | disabled | **No disk persistence (RDB off)** — avoids competing with PostgreSQL for disk I/O |
| `appendonly` | `no` | **No AOF persistence** — pure in-memory cache |
| `maxmemory` | `256mb` | Hard cap on Redis RAM usage |
| `maxmemory-policy` | `allkeys-lru` | Evicts least-recently-used keys when memory is full |
| `maxmemory-samples` | `5` | Ideal balance between performance and LRU precision |
| `activedefrag` | `yes` | Automatically defragments memory in the background |

Dangerous commands are **renamed to empty** (disabled): `FLUSHDB`, `FLUSHALL`, `CONFIG`, `SHUTDOWN`, `DEBUG`.

> **Password note:** The `requirepass` directive is intentionally absent from `redis.conf` to avoid hardcoding secrets in git. The password is injected by docker-compose from the `REDIS_PASSWORD` environment variable via the `--requirepass` flag.

---

### `package.json` — Node Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| `ioredis` | `^5.11.1` | Redis client for Node.js |
| `dotenv` | `^17.4.2` | Loads `.env` file into `process.env` |

These dependencies are used by backend utilities or scripts that interact with Redis.

---

### `data/tranco_top1m_domains.csv` — Domain Whitelist

A ~22 MB CSV file containing the **Tranco top 1 million domains** (a well-known research ranking of popular domains). Format:

```csv
1,google.com
2,facebook.com
3,youtube.com
...
```

> This file is listed in `.gitignore` due to its size. Download it from [Tranco List](https://tranco-list.eu/) if needed.

---

## How Redis is Used by the Backend

Redis stores two types of data in memory, plus rate-limiting keys managed by the backend:

| What | Redis Key | Type | TTL | Purpose |
|------|-----------|------|-----|---------|
| Domain verdict cache | `verdict:<domain>` | String (JSON) | 24 hours | Cache ML verdicts to avoid repeated classification calls |
| Global statistics | `stats:global` | String (JSON) | 5 minutes | Cache expensive aggregate queries from PostgreSQL |
| Rate limiting | `rl:*` | Managed by `express-rate-limit` | Varies | Backend-managed rate limiting (not configured here) |

**Important:** Only `malicious` and `benign` verdicts are cached. `unknown` verdicts (when the ML model is down) are **never cached** — they are transient and should be retried on the next check.

### Request Flow

```
User visits a domain
        │
        ▼
  ┌─ Is verdict:<domain> in Redis? ──▶ YES → Return cached verdict (cached: true)
  │     NO (cache miss)
  │     ▼
  ├─ Call ML model for classification
  │     │
  │     ▼
  ├─ Save to PostgreSQL (fn_upsert_domain + fn_save_features)
  │     │
  │     ▼
  ├─ If verdict ≠ unknown → Cache in Redis for 24h
  │     │
  │     ▼
  └─ Log check event (fn_log_check)
        │
        ▼
    Return verdict to client
```

### Cache Invalidation

When an admin reclassifies a domain, the cached verdict is deleted so the next request fetches the updated result:

```js
await db.query('SELECT fn_upsert_domain($1,$2,$3)', [domain, newVerdict, confidence]);
await redis.del(`verdict:${domain}`);
```

---

## Quick Start

### 1. Clone and configure

```bash
git clone https://github.com/lisettemel/Intelli-db-cache.git
cd Intelli-db-cache/cache
```

Create a `.env` file in the `cache/` directory with the required variables:

```env
DB_BIND_IP=127.0.0.1        # Use VM private IP in production (e.g. 10.0.0.5)
REDIS_BIND_IP=127.0.0.1     # Use VM private IP in production

DB_NAME=intellidns
DB_USER=intellidns_backend_client
DB_PASSWORD=yourSecurePassword

REDIS_HOST=127.0.0.1
REDIS_PORT=6379
REDIS_PASSWORD=yourSecureRedisPassword
```

> **Never commit `.env` to git.** It is already listed in `.gitignore`.

### 2. Start services

```bash
docker-compose up -d
```

This will:
- Start **PostgreSQL 16** on port `5432` and automatically create the database schema and functions.
- Start **Redis 7** on port `6379` with the hardened configuration.

### 3. Verify

```bash
# Check containers are running
docker ps

# Test PostgreSQL connection
docker exec -it intellidns_postgres psql -U intellidns_backend_client -d intellidns -c "\dt"

# Test Redis connection
docker exec -it intellidns_redis redis-cli -a <your_redis_password> PING
# Expected output: PONG
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