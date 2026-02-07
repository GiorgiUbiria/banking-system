# Mini Banking API

Backend for a simplified banking platform: double-entry ledger, JWT auth, transfers and currency exchange. Built with Go, Chi, GORM, PostgreSQL.

## User management (Option B)

No registration endpoint. The app uses **3 pre-seeded test users** created on first run:

| Email           | Password   |
|-----------------|------------|
| user1@test.com  | password123 |
| user2@test.com  | password123 |
| user3@test.com  | password123 |

Each user has one USD account (initial balance $1000) and one EUR account (initial balance €500). Seed is idempotent: it skips if these users already exist.

## Tech stack

- **Go**, Chi router, GORM, PostgreSQL, JWT (golang-jwt), bcrypt, Zap, Swagger (swaggo)
- **Docker** for local run and for deployment build

## Local setup

### With Docker Compose (recommended)

```bash
cp configs/config.example.yaml configs/config.yaml
# Edit configs/config.yaml if you need different DB credentials (default matches docker-compose)
docker compose up --build
```

API: http://localhost:8080  
Swagger: http://localhost:8080/swagger/index.html  

The Compose stack runs the API (from Dockerfile) and PostgreSQL. The `configs` directory is mounted so the app can read `config.yaml` (DSN points at the `db` service).

### Without Docker (Go + local PostgreSQL)

1. Create a database and user (e.g. database `ledger`, user `banking`, password of choice).
2. Copy and edit config:

   ```bash
   cp configs/config.example.yaml configs/config.yaml
   ```

   Set `db.dsn` to your Postgres URL (e.g. `postgres://banking:yourpassword@localhost:5432/ledger?sslmode=disable`), and set `jwt.secret`.
3. Run the server:

   ```bash
   go run ./cmd/server
   ```

## Remote deployment

### Setup strategy

- **Local:** Config is read from `configs/config.yaml` (DSN, JWT secret, exchange rate). Docker Compose provides the DB and mounts the config dir.
- **Remote (e.g. Render):** The Docker image does **not** bundle the config file. The app starts with env-only config:
  - **DATABASE_URL** – PostgreSQL connection string (required).
  - **JWT_SECRET** – Secret for signing JWTs (required).

If these env vars are set, they override the config file. If the config file is missing (as in the deployed container), the app still runs as long as `DATABASE_URL` and `JWT_SECRET` are set. Exchange rate defaults to 0.92 when no file is present.

### Backend (Render)

1. Create a **Web Service**, connect the repo, set **Environment** to **Docker** (uses the repo Dockerfile).
2. Create a **PostgreSQL** service in the same Render account.
3. In the Web Service → **Environment**, add:
   - **DATABASE_URL** = Internal Database URL from the PostgreSQL service.
   - **JWT_SECRET** = a long random secret (e.g. `openssl rand -hex 32`).
4. Optionally link the PostgreSQL instance to the Web Service so Render can inject `DATABASE_URL` automatically.

CORS allows the Netlify frontend origin; add more in `internal/routes/routes.go` if needed.

## API overview

- **Auth:** `POST /auth/login`, `GET /auth/me`
- **Accounts:** `GET /accounts`, `GET /accounts/:id/balance`, `GET /accounts/reconcile`
- **Transactions:** `POST /transactions/transfer`, `POST /transactions/exchange`, `GET /transactions?type=&page=&limit=`
- **Ledger:** `GET /ledger?account_id=&tx_id=&page=&limit=`

Structured JSON errors: `{"error": "message"}`.  
Swagger: `/swagger/index.html`.

## Design notes

- **Double-entry ledger:** Every transfer/exchange creates ledger entries (debit/credit); account balances are stored for performance and kept in sync within the same DB transaction. `GET /accounts/reconcile` checks that each account’s balance matches the sum of its ledger entries.
- **Concurrency:** Transfer and exchange handlers lock account rows with `SELECT ... FOR UPDATE` in a consistent order (by account ID) to avoid deadlocks and lost updates.
- **Precision:** Monetary amounts use `shopspring/decimal`; exchange rate is fixed (1 USD = 0.92 EUR) and configurable.
