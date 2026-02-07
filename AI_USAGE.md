# AI Usage

AI assistance was used via **Cursor IDE**. The following entries document substantial AI interactions for this backend (Mini Banking API) assessment.

---

## AI-1

- **Purpose:** Seed — structure for 3 users with USD/EUR accounts.
- **Tool & Model:** Cursor IDE (AI assistant).
- **Prompt:** Create seed data for 3 users, each with USD and EUR accounts and initial balances.
- **How the response was used:** Used for the shape of the seed.

---

## AI-2

- **Purpose:** Handlers — pattern similar to existing balance handler.
- **Tool & Model:** Cursor IDE (AI assistant).
- **Prompt:** Add handlers for me, transactions following the same style as GET /accounts/:id/balance.
- **How the response was used:** Used as a rough template.

---

## AI-3

- **Purpose:** CORS for Chi router.
- **Tool & Model:** Cursor IDE (AI assistant).
- **Prompt:** Configure CORS on Chi so the frontend can call the API (origins, methods).
- **How the response was used:** Used to get the go-chi/cors import and options; origin list and wiring done manually.

---

## AI-4

- **Purpose:** Config from env (DATABASE_URL, JWT_SECRET) when no file.
- **Tool & Model:** Cursor IDE (AI assistant).
- **Prompt:** Read DATABASE_URL and JWT_SECRET from env and run without config file for Render.
- **How the response was used:** Used only for the idea of env overrides; config loading and defaults implemented manually.

---

## AI-5

- **Purpose:** Concurrency — avoid double-spend on parallel transfers.
- **Tool & Model:** Cursor IDE (AI assistant).
- **Prompt:** How to prevent race conditions when two transfers hit the same account (e.g. FOR UPDATE, lock order).
- **How the response was used:** Used as reference for FOR UPDATE and lock ordering.

---

## AI-6

- **Purpose:** Commit message wording.
- **Tool & Model:** Cursor IDE (AI assistant).
- **Prompt:** Commit changes in the style of my previous commits.
- **How the response was used:** Used only for commit message automation. 

---

## AI-7

- **Purpose:** Swagger (swaggo) comment format.
- **Tool & Model:** Cursor IDE (AI assistant).
- **Prompt:** Add swaggo comments above handlers for Swagger docs.
- **How the response was used:** Used for comment structure and tags.

---

## AI-8

- **Purpose:** Render deployment and DB setup.
- **Tool & Model:** Cursor IDE (AI assistant).
- **Prompt:** How to deploy this Go app on Render and attach PostgreSQL.
- **How the response was used:** Used as guidance only; actual Render and env setup done manually.
