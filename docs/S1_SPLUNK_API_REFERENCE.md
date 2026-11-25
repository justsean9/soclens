# SentinelOne v2.1 & Splunk ES 8.6 REST API Contract Reference

Use these verified endpoint contracts, pagination limits, rate-limit budgets, and safety guardrails when implementing `soclens` client methods.

---

## 1. SentinelOne Management REST API (`v2.1`)

### Authentication, Pagination & Rate Limits
- **Base URL:** `https://<s1-console-host>/web/api/v2.1`
- **Headers:**
  - `Authorization: ApiToken <S1_API_TOKEN>`
  - `Content-Type: application/json`
- **Pagination Rules (Verified from S1 Mgmt API 2.1 Spec):**
  - Standard `limit` range is **`1` to `100`** on `/agents`, `/threats`, `/sites`, `/users`, etc. (do **not** hardcode `limit=1000` without fallback—default page size to `limit=100` and iterate using `cursor=<pagination.nextCursor>` until `nextCursor` is `null`).
  - Use `countOnly=true` when only summary badge counts are needed.
- **Rate Limits & Burst Budgets (Per API Token):**
  - `/accounts`: 100 req/s (burst 10)
  - `/sites`: 100 req/s (burst 10)
  - `/rbac`: 50 req/s (burst 100)
  - `/users`: 40 req/s (burst 80) | `/service-users`: 5 req/s (burst 10)
  - `/agents`: 25 req/s
  - `/exclusions`: **25 req/s (burst 25)** — pace bulk exclusion cloning batches at ~10–15 req/s with retry/backoff on HTTP `429`!
  - `/threats`: 10 req/s (burst 50)
- **CRITICAL WRITE ENVELOPE GUARDRAIL:**
  - S1 `POST` / `PUT` / `DELETE` action endpoints take `{"filter": {...}, "data": {...}}`.
  - **NEVER send an empty `"filter": {}`** on mutations (`/threats/*`, `/agents/actions/*`, `/exclusions`, `/users/*`, `/restrictions`). An empty filter applies the mutation to **every entity across the entire tenant**! Enforce a client-level assertion requiring non-empty `ids`, `siteIds`, `groupIds`, or `accountIds` inside `filter`.

### A. Accounts, Sites & Groups (Configurable Tier Prefixes e.g. `MDR-*` / `MSSP-*`)
- **List Accounts:** `GET /web/api/v2.1/accounts?limit=100` (extract `<ORG_ACCOUNT>` `accountId` & licensed SKUs/add-ons).
- **List Sites:** `GET /web/api/v2.1/sites?accountIds=<acct_id>&limit=100&cursor=<cur>`
  - Note: S1 wraps site lists inside `response["data"]["sites"]` (verify both `data.sites` and list-style `data` shapes cleanly).
  - Key fields: `id`, `name` (e.g., `MDR-1234`, `MSSP-8298`), `state` (`active`, `expired`, `deleted`), `siteType` (`Paid`, `Trial`), `activeLicenses`, `totalLicenses`, `unlimitedLicenses`, `expiration`, `unlimitedExpiration`, `sku`, `suite`.
- **Get / Copy Site Policy:** `GET /web/api/v2.1/sites/{site_id}/policy` & `PUT /web/api/v2.1/sites/{site_id}/policy` (`{"data": <policy_obj>}`).
- **Create Site:** `POST /web/api/v2.1/sites`
  ```json
  {
    "data": {
      "accountId": "<ACCOUNT_ID>",
      "name": "MDR-1234",
      "description": "Managed Detection & Response - Tenant 1234",
      "siteType": "Paid",
      "unlimitedExpiration": true,
      "expiration": null,
      "unlimitedLicenses": false,
      "totalLicenses": 50,
      "sku": "Complete",
      "inherits": true
    }
  }
  ```
