# Distributed Identity & Authorization PoC (v3)
**Config & Request Plane (CLI + Web UI) + Dual-Write Realization (Ory Keto + OpenLDAP) + Edge PBAC (Ory Oathkeeper)**

## Overview
This self-contained project demonstrates a migration-friendly distributed authorization architecture:
- **Existing OIDC (`mock-oidc` :4000):** Issues RS256 JWTs for User SSO (`alice`, `bob`) and App-to-App client credentials (`app-foo` -> `app-bar`).
- **Central ODB (`mock-odb` :4001):** Single source of truth for `Jira` (`JIRA-100`) and `Application` (`resourceId`, `label`, `stackId`) topology.
- **Config & Request Plane (`governance` :4002):**
  - **Web UI (`http://localhost:4002`):** Browser dashboard to register Role/Policy templates, submit access requests (`PENDING`), approve/reject tickets, and inspect audit logs.
  - **CLI (`./cli.sh`):** Zero-dependency shell CLI to drive the exact same Config & Request Plane workflows.
  - **Dual-Write Realization:** Approving a request writes active permissions simultaneously to **Ory Keto** (relation tuples) and **OpenLDAP** (`groupOfNames` DIT).
- **Ory Keto (`:4466` Read / `:4467` Write):** Evaluates inherited `Jira` -> `Application` relationships (`foo-secret`).
- **Ory Oathkeeper (`:4455`):** Edge PEP enforcing JWT SSO validation, Keto secret checks, and `Foo` -> `Bar` PBAC (`bar:all` scope across all `/bar/**` endpoints).
- **OpenLDAP (`:389`):** Legacy directory receiving realized `ou=JIRA-100` containers and `cn=foo-secret` group memberships.

## Quick Start
```bash
cd distributed-authz-poc
docker compose up -d
```

1. **Open the Web UI:** Visit `http://localhost:4002` in your browser to sync ODB, submit a request for `foo-secret`, approve it, and view audit logs.
2. **Or run the CLI / End-to-End Test:**
```bash
./cli.sh sync-odb
./cli.sh request-access alice foo-secret jira JIRA-100 "Need production secret access"
./cli.sh list-requests
# Approve using the request ID printed above:
./cli.sh approve <REQUEST_ID> manager-bob
# Or run the automated end-to-end verification script:
./test-flow.sh
```
