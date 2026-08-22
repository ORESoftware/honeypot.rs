# Implementation plan

## Phase 1 — low-interaction sensor

- Leptos SSR decoy UI and bounded Axum routes.
- Synthetic vendor-neutral honeytokens.
- HMAC-pseudonymized, signed structured events.
- In-memory evidence ledger and reversible response recommendations.
- Unit and HTTP integration tests.

## Phase 2 — cluster canary

- Build an immutable OCI image.
- Deploy through Cloudflare Tunnel into a dedicated namespace.
- Verify deny-all egress, no service-account token, read-only filesystem, body/time/concurrency limits, and graceful kill switch.
- Send events to a test-only sink and prove raw addresses and credentials are absent.

## Phase 3 — edge integration

- Add an exact-path Worker or ruleset for a dedicated decoy hostname.
- Apply edge body and rate limits before Tunnel forwarding.
- Correlate Ray ID with signed origin events.
- Keep response-controller credentials and TTL state outside the pod.

## Phase 4 — controlled expansion

- Add new lure families only after each has a written objective, bounded protocol behavior, test coverage, retention policy, and shutdown procedure.
- High-interaction protocols, malware collection, packet capture, and real credential emulation require a separately isolated research environment and explicit authorization.
