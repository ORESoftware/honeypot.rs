# Fair-response policy

The service records evidence and recommends proportionate defensive friction. It does not directly mutate Cloudflare policy.

## Default ladder

| Evidence observed in 24 hours | Recommendation | Maximum default duration |
|---|---|---:|
| First lure view or ordinary scanner path | Observe | none |
| High-rate, low-confidence reconnaissance | Rate limit | 15 minutes |
| Three distinct lure families | Managed challenge | 30 minutes |
| First exact honeytoken reuse | Managed challenge | 1 hour |
| Repeated token reuse or repeated exploit probes | Temporary block | 24 hours |
| Sustained activity across at least three independent lure families | Human review; optional interim hold | 7 days |

## Required safeguards

- Expiration is mandatory for every automated edge action.
- Source IP alone is insufficient for a permanent action.
- Shared networks, mobile carrier NAT, VPN exits, Tor, compromised hosts, and security scanners can produce misleading attribution.
- Operators must be able to allowlist researchers and known internal scanners.
- Every action must be traceable to signed event identifiers and a policy version.
- A false-positive report should trigger prompt review and early removal.
- Escalation beyond seven days requires human approval and corroborating evidence outside this service.

## Prohibited responses

No retaliation, exploit delivery, persistence, destructive traffic, credential stuffing, public attribution, harassment, or attempts to identify the individual behind a network address.
