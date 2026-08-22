# Threat model

## Objective

Collect high-confidence evidence that automated scanners or operators touched a synthetic resource, while keeping the service too constrained to become useful infrastructure for the attacker.

## Protected assets

- The Kubernetes cluster and neighboring workloads.
- Cloudflare, GitHub, database, and cluster-administration credentials.
- Source addresses and other potentially identifying telemetry.
- The integrity of evidence used for temporary defensive controls.
- Operator time and infrastructure budget.

## Adversaries and expected behavior

The first release assumes opportunistic scanners, credential harvesters, exploit automation, and low-sophistication manual follow-up. It does not attempt to host malware, execute uploaded code, offer an interactive shell, emulate a database, or safely contain an advanced persistent actor.

## Trust boundaries

1. **Cloudflare edge:** absorbs DDoS, applies WAF/bot controls, rejects large bodies, and forwards only bounded traffic.
2. **Cloudflare Tunnel:** outbound-only transport to the cluster. The origin is not exposed through a public load balancer.
3. **Honeypot namespace:** isolated, non-root, read-only workload with no Kubernetes token, no persistent volume, and deny-all egress.
4. **Telemetry sink:** receives signed, privacy-minimized events. It is not part of the request path and must reject invalid signatures.
5. **Response controller:** separate from the honeypot. It correlates evidence and manages TTL-based edge controls; the pod has no Cloudflare mutation credentials.

## Abuse cases and controls

| Threat | Control |
|---|---|
| Attacker turns the decoy into a pivot | No command execution, no interpreter, no outbound network, no service-account token, read-only filesystem |
| DDoS exhausts the cluster | Cloudflare edge termination; exact-path diversion only; origin rate limits and kill switch |
| Fake credentials are mistaken for real ones | Vendor-neutral `ores_hp_v1_` namespace and `.invalid` endpoints |
| Header spoofing fabricates victim IPs | Honor Cloudflare identity headers only when the immediate peer is in an explicit trusted proxy CIDR |
| Logs capture secrets or personal data | Never log raw bodies, headers, cookies, query strings, IPs, or user agents; HMAC pseudonyms only |
| IP attribution harms innocent users | No permanent IP-only blacklist; bounded challenge/block TTLs; human review and allowlisting |
| Evidence is altered in transit | Canonical JSON event payload signed with HMAC-SHA256 |
| Honeypot fingerprint attracts research noise | Generic health responses and ordinary decoy application pages; documented researcher allowlisting |
| Operator overreacts | Policy engine emits recommendations, not direct punishment; response controller enforces separate approval rules |

## Explicitly out of scope

- Hack-back or counter-intrusion.
- Malware delivery or booby-trapped downloads.
- Public naming, shaming, or real-world identity attribution.
- Full packet capture by default.
- Retaining submitted passwords or request bodies.
- Interactive SSH/RDP/database emulation.
- Redirecting volumetric attacks to any origin.
