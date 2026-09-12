# Cloudflare and DDoS architecture

## Core rule

Do not point denial-of-service traffic at the honeypot. A honeypot is an evidence sensor, not a scrubbing center. Volumetric traffic must be absorbed, challenged, rate-limited, or dropped at Cloudflare before an origin request is created.

```text
Internet
  -> Cloudflare DDoS protection
  -> WAF / bot controls / rate limits
  -> exact decoy hostname or narrowly selected impossible paths
  -> Cloudflare Tunnel
  -> ClusterIP Service
  -> constrained honeypot pod
```

## Safe diversion

A later edge phase may divert exact paths that should never exist on selected production hosts, such as `/.env` or `/.git/config`. The rule must:

- match exact path classes rather than all suspicious traffic;
- enforce body-size and request-rate ceilings at the edge;
- reject non-HTTP floods without contacting the cluster;
- preserve the Cloudflare Ray ID for correlation;
- stop forwarding when the origin health budget is exceeded;
- provide a kill switch that returns an edge-generated 404;
- never route arbitrary production requests into the decoy.

## Response-control separation

The honeypot emits signed recommendations. A separate controller may reconcile a Cloudflare custom list or rule with TTLs after correlation. The controller owns the durable expiration ledger. Cloudflare mutation credentials are never mounted into the honeypot pod.

## Origin protection checklist

- Cloudflare Tunnel is outbound-only.
- No public Kubernetes LoadBalancer or NodePort exists for this workload.
- The NetworkPolicy accepts traffic only from the verified cloudflared namespace and pod labels.
- The pod has deny-all egress.
- Concurrency, timeout, and body limits are enforced in both the edge and application.
- A high-load condition fails closed with an edge response rather than forwarding more traffic.
