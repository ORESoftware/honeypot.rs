# Kubernetes deployment contract

The application repository owns namespace-scoped resources in `deploy/k8s`:

- Deployment
- ClusterIP Service
- ExternalSecret
- workload-specific NetworkPolicy

`ORESoftware/k8s-cluster` owns the namespace, ResourceQuota, LimitRange, default-deny tenancy policies, service account, RBAC, AppProject, and Argo Application registration.

## Required promotion inputs

Before deployment, replace the fail-closed image placeholder with an immutable digest and verify:

- the `honeypot-rs` namespace exists with Pod Security Admission set to `restricted`;
- the platform service account exists and has no workload API permissions;
- External Secrets Operator can resolve the two independent HMAC keys;
- cloudflared namespace and pod labels match the NetworkPolicy selectors;
- the installed CNI enforces NetworkPolicy;
- the container digest was built from the reviewed PR head;
- the public hostname routes only through Cloudflare Tunnel;
- no public load balancer, NodePort, PVC, or default egress is introduced.

The deployment intentionally starts with one replica. Horizontal scaling requires replacing the in-memory evidence ledger with a bounded shared store or accepting that each replica recommends policy independently.
