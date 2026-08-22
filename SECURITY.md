# Security policy

Please report vulnerabilities privately through GitHub Security Advisories for this repository. Do not test the public decoy using destructive payloads, volumetric traffic, persistence mechanisms, malware, or third-party credentials.

The service intentionally exposes synthetic credentials. A credential prefixed with `ores_hp_v1_` is a honeytoken and must never be promoted into a real authentication system.

Operational incidents involving observed traffic should preserve evidence without publishing raw source addresses or attempting attribution. Temporary mitigation should be time-bounded, reversible, and reviewed under `docs/FAIR_RESPONSE.md`.
