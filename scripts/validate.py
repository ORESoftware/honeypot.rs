#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]

REQUIRED = {
    "Cargo.toml",
    "rust-toolchain.toml",
    "src/main.rs",
    "Dockerfile",
    "SECURITY.md",
    "docs/THREAT_MODEL.md",
    "docs/FAIR_RESPONSE.md",
    "docs/CLOUDFLARE_DDOS.md",
    "docs/KUBERNETES.md",
    "deploy/k8s/kustomization.yaml",
    "deploy/k8s/deployment.yaml",
    "deploy/k8s/service.yaml",
    "deploy/k8s/externalsecret.yaml",
    "deploy/k8s/networkpolicy.yaml",
}


def fail(message: str) -> None:
    print(f"validation error: {message}", file=sys.stderr)
    raise SystemExit(1)


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def main() -> None:
    missing = sorted(path for path in REQUIRED if not (ROOT / path).is_file())
    if missing:
        fail(f"missing required files: {', '.join(missing)}")

    manifest = tomllib.loads(text("Cargo.toml"))
    package = manifest.get("package", {})
    if package.get("name") != "honeypot-rs":
        fail("Cargo package name must remain honeypot-rs")
    if package.get("publish") is not False:
        fail("crate publication must remain disabled")

    source = text("src/main.rs")
    for required in (
        "ores_hp_v1",
        "event-signature",
        "actor-ip",
        "TRUSTED_PROXY_CIDRS",
        "managed_challenge",
        "temporary_block",
        "human_review",
    ):
        if required not in source:
            fail(f"source is missing security contract marker: {required}")
    for prohibited in (
        "Command::new",
        "std::process",
        "TcpStream::connect",
        "reqwest::",
        "hyper::client",
    ):
        if prohibited in source:
            fail(f"network or command execution primitive is prohibited: {prohibited}")

    deployment = text("deploy/k8s/deployment.yaml")
    for required in (
        "automountServiceAccountToken: false",
        "runAsNonRoot: true",
        "readOnlyRootFilesystem: true",
        "allowPrivilegeEscalation: false",
        "seccompProfile:",
        "drop:\n                - ALL",
        "ephemeral-storage:",
        "@sha256:",
    ):
        if required not in deployment:
            fail(f"deployment is missing hardening control: {required}")
    for prohibited in (
        "image: latest",
        "privileged: true",
        "hostNetwork: true",
        "hostPID: true",
        "hostIPC: true",
    ):
        if prohibited in deployment:
            fail(f"deployment contains prohibited setting: {prohibited}")

    service = text("deploy/k8s/service.yaml")
    if "type: ClusterIP" not in service:
        fail("service must remain ClusterIP-only")
    for prohibited in ("NodePort", "LoadBalancer", "externalIPs"):
        if prohibited in service:
            fail(f"public service exposure is prohibited: {prohibited}")

    policy = text("deploy/k8s/networkpolicy.yaml")
    if "egress: []" not in policy:
        fail("workload NetworkPolicy must deny all egress")
    if "cloudflared" not in policy:
        fail("ingress must remain scoped to cloudflared")

    for path in (ROOT / "deploy/k8s").glob("*.yaml"):
        rendered = path.read_text(encoding="utf-8")
        for cluster_scoped in (
            "kind: Namespace",
            "kind: ClusterRole",
            "kind: ClusterRoleBinding",
            "kind: CustomResourceDefinition",
            "kind: StorageClass",
        ):
            if cluster_scoped in rendered:
                fail(f"application repo may not own {cluster_scoped} ({path.name})")

    docs = "\n".join(
        text(path)
        for path in (
            "README.md",
            "docs/THREAT_MODEL.md",
            "docs/FAIR_RESPONSE.md",
            "docs/CLOUDFLARE_DDOS.md",
        )
    ).casefold()
    for phrase in (
        "no hack-back",
        "no permanent ip-only blacklist",
        "do not point denial-of-service traffic at the honeypot",
        "expiration is mandatory",
    ):
        if phrase not in docs:
            fail(f"documentation is missing defensive boundary: {phrase}")

    print("repository policy validation passed")


if __name__ == "__main__":
    main()
