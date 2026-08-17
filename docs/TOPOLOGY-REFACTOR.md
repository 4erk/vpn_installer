# Topology refactor 0.20.2

This file is the implementation ledger for the single/dual topology architecture. A release is not complete while any required checkbox remains open.

## Invariants

- [x] Existing dual deployments render the same primary `vless-uri.txt` bytes.
- [x] A single RU gateway installs no WireGuard or interserver transport artifacts, packages, services, probes, or secrets.
- [x] A single foreign gateway installs no WireGuard or interserver transport artifacts, packages, services, probes, or secrets.
- [x] A dual gateway never receives the exit private WireGuard key or interserver server private key.
- [x] A dual exit never receives Reality private keys, client credentials, or web-admin credentials.
- [x] Install, rollback, remove, health, and drift control touch only resources owned by the compiled node plan.
- [x] Missing capabilities are reported as not applicable, never as healthy or failed.
- [x] A single gateway has no WireGuard, interserver, or web-admin dependencies.
- [x] Web-admin exists only on the public gateway in `dual` and exposes only the two compiled egresses.
- [x] Its public port is firewall-gated to a recent source address that reached the TCP/UDP VPN ingress.
- [x] Installation acceptance uses the generated primary VLESS URI and never changes the local default route or active VPN client.

## Delivery slices

- [x] Characterization tests for the current dual URI, route order, bundles, manifests, and install order.
- [x] Canonical `DeploymentSpec`, `TopologySpec`, `NodeSpec`, and `NodePlan`.
- [x] Current-schema update window with no runtime migration adapters.
- [x] Minimal per-node runtime configuration and secret projection.
- [x] Capability-driven renderer, artifacts, package set, services, probes, and manifest.
- [x] Single gateway routing and DNS without fake interserver state.
- [x] Capability-aware server installer, rollback, removal, agent, health, and diagnostics.
- [x] Topology-aware workflows, client artifacts, web-admin, status, diagnose, maintain, and live verify.
- [x] Unit, Docker, lab, interrupted-install, and rollback matrix for `single-ru`, `single-foreign`, and `dual`.
- [x] Documentation, changelog, compatibility evidence, release audit, and production acceptance.

The `0.20.2` release gate requires config/state schema 3, manifest/install-plan schema 4 and diagnostics schema 5 on every installed node. Production acceptance is complete only after the unchanged primary VLESS URI passes the public gateway, Xray, router, optional interserver transport and selected egress.

## Compatibility boundary

Release `0.20.2` supports fresh install, `0.20.1 -> 0.20.2`, and same-version reinstall. Its compatible installed range is `0.20.1..0.20.2`; both versions use the same schemas and canonical node contract. All CLI node selection uses only `--node gateway|exit|all`.

No version-specific adapter is packaged. Unsupported versions fail on the manifest version before managed files change. See [DEPRECATIONS.md](./DEPRECATIONS.md) for the current policy.

## Acceptance matrix

| Case | Gateway | Exit | Interserver | Expected client egress |
| --- | --- | --- | --- | --- |
| `single-ru` | RU | absent | absent | RU |
| `single-foreign` | foreign | absent | absent | foreign |
| `dual` | RU | foreign | required | policy-selected RU/foreign |
