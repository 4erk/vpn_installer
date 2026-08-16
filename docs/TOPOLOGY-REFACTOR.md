# Topology refactor 0.20.0

This file is the implementation ledger for the single/dual topology migration. A release is not complete while any required checkbox remains open.

## Invariants

- [x] Existing dual deployments render the same primary `vless-uri.txt` bytes.
- [x] A single RU gateway installs no WireGuard or interserver transport artifacts, packages, services, probes, or secrets.
- [x] A single foreign gateway installs no WireGuard or interserver transport artifacts, packages, services, probes, or secrets.
- [x] A dual gateway never receives the exit private WireGuard key or interserver server private key.
- [x] A dual exit never receives Reality private keys, client credentials, or web-admin credentials.
- [x] Install, rollback, remove, health, and drift control touch only resources owned by the compiled node plan.
- [x] Missing capabilities are reported as not applicable, never as healthy or failed.
- [x] Web-admin remains available on every gateway and only exposes egresses compiled for that topology.
- [x] Installation acceptance uses the generated primary VLESS URI and never changes the local default route or active VPN client.

## Delivery slices

- [x] Characterization tests for the current dual URI, route order, bundles, manifests, and install order.
- [x] Canonical `DeploymentSpec`, `TopologySpec`, `NodeSpec`, and `NodePlan`.
- [x] One-time local migration from `RU_*`/`FOREIGN_*` topology fields to gateway/exit fields.
- [x] Minimal per-node runtime configuration and secret projection.
- [x] Capability-driven renderer, artifacts, package set, services, probes, and manifest.
- [x] Single gateway routing and DNS without fake interserver state.
- [x] Capability-aware server installer, rollback, removal, agent, health, and diagnostics.
- [x] Topology-aware workflows, client artifacts, web-admin, status, diagnose, maintain, and live verify.
- [x] Unit, Docker, lab, interrupted-install, and rollback matrix for `single-ru`, `single-foreign`, and `dual`.
- [x] Documentation, changelog, migration evidence, release audit, and production acceptance.

Production acceptance completed on 2026-08-17 for deployment `1`: both schema-3 nodes report `drift: none`, diagnostics schema 4 reports no classified events since release, and an independent runner verified the unchanged primary VLESS URI through gateway, Xray, router, interserver transport, and exit egress.

## Deprecation boundary

Release `0.20.0` may read the following legacy inputs only at the local migration boundary:

- `RU_PUBLIC_IP` and `FOREIGN_PUBLIC_IP`;
- state keys `ru-gateway` and `foreign-exit`;
- CLI role aliases `ru-gateway` and `foreign-exit`;
- installed manifests whose role uses either legacy value.

The compiler and all newly installed runtime files must use canonical topology/node fields. Successful migration records config schema 2, manifest schema 3 and `legacy_inputs=[]`. The follow-up cleanup patch removes the boundary readers after every managed node reports manifest schema 3 and diagnostics schema 4.

## Acceptance matrix

| Case | Gateway | Exit | Interserver | Expected client egress |
| --- | --- | --- | --- | --- |
| `single-ru` | RU | absent | absent | RU |
| `single-foreign` | foreign | absent | absent | foreign |
| `dual` | RU | foreign | required | policy-selected RU/foreign |
