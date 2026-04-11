# Portable Private VPN Stack

Two-hop private VPN bundle for the flow `client -> RU gateway -> foreign exit`.

What this repository gives you:

- `install.sh` to install either `ru-gateway` or `foreign-exit` on Ubuntu 24.04.
- `scripts/gen-secrets.sh` to generate one deployment `.env`.
- `scripts/render-config.sh` to render server-side configs locally before deploy.
- `scripts/gen-client-profiles.sh` to build cross-platform client configs.
- `scripts/fetch-assets.sh` to preseed rule assets locally for first boot.
- `scripts/render-cloud-init.sh` to produce self-contained `cloud-init` files.
- `scripts/package-bundle.sh` to build uploadable per-role tarballs for manual deploy.
- `scripts/smoke-test.sh` to run or print post-deploy checks for both servers.

## Topology

- Client connects only to the RU server over `VLESS + REALITY` on `443/tcp`.
- RU server routes Russian traffic out directly.
- RU server routes non-Russian traffic into a WireGuard tunnel to the foreign server.
- Foreign server NATs WireGuard traffic to the public internet.
- Foreign server can additionally block Russian CIDRs on the egress path.

## Quick Start

1. Generate a deployment file:

```bash
./scripts/gen-secrets.sh ./deployments/my-stack.env
```

2. Edit the generated file and fill at least:

- `RU_PUBLIC_IP`
- `FOREIGN_PUBLIC_IP`
- `RU_REALITY_SERVER_NAME`
- `RU_REALITY_HANDSHAKE_SERVER`

3. Render local previews:

```bash
./scripts/render-config.sh ./deployments/my-stack.env
```

4. Optionally prefetch rule assets for offline-ish first boot:

```bash
./scripts/fetch-assets.sh ./deployments/my-stack.env
```

5. Generate client configs:

```bash
./scripts/gen-client-profiles.sh ./deployments/my-stack.env
```

6. Generate self-contained cloud-init files:

```bash
./scripts/render-cloud-init.sh ./deployments/my-stack.env
```

7. Boot VPS instances with the generated files from `out/<deployment>/cloud-init/`, or upload the bundle and run:

```bash
sudo ./install.sh --role foreign-exit --env-file ./out/<deployment>/server/foreign.env --assets-dir ./out/<deployment>/assets
sudo ./install.sh --role ru-gateway --env-file ./out/<deployment>/server/ru.env --assets-dir ./out/<deployment>/assets
```

8. If you prefer manual upload packages instead of `cloud-init`:

```bash
./scripts/package-bundle.sh ./deployments/my-stack.env
```

9. After deploy, run smoke checks:

```bash
./scripts/smoke-test.sh ./deployments/my-stack.env
./scripts/smoke-test.sh ./deployments/my-stack.env --ru-ssh root@RU_IP --foreign-ssh root@FOREIGN_IP
```

## Output Layout

After rendering, artifacts are written to:

```text
out/<deployment>/
  assets/
  bundle/
  client/
  cloud-init/
  preview/
  server/
```

## Notes

- Client configs are sing-box-compatible JSON profiles. Hiddify can import local sing-box configs.
- The Linux-specific client profile enables `auto_redirect`; the cross-platform profile does not.
- The v1 bundle is intentionally `IPv4-only fail-closed` for internet egress to avoid accidental IPv6 leaks around the foreign hop.
- The foreign RU block is CIDR-based and uses IPdeny aggregated zone lists by default.
- The RU route rules use local `sing-geosite` and `sing-geoip` `.srs` assets.
