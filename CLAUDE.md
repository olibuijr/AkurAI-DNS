# CLAUDE.md

## What

AkurAI DNS -- production-grade authoritative DNS server in pure Rust. Serves zones for AkurAI infrastructure (olibuijr.com, golfsetridak.is, future customer domains). Deployed to EC2 at 3.94.46.219.

## Architecture

```
src/
  dns.rs     — Wire protocol: parse/serialize DNS messages, record constructors
  zone.rs    — Zone data model + TOML loader, ZoneSet with longest-suffix matching
  server.rs  — UDP + TCP server, rate limiting, EDNS0, SIGHUP reload, health check
  main.rs    — Entry point, config from env, wires everything together
zones/       — TOML zone files (deployed to /etc/akurai-dns/zones/)
deploy.sh    — Build musl binary, upload, install systemd service, healthcheck
```

## Build

```bash
# Dev build
cargo build

# Release (musl static binary for Linux deploy)
CC_x86_64_unknown_linux_musl=musl-gcc cargo build --release --target x86_64-unknown-linux-musl
```

Requires `rustup target add x86_64-unknown-linux-musl` and `musl-gcc` (package `musl-tools` on Debian/Ubuntu).

## Deploy

```bash
./deploy.sh
```

Reads `DNS_DEPLOY_HOST` (default: `akurai-mail` SSH alias) and `DNS_DEPLOY_USER` (default: `root`). Bumps VERSION, updates CHANGELOG.md, uploads binary + zones, installs systemd service, runs healthcheck.

## Env vars

| Variable | Default | Description |
|----------|---------|-------------|
| `DNS_ZONE_DIR` | `/etc/akurai-dns/zones` | Directory containing .toml zone files |
| `DNS_LISTEN` | `0.0.0.0` | Bind address |
| `DNS_PORT` | `53` | Listen port |
| `RUST_LOG` | `info` | Tracing filter (`debug` for per-query logs) |

## Zone file format

TOML files in `DNS_ZONE_DIR`. One file per zone. See `zones/golfsetridak.is.toml` for a complete example.

- `@` in record names expands to zone apex
- Bare names (no trailing dot) get zone name appended
- Supported types: A, AAAA, CNAME, MX, TXT, NS, SRV, CAA

## Reload zones

```bash
# Without restart
sudo systemctl reload akurai-dns   # sends SIGHUP
# Or
sudo kill -HUP $(pidof akurai-dns)
```

## Constraints

- **musl**: Production binary must be statically linked (musl target). No glibc on minimal EC2 images.
- **Port 53**: Requires root or CAP_NET_BIND_SERVICE. The systemd unit uses AmbientCapabilities.
- **No recursion**: This is authoritative-only. Queries for zones we don't serve get REFUSED.
- **No DNSSEC** yet. Zone signing is a future addition.
- **dns.rs is written by another agent**: Do not modify it. Coordinate interface changes.

## Testing

```bash
# Local test (needs port 53 or override)
DNS_PORT=5353 DNS_ZONE_DIR=./zones cargo run

# Query
dig @127.0.0.1 -p 5353 golfsetridak.is A
dig @127.0.0.1 -p 5353 health.akurai-dns. TXT

# TCP
dig @127.0.0.1 -p 5353 golfsetridak.is A +tcp
```

## Related

- **1984dns CLI** (`~/Projects/1984dns`): bash tool for updating DNS at 1984.is registrar
- **Homelab DNS** (`prox1/prox4`): existing BIND split-brain DNS being replaced by this
- **AkurAI platform**: This server will eventually host DNS for all AkurAI customer domains
