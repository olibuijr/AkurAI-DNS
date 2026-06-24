# AkurAI DNS

Production-grade authoritative DNS server in pure Rust. No dependencies beyond tokio, serde, toml, and tracing. Statically linked musl binary, single-file deploy.

## Build

```bash
cargo build --release --target x86_64-unknown-linux-musl
```

## Configure zones

Create TOML files in `/etc/akurai-dns/zones/` (or set `DNS_ZONE_DIR`):

```toml
[zone]
name = "example.com."
ttl = 3600

[soa]
mname = "ns1.example.com."
rname = "admin.example.com."
serial = 2026062401
refresh = 3600
retry = 900
expire = 604800
minimum = 300

[[ns]]
name = "ns1.example.com."

[[ns]]
name = "ns2.example.com."

[[record]]
name = "@"
type = "A"
value = "1.2.3.4"

[[record]]
name = "www"
type = "CNAME"
value = "example.com."

[[record]]
name = "@"
type = "MX"
priority = 10
value = "mail.example.com."

[[record]]
name = "@"
type = "TXT"
value = "v=spf1 ip4:1.2.3.4 -all"
```

Supported record types: A, AAAA, CNAME, MX, TXT, NS, SRV, CAA.

## Run

```bash
DNS_ZONE_DIR=./zones DNS_PORT=5353 ./akurai-dns
```

## Deploy

```bash
./deploy.sh   # builds, uploads to EC2, installs systemd service, healthchecks
```

## Reload zones without restart

```bash
systemctl reload akurai-dns
```

## Features

- UDP + TCP on port 53
- EDNS0 (advertises 4096 byte UDP)
- Per-IP rate limiting (100 qps)
- SIGHUP graceful zone reload
- Health check: `dig health.akurai-dns. TXT` returns `"ok"`
- Hardened systemd unit (NoNewPrivileges, ProtectSystem, ProtectHome)

## License

MIT
