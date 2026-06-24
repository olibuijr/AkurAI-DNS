use crate::dns::{Message, Record, RData, DnsError, TYPE_OPT, CLASS_IN};
use crate::zone::ZoneSet;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info, warn};

const DEFAULT_UDP_LIMIT: usize = 512;
const EDNS_UDP_LIMIT: usize = 4096;
const TCP_MAX_MSG: usize = 65535;
const TCP_TIMEOUT: Duration = Duration::from_secs(10);
const RATE_LIMIT_QPS: u32 = 100;
const RATE_WINDOW: Duration = Duration::from_secs(1);
const HEALTH_NAME: &str = "health.akurai-dns.";

// ── Rate limiter ─────────────────────────────────────────────────────

struct RateLimiter {
    map: HashMap<IpAddr, (u32, Instant)>,
}

impl RateLimiter {
    fn new() -> Self {
        RateLimiter {
            map: HashMap::new(),
        }
    }

    /// Returns true if the request is allowed.
    fn check(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let entry = self.map.entry(ip).or_insert((0, now));

        if now.duration_since(entry.1) >= RATE_WINDOW {
            // New window
            entry.0 = 1;
            entry.1 = now;
            true
        } else {
            entry.0 += 1;
            entry.0 <= RATE_LIMIT_QPS
        }
    }

    /// Remove entries older than 10 seconds.
    fn cleanup(&mut self) {
        let cutoff = Instant::now() - Duration::from_secs(10);
        self.map.retain(|_, (_, ts)| *ts > cutoff);
    }
}

// ── Query processing ─────────────────────────────────────────────────

fn process_query(query: &Message, zones: &ZoneSet) -> Message {
    let mut response = Message::new_response(query);
    let start = Instant::now();

    // Detect EDNS0
    let mut client_udp_size: Option<u16> = None;
    for rec in &query.additional {
        if let RData::OPT { udp_size } = &rec.rdata {
            client_udp_size = Some(*udp_size);
        }
    }

    if query.questions.is_empty() {
        response.set_rcode(1); // FORMERR
        return response;
    }

    let question = &query.questions[0];
    let qname = question.name.to_lowercase();
    let qtype = question.qtype;

    // Health check
    if qname == HEALTH_NAME {
        response.header.aa = true;
        response.answers.push(Record::new_txt(HEALTH_NAME, 0, "ok"));
        add_edns_response(&mut response, client_udp_size);
        return response;
    }

    // Find authoritative zone
    match zones.find_zone(&qname) {
        None => {
            // REFUSED — we are not authoritative
            response.set_rcode(5);
        }
        Some(zone) => {
            response.header.aa = true;

            let answers = zone.lookup(&qname, qtype);
            if !answers.is_empty() {
                response.answers = answers;
                // Add authority section (NS records)
                response.authority = zone.ns_records.clone();
            } else if zone.name_exists(&qname) {
                // Name exists but no records of this type → NODATA (RCODE 0 + empty answer + SOA)
                response.authority.push(zone.soa_record.clone());
            } else {
                // NXDOMAIN
                response.set_rcode(3);
                response.authority.push(zone.soa_record.clone());
            }
        }
    }

    // Add EDNS0 OPT to response if client sent one
    add_edns_response(&mut response, client_udp_size);

    let elapsed = start.elapsed();
    debug!(
        qname = %qname,
        qtype = qtype,
        rcode = response.header.rcode,
        elapsed_us = elapsed.as_micros() as u64,
        "Processed query"
    );

    response
}

fn add_edns_response(response: &mut Message, client_udp_size: Option<u16>) {
    if client_udp_size.is_some() {
        // Add OPT record advertising our 4096 UDP size
        response.additional.push(Record {
            name: String::new(), // OPT uses root name
            rtype: TYPE_OPT,
            class: EDNS_UDP_LIMIT as u16,
            ttl: 0,
            rdata: RData::OPT { udp_size: EDNS_UDP_LIMIT as u16 },
        });
    }
}

/// Determine the UDP size limit based on EDNS0.
fn udp_limit(query: &Message) -> usize {
    for rec in &query.additional {
        if let RData::OPT { udp_size } = &rec.rdata {
            return (*udp_size as usize).max(512).min(4096);
        }
    }
    DEFAULT_UDP_LIMIT
}

// ── UDP server ───────────────────────────────────────────────────────

pub async fn run_udp(
    listen: &str,
    port: u16,
    zones: Arc<RwLock<ZoneSet>>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
) -> std::io::Result<()> {
    let addr = format!("{listen}:{port}");
    let socket = Arc::new(UdpSocket::bind(&addr).await?);
    info!(addr = %addr, "UDP server listening");

    let mut buf = vec![0u8; 4096];

    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "UDP recv error");
                continue;
            }
        };

        // Rate limit
        {
            let mut rl = rate_limiter.lock().await;
            if !rl.check(src.ip()) {
                debug!(client = %src.ip(), "Rate limited");
                continue;
            }
        }

        let data = buf[..len].to_vec();
        let socket_clone = socket.clone();
        let zones_clone = zones.clone();

        // Spawn handler so we don't block the recv loop
        tokio::spawn(async move {
            let start = Instant::now();
            let query = match Message::parse(&data) {
                Ok(q) => q,
                Err(e) => {
                    warn!(client = %src, error = %e, "Bad UDP query");
                    return;
                }
            };

            let qname = query
                .questions
                .first()
                .map(|q| q.name.as_str())
                .unwrap_or("?");
            let qtype = query.questions.first().map(|q| q.qtype).unwrap_or(0);

            let limit = udp_limit(&query);
            let zones_guard = zones_clone.read().await;
            let response = process_query(&query, &zones_guard);
            drop(zones_guard);

            let (mut bytes, truncated) = response.serialize_with_limit(limit);
            if truncated {
                // Re-serialize with TC=1
                let mut trunc_resp = Message::new_response(&query);
                trunc_resp.header.tc = true;
                trunc_resp.header.aa = response.header.aa;
                trunc_resp.set_rcode(response.header.rcode);
                bytes = trunc_resp.serialize();
            }

            if let Err(e) = socket_clone.send_to(&bytes, src).await {
                warn!(client = %src, error = %e, "UDP send error");
            }

            info!(
                client = %src,
                qname = %qname,
                qtype = qtype,
                rcode = response.header.rcode,
                size = bytes.len(),
                elapsed_us = start.elapsed().as_micros() as u64,
                "UDP query"
            );
        });
    }
}

// ── TCP server ───────────────────────────────────────────────────────

pub async fn run_tcp(
    listen: &str,
    port: u16,
    zones: Arc<RwLock<ZoneSet>>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
) -> std::io::Result<()> {
    let addr = format!("{listen}:{port}");
    let listener = TcpListener::bind(&addr).await?;
    info!(addr = %addr, "TCP server listening");

    loop {
        let (stream, src) = match listener.accept().await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "TCP accept error");
                continue;
            }
        };

        // Rate limit
        {
            let mut rl = rate_limiter.lock().await;
            if !rl.check(src.ip()) {
                debug!(client = %src.ip(), "TCP rate limited");
                continue;
            }
        }

        let zones_clone = zones.clone();
        tokio::spawn(async move {
            if let Err(e) =
                tokio::time::timeout(TCP_TIMEOUT, handle_tcp(stream, src, zones_clone)).await
            {
                debug!(client = %src, "TCP timeout: {e}");
            }
        });
    }
}

async fn handle_tcp(
    mut stream: TcpStream,
    src: SocketAddr,
    zones: Arc<RwLock<ZoneSet>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();

    // Read 2-byte length prefix
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let msg_len = u16::from_be_bytes(len_buf) as usize;

    if msg_len == 0 || msg_len > TCP_MAX_MSG {
        return Ok(());
    }

    let mut data = vec![0u8; msg_len];
    stream.read_exact(&mut data).await?;

    let query = Message::parse(&data)?;

    let qname = query
        .questions
        .first()
        .map(|q| q.name.as_str())
        .unwrap_or("?")
        .to_string();
    let qtype = query.questions.first().map(|q| q.qtype).unwrap_or(0);

    let zones_guard = zones.read().await;
    let response = process_query(&query, &zones_guard);
    drop(zones_guard);

    let bytes = response.serialize();

    // Write 2-byte length prefix + response
    let resp_len = (bytes.len() as u16).to_be_bytes();
    stream.write_all(&resp_len).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;

    info!(
        client = %src,
        qname = %qname,
        qtype = qtype,
        rcode = response.header.rcode,
        size = bytes.len(),
        elapsed_us = start.elapsed().as_micros() as u64,
        "TCP query"
    );

    Ok(())
}

// ── Public entry point ───────────────────────────────────────────────

pub async fn run(
    listen: String,
    port: u16,
    zones: Arc<RwLock<ZoneSet>>,
    zone_dir: String,
) {
    let rate_limiter = Arc::new(Mutex::new(RateLimiter::new()));

    // Periodic rate limiter cleanup
    let rl_cleanup = rate_limiter.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            rl_cleanup.lock().await.cleanup();
        }
    });

    // SIGHUP handler for zone reload
    let zones_reload = zones.clone();
    let zone_dir_reload = zone_dir.clone();
    tokio::spawn(async move {
        let mut hup = signal(SignalKind::hangup()).expect("Failed to register SIGHUP handler");
        loop {
            hup.recv().await;
            info!("SIGHUP received, reloading zones");
            match ZoneSet::load_dir(std::path::Path::new(&zone_dir_reload)) {
                Ok(new_zones) => {
                    let mut w = zones_reload.write().await;
                    *w = new_zones;
                    info!("Zones reloaded successfully");
                }
                Err(e) => {
                    error!(error = %e, "Zone reload failed, keeping old zones");
                }
            }
        }
    });

    // Start UDP + TCP
    let udp_zones = zones.clone();
    let udp_rl = rate_limiter.clone();
    let udp_listen = listen.clone();

    let tcp_zones = zones.clone();
    let tcp_rl = rate_limiter.clone();
    let tcp_listen = listen.clone();

    tokio::select! {
        r = run_udp(&udp_listen, port, udp_zones, udp_rl) => {
            error!("UDP server exited: {:?}", r);
        }
        r = run_tcp(&tcp_listen, port, tcp_zones, tcp_rl) => {
            error!("TCP server exited: {:?}", r);
        }
    }
}
