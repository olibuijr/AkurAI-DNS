mod dns;
mod server;
mod zone;

use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    // Init tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Config from env
    let zone_dir = std::env::var("DNS_ZONE_DIR").unwrap_or_else(|_| "/etc/akurai-dns/zones".into());
    let listen = std::env::var("DNS_LISTEN").unwrap_or_else(|_| "0.0.0.0".into());
    let port: u16 = std::env::var("DNS_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(53);

    info!(zone_dir = %zone_dir, listen = %listen, port = port, "AkurAI DNS starting");

    // Load zones
    let zones = match zone::ZoneSet::load_dir(Path::new(&zone_dir)) {
        Ok(z) => z,
        Err(e) => {
            eprintln!("FATAL: Failed to load zones from {zone_dir}: {e}");
            std::process::exit(1);
        }
    };

    let zones = Arc::new(RwLock::new(zones));

    info!("Zones loaded, starting server");

    // Run server (blocks until exit)
    server::run(listen, port, zones, zone_dir).await;
}
