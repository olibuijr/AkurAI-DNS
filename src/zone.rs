use crate::dns::{
    Record, CLASS_IN, TYPE_A, TYPE_AAAA, TYPE_ANY, TYPE_CAA, TYPE_CNAME, TYPE_MX, TYPE_NS,
    TYPE_SOA, TYPE_SRV, TYPE_TXT,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use tracing::{info, warn};

// ── TOML schema ──────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ZoneFile {
    zone: ZoneMeta,
    soa: SoaConfig,
    ns: Vec<NsEntry>,
    record: Option<Vec<RecordEntry>>,
}

#[derive(Deserialize)]
struct ZoneMeta {
    name: String,
    ttl: u32,
}

#[derive(Deserialize)]
struct SoaConfig {
    mname: String,
    rname: String,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
}

#[derive(Deserialize)]
struct NsEntry {
    name: String,
}

#[derive(Deserialize)]
struct RecordEntry {
    name: String,
    #[serde(rename = "type")]
    rtype: String,
    value: String,
    #[serde(default)]
    ttl: Option<u32>,
    #[serde(default)]
    priority: Option<u16>,
    // SRV fields
    #[serde(default)]
    weight: Option<u16>,
    #[serde(default)]
    port: Option<u16>,
    // CAA fields
    #[serde(default)]
    flag: Option<u8>,
    #[serde(default)]
    tag: Option<String>,
}

// ── Runtime structs ──────────────────────────────────────────────────

pub struct Zone {
    pub name: String,
    pub ttl: u32,
    /// (lowercase_fqdn, record_type) → Vec<Record>
    records: HashMap<(String, u16), Vec<Record>>,
    /// NS records for the zone apex
    pub ns_records: Vec<Record>,
    /// SOA record for the zone apex
    pub soa_record: Record,
}

pub struct ZoneSet {
    /// Zones keyed by their lowercase name (with trailing dot)
    zones: HashMap<String, Zone>,
    /// Zone names sorted longest-first for suffix matching
    sorted_names: Vec<String>,
}

// ── Zone implementation ──────────────────────────────────────────────

impl Zone {
    /// Expand a record name relative to the zone.
    /// - `@` → zone name
    /// - name without trailing dot → name.zone_name
    /// - name with trailing dot → kept as-is
    fn expand_name(raw: &str, zone_name: &str) -> String {
        if raw == "@" {
            zone_name.to_lowercase()
        } else if raw.ends_with('.') {
            raw.to_lowercase()
        } else {
            format!("{}.{}", raw, zone_name).to_lowercase()
        }
    }

    pub fn from_toml(text: &str) -> Result<Self, String> {
        let zf: ZoneFile = toml::from_str(text).map_err(|e| format!("TOML parse error: {e}"))?;

        let zone_name = if zf.zone.name.ends_with('.') {
            zf.zone.name.to_lowercase()
        } else {
            format!("{}.", zf.zone.name).to_lowercase()
        };
        let ttl = zf.zone.ttl;

        let mut records: HashMap<(String, u16), Vec<Record>> = HashMap::new();

        // SOA
        let soa_record = Record::new_soa(
            &zone_name,
            ttl,
            &zf.soa.mname,
            &zf.soa.rname,
            zf.soa.serial,
            zf.soa.refresh,
            zf.soa.retry,
            zf.soa.expire,
            zf.soa.minimum,
        );
        records
            .entry((zone_name.clone(), TYPE_SOA))
            .or_default()
            .push(soa_record.clone());

        let soa_for_authority = soa_record.clone();

        // NS
        let mut ns_records = Vec::new();
        for ns in &zf.ns {
            let rec = Record::new_ns(&zone_name, ttl, &ns.name);
            ns_records.push(rec.clone());
            records
                .entry((zone_name.clone(), TYPE_NS))
                .or_default()
                .push(rec);
        }

        // User records
        if let Some(entries) = &zf.record {
            for entry in entries {
                let fqdn = Self::expand_name(&entry.name, &zone_name);
                let entry_ttl = entry.ttl.unwrap_or(ttl);

                let (rtype, rec) = match entry.rtype.to_uppercase().as_str() {
                    "A" => {
                        let ip: std::net::Ipv4Addr = entry
                            .value
                            .parse()
                            .map_err(|e| format!("Bad A record '{}': {e}", entry.value))?;
                        (TYPE_A, Record::new_a(&fqdn, entry_ttl, ip.octets()))
                    }
                    "AAAA" => {
                        let ip: std::net::Ipv6Addr = entry
                            .value
                            .parse()
                            .map_err(|e| format!("Bad AAAA record '{}': {e}", entry.value))?;
                        (TYPE_AAAA, Record::new_aaaa(&fqdn, entry_ttl, ip.octets()))
                    }
                    "CNAME" => (
                        TYPE_CNAME,
                        Record::new_cname(&fqdn, entry_ttl, &entry.value),
                    ),
                    "MX" => {
                        let priority = entry.priority.unwrap_or(10);
                        (
                            TYPE_MX,
                            Record::new_mx(&fqdn, entry_ttl, priority, &entry.value),
                        )
                    }
                    "TXT" => (TYPE_TXT, Record::new_txt(&fqdn, entry_ttl, &entry.value)),
                    "NS" => (TYPE_NS, Record::new_ns(&fqdn, entry_ttl, &entry.value)),
                    "SRV" => {
                        let priority = entry.priority.unwrap_or(0);
                        let weight = entry.weight.unwrap_or(0);
                        let port = entry.port.unwrap_or(0);
                        (
                            TYPE_SRV,
                            Record::new_srv(&fqdn, entry_ttl, priority, weight, port, &entry.value),
                        )
                    }
                    "CAA" => {
                        let flag = entry.flag.unwrap_or(0);
                        let tag = entry.tag.clone().unwrap_or_else(|| "issue".to_string());
                        (
                            TYPE_CAA,
                            Record::new_caa(&fqdn, entry_ttl, flag, &tag, &entry.value),
                        )
                    }
                    other => {
                        return Err(format!("Unsupported record type: {other}"));
                    }
                };

                records.entry((fqdn, rtype)).or_default().push(rec);
            }
        }

        Ok(Zone {
            name: zone_name,
            ttl,
            records,
            ns_records,
            soa_record: soa_for_authority,
        })
    }

    /// Look up records by FQDN and query type.
    ///
    /// - TYPE_ANY returns all records for that name.
    /// - If an A/AAAA query hits a CNAME, the CNAME is returned (caller can chase).
    pub fn lookup(&self, name: &str, qtype: u16) -> Vec<Record> {
        let key = name.to_lowercase();

        if qtype == TYPE_ANY {
            // Return every record for this name regardless of type
            return self
                .records
                .iter()
                .filter(|((n, _), _)| *n == key)
                .flat_map(|(_, v)| v.clone())
                .collect();
        }

        // Direct match
        if let Some(recs) = self.records.get(&(key.clone(), qtype)) {
            return recs.clone();
        }

        // CNAME chasing: if we asked for A/AAAA/etc but there's a CNAME, return it
        if qtype != TYPE_CNAME {
            if let Some(cnames) = self.records.get(&(key, TYPE_CNAME)) {
                return cnames.clone();
            }
        }

        Vec::new()
    }

    /// Check whether a name exists in this zone at all (for NXDOMAIN vs NODATA).
    pub fn name_exists(&self, name: &str) -> bool {
        let key = name.to_lowercase();
        self.records.keys().any(|(n, _)| *n == key)
    }
}

// ── ZoneSet implementation ───────────────────────────────────────────

impl ZoneSet {
    pub fn new() -> Self {
        ZoneSet {
            zones: HashMap::new(),
            sorted_names: Vec::new(),
        }
    }

    /// Load all `.toml` zone files from a directory.
    pub fn load_dir(dir: &Path) -> Result<Self, String> {
        let mut zs = ZoneSet::new();

        let entries = std::fs::read_dir(dir)
            .map_err(|e| format!("Cannot read zone dir {}: {e}", dir.display()))?;

        for entry in entries {
            let entry = entry.map_err(|e| format!("Dir entry error: {e}"))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }

            let text = std::fs::read_to_string(&path)
                .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;

            match Zone::from_toml(&text) {
                Ok(zone) => {
                    info!(zone = %zone.name, file = %path.display(), "Loaded zone");
                    zs.zones.insert(zone.name.clone(), zone);
                }
                Err(e) => {
                    warn!(file = %path.display(), error = %e, "Failed to load zone");
                    return Err(format!("Zone file {}: {e}", path.display()));
                }
            }
        }

        // Sort names longest first for correct suffix matching
        zs.sorted_names = zs.zones.keys().cloned().collect();
        zs.sorted_names
            .sort_by(|a, b| b.len().cmp(&a.len()));

        info!(count = zs.zones.len(), "Zone set loaded");
        Ok(zs)
    }

    /// Find the zone that is authoritative for `name` (longest suffix match).
    pub fn find_zone(&self, name: &str) -> Option<&Zone> {
        let lower = name.to_lowercase();
        for zname in &self.sorted_names {
            if lower == *zname || lower.ends_with(&format!(".{zname}")) {
                return self.zones.get(zname);
            }
        }
        None
    }
}
