use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

// ---------------------------------------------------------------------------
// Record type constants
// ---------------------------------------------------------------------------

pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_MX: u16 = 15;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_OPT: u16 = 41;
pub const TYPE_CAA: u16 = 257;
pub const TYPE_ANY: u16 = 255;
pub const CLASS_IN: u16 = 1;

// ---------------------------------------------------------------------------
// RCODE constants
// ---------------------------------------------------------------------------

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_REFUSED: u8 = 5;

/// Maximum number of compression pointer jumps before we declare a loop.
const MAX_COMPRESSION_JUMPS: usize = 256;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    TooShort,
    InvalidHeader,
    InvalidName,
    InvalidRecord,
    CompressionLoop,
    BufferOverflow,
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::TooShort => write!(f, "packet too short"),
            DnsError::InvalidHeader => write!(f, "invalid header"),
            DnsError::InvalidName => write!(f, "invalid domain name"),
            DnsError::InvalidRecord => write!(f, "invalid resource record"),
            DnsError::CompressionLoop => write!(f, "compression pointer loop"),
            DnsError::BufferOverflow => write!(f, "buffer overflow"),
        }
    }
}

impl std::error::Error for DnsError {}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Header {
    pub id: u16,
    pub qr: bool,
    pub opcode: u8,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub rcode: u8,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

#[derive(Debug, Clone)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone)]
pub enum RData {
    A([u8; 4]),
    AAAA([u8; 16]),
    CNAME(String),
    MX { preference: u16, exchange: String },
    TXT(String),
    NS(String),
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    CAA {
        flags: u8,
        tag: String,
        value: String,
    },
    OPT {
        udp_size: u16,
    },
    Unknown(Vec<u8>),
}

impl RData {
    /// Returns the DNS type code for this rdata variant.
    pub fn type_code(&self) -> u16 {
        match self {
            RData::A(_) => TYPE_A,
            RData::AAAA(_) => TYPE_AAAA,
            RData::CNAME(_) => TYPE_CNAME,
            RData::MX { .. } => TYPE_MX,
            RData::TXT(_) => TYPE_TXT,
            RData::NS(_) => TYPE_NS,
            RData::SOA { .. } => TYPE_SOA,
            RData::SRV { .. } => TYPE_SRV,
            RData::CAA { .. } => TYPE_CAA,
            RData::OPT { .. } => TYPE_OPT,
            RData::Unknown(_) => 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: RData,
}

#[derive(Debug, Clone)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
}

// ---------------------------------------------------------------------------
// Record constructors
// ---------------------------------------------------------------------------

impl Record {
    pub fn new_a(name: &str, ttl: u32, ip: [u8; 4]) -> Record {
        Record {
            name: normalize_name(name),
            rtype: TYPE_A,
            class: CLASS_IN,
            ttl,
            rdata: RData::A(ip),
        }
    }

    pub fn new_aaaa(name: &str, ttl: u32, ip: [u8; 16]) -> Record {
        Record {
            name: normalize_name(name),
            rtype: TYPE_AAAA,
            class: CLASS_IN,
            ttl,
            rdata: RData::AAAA(ip),
        }
    }

    pub fn new_cname(name: &str, ttl: u32, target: &str) -> Record {
        Record {
            name: normalize_name(name),
            rtype: TYPE_CNAME,
            class: CLASS_IN,
            ttl,
            rdata: RData::CNAME(normalize_name(target)),
        }
    }

    pub fn new_mx(name: &str, ttl: u32, preference: u16, exchange: &str) -> Record {
        Record {
            name: normalize_name(name),
            rtype: TYPE_MX,
            class: CLASS_IN,
            ttl,
            rdata: RData::MX {
                preference,
                exchange: normalize_name(exchange),
            },
        }
    }

    pub fn new_txt(name: &str, ttl: u32, text: &str) -> Record {
        Record {
            name: normalize_name(name),
            rtype: TYPE_TXT,
            class: CLASS_IN,
            ttl,
            rdata: RData::TXT(text.to_string()),
        }
    }

    pub fn new_ns(name: &str, ttl: u32, nsdname: &str) -> Record {
        Record {
            name: normalize_name(name),
            rtype: TYPE_NS,
            class: CLASS_IN,
            ttl,
            rdata: RData::NS(normalize_name(nsdname)),
        }
    }

    pub fn new_soa(
        name: &str,
        ttl: u32,
        mname: &str,
        rname: &str,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    ) -> Record {
        Record {
            name: normalize_name(name),
            rtype: TYPE_SOA,
            class: CLASS_IN,
            ttl,
            rdata: RData::SOA {
                mname: normalize_name(mname),
                rname: normalize_name(rname),
                serial,
                refresh,
                retry,
                expire,
                minimum,
            },
        }
    }

    pub fn new_srv(
        name: &str,
        ttl: u32,
        priority: u16,
        weight: u16,
        port: u16,
        target: &str,
    ) -> Record {
        Record {
            name: normalize_name(name),
            rtype: TYPE_SRV,
            class: CLASS_IN,
            ttl,
            rdata: RData::SRV {
                priority,
                weight,
                port,
                target: normalize_name(target),
            },
        }
    }

    pub fn new_caa(name: &str, ttl: u32, flags: u8, tag: &str, value: &str) -> Record {
        Record {
            name: normalize_name(name),
            rtype: TYPE_CAA,
            class: CLASS_IN,
            ttl,
            rdata: RData::CAA {
                flags,
                tag: tag.to_string(),
                value: value.to_string(),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Name normalization
// ---------------------------------------------------------------------------

/// Ensure a name is lowercase and FQDN (ends with '.').
fn normalize_name(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with('.') {
        lower
    } else {
        format!("{lower}.")
    }
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

/// A cursor over a byte slice for parsing DNS messages.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn read_u8(&mut self) -> Result<u8, DnsError> {
        if self.pos >= self.data.len() {
            return Err(DnsError::TooShort);
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u16(&mut self) -> Result<u16, DnsError> {
        if self.pos + 2 > self.data.len() {
            return Err(DnsError::TooShort);
        }
        let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read_u32(&mut self) -> Result<u32, DnsError> {
        if self.pos + 4 > self.data.len() {
            return Err(DnsError::TooShort);
        }
        let v = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], DnsError> {
        if self.pos + n > self.data.len() {
            return Err(DnsError::TooShort);
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }
}

/// Parse a DNS domain name from the packet, following compression pointers.
/// `data` is the full original packet (needed for pointer offsets).
/// `pos` is the current read position; returns the new position after the name
/// (which may differ from where the pointer chain ends).
fn parse_name(data: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut jumps = 0;
    // The position after the first pointer (or after the null terminator if no pointer).
    let mut end_pos: Option<usize> = None;

    loop {
        if pos >= data.len() {
            return Err(DnsError::TooShort);
        }
        let len_byte = data[pos];

        if len_byte == 0 {
            // End of name
            if end_pos.is_none() {
                end_pos = Some(pos + 1);
            }
            break;
        }

        // Check for compression pointer: top 2 bits are 11
        if len_byte & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() {
                return Err(DnsError::TooShort);
            }
            let pointer = ((len_byte as u16 & 0x3F) << 8) | data[pos + 1] as u16;
            if end_pos.is_none() {
                end_pos = Some(pos + 2);
            }
            jumps += 1;
            if jumps > MAX_COMPRESSION_JUMPS {
                return Err(DnsError::CompressionLoop);
            }
            pos = pointer as usize;
            continue;
        }

        // Regular label
        let label_len = len_byte as usize;
        if label_len > 63 {
            return Err(DnsError::InvalidName);
        }
        if pos + 1 + label_len > data.len() {
            return Err(DnsError::TooShort);
        }
        let label = &data[pos + 1..pos + 1 + label_len];
        // Validate label bytes (RFC allows any octet, but we lowercase for storage)
        let label_str = std::str::from_utf8(label)
            .map_err(|_| DnsError::InvalidName)?
            .to_ascii_lowercase();
        labels.push(label_str);
        pos += 1 + label_len;
    }

    // Build FQDN
    let mut name = labels.join(".");
    name.push('.');

    // Total name length check (RFC 1035: 255 octets max)
    if name.len() > 255 {
        return Err(DnsError::InvalidName);
    }

    Ok((name, end_pos.unwrap_or(pos)))
}

/// Parse a name using the cursor's position, advancing the cursor.
fn parse_name_from_cursor(cursor: &mut Cursor<'_>) -> Result<String, DnsError> {
    let (name, new_pos) = parse_name(cursor.data, cursor.pos)?;
    cursor.pos = new_pos;
    Ok(name)
}

// ---------------------------------------------------------------------------
// Header parsing / serialization
// ---------------------------------------------------------------------------

impl Header {
    fn parse(cursor: &mut Cursor<'_>) -> Result<Header, DnsError> {
        if cursor.remaining() < 12 {
            return Err(DnsError::InvalidHeader);
        }
        let id = cursor.read_u16().map_err(|_| DnsError::InvalidHeader)?;
        let flags = cursor.read_u16().map_err(|_| DnsError::InvalidHeader)?;
        let qdcount = cursor.read_u16().map_err(|_| DnsError::InvalidHeader)?;
        let ancount = cursor.read_u16().map_err(|_| DnsError::InvalidHeader)?;
        let nscount = cursor.read_u16().map_err(|_| DnsError::InvalidHeader)?;
        let arcount = cursor.read_u16().map_err(|_| DnsError::InvalidHeader)?;

        Ok(Header {
            id,
            qr: (flags >> 15) & 1 == 1,
            opcode: ((flags >> 11) & 0xF) as u8,
            aa: (flags >> 10) & 1 == 1,
            tc: (flags >> 9) & 1 == 1,
            rd: (flags >> 8) & 1 == 1,
            ra: (flags >> 7) & 1 == 1,
            rcode: (flags & 0xF) as u8,
            qdcount,
            ancount,
            nscount,
            arcount,
        })
    }

    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.id.to_be_bytes());

        let mut flags: u16 = 0;
        if self.qr {
            flags |= 1 << 15;
        }
        flags |= (self.opcode as u16 & 0xF) << 11;
        if self.aa {
            flags |= 1 << 10;
        }
        if self.tc {
            flags |= 1 << 9;
        }
        if self.rd {
            flags |= 1 << 8;
        }
        if self.ra {
            flags |= 1 << 7;
        }
        flags |= self.rcode as u16 & 0xF;

        buf.extend_from_slice(&flags.to_be_bytes());
        buf.extend_from_slice(&self.qdcount.to_be_bytes());
        buf.extend_from_slice(&self.ancount.to_be_bytes());
        buf.extend_from_slice(&self.nscount.to_be_bytes());
        buf.extend_from_slice(&self.arcount.to_be_bytes());
    }
}

// ---------------------------------------------------------------------------
// Question parsing / serialization
// ---------------------------------------------------------------------------

impl Question {
    fn parse(cursor: &mut Cursor<'_>) -> Result<Question, DnsError> {
        let name = parse_name_from_cursor(cursor)?;
        let qtype = cursor.read_u16().map_err(|_| DnsError::InvalidRecord)?;
        let qclass = cursor.read_u16().map_err(|_| DnsError::InvalidRecord)?;
        Ok(Question {
            name,
            qtype,
            qclass,
        })
    }

    fn serialize(&self, buf: &mut Vec<u8>, compression: &mut CompressionMap) {
        write_name(buf, &self.name, compression);
        buf.extend_from_slice(&self.qtype.to_be_bytes());
        buf.extend_from_slice(&self.qclass.to_be_bytes());
    }
}

// ---------------------------------------------------------------------------
// Record parsing / serialization
// ---------------------------------------------------------------------------

impl Record {
    fn parse(cursor: &mut Cursor<'_>) -> Result<Record, DnsError> {
        let name = parse_name_from_cursor(cursor)?;
        let rtype = cursor.read_u16().map_err(|_| DnsError::InvalidRecord)?;
        let class = cursor.read_u16().map_err(|_| DnsError::InvalidRecord)?;
        let ttl = cursor.read_u32().map_err(|_| DnsError::InvalidRecord)?;
        let rdlength = cursor.read_u16().map_err(|_| DnsError::InvalidRecord)? as usize;

        if cursor.remaining() < rdlength {
            return Err(DnsError::InvalidRecord);
        }

        let rdata_start = cursor.pos;
        let rdata_end = rdata_start + rdlength;

        let rdata = match rtype {
            TYPE_A => {
                if rdlength != 4 {
                    return Err(DnsError::InvalidRecord);
                }
                let bytes = cursor.read_bytes(4).map_err(|_| DnsError::InvalidRecord)?;
                RData::A([bytes[0], bytes[1], bytes[2], bytes[3]])
            }
            TYPE_AAAA => {
                if rdlength != 16 {
                    return Err(DnsError::InvalidRecord);
                }
                let bytes = cursor
                    .read_bytes(16)
                    .map_err(|_| DnsError::InvalidRecord)?;
                let mut addr = [0u8; 16];
                addr.copy_from_slice(bytes);
                RData::AAAA(addr)
            }
            TYPE_CNAME => {
                let cname = parse_name_from_cursor(cursor)?;
                RData::CNAME(cname)
            }
            TYPE_NS => {
                let ns = parse_name_from_cursor(cursor)?;
                RData::NS(ns)
            }
            TYPE_MX => {
                let preference = cursor.read_u16().map_err(|_| DnsError::InvalidRecord)?;
                let exchange = parse_name_from_cursor(cursor)?;
                RData::MX {
                    preference,
                    exchange,
                }
            }
            TYPE_TXT => {
                // TXT records contain one or more character strings.
                // Each is length-prefixed. We concatenate them.
                let mut text = String::new();
                while cursor.pos < rdata_end {
                    let str_len =
                        cursor.read_u8().map_err(|_| DnsError::InvalidRecord)? as usize;
                    if cursor.pos + str_len > rdata_end {
                        return Err(DnsError::InvalidRecord);
                    }
                    let bytes = cursor
                        .read_bytes(str_len)
                        .map_err(|_| DnsError::InvalidRecord)?;
                    let s = std::str::from_utf8(bytes).map_err(|_| DnsError::InvalidRecord)?;
                    text.push_str(s);
                }
                RData::TXT(text)
            }
            TYPE_SOA => {
                let mname = parse_name_from_cursor(cursor)?;
                let rname = parse_name_from_cursor(cursor)?;
                let serial = cursor.read_u32().map_err(|_| DnsError::InvalidRecord)?;
                let refresh = cursor.read_u32().map_err(|_| DnsError::InvalidRecord)?;
                let retry = cursor.read_u32().map_err(|_| DnsError::InvalidRecord)?;
                let expire = cursor.read_u32().map_err(|_| DnsError::InvalidRecord)?;
                let minimum = cursor.read_u32().map_err(|_| DnsError::InvalidRecord)?;
                RData::SOA {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                }
            }
            TYPE_SRV => {
                let priority = cursor.read_u16().map_err(|_| DnsError::InvalidRecord)?;
                let weight = cursor.read_u16().map_err(|_| DnsError::InvalidRecord)?;
                let port = cursor.read_u16().map_err(|_| DnsError::InvalidRecord)?;
                let target = parse_name_from_cursor(cursor)?;
                RData::SRV {
                    priority,
                    weight,
                    port,
                    target,
                }
            }
            TYPE_CAA => {
                if rdlength < 2 {
                    return Err(DnsError::InvalidRecord);
                }
                let flags = cursor.read_u8().map_err(|_| DnsError::InvalidRecord)?;
                let tag_len =
                    cursor.read_u8().map_err(|_| DnsError::InvalidRecord)? as usize;
                if cursor.pos + tag_len > rdata_end {
                    return Err(DnsError::InvalidRecord);
                }
                let tag_bytes = cursor
                    .read_bytes(tag_len)
                    .map_err(|_| DnsError::InvalidRecord)?;
                let tag =
                    std::str::from_utf8(tag_bytes).map_err(|_| DnsError::InvalidRecord)?;
                let value_len = rdata_end - cursor.pos;
                let value_bytes = cursor
                    .read_bytes(value_len)
                    .map_err(|_| DnsError::InvalidRecord)?;
                let value =
                    std::str::from_utf8(value_bytes).map_err(|_| DnsError::InvalidRecord)?;
                RData::CAA {
                    flags,
                    tag: tag.to_string(),
                    value: value.to_string(),
                }
            }
            TYPE_OPT => {
                // OPT pseudo-record: class field = UDP payload size, name = "."
                // Skip rdata (options we don't process)
                cursor.pos = rdata_end;
                RData::OPT { udp_size: class }
            }
            _ => {
                let bytes = cursor
                    .read_bytes(rdlength)
                    .map_err(|_| DnsError::InvalidRecord)?;
                RData::Unknown(bytes.to_vec())
            }
        };

        // Ensure cursor is at rdata_end (some parsers may under-read)
        if cursor.pos != rdata_end {
            // For name-containing records the cursor may have advanced past rdata_end
            // due to compression. But it should never be before.
            if cursor.pos < rdata_end {
                cursor.pos = rdata_end;
            }
        }

        Ok(Record {
            name,
            rtype,
            class,
            ttl,
            rdata,
        })
    }

    fn serialize(&self, buf: &mut Vec<u8>, compression: &mut CompressionMap) {
        // OPT is special: name is root ".", class is UDP size, TTL encodes extended rcode/flags
        if self.rtype == TYPE_OPT {
            buf.push(0); // root name
            buf.extend_from_slice(&self.rtype.to_be_bytes());
            // class = udp size
            if let RData::OPT { udp_size } = &self.rdata {
                buf.extend_from_slice(&udp_size.to_be_bytes());
            } else {
                buf.extend_from_slice(&self.class.to_be_bytes());
            }
            buf.extend_from_slice(&self.ttl.to_be_bytes()); // extended rcode + flags
            buf.extend_from_slice(&0u16.to_be_bytes()); // rdlength = 0 (no options)
            return;
        }

        write_name(buf, &self.name, compression);
        buf.extend_from_slice(&self.rtype.to_be_bytes());
        buf.extend_from_slice(&self.class.to_be_bytes());
        buf.extend_from_slice(&self.ttl.to_be_bytes());

        // Placeholder for rdlength
        let rdlength_pos = buf.len();
        buf.extend_from_slice(&0u16.to_be_bytes());

        let rdata_start = buf.len();

        match &self.rdata {
            RData::A(ip) => {
                buf.extend_from_slice(ip);
            }
            RData::AAAA(ip) => {
                buf.extend_from_slice(ip);
            }
            RData::CNAME(name) => {
                write_name(buf, name, compression);
            }
            RData::NS(name) => {
                write_name(buf, name, compression);
            }
            RData::MX {
                preference,
                exchange,
            } => {
                buf.extend_from_slice(&preference.to_be_bytes());
                write_name(buf, exchange, compression);
            }
            RData::TXT(text) => {
                // Split into 255-byte chunks
                let bytes = text.as_bytes();
                if bytes.is_empty() {
                    // Empty TXT: single zero-length character string
                    buf.push(0);
                } else {
                    let mut offset = 0;
                    while offset < bytes.len() {
                        let chunk_len = std::cmp::min(255, bytes.len() - offset);
                        buf.push(chunk_len as u8);
                        buf.extend_from_slice(&bytes[offset..offset + chunk_len]);
                        offset += chunk_len;
                    }
                }
            }
            RData::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                write_name(buf, mname, compression);
                write_name(buf, rname, compression);
                buf.extend_from_slice(&serial.to_be_bytes());
                buf.extend_from_slice(&refresh.to_be_bytes());
                buf.extend_from_slice(&retry.to_be_bytes());
                buf.extend_from_slice(&expire.to_be_bytes());
                buf.extend_from_slice(&minimum.to_be_bytes());
            }
            RData::SRV {
                priority,
                weight,
                port,
                target,
            } => {
                buf.extend_from_slice(&priority.to_be_bytes());
                buf.extend_from_slice(&weight.to_be_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
                write_name(buf, target, compression);
            }
            RData::CAA { flags, tag, value } => {
                buf.push(*flags);
                buf.push(tag.len() as u8);
                buf.extend_from_slice(tag.as_bytes());
                buf.extend_from_slice(value.as_bytes());
            }
            RData::OPT { .. } => {
                // Handled above, should not reach here
            }
            RData::Unknown(data) => {
                buf.extend_from_slice(data);
            }
        }

        // Patch rdlength
        let rdlength = (buf.len() - rdata_start) as u16;
        buf[rdlength_pos] = (rdlength >> 8) as u8;
        buf[rdlength_pos + 1] = (rdlength & 0xFF) as u8;
    }
}

// ---------------------------------------------------------------------------
// Name compression for serialization
// ---------------------------------------------------------------------------

type CompressionMap = HashMap<String, u16>;

/// Write a DNS name with compression. The `compression` map tracks
/// previously written name suffixes and their offsets.
fn write_name(buf: &mut Vec<u8>, name: &str, compression: &mut CompressionMap) {
    // Strip trailing dot for processing, we'll handle it
    let name = if name.ends_with('.') {
        &name[..name.len() - 1]
    } else {
        name
    };

    if name.is_empty() {
        // Root name
        buf.push(0);
        return;
    }

    let labels: Vec<&str> = name.split('.').collect();

    for i in 0..labels.len() {
        // Check if the suffix from this label onwards has been seen
        let suffix = labels[i..].join(".");
        let suffix_key = suffix.to_ascii_lowercase();

        if let Some(&offset) = compression.get(&suffix_key) {
            // Emit a compression pointer
            let pointer = 0xC000 | offset;
            buf.extend_from_slice(&(pointer as u16).to_be_bytes());
            return;
        }

        // Record this suffix's offset (only if it fits in 14 bits)
        let current_offset = buf.len();
        if current_offset < 0x3FFF {
            compression.insert(suffix_key, current_offset as u16);
        }

        // Write the label
        let label = labels[i].as_bytes();
        buf.push(label.len() as u8);
        buf.extend_from_slice(label);
    }

    // Null terminator
    buf.push(0);
}

// ---------------------------------------------------------------------------
// Message implementation
// ---------------------------------------------------------------------------

impl Message {
    /// Parse a DNS message from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Message, DnsError> {
        if data.len() < 12 {
            return Err(DnsError::TooShort);
        }

        let mut cursor = Cursor::new(data);
        let header = Header::parse(&mut cursor)?;

        let mut questions = Vec::with_capacity(header.qdcount as usize);
        for _ in 0..header.qdcount {
            questions.push(Question::parse(&mut cursor)?);
        }

        let mut answers = Vec::with_capacity(header.ancount as usize);
        for _ in 0..header.ancount {
            answers.push(Record::parse(&mut cursor)?);
        }

        let mut authority = Vec::with_capacity(header.nscount as usize);
        for _ in 0..header.nscount {
            authority.push(Record::parse(&mut cursor)?);
        }

        let mut additional = Vec::with_capacity(header.arcount as usize);
        for _ in 0..header.arcount {
            additional.push(Record::parse(&mut cursor)?);
        }

        Ok(Message {
            header,
            questions,
            answers,
            authority,
            additional,
        })
    }

    /// Serialize this message to wire format.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);
        let mut compression = CompressionMap::new();

        // Update header counts to match actual section lengths
        let mut header = self.header.clone();
        header.qdcount = self.questions.len() as u16;
        header.ancount = self.answers.len() as u16;
        header.nscount = self.authority.len() as u16;
        header.arcount = self.additional.len() as u16;

        header.serialize(&mut buf);

        for q in &self.questions {
            q.serialize(&mut buf, &mut compression);
        }

        for r in &self.answers {
            r.serialize(&mut buf, &mut compression);
        }

        for r in &self.authority {
            r.serialize(&mut buf, &mut compression);
        }

        for r in &self.additional {
            r.serialize(&mut buf, &mut compression);
        }

        buf
    }

    /// Serialize with a size limit. Returns (bytes, was_truncated).
    /// If the full message exceeds `max_size`, records are dropped from
    /// additional, then authority, then answers until it fits. If still
    /// too large, TC is set and only the header+questions are returned.
    pub fn serialize_with_limit(&self, max_size: usize) -> (Vec<u8>, bool) {
        // Try full serialization first
        let full = self.serialize();
        if full.len() <= max_size {
            return (full, false);
        }

        // Try progressively dropping sections
        let sections: &[(&[Record], &[Record], &[Record])] = &[
            (&self.answers, &self.authority, &[]),          // drop additional
            (&self.answers, &[], &[]),                      // drop authority too
            (&[], &[], &[]),                                // drop answers too
        ];

        for &(answers, authority, additional) in sections {
            let mut msg = self.clone();
            msg.answers = answers.to_vec();
            msg.authority = authority.to_vec();
            msg.additional = additional.to_vec();
            msg.header.tc = true;
            let bytes = msg.serialize();
            if bytes.len() <= max_size {
                return (bytes, true);
            }
        }

        // Last resort: header + questions only, TC=1
        let mut msg = self.clone();
        msg.answers.clear();
        msg.authority.clear();
        msg.additional.clear();
        msg.header.tc = true;
        let bytes = msg.serialize();
        (bytes, true)
    }

    /// Create a response skeleton from a query. Copies the ID, sets QR=1, AA=1,
    /// copies RD from the query, and copies the question section.
    pub fn new_response(query: &Message) -> Message {
        Message {
            header: Header {
                id: query.header.id,
                qr: true,
                opcode: query.header.opcode,
                aa: true,
                tc: false,
                rd: query.header.rd,
                ra: false,
                rcode: RCODE_NOERROR,
                qdcount: query.questions.len() as u16,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: query.questions.clone(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }

    /// Set the response code.
    pub fn set_rcode(&mut self, rcode: u8) {
        self.header.rcode = rcode;
    }

    /// Check if the query contains an EDNS0 OPT record.
    pub fn has_edns(&self) -> bool {
        self.additional.iter().any(|r| r.rtype == TYPE_OPT)
    }

    /// Get the EDNS0 UDP payload size from the query, if present.
    pub fn edns_udp_size(&self) -> Option<u16> {
        self.additional.iter().find_map(|r| {
            if r.rtype == TYPE_OPT {
                if let RData::OPT { udp_size } = &r.rdata {
                    Some(*udp_size)
                } else {
                    Some(r.class)
                }
            } else {
                None
            }
        })
    }

    /// Add an EDNS0 OPT record to the additional section advertising the given
    /// UDP payload size.
    pub fn add_edns(&mut self, udp_size: u16) {
        self.additional.push(Record {
            name: ".".to_string(),
            rtype: TYPE_OPT,
            class: udp_size,
            ttl: 0,
            rdata: RData::OPT { udp_size },
        });
    }
}

// ---------------------------------------------------------------------------
// Display implementations for debugging
// ---------------------------------------------------------------------------

impl fmt::Display for RData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RData::A(ip) => write!(f, "{}", Ipv4Addr::from(*ip)),
            RData::AAAA(ip) => write!(f, "{}", Ipv6Addr::from(*ip)),
            RData::CNAME(name) => write!(f, "{name}"),
            RData::NS(name) => write!(f, "{name}"),
            RData::MX {
                preference,
                exchange,
            } => write!(f, "{preference} {exchange}"),
            RData::TXT(text) => write!(f, "\"{text}\""),
            RData::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => write!(
                f,
                "{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
            ),
            RData::SRV {
                priority,
                weight,
                port,
                target,
            } => write!(f, "{priority} {weight} {port} {target}"),
            RData::CAA { flags, tag, value } => write!(f, "{flags} {tag} \"{value}\""),
            RData::OPT { udp_size } => write!(f, "OPT udp_size={udp_size}"),
            RData::Unknown(data) => write!(f, "<unknown {} bytes>", data.len()),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNS query packet for "example.com" A record.
    fn build_query_packet(name: &str, qtype: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        // Header
        buf.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
        buf.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        // Question: name
        let name = if name.ends_with('.') {
            &name[..name.len() - 1]
        } else {
            name
        };
        for label in name.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // null terminator

        // QTYPE, QCLASS
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&CLASS_IN.to_be_bytes());
        buf
    }

    #[test]
    fn test_parse_simple_query() {
        let packet = build_query_packet("example.com", TYPE_A);
        let msg = Message::parse(&packet).unwrap();
        assert_eq!(msg.header.id, 0x1234);
        assert!(!msg.header.qr);
        assert!(msg.header.rd);
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].name, "example.com.");
        assert_eq!(msg.questions[0].qtype, TYPE_A);
        assert_eq!(msg.questions[0].qclass, CLASS_IN);
    }

    #[test]
    fn test_roundtrip_response() {
        let query_pkt = build_query_packet("golfsetridak.is", TYPE_A);
        let query = Message::parse(&query_pkt).unwrap();
        let mut response = Message::new_response(&query);
        response
            .answers
            .push(Record::new_a("golfsetridak.is.", 300, [93, 95, 230, 10]));
        response
            .answers
            .push(Record::new_a("golfsetridak.is.", 300, [93, 95, 230, 11]));

        let bytes = response.serialize();
        let parsed = Message::parse(&bytes).unwrap();

        assert!(parsed.header.qr);
        assert!(parsed.header.aa);
        assert_eq!(parsed.header.rcode, RCODE_NOERROR);
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.questions[0].name, "golfsetridak.is.");
        assert_eq!(parsed.answers.len(), 2);

        if let RData::A(ip) = &parsed.answers[0].rdata {
            assert_eq!(ip, &[93, 95, 230, 10]);
        } else {
            panic!("expected A record");
        }
    }

    #[test]
    fn test_name_compression() {
        let query_pkt = build_query_packet("example.com", TYPE_A);
        let query = Message::parse(&query_pkt).unwrap();
        let mut response = Message::new_response(&query);

        // Add multiple records with the same name — compression should kick in
        for i in 0..5 {
            response
                .answers
                .push(Record::new_a("example.com.", 300, [10, 0, 0, i]));
        }

        let bytes = response.serialize();
        // The serialized form should be significantly smaller than without compression.
        // Without compression, each name would be 13 bytes. With compression, subsequent
        // names are 2 bytes (pointer).
        assert!(bytes.len() < 12 + 17 + 5 * (13 + 10 + 4)); // rough upper bound

        // Verify it parses back correctly
        let parsed = Message::parse(&bytes).unwrap();
        assert_eq!(parsed.answers.len(), 5);
        for (i, rec) in parsed.answers.iter().enumerate() {
            assert_eq!(rec.name, "example.com.");
            if let RData::A(ip) = &rec.rdata {
                assert_eq!(ip[3], i as u8);
            }
        }
    }

    #[test]
    fn test_compression_pointer_parsing() {
        // Build a packet with a compression pointer in the answer section
        let mut pkt = Vec::new();
        // Header
        pkt.extend_from_slice(&0xABCDu16.to_be_bytes());
        pkt.extend_from_slice(&0x8400u16.to_be_bytes()); // QR=1, AA=1
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        pkt.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        // Question: "test.example.com."
        let name_offset = pkt.len(); // offset of "test"
        pkt.push(4);
        pkt.extend_from_slice(b"test");
        let example_offset = pkt.len(); // offset of "example"
        pkt.push(7);
        pkt.extend_from_slice(b"example");
        pkt.push(3);
        pkt.extend_from_slice(b"com");
        pkt.push(0);
        pkt.extend_from_slice(&TYPE_A.to_be_bytes());
        pkt.extend_from_slice(&CLASS_IN.to_be_bytes());

        // Answer: name uses pointer to "test.example.com." at name_offset
        let pointer = 0xC000 | name_offset as u16;
        pkt.extend_from_slice(&pointer.to_be_bytes());
        pkt.extend_from_slice(&TYPE_A.to_be_bytes());
        pkt.extend_from_slice(&CLASS_IN.to_be_bytes());
        pkt.extend_from_slice(&300u32.to_be_bytes());
        pkt.extend_from_slice(&4u16.to_be_bytes()); // rdlength
        pkt.extend_from_slice(&[1, 2, 3, 4]);

        let msg = Message::parse(&pkt).unwrap();
        assert_eq!(msg.answers[0].name, "test.example.com.");
        if let RData::A(ip) = &msg.answers[0].rdata {
            assert_eq!(ip, &[1, 2, 3, 4]);
        } else {
            panic!("expected A record");
        }
    }

    #[test]
    fn test_too_short_packet() {
        assert!(Message::parse(&[0; 5]).is_err());
        assert!(Message::parse(&[]).is_err());
    }

    #[test]
    fn test_compression_loop_detection() {
        // Create a packet where a name pointer points to itself
        let mut pkt = vec![0u8; 12]; // header
        pkt[4] = 0; // QDCOUNT = 1
        pkt[5] = 1;
        // Name at offset 12 is a pointer to offset 12 (self-referencing)
        pkt.push(0xC0);
        pkt.push(12);
        // QTYPE and QCLASS
        pkt.extend_from_slice(&TYPE_A.to_be_bytes());
        pkt.extend_from_slice(&CLASS_IN.to_be_bytes());

        let result = Message::parse(&pkt);
        assert!(matches!(result, Err(DnsError::CompressionLoop)));
    }

    #[test]
    fn test_txt_record_roundtrip() {
        let query_pkt = build_query_packet("example.com", TYPE_TXT);
        let query = Message::parse(&query_pkt).unwrap();
        let mut response = Message::new_response(&query);
        response
            .answers
            .push(Record::new_txt("example.com.", 300, "v=spf1 include:_spf.google.com ~all"));

        let bytes = response.serialize();
        let parsed = Message::parse(&bytes).unwrap();
        assert_eq!(parsed.answers.len(), 1);
        if let RData::TXT(text) = &parsed.answers[0].rdata {
            assert_eq!(text, "v=spf1 include:_spf.google.com ~all");
        } else {
            panic!("expected TXT record");
        }
    }

    #[test]
    fn test_soa_record_roundtrip() {
        let query_pkt = build_query_packet("example.com", TYPE_SOA);
        let query = Message::parse(&query_pkt).unwrap();
        let mut response = Message::new_response(&query);
        response.answers.push(Record::new_soa(
            "example.com.",
            3600,
            "ns1.example.com.",
            "admin.example.com.",
            2024010101,
            3600,
            900,
            604800,
            86400,
        ));

        let bytes = response.serialize();
        let parsed = Message::parse(&bytes).unwrap();
        assert_eq!(parsed.answers.len(), 1);
        if let RData::SOA {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } = &parsed.answers[0].rdata
        {
            assert_eq!(mname, "ns1.example.com.");
            assert_eq!(rname, "admin.example.com.");
            assert_eq!(*serial, 2024010101);
            assert_eq!(*refresh, 3600);
            assert_eq!(*retry, 900);
            assert_eq!(*expire, 604800);
            assert_eq!(*minimum, 86400);
        } else {
            panic!("expected SOA record");
        }
    }

    #[test]
    fn test_mx_record_roundtrip() {
        let query_pkt = build_query_packet("example.com", TYPE_MX);
        let query = Message::parse(&query_pkt).unwrap();
        let mut response = Message::new_response(&query);
        response
            .answers
            .push(Record::new_mx("example.com.", 3600, 10, "mail.example.com."));

        let bytes = response.serialize();
        let parsed = Message::parse(&bytes).unwrap();
        if let RData::MX {
            preference,
            exchange,
        } = &parsed.answers[0].rdata
        {
            assert_eq!(*preference, 10);
            assert_eq!(exchange, "mail.example.com.");
        } else {
            panic!("expected MX record");
        }
    }

    #[test]
    fn test_aaaa_record_roundtrip() {
        let query_pkt = build_query_packet("example.com", TYPE_AAAA);
        let query = Message::parse(&query_pkt).unwrap();
        let mut response = Message::new_response(&query);
        let ipv6: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];
        response
            .answers
            .push(Record::new_aaaa("example.com.", 300, ipv6));

        let bytes = response.serialize();
        let parsed = Message::parse(&bytes).unwrap();
        if let RData::AAAA(ip) = &parsed.answers[0].rdata {
            assert_eq!(ip, &ipv6);
        } else {
            panic!("expected AAAA record");
        }
    }

    #[test]
    fn test_cname_record_roundtrip() {
        let query_pkt = build_query_packet("www.example.com", TYPE_CNAME);
        let query = Message::parse(&query_pkt).unwrap();
        let mut response = Message::new_response(&query);
        response.answers.push(Record::new_cname(
            "www.example.com.",
            300,
            "example.com.",
        ));

        let bytes = response.serialize();
        let parsed = Message::parse(&bytes).unwrap();
        if let RData::CNAME(target) = &parsed.answers[0].rdata {
            assert_eq!(target, "example.com.");
        } else {
            panic!("expected CNAME record");
        }
    }

    #[test]
    fn test_ns_record_roundtrip() {
        let query_pkt = build_query_packet("example.com", TYPE_NS);
        let query = Message::parse(&query_pkt).unwrap();
        let mut response = Message::new_response(&query);
        response
            .answers
            .push(Record::new_ns("example.com.", 3600, "ns1.example.com."));
        response
            .answers
            .push(Record::new_ns("example.com.", 3600, "ns2.example.com."));

        let bytes = response.serialize();
        let parsed = Message::parse(&bytes).unwrap();
        assert_eq!(parsed.answers.len(), 2);
        if let RData::NS(name) = &parsed.answers[0].rdata {
            assert_eq!(name, "ns1.example.com.");
        } else {
            panic!("expected NS record");
        }
    }

    #[test]
    fn test_srv_record_roundtrip() {
        let query_pkt = build_query_packet("_sip._tcp.example.com", TYPE_SRV);
        let query = Message::parse(&query_pkt).unwrap();
        let mut response = Message::new_response(&query);
        response.answers.push(Record::new_srv(
            "_sip._tcp.example.com.",
            300,
            10,
            60,
            5060,
            "sipserver.example.com.",
        ));

        let bytes = response.serialize();
        let parsed = Message::parse(&bytes).unwrap();
        if let RData::SRV {
            priority,
            weight,
            port,
            target,
        } = &parsed.answers[0].rdata
        {
            assert_eq!(*priority, 10);
            assert_eq!(*weight, 60);
            assert_eq!(*port, 5060);
            assert_eq!(target, "sipserver.example.com.");
        } else {
            panic!("expected SRV record");
        }
    }

    #[test]
    fn test_caa_record_roundtrip() {
        let query_pkt = build_query_packet("example.com", TYPE_CAA);
        let query = Message::parse(&query_pkt).unwrap();
        let mut response = Message::new_response(&query);
        response.answers.push(Record::new_caa(
            "example.com.",
            3600,
            0,
            "issue",
            "letsencrypt.org",
        ));

        let bytes = response.serialize();
        let parsed = Message::parse(&bytes).unwrap();
        if let RData::CAA { flags, tag, value } = &parsed.answers[0].rdata {
            assert_eq!(*flags, 0);
            assert_eq!(tag, "issue");
            assert_eq!(value, "letsencrypt.org");
        } else {
            panic!("expected CAA record");
        }
    }

    #[test]
    fn test_edns_opt_roundtrip() {
        // Build a query with EDNS0 OPT in additional
        let mut pkt = build_query_packet("example.com", TYPE_A);
        // Fix ARCOUNT to 1
        pkt[10] = 0;
        pkt[11] = 1;
        // OPT record: name = root (0x00), type = 41, class (UDP size) = 4096,
        // TTL = 0 (extended rcode + version + flags), rdlength = 0
        pkt.push(0x00); // root name
        pkt.extend_from_slice(&TYPE_OPT.to_be_bytes());
        pkt.extend_from_slice(&4096u16.to_be_bytes()); // class = UDP payload size
        pkt.extend_from_slice(&0u32.to_be_bytes()); // TTL
        pkt.extend_from_slice(&0u16.to_be_bytes()); // rdlength

        let query = Message::parse(&pkt).unwrap();
        assert!(query.has_edns());
        assert_eq!(query.edns_udp_size(), Some(4096));

        let mut response = Message::new_response(&query);
        response.add_edns(4096);

        let bytes = response.serialize();
        let parsed = Message::parse(&bytes).unwrap();
        assert!(parsed.has_edns());
    }

    #[test]
    fn test_serialize_with_limit_truncation() {
        let query_pkt = build_query_packet("example.com", TYPE_A);
        let query = Message::parse(&query_pkt).unwrap();
        let mut response = Message::new_response(&query);

        // Add many records to exceed 512 bytes
        for i in 0..50u8 {
            response
                .answers
                .push(Record::new_a("example.com.", 300, [10, 0, 0, i]));
        }

        let (bytes, truncated) = response.serialize_with_limit(512);
        assert!(truncated);
        assert!(bytes.len() <= 512);

        // Verify the TC bit is set
        let parsed = Message::parse(&bytes).unwrap();
        assert!(parsed.header.tc);
    }

    #[test]
    fn test_set_rcode() {
        let query_pkt = build_query_packet("example.com", TYPE_A);
        let query = Message::parse(&query_pkt).unwrap();
        let mut response = Message::new_response(&query);
        response.set_rcode(RCODE_NXDOMAIN);
        assert_eq!(response.header.rcode, RCODE_NXDOMAIN);

        let bytes = response.serialize();
        let parsed = Message::parse(&bytes).unwrap();
        assert_eq!(parsed.header.rcode, RCODE_NXDOMAIN);
    }

    #[test]
    fn test_case_insensitive_names() {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0x1234u16.to_be_bytes());
        pkt.extend_from_slice(&0x0100u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());

        // "EXAMPLE.COM" in uppercase
        pkt.push(7);
        pkt.extend_from_slice(b"EXAMPLE");
        pkt.push(3);
        pkt.extend_from_slice(b"COM");
        pkt.push(0);
        pkt.extend_from_slice(&TYPE_A.to_be_bytes());
        pkt.extend_from_slice(&CLASS_IN.to_be_bytes());

        let msg = Message::parse(&pkt).unwrap();
        assert_eq!(msg.questions[0].name, "example.com.");
    }

    #[test]
    fn test_rdata_type_code() {
        assert_eq!(RData::A([0; 4]).type_code(), TYPE_A);
        assert_eq!(RData::AAAA([0; 16]).type_code(), TYPE_AAAA);
        assert_eq!(RData::CNAME("x.".into()).type_code(), TYPE_CNAME);
        assert_eq!(RData::NS("x.".into()).type_code(), TYPE_NS);
        assert_eq!(
            RData::MX {
                preference: 10,
                exchange: "x.".into()
            }
            .type_code(),
            TYPE_MX
        );
        assert_eq!(RData::TXT("x".into()).type_code(), TYPE_TXT);
        assert_eq!(
            RData::SOA {
                mname: "a.".into(),
                rname: "b.".into(),
                serial: 1,
                refresh: 2,
                retry: 3,
                expire: 4,
                minimum: 5,
            }
            .type_code(),
            TYPE_SOA
        );
        assert_eq!(
            RData::SRV {
                priority: 0,
                weight: 0,
                port: 0,
                target: "x.".into()
            }
            .type_code(),
            TYPE_SRV
        );
        assert_eq!(
            RData::CAA {
                flags: 0,
                tag: "issue".into(),
                value: "x".into()
            }
            .type_code(),
            TYPE_CAA
        );
        assert_eq!(RData::OPT { udp_size: 4096 }.type_code(), TYPE_OPT);
        assert_eq!(RData::Unknown(vec![]).type_code(), 0);
    }

    #[test]
    fn test_long_txt_record() {
        // TXT with > 255 bytes should be split into multiple character strings
        let long_text = "a".repeat(300);
        let query_pkt = build_query_packet("example.com", TYPE_TXT);
        let query = Message::parse(&query_pkt).unwrap();
        let mut response = Message::new_response(&query);
        response
            .answers
            .push(Record::new_txt("example.com.", 300, &long_text));

        let bytes = response.serialize();
        let parsed = Message::parse(&bytes).unwrap();
        if let RData::TXT(text) = &parsed.answers[0].rdata {
            assert_eq!(text, &long_text);
        } else {
            panic!("expected TXT record");
        }
    }

    #[test]
    fn test_normalize_name() {
        assert_eq!(normalize_name("example.com"), "example.com.");
        assert_eq!(normalize_name("example.com."), "example.com.");
        assert_eq!(normalize_name("EXAMPLE.COM"), "example.com.");
    }

    #[test]
    fn test_new_response_copies_query_id() {
        let query_pkt = build_query_packet("test.example.com", TYPE_A);
        let query = Message::parse(&query_pkt).unwrap();
        let response = Message::new_response(&query);
        assert_eq!(response.header.id, query.header.id);
        assert!(response.header.qr);
        assert!(response.header.aa);
        assert_eq!(response.header.rd, query.header.rd);
        assert_eq!(response.questions.len(), query.questions.len());
        assert_eq!(response.questions[0].name, query.questions[0].name);
    }
}
