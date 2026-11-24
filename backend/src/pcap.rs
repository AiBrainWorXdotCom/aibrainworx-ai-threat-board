use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use chrono::Utc;
use serde::Serialize;

use crate::a2ui::{build_pcap_a2ui_surface, A2uiSurfacePayload};
use crate::security::strip_invisible_unicode;
use crate::store::ThreatStore;

pub const MAX_PCAP_BYTES: usize = 25 * 1024 * 1024;
const MAX_PACKETS: usize = 250_000;
const MAX_UNIQUE_ENDPOINTS: usize = 5_000;
const MAX_UNIQUE_DOMAINS: usize = 5_000;
const MAX_DNS_POINTER_HOPS: usize = 16;

#[derive(Debug, Clone, Serialize)]
pub struct PcapEndpointStat {
    pub ip: String,
    pub packets: u64,
    pub bytes: u64,
    pub ports: Vec<u16>,
    pub protocols: Vec<String>,
    pub is_flagged: bool,
    pub matched_feeds: Vec<String>,
    pub wireshark_filter: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PcapPortStat {
    pub port: u16,
    pub protocol: String,
    pub service_name: String,
    pub packets: u64,
    pub unique_hosts: usize,
    pub is_high_risk: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PcapHostIndicator {
    pub host: String,
    pub kind: String, // "DNS" | "TLS SNI" | "HTTP Host"
    pub count: u64,
    pub is_flagged: bool,
    pub matched_feeds: Vec<String>,
    pub suspicious_reason: Option<String>,
    pub wireshark_filter: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PcapMaliciousHit {
    pub indicator: String,
    pub indicator_type: String, // "Botnet C2" | "Scanner IP" | "Compromised IP" | "Phishing Domain" | "C2 Hostname"
    pub severity: String,       // "CRITICAL" | "HIGH" | "MEDIUM"
    pub feeds: Vec<String>,
    pub detail: String,
    pub packets: u64,
    pub ports: Vec<u16>,
    pub wireshark_filter: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PcapAnomaly {
    pub kind: String,
    pub severity: String, // "HIGH" | "MEDIUM" | "INFO"
    pub title: String,
    pub detail: String,
    pub wireshark_filter: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PcapAnalysisReport {
    pub filename: String,
    pub format: String, // "PCAP" | "PCAPNG"
    pub file_bytes: usize,
    pub parse_ms: u64,
    pub packets_parsed: u64,
    pub packets_truncated: bool,
    pub total_bytes_observed: u64,
    pub protocol_counts: HashMap<String, u64>,
    pub unique_external_ips: usize,
    pub unique_internal_ips: usize,
    pub unique_domains: usize,
    pub malicious_hits: Vec<PcapMaliciousHit>,
    pub anomalies: Vec<PcapAnomaly>,
    pub top_external_ips: Vec<PcapEndpointStat>,
    pub top_ports: Vec<PcapPortStat>,
    pub observed_hosts: Vec<PcapHostIndicator>,
    pub http_user_agents: Vec<String>,
    pub master_wireshark_filter: String,
    pub ai_prompt_summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub a2ui: Option<A2uiSurfacePayload>,
}

#[derive(Default)]
struct EndpointAccum {
    packets: u64,
    bytes: u64,
    ports: HashSet<u16>,
    protocols: HashSet<&'static str>,
}

#[derive(Default)]
struct PortAccum {
    packets: u64,
    hosts: HashSet<IpAddr>,
    proto: &'static str,
}

#[derive(Default)]
struct HostAccum {
    count: u64,
    kinds: HashSet<&'static str>,
}

#[derive(Default)]
struct ScanAccum {
    distinct_dst_ports: HashSet<u16>,
    syn_count: u64,
    dst_ips: HashSet<IpAddr>,
}

#[derive(Default)]
struct PcapAccumulator {
    packets_parsed: u64,
    packets_truncated: bool,
    total_bytes_observed: u64,
    protocol_counts: HashMap<String, u64>,
    external_ips: HashMap<IpAddr, EndpointAccum>,
    internal_ips: HashSet<IpAddr>,
    ports: HashMap<(u16, &'static str), PortAccum>,
    hosts: HashMap<String, HostAccum>,
    user_agents: HashSet<String>,
    scan_tracker: HashMap<IpAddr, ScanAccum>,
    cleartext_ports_seen: HashMap<u16, u64>,
}

fn read_u16(bytes: &[u8], offset: usize, le: bool) -> Option<u16> {
    let slice = bytes.get(offset..offset + 2)?;
    let arr: [u8; 2] = slice.try_into().ok()?;
    Some(if le {
        u16::from_le_bytes(arr)
    } else {
        u16::from_be_bytes(arr)
    })
}

fn read_u32(bytes: &[u8], offset: usize, le: bool) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    let arr: [u8; 4] = slice.try_into().ok()?;
    Some(if le {
        u32::from_le_bytes(arr)
    } else {
        u32::from_be_bytes(arr)
    })
}

fn is_non_global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || (o[0] == 100 && (64..=127).contains(&o[1])) // CGNAT 100.64.0.0/10
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                || (segs[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                || (segs[0] & 0xffc0) == 0xfe80 // Link-local fe80::/10
        }
    }
}

pub fn port_service_name(port: u16) -> &'static str {
    match port {
        20 | 21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        67 | 68 => "DHCP",
        80 => "HTTP",
        110 => "POP3",
        123 => "NTP",
        135 => "MSRPC",
        137..=139 => "NetBIOS",
        143 => "IMAP",
        161 => "SNMP",
        389 => "LDAP",
        443 => "HTTPS",
        445 => "SMB",
        465 | 587 => "SMTPS",
        993 => "IMAPS",
        1433 => "MSSQL",
        1521 => "Oracle",
        2222 => "SSH-Alt",
        3306 => "MySQL",
        3389 => "RDP",
        4444 => "Metasploit/C2",
        5060 => "SIP",
        5432 => "PostgreSQL",
        5900 => "VNC",
        6379 => "Redis",
        8000 => "HTTP-Alt",
        8080 => "HTTP-Proxy",
        8443 => "HTTPS-Alt",
        9000 => "HTTP/Sonar",
        9200 => "Elasticsearch",
        11434 => "Ollama",
        27017 => "MongoDB",
        _ => "TCP/UDP",
    }
}

fn is_high_risk_port(port: u16) -> bool {
    matches!(
        port,
        21 | 22 | 23 | 135 | 139 | 445 | 1433 | 3306 | 3389 | 4444 | 5900 | 6379 | 9200 | 11434
    )
}

fn escape_wireshark_str(s: &str) -> String {
    strip_invisible_unicode(s)
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

pub fn build_ip_wireshark_filter(ip: &str, port: Option<u16>) -> String {
    let field = if ip.contains(':') {
        "ipv6.addr"
    } else {
        "ip.addr"
    };
    match port {
        Some(p) if p > 0 => format!("{field} == {ip} && (tcp.port == {p} || udp.port == {p})"),
        _ => format!("{field} == {ip}"),
    }
}

pub fn build_host_wireshark_filter(host: &str) -> String {
    let clean = escape_wireshark_str(host);
    format!(
        "dns.qry.name contains \"{clean}\" || tls.handshake.extensions_server_name contains \"{clean}\" || http.host contains \"{clean}\""
    )
}

/// Generates a ready-to-paste Wireshark Display Filter from live Threat Board telemetry.
pub fn build_live_telemetry_wireshark_filter(store: &ThreatStore) -> String {
    let mut v4_ips: Vec<String> = Vec::new();
    let mut seen = HashSet::new();

    for c2 in &store.telemetry.botnet_c2s {
        if let Ok(IpAddr::V4(v4)) = c2.ip_address.trim().parse::<IpAddr>() {
            let s = v4.to_string();
            if seen.insert(s.clone()) {
                v4_ips.push(s);
            }
        }
    }
    for atk in store.telemetry.top_attacking_ips.iter().take(25) {
        if let Ok(IpAddr::V4(v4)) = atk.ip.trim().parse::<IpAddr>() {
            let s = v4.to_string();
            if seen.insert(s.clone()) {
                v4_ips.push(s);
            }
        }
    }

    let mut clauses = Vec::new();
    if !v4_ips.is_empty() {
        clauses.push(format!("ip.addr in {{{}}}", v4_ips.join(" ")));
    }
    let top_ports: Vec<String> = store
        .telemetry
        .top_attacked_ports
        .iter()
        .take(5)
        .map(|p| p.port.to_string())
        .collect();
    if !top_ports.is_empty() {
        clauses.push(format!("tcp.port in {{{}}}", top_ports.join(" ")));
    }

    if clauses.is_empty() {
        "tcp.flags.syn == 1 && tcp.flags.ack == 0".to_string()
    } else {
        clauses.join(" || ")
    }
}

impl PcapAccumulator {
    fn bump_proto(&mut self, name: &str) {
        *self.protocol_counts.entry(name.to_string()).or_insert(0) += 1;
    }

    fn record_endpoint(&mut self, ip: IpAddr, len: u64, port: Option<u16>, proto: &'static str) {
        if is_non_global_ip(ip) {
            if self.internal_ips.len() < MAX_UNIQUE_ENDPOINTS {
                self.internal_ips.insert(ip);
            }
            return;
        }
        if !self.external_ips.contains_key(&ip) && self.external_ips.len() >= MAX_UNIQUE_ENDPOINTS {
            return;
        }
        let entry = self.external_ips.entry(ip).or_default();
        entry.packets += 1;
        entry.bytes = entry.bytes.saturating_add(len);
        if let Some(p) = port {
            if entry.ports.len() < 32 {
                entry.ports.insert(p);
            }
        }
        entry.protocols.insert(proto);
    }

    fn record_host(&mut self, raw_host: &str, kind: &'static str) {
        let cleaned = strip_invisible_unicode(raw_host)
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if cleaned.len() < 3 || cleaned.len() > 253 || !cleaned.contains('.') {
            return;
        }
        if !cleaned
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
        {
            return;
        }
        if !self.hosts.contains_key(&cleaned) && self.hosts.len() >= MAX_UNIQUE_DOMAINS {
            return;
        }
        let entry = self.hosts.entry(cleaned).or_default();
        entry.count += 1;
        entry.kinds.insert(kind);
    }

    fn process_frame(&mut self, link_type: u32, frame: &[u8]) {
        if self.packets_parsed >= MAX_PACKETS as u64 {
            self.packets_truncated = true;
            return;
        }
        self.packets_parsed += 1;
        self.total_bytes_observed = self.total_bytes_observed.saturating_add(frame.len() as u64);

        let (ethertype, l3_payload) = match link_type {
            // Ethernet II + optional 802.1Q / 802.1AD VLAN tags
            1 => {
                if frame.len() < 14 {
                    return;
                }
                let mut offset = 12usize;
                let mut et = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
                offset += 2;
                let mut vlan_hops = 0;
                while (et == 0x8100 || et == 0x88a8 || et == 0x9100) && vlan_hops < 3 {
                    let Some(next_et) = read_u16(frame, offset + 2, false) else {
                        return;
                    };
                    et = next_et;
                    offset += 4;
                    vlan_hops += 1;
                }
                let Some(payload) = frame.get(offset..) else {
                    return;
                };
                (et, payload)
            }
            // BSD Loopback / Null
            0 | 108 => {
                if frame.len() < 4 {
                    return;
                }
                let fam_le = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]);
                let fam_be = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
                let et = if fam_le == 2 || fam_be == 2 {
                    0x0800
                } else if matches!(fam_le, 24 | 28 | 30 | 10) || matches!(fam_be, 24 | 28 | 30 | 10)
                {
                    0x86DD
                } else {
                    return;
                };
                (et, &frame[4..])
            }
            // Raw IP
            101 => {
                let Some(&first) = frame.first() else {
                    return;
                };
                let et = match first >> 4 {
                    4 => 0x0800,
                    6 => 0x86DD,
                    _ => return,
                };
                (et, frame)
            }
            // Linux Cooked SLL v1 (16 bytes)
            113 => {
                let Some(et) = read_u16(frame, 14, false) else {
                    return;
                };
                let Some(payload) = frame.get(16..) else {
                    return;
                };
                (et, payload)
            }
            // Linux Cooked SLL v2 (20 bytes)
            276 => {
                let Some(et) = read_u16(frame, 0, false) else {
                    return;
                };
                let Some(payload) = frame.get(20..) else {
                    return;
                };
                (et, payload)
            }
            _ => return,
        };

        match ethertype {
            0x0800 => self.parse_ipv4(l3_payload, frame.len() as u64),
            0x86DD => self.parse_ipv6(l3_payload, frame.len() as u64),
            0x0806 => self.bump_proto("ARP"),
            _ => self.bump_proto("Other"),
        }
    }

    fn parse_ipv4(&mut self, pkt: &[u8], frame_len: u64) {
        if pkt.len() < 20 {
            return;
        }
        let version = pkt[0] >> 4;
        let ihl = ((pkt[0] & 0x0f) as usize) * 4;
        if version != 4 || ihl < 20 || pkt.len() < ihl {
            return;
        }
        let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        let end = if total_len >= ihl && total_len <= pkt.len() {
            total_len
        } else {
            pkt.len()
        };
        let proto = pkt[9];
        let src = IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]));
        let dst = IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]));
        let l4 = &pkt[ihl..end];
        self.parse_l4(src, dst, proto, l4, frame_len);
    }

    fn parse_ipv6(&mut self, pkt: &[u8], frame_len: u64) {
        if pkt.len() < 40 || (pkt[0] >> 4) != 6 {
            return;
        }
        let mut next_hdr = pkt[6];
        let src_bytes: [u8; 16] = match pkt[8..24].try_into() {
            Ok(a) => a,
            Err(_) => return,
        };
        let dst_bytes: [u8; 16] = match pkt[24..40].try_into() {
            Ok(a) => a,
            Err(_) => return,
        };
        let src = IpAddr::V6(Ipv6Addr::from(src_bytes));
        let dst = IpAddr::V6(Ipv6Addr::from(dst_bytes));

        let mut offset = 40usize;
        let mut ext_hops = 0;
        while matches!(next_hdr, 0 | 43 | 44 | 60) && ext_hops < 6 {
            if next_hdr == 44 {
                // Fragment header is fixed 8 bytes
                let Some(&nh) = pkt.get(offset) else {
                    return;
                };
                next_hdr = nh;
                offset += 8;
            } else {
                let Some(&nh) = pkt.get(offset) else {
                    return;
                };
                let Some(&hdr_ext_len) = pkt.get(offset + 1) else {
                    return;
                };
                next_hdr = nh;
                offset += (hdr_ext_len as usize + 1) * 8;
            }
            ext_hops += 1;
        }
        let Some(l4) = pkt.get(offset..) else {
            return;
        };
        self.parse_l4(src, dst, next_hdr, l4, frame_len);
    }

    fn parse_l4(&mut self, src: IpAddr, dst: IpAddr, proto: u8, l4: &[u8], frame_len: u64) {
        match proto {
            // TCP
            6 => {
                if l4.len() < 20 {
                    return;
                }
                let src_port = u16::from_be_bytes([l4[0], l4[1]]);
                let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
                let data_offset = ((l4[12] >> 4) as usize) * 4;
                if data_offset < 20 || l4.len() < data_offset {
                    return;
                }
                let flags = l4[13];
                let is_syn_only = (flags & 0x02) != 0 && (flags & 0x10) == 0;
                let payload = &l4[data_offset..];

                self.bump_proto("TCP");
                self.record_endpoint(src, frame_len, Some(dst_port), "TCP");
                self.record_endpoint(dst, frame_len, Some(dst_port), "TCP");
                self.record_port(dst_port, "TCP", dst);

                if is_syn_only && self.scan_tracker.len() < 2000 {
                    let scan = self.scan_tracker.entry(src).or_default();
                    scan.syn_count += 1;
                    if scan.distinct_dst_ports.len() < 128 {
                        scan.distinct_dst_ports.insert(dst_port);
                    }
                    if scan.dst_ips.len() < 64 {
                        scan.dst_ips.insert(dst);
                    }
                }

                if matches!(dst_port, 21 | 23) || matches!(src_port, 21 | 23) {
                    let cp = if matches!(dst_port, 21 | 23) {
                        dst_port
                    } else {
                        src_port
                    };
                    *self.cleartext_ports_seen.entry(cp).or_insert(0) += 1;
                }

                if !payload.is_empty() {
                    if let Some(sni) = extract_tls_sni(payload) {
                        self.bump_proto("TLS");
                        self.record_endpoint(dst, 0, Some(dst_port), "TLS");
                        self.record_host(&sni, "TLS SNI");
                    } else if let Some((host, ua)) = extract_http_request(payload) {
                        self.bump_proto("HTTP");
                        self.record_endpoint(dst, 0, Some(dst_port), "HTTP");
                        if dst_port == 80 || dst_port == 8080 || dst_port == 8000 {
                            *self.cleartext_ports_seen.entry(dst_port).or_insert(0) += 1;
                        }
                        if let Some(h) = host {
                            self.record_host(&h, "HTTP Host");
                        }
                        if let Some(u) = ua {
                            if self.user_agents.len() < 20 {
                                self.user_agents.insert(u);
                            }
                        }
                    } else if (dst_port == 53 || src_port == 53) && payload.len() > 14 {
                        // DNS over TCP has a 2-byte length prefix
                        if let Some(qname) = extract_dns_qname(&payload[2..]) {
                            self.bump_proto("DNS");
                            self.record_host(&qname, "DNS");
                        }
                    }
                }
            }
            // UDP
            17 => {
                if l4.len() < 8 {
                    return;
                }
                let src_port = u16::from_be_bytes([l4[0], l4[1]]);
                let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
                let payload = &l4[8..];

                self.bump_proto("UDP");
                self.record_endpoint(src, frame_len, Some(dst_port), "UDP");
                self.record_endpoint(dst, frame_len, Some(dst_port), "UDP");
                self.record_port(dst_port, "UDP", dst);

                if dst_port == 53 || src_port == 53 {
                    self.bump_proto("DNS");
                    if let Some(qname) = extract_dns_qname(payload) {
                        self.record_host(&qname, "DNS");
                    }
                }
            }
            1 | 58 => {
                self.bump_proto("ICMP");
                self.record_endpoint(src, frame_len, None, "ICMP");
                self.record_endpoint(dst, frame_len, None, "ICMP");
            }
            _ => {
                self.bump_proto("Other");
            }
        }
    }

    fn record_port(&mut self, port: u16, proto: &'static str, dst: IpAddr) {
        // Ignore high ephemeral destination ports unless already tracked or standard range
        if port == 0 || (port >= 49152 && self.ports.len() >= 1024) {
            return;
        }
        if !self.ports.contains_key(&(port, proto)) && self.ports.len() >= 2048 {
            return;
        }
        let entry = self
            .ports
            .entry((port, proto))
            .or_insert_with(|| PortAccum {
                packets: 0,
                hosts: HashSet::new(),
                proto,
            });
        entry.packets += 1;
        if entry.hosts.len() < 256 {
            entry.hosts.insert(dst);
        }
    }
}

/// Safely extracts the first DNS query name (QNAME) from a DNS message, preventing
/// infinite compression pointer loops via a strict hop limit and visited offset set.
fn extract_dns_qname(dns: &[u8]) -> Option<String> {
    if dns.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([dns[2], dns[3]]);
    let is_response = (flags & 0x8000) != 0;
    let qdcount = u16::from_be_bytes([dns[4], dns[5]]);
    if qdcount == 0 {
        return None;
    }
    // Parse query question section whether query or response (responses echo the question)
    let _ = is_response;
    let mut offset = 12usize;
    let mut labels: Vec<String> = Vec::new();
    let mut visited = HashSet::new();
    let mut hops = 0usize;

    while offset < dns.len() && labels.len() < 32 {
        let len = dns[offset];
        if len == 0 {
            break;
        }
        if (len & 0xC0) == 0xC0 {
            if hops >= MAX_DNS_POINTER_HOPS || offset + 1 >= dns.len() {
                return None;
            }
            let ptr = (((len & 0x3F) as usize) << 8) | (dns[offset + 1] as usize);
            if ptr >= dns.len() || !visited.insert(ptr) {
                return None;
            }
            offset = ptr;
            hops += 1;
            continue;
        }
        if (len & 0xC0) != 0 {
            return None;
        }
        let llen = len as usize;
        offset += 1;
        let label_bytes = dns.get(offset..offset + llen)?;
        if !label_bytes
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }
        labels.push(String::from_utf8_lossy(label_bytes).to_ascii_lowercase());
        offset += llen;
    }

    if labels.len() >= 2 {
        Some(labels.join("."))
    } else {
        None
    }
}

/// Safely parses a TLS ClientHello record to extract the Server Name Indication (SNI, ext 0x0000).
fn extract_tls_sni(payload: &[u8]) -> Option<String> {
    // TLS record header (5 bytes): ContentType=0x16 (Handshake), Version=0x03 0x00..0x04
    if payload.len() < 43 || payload[0] != 0x16 || payload[1] != 0x03 {
        return None;
    }
    let rec_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    let end = (5 + rec_len).min(payload.len());
    let hs = payload.get(5..end)?;
    // HandshakeType=0x01 (ClientHello)
    if hs.len() < 38 || hs[0] != 0x01 {
        return None;
    }
    // Skip handshake header (4) + client version (2) + random (32) = 38 bytes
    let mut pos = 38usize;
    let sess_id_len = *hs.get(pos)? as usize;
    pos = pos.checked_add(1)?.checked_add(sess_id_len)?;
    let cipher_len = read_u16(hs, pos, false)? as usize;
    pos = pos.checked_add(2)?.checked_add(cipher_len)?;
    let comp_len = *hs.get(pos)? as usize;
    pos = pos.checked_add(1)?.checked_add(comp_len)?;
    let ext_total_len = read_u16(hs, pos, false)? as usize;
    pos = pos.checked_add(2)?;
    let ext_end = pos.checked_add(ext_total_len)?.min(hs.len());

    while pos + 4 <= ext_end {
        let ext_type = read_u16(hs, pos, false)?;
        let ext_len = read_u16(hs, pos + 2, false)? as usize;
        pos += 4;
        let ext_data = hs.get(pos..pos.checked_add(ext_len)?)?;
        if ext_type == 0x0000 {
            // server_name list: list_len (2), name_type (1 == 0x00 host_name), name_len (2), bytes
            if ext_data.len() >= 5 && ext_data[2] == 0x00 {
                let name_len = read_u16(ext_data, 3, false)? as usize;
                let name_bytes = ext_data.get(5..5 + name_len)?;
                let sni = std::str::from_utf8(name_bytes).ok()?.trim();
                if !sni.is_empty() && sni.len() <= 253 {
                    return Some(sni.to_ascii_lowercase());
                }
            }
        }
        pos += ext_len;
    }
    None
}

/// Extracts cleartext HTTP `Host` and `User-Agent` headers from a TCP payload if present.
fn extract_http_request(payload: &[u8]) -> Option<(Option<String>, Option<String>)> {
    const METHODS: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"HEAD ",
        b"PUT ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
        b"CONNECT ",
    ];
    if !METHODS.iter().any(|m| payload.starts_with(m)) {
        return None;
    }
    let slice = &payload[..payload.len().min(2048)];
    let text = std::str::from_utf8(slice).ok()?;
    let mut host: Option<String> = None;
    let mut ua: Option<String> = None;
    for line in text.lines().skip(1).take(24) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            let kl = k.trim().to_ascii_lowercase();
            let val = strip_invisible_unicode(v.trim());
            if kl == "host" && host.is_none() {
                let host_only = val.split(':').next().unwrap_or("").trim();
                if !host_only.is_empty() {
                    host = Some(host_only.to_ascii_lowercase());
                }
            } else if kl == "user-agent" && ua.is_none() && !val.is_empty() {
                let clipped: String = val.chars().take(120).collect();
                ua = Some(clipped);
            }
        }
    }
    Some((host, ua))
}

fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    let len = s.len() as f64;
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }
    let mut ent = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            ent -= p * p.log2();
        }
    }
    ent
}

fn check_dns_tunneling_suspect(domain: &str) -> Option<String> {
    let first_label = domain.split('.').next().unwrap_or("");
    if first_label.len() >= 36 && shannon_entropy(first_label) >= 3.8 {
        return Some(format!(
            "High-entropy long subdomain ({} chars, entropy {:.2}) — possible DNS tunneling/DGA",
            first_label.len(),
            shannon_entropy(first_label)
        ));
    }
    if domain.len() >= 85 {
        return Some(format!(
            "Unusually long DNS query ({} chars) — inspect for DNS exfiltration",
            domain.len()
        ));
    }
    None
}

fn parse_classic_pcap(data: &[u8], acc: &mut PcapAccumulator) -> Result<(), String> {
    if data.len() < 24 {
        return Err("Truncated PCAP global header (<24 bytes)".to_string());
    }
    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let le = match magic {
        0xD4C3B2A1 | 0x4D3CB2A1 => true,  // Little-endian (usec / nsec)
        0xA1B2C3D4 | 0xA1B23C4D => false, // Big-endian (usec / nsec)
        _ => return Err("Unsupported PCAP magic header".to_string()),
    };
    let link_type = read_u32(data, 20, le).ok_or("Invalid PCAP link type")?;
    let mut offset = 24usize;
    while offset + 16 <= data.len() {
        let Some(incl_len) = read_u32(data, offset + 8, le) else {
            break;
        };
        offset += 16;
        let plen = incl_len as usize;
        if plen == 0 || offset.checked_add(plen).is_none_or(|end| end > data.len()) {
            break;
        }
        acc.process_frame(link_type, &data[offset..offset + plen]);
        offset += plen;
        if acc.packets_truncated {
            break;
        }
    }
    Ok(())
}

fn parse_pcapng(data: &[u8], acc: &mut PcapAccumulator) -> Result<(), String> {
    if data.len() < 28 {
        return Err("Truncated PCAPNG Section Header Block".to_string());
    }
    let mut offset = 0usize;
    let mut le = true;
    let mut interfaces: Vec<u32> = Vec::new();

    while offset + 12 <= data.len() {
        // Section Header Block type is 0x0A0D0D0A (palindromic across endianness!)
        let raw_type = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        if raw_type == 0x0A0D0D0A {
            if offset + 28 > data.len() {
                break;
            }
            let bom = u32::from_le_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
            ]);
            le = match bom {
                0x1A2B3C4D => true,
                0x4D3C2B1A => false,
                _ => return Err("Invalid PCAPNG byte-order magic".to_string()),
            };
            interfaces.clear();
        }

        let Some(block_type) = read_u32(data, offset, le) else {
            break;
        };
        let Some(block_len) = read_u32(data, offset + 4, le).map(|v| v as usize) else {
            break;
        };
        if block_len < 12 || !block_len.is_multiple_of(4) || offset + block_len > data.len() {
            break;
        }

        match block_type {
            // Interface Description Block (IDB)
            0x00000001 => {
                if let Some(lt) = read_u16(data, offset + 8, le) {
                    interfaces.push(lt as u32);
                }
            }
            // Enhanced Packet Block (EPB)
            0x00000006 if block_len >= 32 => {
                let iface_id = read_u32(data, offset + 8, le).unwrap_or(0) as usize;
                let cap_len = read_u32(data, offset + 20, le).unwrap_or(0) as usize;
                let lt = interfaces.get(iface_id).copied().unwrap_or(1);
                let pkt_start = offset + 28;
                if let Some(pkt_end) = pkt_start.checked_add(cap_len) {
                    if pkt_end <= offset + block_len - 4 {
                        acc.process_frame(lt, &data[pkt_start..pkt_end]);
                    }
                }
            }
            // Simple Packet Block (SPB)
            0x00000003 if block_len >= 16 => {
                let orig_len = read_u32(data, offset + 8, le).unwrap_or(0) as usize;
                let lt = interfaces.first().copied().unwrap_or(1);
                let pkt_start = offset + 12;
                let avail = (offset + block_len - 4).saturating_sub(pkt_start);
                let cap_len = orig_len.min(avail);
                if cap_len > 0 {
                    acc.process_frame(lt, &data[pkt_start..pkt_start + cap_len]);
                }
            }
            _ => {}
        }

        offset += block_len;
        if acc.packets_truncated {
            break;
        }
    }
    Ok(())
}

/// Parses raw `.pcap` or `.pcapng` bytes strictly in memory and correlates extracted IPs,
/// DNS queries, TLS SNIs, HTTP hosts, and ports against live `ThreatStore` intelligence.
pub fn analyze_pcap_bytes(
    filename: &str,
    data: &[u8],
    store: &ThreatStore,
) -> Result<PcapAnalysisReport, String> {
    let t0 = Instant::now();
    if data.is_empty() {
        return Err("Uploaded capture file is empty".to_string());
    }
    if data.len() > MAX_PCAP_BYTES {
        return Err(format!(
            "Capture exceeds maximum allowed size of {} MB",
            MAX_PCAP_BYTES / (1024 * 1024)
        ));
    }
    if data.len() < 24 {
        return Err("File is too small to be a valid .pcap or .pcapng capture".to_string());
    }

    let mut acc = PcapAccumulator::default();
    let magic_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let format = if magic_be == 0x0A0D0D0A {
        parse_pcapng(data, &mut acc)?;
        "PCAPNG"
    } else if matches!(magic_be, 0xA1B2C3D4 | 0xD4C3B2A1 | 0xA1B23C4D | 0x4D3CB2A1) {
        parse_classic_pcap(data, &mut acc)?;
        "PCAP"
    } else {
        return Err(
            "Unrecognized capture format. Please upload a valid Wireshark .pcap or .pcapng file."
                .to_string(),
        );
    };

    // Build fast threat correlation lookup indices from live ThreatStore
    let mut c2_by_ip: HashMap<String, (&str, u16, &str)> = HashMap::new();
    let mut c2_by_host: HashMap<String, (&str, &str)> = HashMap::new();
    for c2 in &store.telemetry.botnet_c2s {
        c2_by_ip.insert(
            c2.ip_address.trim().to_string(),
            (
                c2.malware.as_str(),
                c2.port,
                c2.country.as_deref().unwrap_or("--"),
            ),
        );
        if let Some(h) = c2.hostname.as_deref() {
            let hl = h.trim().to_ascii_lowercase();
            if !hl.is_empty() {
                c2_by_host.insert(hl, (c2.malware.as_str(), c2.ip_address.as_str()));
            }
        }
    }
    let mut sans_by_ip: HashMap<String, (u64, u64)> = HashMap::new();
    for ip in &store.telemetry.top_attacking_ips {
        sans_by_ip.insert(ip.ip.trim().to_string(), (ip.attacks, ip.count));
    }
    let mut phish_by_domain: HashMap<String, &str> = HashMap::new();
    for ph in &store.telemetry.phishing_urls {
        let dom = ph.domain.trim().to_ascii_lowercase();
        if !dom.is_empty() {
            phish_by_domain.insert(dom, ph.suspected_brand.as_deref().unwrap_or("Phishing"));
        }
    }

    let mut malicious_hits: Vec<PcapMaliciousHit> = Vec::new();
    let mut top_external_ips: Vec<PcapEndpointStat> = Vec::new();

    for (ip, stat) in &acc.external_ips {
        let ip_str = ip.to_string();
        let mut feeds: Vec<String> = Vec::new();
        let mut details: Vec<String> = Vec::new();
        let mut ind_type = "External IP";
        let mut severity = "MEDIUM";

        if let Some((malware, c2_port, country)) = c2_by_ip.get(&ip_str) {
            feeds.push("abuse.ch Feodo Tracker".to_string());
            details.push(format!("Botnet C2 ({malware}, port {c2_port}, {country})"));
            ind_type = "Botnet C2";
            severity = "CRITICAL";
        }
        if let Some((attacks, packets)) = sans_by_ip.get(&ip_str) {
            feeds.push("SANS ISC Top Attackers".to_string());
            details.push(format!("Scanner IP ({attacks} attacks, {packets} packets)"));
            if severity != "CRITICAL" {
                ind_type = "Scanner IP";
                severity = "HIGH";
            }
        }
        if store.compromised_ips_set.contains(&ip_str) {
            feeds.push("Emerging Threats Blocklist".to_string());
            details.push("Present in Emerging Threats compromised-ips blocklist".to_string());
            if severity == "MEDIUM" {
                ind_type = "Compromised IP";
                severity = "HIGH";
            }
        }
        if let Some(pulses) = store.otx_pulses.ip_pulses.get(&ip_str) {
            feeds.push("AlienVault / LevelBlue OTX".to_string());
            details.push(format!("OTX Pulses: {}", pulses.join(" · ")));
            if severity == "MEDIUM" {
                ind_type = "OTX Pulse IP";
                severity = "HIGH";
            }
        }

        let mut ports: Vec<u16> = stat.ports.iter().copied().collect();
        ports.sort_unstable();
        ports.truncate(8);
        let mut protos: Vec<String> = stat.protocols.iter().map(|s| (*s).to_string()).collect();
        protos.sort();
        let preferred_port = c2_by_ip
            .get(&ip_str)
            .map(|(_, c2_port, _)| *c2_port)
            .or_else(|| {
                if ports.len() == 1 {
                    ports.first().copied()
                } else {
                    None
                }
            });
        let ws_filter = build_ip_wireshark_filter(&ip_str, preferred_port);
        let is_flagged = !feeds.is_empty();

        if is_flagged {
            malicious_hits.push(PcapMaliciousHit {
                indicator: ip_str.clone(),
                indicator_type: ind_type.to_string(),
                severity: severity.to_string(),
                feeds: feeds.clone(),
                detail: details.join(" · "),
                packets: stat.packets,
                ports: ports.clone(),
                wireshark_filter: ws_filter.clone(),
            });
        }

        top_external_ips.push(PcapEndpointStat {
            ip: ip_str,
            packets: stat.packets,
            bytes: stat.bytes,
            ports,
            protocols: protos,
            is_flagged,
            matched_feeds: feeds,
            wireshark_filter: ws_filter,
        });
    }

    top_external_ips.sort_by(|a, b| {
        b.is_flagged
            .cmp(&a.is_flagged)
            .then_with(|| b.packets.cmp(&a.packets))
            .then_with(|| b.bytes.cmp(&a.bytes))
    });
    top_external_ips.truncate(20);

    // Correlate DNS, TLS SNI, and HTTP Host domains
    let mut observed_hosts: Vec<PcapHostIndicator> = Vec::new();
    let mut anomalies: Vec<PcapAnomaly> = Vec::new();

    for (host, hstat) in &acc.hosts {
        let mut feeds = Vec::new();
        let mut details = Vec::new();
        let mut hit_type = "Phishing Domain";
        let mut severity = "HIGH";

        if let Some((malware, c2_ip)) = c2_by_host.get(host) {
            feeds.push("abuse.ch Feodo Tracker".to_string());
            details.push(format!("C2 hostname for {malware} ({c2_ip})"));
            hit_type = "C2 Hostname";
            severity = "CRITICAL";
        }
        // Check exact or parent domain against OpenPhish
        let phish_match = phish_by_domain.get(host).copied().or_else(|| {
            host.split_once('.')
                .and_then(|(_, parent)| phish_by_domain.get(parent).copied())
        });
        if let Some(brand) = phish_match {
            feeds.push("OpenPhish".to_string());
            details.push(format!("Active phishing campaign domain ({brand})"));
        }
        let otx_dom_match = store.otx_pulses.domain_pulses.get(host).or_else(|| {
            host.split_once('.')
                .and_then(|(_, parent)| store.otx_pulses.domain_pulses.get(parent))
        });
        if let Some(pulses) = otx_dom_match {
            feeds.push("AlienVault / LevelBlue OTX".to_string());
            details.push(format!("OTX Pulses: {}", pulses.join(" · ")));
            if hit_type == "Phishing Domain" && phish_match.is_none() {
                hit_type = "OTX Pulse Domain";
            }
        }

        let suspicious_reason = check_dns_tunneling_suspect(host);
        let ws_filter = build_host_wireshark_filter(host);
        let is_flagged = !feeds.is_empty();

        if is_flagged {
            malicious_hits.push(PcapMaliciousHit {
                indicator: host.clone(),
                indicator_type: hit_type.to_string(),
                severity: severity.to_string(),
                feeds: feeds.clone(),
                detail: details.join(" · "),
                packets: hstat.count,
                ports: vec![],
                wireshark_filter: ws_filter.clone(),
            });
        }

        if let Some(reason) = &suspicious_reason {
            if anomalies.len() < 8 {
                anomalies.push(PcapAnomaly {
                    kind: "DNS_TUNNELING".to_string(),
                    severity: "MEDIUM".to_string(),
                    title: format!("Suspicious DNS query: {host}"),
                    detail: reason.clone(),
                    wireshark_filter: format!("dns.qry.name == \"{}\"", escape_wireshark_str(host)),
                });
            }
        }

        let kind_label = if hstat.kinds.contains("TLS SNI") {
            "TLS SNI"
        } else if hstat.kinds.contains("HTTP Host") {
            "HTTP Host"
        } else {
            "DNS"
        };

        observed_hosts.push(PcapHostIndicator {
            host: host.clone(),
            kind: kind_label.to_string(),
            count: hstat.count,
            is_flagged,
            matched_feeds: feeds,
            suspicious_reason,
            wireshark_filter: ws_filter,
        });
    }

    observed_hosts.sort_by(|a, b| {
        b.is_flagged
            .cmp(&a.is_flagged)
            .then_with(|| {
                b.suspicious_reason
                    .is_some()
                    .cmp(&a.suspicious_reason.is_some())
            })
            .then_with(|| b.count.cmp(&a.count))
    });
    observed_hosts.truncate(30);

    // Behavioral heuristic: Port scan / SYN sweep detection
    for (src_ip, scan) in &acc.scan_tracker {
        if scan.distinct_dst_ports.len() >= 10 || scan.syn_count >= 20 {
            let ip_s = src_ip.to_string();
            let field = if src_ip.is_ipv6() {
                "ipv6.src"
            } else {
                "ip.src"
            };
            anomalies.push(PcapAnomaly {
                kind: "PORT_SCAN".to_string(),
                severity: "HIGH".to_string(),
                title: format!(
                    "Port scan / SYN sweep detected from {ip_s} ({} distinct ports)",
                    scan.distinct_dst_ports.len()
                ),
                detail: format!(
                    "{} TCP SYN probes across {} destination port(s) and {} target host(s).",
                    scan.syn_count,
                    scan.distinct_dst_ports.len(),
                    scan.dst_ips.len()
                ),
                wireshark_filter: format!(
                    "{field} == {ip_s} && tcp.flags.syn == 1 && tcp.flags.ack == 0"
                ),
            });
        }
    }

    // Behavioral heuristic: Cleartext protocols observed
    for (&cp, &cnt) in &acc.cleartext_ports_seen {
        let svc = port_service_name(cp);
        let sev = if matches!(cp, 21 | 23) {
            "HIGH"
        } else {
            "INFO"
        };
        anomalies.push(PcapAnomaly {
            kind: "CLEARTEXT_PROTOCOL".to_string(),
            severity: sev.to_string(),
            title: format!("Cleartext {svc} traffic observed on port {cp} ({cnt} packets)"),
            detail: format!(
                "Unencrypted {svc} traffic can expose credentials, tokens, or C2 payloads on the wire."
            ),
            wireshark_filter: format!("tcp.port == {cp}"),
        });
    }

    malicious_hits.sort_by(|a, b| {
        let rank = |s: &str| match s {
            "CRITICAL" => 3,
            "HIGH" => 2,
            _ => 1,
        };
        rank(&b.severity)
            .cmp(&rank(&a.severity))
            .then_with(|| b.packets.cmp(&a.packets))
    });
    malicious_hits.truncate(40);
    anomalies.truncate(12);

    let mut top_ports: Vec<PcapPortStat> = acc
        .ports
        .iter()
        .map(|((port, _), pstat)| PcapPortStat {
            port: *port,
            protocol: pstat.proto.to_string(),
            service_name: port_service_name(*port).to_string(),
            packets: pstat.packets,
            unique_hosts: pstat.hosts.len(),
            is_high_risk: is_high_risk_port(*port),
        })
        .collect();
    top_ports.sort_by_key(|a| std::cmp::Reverse(a.packets));
    top_ports.truncate(10);

    // Master Wireshark Display Filter focusing on all malicious hits (or top external talkers)
    let master_wireshark_filter = if !malicious_hits.is_empty() {
        malicious_hits
            .iter()
            .take(8)
            .map(|h| format!("({})", h.wireshark_filter))
            .collect::<Vec<_>>()
            .join(" || ")
    } else if !top_external_ips.is_empty() {
        let v4s: Vec<String> = top_external_ips
            .iter()
            .filter(|e| !e.ip.contains(':'))
            .take(8)
            .map(|e| e.ip.clone())
            .collect();
        if !v4s.is_empty() {
            format!("ip.addr in {{{}}}", v4s.join(" "))
        } else {
            top_external_ips[0].wireshark_filter.clone()
        }
    } else {
        "tcp || udp || dns".to_string()
    };

    let mut user_agents: Vec<String> = acc.user_agents.into_iter().collect();
    user_agents.sort();
    user_agents.truncate(10);

    let clean_filename: String = strip_invisible_unicode(filename.trim())
        .chars()
        .take(120)
        .collect();
    let clean_filename = if clean_filename.is_empty() {
        "capture.pcap".to_string()
    } else {
        clean_filename
    };

    let ai_prompt_summary = format!(
        "Analyze this offline Wireshark {} capture ({}): {} packets parsed, {} external IPs, {} observed DNS/TLS/HTTP hosts, {} live threat-feed IOC matches ({}), and {} behavioral anomalies ({}). Prioritize containment steps and hunting queries.",
        format,
        clean_filename,
        acc.packets_parsed,
        acc.external_ips.len(),
        acc.hosts.len(),
        malicious_hits.len(),
        if malicious_hits.is_empty() {
            "none".to_string()
        } else {
            malicious_hits
                .iter()
                .take(4)
                .map(|h| format!("{} [{}]", h.indicator, h.indicator_type))
                .collect::<Vec<_>>()
                .join(", ")
        },
        anomalies.len(),
        if anomalies.is_empty() {
            "none".to_string()
        } else {
            anomalies
                .iter()
                .take(3)
                .map(|a| a.kind.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        }
    );

    let mut report = PcapAnalysisReport {
        filename: clean_filename,
        format: format.to_string(),
        file_bytes: data.len(),
        parse_ms: t0.elapsed().as_millis() as u64,
        packets_parsed: acc.packets_parsed,
        packets_truncated: acc.packets_truncated,
        total_bytes_observed: acc.total_bytes_observed,
        protocol_counts: acc.protocol_counts,
        unique_external_ips: acc.external_ips.len(),
        unique_internal_ips: acc.internal_ips.len(),
        unique_domains: acc.hosts.len(),
        malicious_hits,
        anomalies,
        top_external_ips,
        top_ports,
        observed_hosts,
        http_user_agents: user_agents,
        master_wireshark_filter,
        ai_prompt_summary,
        a2ui: None,
    };

    report.a2ui = Some(build_pcap_a2ui_surface(&report, Utc::now()));
    Ok(report)
}

/// Builds a genuine, spec-valid binary `.pcap` capture in memory so analysts can test
/// the full binary PCAP parser + live CTI correlation in 1 click without needing a file.
pub fn build_synthetic_sample_pcap(store: &ThreatStore) -> Vec<u8> {
    let mut out = Vec::with_capacity(4096);
    // PCAP global header (little-endian microsecond, Ethernet link type 1)
    out.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());

    let local_ip = Ipv4Addr::new(10, 0, 14, 25);
    // Pick a real live Feodo C2 or Top Attacker IP from the local store if populated,
    // falling back to RFC-5737 documentation IP 198.51.100.42
    let flagged_ip = store
        .telemetry
        .botnet_c2s
        .first()
        .and_then(|c| c.ip_address.parse::<Ipv4Addr>().ok())
        .or_else(|| {
            store
                .telemetry
                .top_attacking_ips
                .first()
                .and_then(|i| i.ip.parse::<Ipv4Addr>().ok())
        })
        .unwrap_or_else(|| Ipv4Addr::new(198, 51, 100, 42));
    let flagged_port = store
        .telemetry
        .botnet_c2s
        .first()
        .map(|c| c.port)
        .unwrap_or(443);

    let benign_ip = Ipv4Addr::new(192, 0, 2, 80);
    let phish_domain = store
        .telemetry
        .phishing_urls
        .first()
        .map(|p| p.domain.clone())
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| "sso-verify-portal.invalid".to_string());

    let mut ts = 1_763_800_000u32;

    // 1. Outbound TLS ClientHello to flagged C2 IP with SNI
    let tls_hello = make_tls_client_hello(&phish_domain);
    for _ in 0..4 {
        append_pcap_packet(
            &mut out,
            ts,
            &make_eth_ipv4_tcp(local_ip, flagged_ip, 51420, flagged_port, 0x18, &tls_hello),
        );
        ts += 1;
    }

    // 2. DNS queries (phishing domain + high-entropy DNS tunneling suspect)
    let dns1 = make_dns_query(&phish_domain);
    append_pcap_packet(
        &mut out,
        ts,
        &make_eth_ipv4_udp(local_ip, Ipv4Addr::new(1, 1, 1, 1), 53110, 53, &dns1),
    );
    ts += 1;
    let dns_tun = make_dns_query("9a8f7e6d5c4b3a291807f6e5d4c3b2a19f8e7d6c.exfil-beacon.invalid");
    append_pcap_packet(
        &mut out,
        ts,
        &make_eth_ipv4_udp(local_ip, Ipv4Addr::new(1, 1, 1, 1), 53111, 53, &dns_tun),
    );
    ts += 1;

    // 3. Cleartext HTTP request on port 80
    let http_req = format!(
        "GET /gate.php HTTP/1.1\r\nHost: {phish_domain}\r\nUser-Agent: Mozilla/5.0 (Sample-SOC-Probe)\r\n\r\n"
    );
    append_pcap_packet(
        &mut out,
        ts,
        &make_eth_ipv4_tcp(local_ip, benign_ip, 52010, 80, 0x18, http_req.as_bytes()),
    );
    ts += 1;

    // 4. Inbound SYN port scan burst from flagged IP across 12 ports
    let scan_ports = [21, 22, 23, 80, 443, 445, 1433, 3306, 3389, 5900, 6379, 8080];
    for p in scan_ports {
        append_pcap_packet(
            &mut out,
            ts,
            &make_eth_ipv4_tcp(flagged_ip, local_ip, 40000 + p, p, 0x02, &[]),
        );
        ts += 1;
    }

    out
}

fn append_pcap_packet(out: &mut Vec<u8>, ts_sec: u32, frame: &[u8]) {
    let len = frame.len() as u32;
    out.extend_from_slice(&ts_sec.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(frame);
}

fn make_eth_ipv4_header(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, l4_len: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(34 + l4_len);
    // Ethernet header (14 bytes)
    buf.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    buf.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    buf.extend_from_slice(&0x0800u16.to_be_bytes());
    // IPv4 header (20 bytes)
    let total_len = (20 + l4_len) as u16;
    buf.push(0x45);
    buf.push(0x00);
    buf.extend_from_slice(&total_len.to_be_bytes());
    buf.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 64, proto, 0x00, 0x00]);
    buf.extend_from_slice(&src.octets());
    buf.extend_from_slice(&dst.octets());
    buf
}

fn make_eth_ipv4_tcp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut buf = make_eth_ipv4_header(src, dst, 6, 20 + payload.len());
    buf.extend_from_slice(&sport.to_be_bytes());
    buf.extend_from_slice(&dport.to_be_bytes());
    buf.extend_from_slice(&1u32.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf.push(0x50); // 20-byte header
    buf.push(flags);
    buf.extend_from_slice(&65535u16.to_be_bytes());
    buf.extend_from_slice(&[0, 0, 0, 0]);
    buf.extend_from_slice(payload);
    buf
}

fn make_eth_ipv4_udp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let mut buf = make_eth_ipv4_header(src, dst, 17, udp_len as usize);
    buf.extend_from_slice(&sport.to_be_bytes());
    buf.extend_from_slice(&dport.to_be_bytes());
    buf.extend_from_slice(&udp_len.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

fn make_dns_query(domain: &str) -> Vec<u8> {
    let mut out = vec![
        0x12, 0x34, // ID
        0x01, 0x00, // Standard query
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in domain.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            continue;
        }
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0x00);
    out.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    out.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    out
}

fn make_tls_client_hello(sni: &str) -> Vec<u8> {
    let sni_bytes = sni.as_bytes();
    let mut sni_ext = Vec::new();
    let list_len = (3 + sni_bytes.len()) as u16;
    sni_ext.extend_from_slice(&0x0000u16.to_be_bytes()); // ext type SNI
    sni_ext.extend_from_slice(&(2 + list_len).to_be_bytes());
    sni_ext.extend_from_slice(&list_len.to_be_bytes());
    sni_ext.push(0x00); // host_name
    sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(sni_bytes);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
    body.extend_from_slice(&[0xAA; 32]); // Random
    body.push(0x00); // Session ID len 0
    body.extend_from_slice(&2u16.to_be_bytes()); // Cipher suites len
    body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    body.push(0x01); // Compression len
    body.push(0x00); // null
    body.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&sni_ext);

    let mut hs = Vec::new();
    hs.push(0x01); // ClientHello
    let bl = body.len();
    hs.push(((bl >> 16) & 0xff) as u8);
    hs.push(((bl >> 8) & 0xff) as u8);
    hs.push((bl & 0xff) as u8);
    hs.extend_from_slice(&body);

    let mut rec = Vec::new();
    rec.push(0x16); // Handshake
    rec.extend_from_slice(&[0x03, 0x01]);
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{BotnetC2, PhishingUrl};

    fn store_with_iocs() -> ThreatStore {
        let mut store = ThreatStore::default();
        store.telemetry.botnet_c2s.push(BotnetC2 {
            ip_address: "198.51.100.42".to_string(),
            port: 443,
            status: "online".to_string(),
            hostname: None,
            as_number: Some(64512),
            as_name: Some("TEST-NET".to_string()),
            country: Some("XX".to_string()),
            malware: "QakBot".to_string(),
            first_seen: None,
            last_online: None,
        });
        store.telemetry.phishing_urls.push(PhishingUrl {
            url: "https://sso-verify-portal.invalid/login".to_string(),
            domain: "sso-verify-portal.invalid".to_string(),
            suspected_brand: Some("Enterprise SSO".to_string()),
        });
        store
    }

    #[test]
    fn parses_synthetic_pcap_and_correlates_c2_phish_dns_sni_and_portscan() {
        let store = store_with_iocs();
        let pcap = build_synthetic_sample_pcap(&store);
        let report = analyze_pcap_bytes("sample.pcap", &pcap, &store).expect("valid pcap");

        assert_eq!(report.format, "PCAP");
        assert!(report.packets_parsed >= 18);
        assert!(report
            .malicious_hits
            .iter()
            .any(|h| h.indicator == "198.51.100.42" && h.indicator_type == "Botnet C2"));
        assert!(report
            .malicious_hits
            .iter()
            .any(|h| h.indicator == "sso-verify-portal.invalid"
                && h.indicator_type == "Phishing Domain"));
        assert!(report
            .observed_hosts
            .iter()
            .any(|h| h.host == "sso-verify-portal.invalid"));
        assert!(report.anomalies.iter().any(|a| a.kind == "PORT_SCAN"));
        assert!(report.anomalies.iter().any(|a| a.kind == "DNS_TUNNELING"));
        assert!(report
            .master_wireshark_filter
            .contains("ip.addr == 198.51.100.42"));
        assert!(report.a2ui.is_some());
    }

    #[test]
    fn parses_minimal_pcapng_enhanced_packet_block() {
        let store = store_with_iocs();
        let frame = make_eth_ipv4_tcp(
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(198, 51, 100, 42),
            55000,
            443,
            0x18,
            &make_tls_client_hello("sso-verify-portal.invalid"),
        );

        let mut ng = Vec::new();
        // SHB (28 bytes)
        ng.extend_from_slice(&0x0A0D0D0Au32.to_le_bytes());
        ng.extend_from_slice(&28u32.to_le_bytes());
        ng.extend_from_slice(&0x1A2B3C4Du32.to_le_bytes());
        ng.extend_from_slice(&1u16.to_le_bytes());
        ng.extend_from_slice(&0u16.to_le_bytes());
        ng.extend_from_slice(&(-1i64).to_le_bytes());
        ng.extend_from_slice(&28u32.to_le_bytes());

        // IDB (20 bytes, Ethernet = 1)
        ng.extend_from_slice(&0x00000001u32.to_le_bytes());
        ng.extend_from_slice(&20u32.to_le_bytes());
        ng.extend_from_slice(&1u16.to_le_bytes());
        ng.extend_from_slice(&0u16.to_le_bytes());
        ng.extend_from_slice(&65535u32.to_le_bytes());
        ng.extend_from_slice(&20u32.to_le_bytes());

        // EPB
        let padded = (frame.len() + 3) & !3;
        let epb_len = (32 + padded) as u32;
        ng.extend_from_slice(&0x00000006u32.to_le_bytes());
        ng.extend_from_slice(&epb_len.to_le_bytes());
        ng.extend_from_slice(&0u32.to_le_bytes()); // iface 0
        ng.extend_from_slice(&0u32.to_le_bytes()); // ts_hi
        ng.extend_from_slice(&0u32.to_le_bytes()); // ts_lo
        ng.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        ng.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        ng.extend_from_slice(&frame);
        ng.resize(ng.len() + (padded - frame.len()), 0);
        ng.extend_from_slice(&epb_len.to_le_bytes());

        let report = analyze_pcap_bytes("wire.pcapng", &ng, &store).expect("valid pcapng");
        assert_eq!(report.format, "PCAPNG");
        assert_eq!(report.packets_parsed, 1);
        assert!(report
            .malicious_hits
            .iter()
            .any(|h| h.indicator == "198.51.100.42"));
        assert!(report
            .observed_hosts
            .iter()
            .any(|h| h.host == "sso-verify-portal.invalid" && h.kind == "TLS SNI"));
    }

    #[test]
    fn dns_compression_pointer_loop_terminates_safely() {
        // Malicious self-referencing DNS compression pointer at offset 12 -> 0xC0 0x0C
        let evil_dns = [
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x0C,
        ];
        assert!(extract_dns_qname(&evil_dns).is_none());
    }

    #[test]
    fn rejects_non_pcap_garbage_and_oversized_inputs() {
        let store = ThreatStore::default();
        assert!(analyze_pcap_bytes("bad.txt", b"not a pcap file at all here!!", &store).is_err());
    }
}
