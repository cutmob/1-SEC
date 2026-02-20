//! Raw packet capture and protocol parsing.
//!
//! Captures packets from a network interface using libpcap, parses protocol headers,
//! detects anomalies, and publishes structured events to the NATS bus for the Go
//! modules to consume.

use crate::events::PacketEvent;
use crate::nats_bridge::EventPublisher;
use anyhow::{Context, Result};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap::Capture;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Anomaly detection thresholds
const SUSPICIOUS_PORT_SCAN_THRESHOLD: usize = 20;
const MAX_PAYLOAD_PREVIEW: usize = 256;
const STATS_INTERVAL_SECS: u64 = 60;

/// Per-source tracking for anomaly detection.
struct SourceTracker {
    /// Ports contacted by each source IP in the current window.
    port_scans: std::collections::HashMap<String, std::collections::HashSet<u16>>,
    /// Packet counts per source IP.
    packet_counts: std::collections::HashMap<String, u64>,
    /// Last stats reset time.
    last_reset: std::time::Instant,
}

impl SourceTracker {
    fn new() -> Self {
        Self {
            port_scans: std::collections::HashMap::new(),
            packet_counts: std::collections::HashMap::new(),
            last_reset: std::time::Instant::now(),
        }
    }

    fn track(&mut self, src_ip: &str, dst_port: u16) -> Vec<String> {
        let mut anomalies = Vec::new();

        // Reset counters periodically
        if self.last_reset.elapsed().as_secs() > STATS_INTERVAL_SECS {
            self.port_scans.clear();
            self.packet_counts.clear();
            self.last_reset = std::time::Instant::now();
        }

        // Track port scan behavior
        let ports = self.port_scans.entry(src_ip.to_string()).or_default();
        ports.insert(dst_port);
        if ports.len() >= SUSPICIOUS_PORT_SCAN_THRESHOLD {
            anomalies.push(format!(
                "port_scan: {} unique ports contacted from {}",
                ports.len(),
                src_ip
            ));
        }

        // Track packet volume
        let count = self.packet_counts.entry(src_ip.to_string()).or_insert(0);
        *count += 1;

        anomalies
    }
}

/// Main packet capture loop. Runs until an error occurs or the process is killed.
pub async fn capture_loop(interface: &str, publisher: EventPublisher) -> Result<()> {
    info!(interface = %interface, "starting packet capture");

    let mut cap = Capture::from_device(interface)?
        .promisc(true)
        .snaplen(65535)
        .timeout(1000)
        .open()
        .with_context(|| format!("opening capture on {}", interface))?;

    // Set BPF filter to only capture TCP/UDP traffic (skip ARP, ICMP for now)
    if let Err(e) = cap.filter("tcp or udp", true) {
        warn!(error = %e, "failed to set BPF filter, capturing all traffic");
    }

    let mut tracker = SourceTracker::new();
    let mut total_packets: u64 = 0;
    let mut published_events: u64 = 0;
    let stats_start = std::time::Instant::now();

    info!("capture active, processing packets");

    loop {
        let raw = match cap.next_packet() {
            Ok(p) => p,
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                warn!(error = %e, "capture error");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };

        total_packets += 1;

        // Log stats periodically
        if total_packets % 10_000 == 0 {
            let elapsed = stats_start.elapsed().as_secs_f64();
            let pps = total_packets as f64 / elapsed;
            info!(
                total = total_packets,
                published = published_events,
                pps = format!("{:.0}", pps),
                "capture stats"
            );
        }

        // Parse the packet
        let parsed = match SlicedPacket::from_ethernet(raw.data) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let (src_ip, dst_ip) = match &parsed.net {
            Some(NetSlice::Ipv4(ipv4)) => {
                let h = ipv4.header();
                (
                    format!(
                        "{}.{}.{}.{}",
                        h.source()[0],
                        h.source()[1],
                        h.source()[2],
                        h.source()[3]
                    ),
                    format!(
                        "{}.{}.{}.{}",
                        h.destination()[0],
                        h.destination()[1],
                        h.destination()[2],
                        h.destination()[3]
                    ),
                )
            }
            Some(NetSlice::Ipv6(ipv6)) => {
                let h = ipv6.header();
                (
                    format!("{:?}", h.source()),
                    format!("{:?}", h.destination()),
                )
            }
            _ => continue,
        };

        let (protocol, src_port, dst_port, flags) = match &parsed.transport {
            Some(TransportSlice::Tcp(tcp)) => {
                let h = tcp.to_header();
                let mut flags = Vec::new();
                if h.syn {
                    flags.push("SYN".to_string());
                }
                if h.ack {
                    flags.push("ACK".to_string());
                }
                if h.fin {
                    flags.push("FIN".to_string());
                }
                if h.rst {
                    flags.push("RST".to_string());
                }
                if h.psh {
                    flags.push("PSH".to_string());
                }
                if h.urg {
                    flags.push("URG".to_string());
                }
                // Detect Christmas tree scan (all flags set)
                if h.syn && h.fin && h.urg && h.psh {
                    flags.push("XMAS_SCAN".to_string());
                }
                // Detect NULL scan (no flags)
                if !h.syn && !h.ack && !h.fin && !h.rst && !h.psh && !h.urg {
                    flags.push("NULL_SCAN".to_string());
                }
                ("tcp".to_string(), h.source_port, h.destination_port, flags)
            }
            Some(TransportSlice::Udp(udp)) => {
                let h = udp.to_header();
                (
                    "udp".to_string(),
                    h.source_port,
                    h.destination_port,
                    Vec::new(),
                )
            }
            _ => continue,
        };

        // Track for anomaly detection
        let mut anomalies = tracker.track(&src_ip, dst_port);

        // Add flag-based anomalies
        if flags.contains(&"XMAS_SCAN".to_string()) {
            anomalies.push("xmas_tree_scan: all TCP flags set".to_string());
        }
        if flags.contains(&"NULL_SCAN".to_string()) {
            anomalies.push("null_scan: no TCP flags set".to_string());
        }

        // Extract payload preview (for pattern matching by Go modules)
        let payload_preview = match &parsed.transport {
            Some(TransportSlice::Tcp(tcp)) => {
                let payload = tcp.payload();
                extract_text_preview(payload)
            }
            Some(TransportSlice::Udp(udp)) => {
                let payload = udp.payload();
                extract_text_preview(payload)
            }
            _ => String::new(),
        };

        // Only publish events that have anomalies, interesting flags, or text payloads
        let should_publish = !anomalies.is_empty()
            || !payload_preview.is_empty()
            || flags.iter().any(|f| f.ends_with("_SCAN"));

        if !should_publish {
            continue;
        }

        let event = PacketEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            protocol,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            length: raw.data.len(),
            flags,
            payload_preview,
            anomalies,
        };

        if let Err(e) = publisher.publish_packet_event(&event).await {
            debug!(error = %e, "failed to publish packet event");
        } else {
            published_events += 1;
        }
    }
}

/// Extract a text preview from a payload slice, returning empty string if binary.
fn extract_text_preview(payload: &[u8]) -> String {
    if payload.is_empty() {
        return String::new();
    }
    let len = payload.len().min(MAX_PAYLOAD_PREVIEW);
    if payload[..len]
        .iter()
        .all(|&b| b >= 0x20 && b < 0x7f || b == b'\n' || b == b'\r' || b == b'\t')
    {
        String::from_utf8_lossy(&payload[..len]).to_string()
    } else {
        String::new()
    }
}
