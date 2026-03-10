//! Analytics module — high-performance computation offloaded from Go.
//!
//! Provides:
//! - Shannon entropy calculation (DNS tunneling / DGA detection)
//! - Consonant ratio analysis (DGA detection)
//! - IP threat scoring aggregation
//! - File hashing (blake3)

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

// ─── Shannon Entropy ────────────────────────────────────────────────────────

/// Calculate Shannon entropy of a string. High entropy (>3.5) suggests
/// encoded/encrypted data — used for DNS tunneling and DGA detection.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq: HashMap<u8, f64> = HashMap::new();
    let bytes = s.as_bytes();
    for &b in bytes {
        *freq.entry(b).or_insert(0.0) += 1.0;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0;
    for &count in freq.values() {
        let p = count / len;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Calculate consonant ratio — DGA domains have abnormally high ratios (>0.7).
pub fn consonant_ratio(s: &str) -> f64 {
    let mut consonants = 0u32;
    let mut alpha = 0u32;
    for c in s.bytes() {
        let lower = c.to_ascii_lowercase();
        if lower >= b'a' && lower <= b'z' {
            alpha += 1;
            if !matches!(lower, b'a' | b'e' | b'i' | b'o' | b'u') {
                consonants += 1;
            }
        }
    }
    if alpha == 0 {
        0.0
    } else {
        consonants as f64 / alpha as f64
    }
}

// ─── IP Threat Scoring ──────────────────────────────────────────────────────

/// Per-IP threat score entry.
#[derive(Debug, Clone)]
pub struct IPScore {
    pub score: i32,
    pub modules: HashMap<String, i32>,
    pub last_seen: Instant,
    pub blocked: bool,
}

/// Thread-safe IP threat scoring aggregator.
/// IPs accumulate severity-weighted points across modules.
/// Auto-blocks at threshold (default 50) from 2+ modules.
#[derive(Clone)]
pub struct IPScorer {
    scores: Arc<RwLock<HashMap<String, IPScore>>>,
    block_threshold: i32,
    min_modules: usize,
}

impl IPScorer {
    pub fn new(block_threshold: i32, min_modules: usize) -> Self {
        Self {
            scores: Arc::new(RwLock::new(HashMap::new())),
            block_threshold,
            min_modules,
        }
    }

    /// Record a threat event for an IP. Returns true if the IP is now blocked.
    pub fn record(&self, ip: &str, module: &str, severity_points: i32) -> bool {
        let mut scores = self.scores.write().unwrap_or_else(|e| e.into_inner());
        let entry = scores.entry(ip.to_string()).or_insert_with(|| IPScore {
            score: 0,
            modules: HashMap::new(),
            last_seen: Instant::now(),
            blocked: false,
        });

        entry.score += severity_points;
        *entry.modules.entry(module.to_string()).or_insert(0) += severity_points;
        entry.last_seen = Instant::now();

        if !entry.blocked
            && entry.score >= self.block_threshold
            && entry.modules.len() >= self.min_modules
        {
            entry.blocked = true;
        }

        entry.blocked
    }

    /// Check if an IP is blocked.
    pub fn is_blocked(&self, ip: &str) -> bool {
        self.scores
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(ip)
            .map_or(false, |e| e.blocked)
    }

    /// Get score and module count for an IP.
    pub fn get_score(&self, ip: &str) -> (i32, usize) {
        self.scores
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(ip)
            .map_or((0, 0), |e| (e.score, e.modules.len()))
    }

    /// Get all tracked IPs with their scores (for API exposure).
    pub fn snapshot(&self) -> Vec<(String, i32, usize, bool)> {
        self.scores
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(ip, e)| (ip.clone(), e.score, e.modules.len(), e.blocked))
            .collect()
    }

    /// Remove entries older than max_age.
    pub fn cleanup(&self, max_age: Duration) {
        let mut scores = self.scores.write().unwrap_or_else(|e| e.into_inner());
        scores.retain(|_, e| e.last_seen.elapsed() < max_age);
    }
}

// ─── Rate Limiter ───────────────────────────────────────────────────────────

/// High-performance token bucket rate limiter using atomic-friendly design.
/// Each IP gets its own bucket with configurable rate and burst.
#[derive(Clone)]
pub struct RateLimiter {
    buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
    rate_per_sec: f64,
    burst: u32,
}

#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    request_count: u64,
}

impl RateLimiter {
    pub fn new(requests_per_minute: u32, burst: u32) -> Self {
        Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
            rate_per_sec: requests_per_minute as f64 / 60.0,
            burst,
        }
    }

    /// Check if a request from this IP should be allowed.
    pub fn allow(&self, ip: &str) -> bool {
        let mut buckets = self.buckets.write().unwrap_or_else(|e| e.into_inner());
        let bucket = buckets
            .entry(ip.to_string())
            .or_insert_with(|| TokenBucket {
                tokens: self.burst as f64,
                last_refill: Instant::now(),
                request_count: 0,
            });

        // Refill tokens based on elapsed time
        let elapsed = bucket.last_refill.elapsed().as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate_per_sec).min(self.burst as f64);
        bucket.last_refill = Instant::now();
        bucket.request_count += 1;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Get current request count for an IP.
    pub fn request_count(&self, ip: &str) -> u64 {
        self.buckets
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(ip)
            .map_or(0, |b| b.request_count)
    }

    /// Cleanup stale buckets.
    pub fn cleanup(&self, max_age: Duration) {
        let mut buckets = self.buckets.write().unwrap_or_else(|e| e.into_inner());
        buckets.retain(|_, b| b.last_refill.elapsed() < max_age);
    }
}

// ─── C2 Beacon Jitter Analyzer ──────────────────────────────────────────────

/// IP pair key for tracking connections between two endpoints.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct IPPair {
    pub src: String,
    pub dst: String,
}

impl IPPair {
    pub fn new(src: &str, dst: &str) -> Self {
        Self {
            src: src.to_string(),
            dst: dst.to_string(),
        }
    }
}

/// Result of C2 beacon jitter analysis.
#[derive(Debug, Clone)]
pub struct BeaconResult {
    pub is_beaconing: bool,
    pub cv: f64,
    pub sample_count: usize,
    pub avg_interval_secs: f64,
}

/// Tracks SYN packet timestamps per IP pair and computes the Coefficient of
/// Variation (CV) of connection intervals. A low CV (<0.1) indicates extreme
/// regularity — a hallmark of C2 heartbeat beacons.
///
/// Design:
/// - Circular buffer of last `max_samples` SYN timestamps per IP pair
/// - Computes CV = stddev / mean of inter-arrival intervals
/// - Flags as BEACONING if CV < threshold and avg interval is in [5s, 1h]
#[derive(Clone)]
pub struct BeaconJitterAnalyzer {
    connections: Arc<RwLock<HashMap<IPPair, Vec<Instant>>>>,
    max_samples: usize,
    cv_threshold: f64,
    min_samples: usize,
}

impl BeaconJitterAnalyzer {
    pub fn new(max_samples: usize, cv_threshold: f64, min_samples: usize) -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            max_samples,
            cv_threshold,
            min_samples,
        }
    }

    /// Record a SYN packet timestamp for an IP pair and check for beaconing.
    pub fn record_syn(&self, src: &str, dst: &str) -> BeaconResult {
        let pair = IPPair::new(src, dst);
        let now = Instant::now();
        let mut conns = self.connections.write().unwrap_or_else(|e| e.into_inner());

        let timestamps = conns.entry(pair).or_insert_with(Vec::new);
        timestamps.push(now);

        // Keep only last max_samples
        if timestamps.len() > self.max_samples {
            let drain_count = timestamps.len() - self.max_samples;
            timestamps.drain(..drain_count);
        }

        if timestamps.len() < self.min_samples {
            return BeaconResult {
                is_beaconing: false,
                cv: 0.0,
                sample_count: timestamps.len(),
                avg_interval_secs: 0.0,
            };
        }

        // Calculate inter-arrival intervals
        let intervals: Vec<f64> = timestamps
            .windows(2)
            .map(|w| w[1].duration_since(w[0]).as_secs_f64())
            .collect();

        if intervals.is_empty() {
            return BeaconResult {
                is_beaconing: false,
                cv: 0.0,
                sample_count: timestamps.len(),
                avg_interval_secs: 0.0,
            };
        }

        let n = intervals.len() as f64;
        let mean = intervals.iter().sum::<f64>() / n;

        if mean <= 0.0 {
            return BeaconResult {
                is_beaconing: false,
                cv: 0.0,
                sample_count: timestamps.len(),
                avg_interval_secs: 0.0,
            };
        }

        let variance = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
        let stddev = variance.sqrt();
        let cv = stddev / mean;

        // Beaconing: CV < threshold AND average interval between 5s and 1h
        let is_beaconing = cv < self.cv_threshold && mean >= 5.0 && mean <= 3600.0;

        BeaconResult {
            is_beaconing,
            cv,
            sample_count: timestamps.len(),
            avg_interval_secs: mean,
        }
    }

    /// Remove entries older than max_age.
    pub fn cleanup(&self, max_age: Duration) {
        let mut conns = self.connections.write().unwrap_or_else(|e| e.into_inner());
        conns.retain(|_, timestamps| {
            if let Some(last) = timestamps.last() {
                last.elapsed() < max_age
            } else {
                false
            }
        });
    }

    /// Get the number of tracked IP pairs.
    pub fn tracked_pairs(&self) -> usize {
        self.connections
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }
}

// ─── File Hashing ───────────────────────────────────────────────────────────

/// Compute blake3 hash of a byte slice. ~3-5x faster than SHA-256.
pub fn blake3_hash(data: &[u8]) -> String {
    let hash = blake3::hash(data);
    hash.to_hex().to_string()
}

/// Compute blake3 hash of a file by path.
pub fn blake3_hash_file(path: &str) -> Result<String, std::io::Error> {
    let data = std::fs::read(path)?;
    Ok(blake3_hash(&data))
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_low() {
        // Repeated character = low entropy
        let e = shannon_entropy("aaaaaaaaaa");
        assert!(e < 0.1, "expected low entropy, got {}", e);
    }

    #[test]
    fn test_shannon_entropy_high() {
        // Random-looking string = high entropy
        let e = shannon_entropy("a8f3k2m9x1q7w4e6");
        assert!(e > 3.0, "expected high entropy, got {}", e);
    }

    #[test]
    fn test_shannon_entropy_empty() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn test_consonant_ratio_normal() {
        let r = consonant_ratio("google");
        assert!(r < 0.7, "expected normal ratio, got {}", r);
    }

    #[test]
    fn test_consonant_ratio_dga() {
        // DGA-like domain with mostly consonants
        let r = consonant_ratio("xkrwmtpnbvs");
        assert!(r > 0.8, "expected high ratio, got {}", r);
    }

    #[test]
    fn test_ip_scorer_basic() {
        let scorer = IPScorer::new(50, 2);
        assert!(!scorer.record("1.2.3.4", "network", 10));
        assert!(!scorer.record("1.2.3.4", "network", 10));
        // Still only 1 module, shouldn't block even at 50+
        assert!(!scorer.record("1.2.3.4", "network", 30));
        // Second module pushes it over
        assert!(scorer.record("1.2.3.4", "injection", 10));
        assert!(scorer.is_blocked("1.2.3.4"));
    }

    #[test]
    fn test_ip_scorer_below_threshold() {
        let scorer = IPScorer::new(50, 2);
        scorer.record("5.6.7.8", "network", 10);
        scorer.record("5.6.7.8", "injection", 10);
        assert!(!scorer.is_blocked("5.6.7.8"));
    }

    #[test]
    fn test_rate_limiter_allows() {
        let rl = RateLimiter::new(600, 10); // 10/sec, burst 10
        for _ in 0..10 {
            assert!(rl.allow("1.2.3.4"));
        }
        // 11th should be denied (burst exhausted)
        assert!(!rl.allow("1.2.3.4"));
    }

    #[test]
    fn test_rate_limiter_different_ips() {
        let rl = RateLimiter::new(60, 5);
        for _ in 0..5 {
            assert!(rl.allow("1.1.1.1"));
            assert!(rl.allow("2.2.2.2"));
        }
        assert!(!rl.allow("1.1.1.1"));
        assert!(!rl.allow("2.2.2.2"));
    }

    #[test]
    fn test_blake3_hash() {
        let hash = blake3_hash(b"hello world");
        assert_eq!(hash.len(), 64); // 32 bytes = 64 hex chars
                                    // blake3 is deterministic
        assert_eq!(hash, blake3_hash(b"hello world"));
        // Different input = different hash
        assert_ne!(hash, blake3_hash(b"hello world!"));
    }

    #[test]
    fn test_beacon_jitter_insufficient_samples() {
        let analyzer = BeaconJitterAnalyzer::new(50, 0.1, 8);
        // Only 3 samples — should not flag
        for _ in 0..3 {
            let result = analyzer.record_syn("10.0.0.1", "192.168.1.100");
            assert!(!result.is_beaconing);
        }
        assert_eq!(analyzer.tracked_pairs(), 1);
    }

    #[test]
    fn test_beacon_jitter_regular_intervals() {
        let analyzer = BeaconJitterAnalyzer::new(50, 0.1, 4);
        // Simulate perfectly regular intervals by recording timestamps
        // Since we can't control time in unit tests, we verify the analyzer
        // correctly tracks samples and returns a result
        for _ in 0..10 {
            let result = analyzer.record_syn("10.0.0.1", "evil.c2.com");
            // With near-zero intervals (sub-ms), these won't be flagged as beaconing
            // because mean interval < 5s threshold
            assert!(!result.is_beaconing || result.avg_interval_secs >= 5.0);
        }
        assert!(analyzer.tracked_pairs() >= 1);
    }

    #[test]
    fn test_beacon_jitter_different_pairs() {
        let analyzer = BeaconJitterAnalyzer::new(50, 0.1, 4);
        analyzer.record_syn("10.0.0.1", "1.2.3.4");
        analyzer.record_syn("10.0.0.2", "5.6.7.8");
        analyzer.record_syn("10.0.0.1", "1.2.3.4");
        assert_eq!(analyzer.tracked_pairs(), 2);
    }

    #[test]
    fn test_beacon_jitter_cleanup() {
        let analyzer = BeaconJitterAnalyzer::new(50, 0.1, 4);
        analyzer.record_syn("10.0.0.1", "1.2.3.4");
        // Cleanup with 0 duration should remove everything
        analyzer.cleanup(Duration::from_secs(0));
        // After cleanup, the pair with a recent timestamp should be gone
        // (since elapsed > 0)
        assert_eq!(analyzer.tracked_pairs(), 0);
    }

    #[test]
    fn test_beacon_jitter_max_samples_cap() {
        let analyzer = BeaconJitterAnalyzer::new(5, 0.1, 3);
        for _ in 0..20 {
            analyzer.record_syn("10.0.0.1", "1.2.3.4");
        }
        // Internal buffer should be capped at 5
        let conns = analyzer.connections.read().unwrap();
        let pair = IPPair::new("10.0.0.1", "1.2.3.4");
        assert_eq!(conns.get(&pair).unwrap().len(), 5);
    }

    #[test]
    fn test_ip_scorer_snapshot() {
        let scorer = IPScorer::new(50, 2);
        scorer.record("1.2.3.4", "network", 10);
        scorer.record("5.6.7.8", "injection", 20);
        let snap = scorer.snapshot();
        assert_eq!(snap.len(), 2);
    }
}
