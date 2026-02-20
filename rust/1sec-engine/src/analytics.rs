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
    if alpha == 0 { 0.0 } else { consonants as f64 / alpha as f64 }
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
        let mut scores = self.scores.write().unwrap();
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
            .unwrap()
            .get(ip)
            .map_or(false, |e| e.blocked)
    }

    /// Get score and module count for an IP.
    pub fn get_score(&self, ip: &str) -> (i32, usize) {
        self.scores
            .read()
            .unwrap()
            .get(ip)
            .map_or((0, 0), |e| (e.score, e.modules.len()))
    }

    /// Get all tracked IPs with their scores (for API exposure).
    pub fn snapshot(&self) -> Vec<(String, i32, usize, bool)> {
        self.scores
            .read()
            .unwrap()
            .iter()
            .map(|(ip, e)| (ip.clone(), e.score, e.modules.len(), e.blocked))
            .collect()
    }

    /// Remove entries older than max_age.
    pub fn cleanup(&self, max_age: Duration) {
        let mut scores = self.scores.write().unwrap();
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
        let mut buckets = self.buckets.write().unwrap();
        let bucket = buckets.entry(ip.to_string()).or_insert_with(|| TokenBucket {
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
            .unwrap()
            .get(ip)
            .map_or(0, |b| b.request_count)
    }

    /// Cleanup stale buckets.
    pub fn cleanup(&self, max_age: Duration) {
        let mut buckets = self.buckets.write().unwrap();
        buckets.retain(|_, b| b.last_refill.elapsed() < max_age);
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
    fn test_ip_scorer_snapshot() {
        let scorer = IPScorer::new(50, 2);
        scorer.record("1.2.3.4", "network", 10);
        scorer.record("5.6.7.8", "injection", 20);
        let snap = scorer.snapshot();
        assert_eq!(snap.len(), 2);
    }
}
