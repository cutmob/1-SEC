//! NATS JetStream bridge — subscribes to security events from the Go engine,
//! runs them through the Rust pattern matcher, and publishes results back.

use crate::events::SecurityEvent;
use crate::matcher::PatternMatcher;
use crate::normalize;
use anyhow::{Context, Result};
use async_nats::jetstream::{self, consumer::PullConsumer};
use std::sync::Arc;
use tokio::sync::Notify;
use tracing::{debug, error, info, warn};

/// Bridge between NATS JetStream and the Rust pattern matcher.
pub struct NatsBridge {
    client: async_nats::Client,
    jetstream: jetstream::Context,
    matcher: Arc<PatternMatcher>,
    shutdown: Arc<Notify>,
    /// Maximum events to buffer before backpressure.
    buffer_size: usize,
}

/// Handle for publishing events from the packet capture thread.
#[derive(Clone)]
pub struct EventPublisher {
    jetstream: jetstream::Context,
}

impl EventPublisher {
    /// Publish a raw packet event to the NATS bus.
    pub async fn publish_packet_event(&self, event: &crate::events::PacketEvent) -> Result<()> {
        let subject = format!("sec.events.packet_capture.{}", event.protocol);
        let payload = serde_json::to_vec(event)?;
        self.jetstream
            .publish(subject, payload.into())
            .await?
            .await?;
        Ok(())
    }
}

impl NatsBridge {
    /// Connect to NATS and start consuming security events.
    pub async fn connect(
        url: &str,
        matcher: PatternMatcher,
        buffer_size: usize,
        workers: usize,
    ) -> Result<Self> {
        info!(url = %url, buffer_size = buffer_size, workers = workers, "connecting to NATS");

        let client = async_nats::connect(url)
            .await
            .with_context(|| format!("connecting to NATS at {}", url))?;

        let jetstream = jetstream::new(client.clone());

        // Ensure the match results stream exists for publishing our results
        let results_stream_config = jetstream::stream::Config {
            name: "SECURITY_MATCH_RESULTS".to_string(),
            subjects: vec!["sec.matches.>".to_string()],
            retention: jetstream::stream::RetentionPolicy::Limits,
            max_age: std::time::Duration::from_secs(7 * 24 * 3600), // 7 days
            max_bytes: 512 * 1024 * 1024,                           // 512MB
            storage: jetstream::stream::StorageType::File,
            discard: jetstream::stream::DiscardPolicy::Old,
            ..Default::default()
        };

        match jetstream.create_stream(results_stream_config.clone()).await {
            Ok(_) => info!("created SECURITY_MATCH_RESULTS stream"),
            Err(_) => {
                // Stream may already exist — try to get it
                match jetstream.get_stream("SECURITY_MATCH_RESULTS").await {
                    Ok(_) => debug!("SECURITY_MATCH_RESULTS stream already exists"),
                    Err(e) => warn!(error = %e, "could not create or get match results stream"),
                }
            }
        }

        let bridge = Self {
            client,
            jetstream,
            matcher: Arc::new(matcher),
            shutdown: Arc::new(Notify::new()),
            buffer_size,
        };

        // Start the consumer loop
        bridge.start_consumer(workers).await?;

        Ok(bridge)
    }

    /// Get a publisher handle for the packet capture thread.
    pub fn clone_publisher(&self) -> EventPublisher {
        EventPublisher {
            jetstream: self.jetstream.clone(),
        }
    }

    /// Start consuming events from the SECURITY_EVENTS stream.
    async fn start_consumer(&self, workers: usize) -> Result<()> {
        // Get or create a durable consumer on the events stream
        let stream = self
            .jetstream
            .get_stream("SECURITY_EVENTS")
            .await
            .with_context(|| "getting SECURITY_EVENTS stream — is the Go engine running?")?;

        let consumer: PullConsumer = stream
            .get_or_create_consumer(
                "rust-engine",
                jetstream::consumer::pull::Config {
                    durable_name: Some("rust-engine".to_string()),
                    filter_subject: "sec.events.>".to_string(),
                    ack_policy: jetstream::consumer::AckPolicy::Explicit,
                    ..Default::default()
                },
            )
            .await
            .with_context(|| "creating consumer on SECURITY_EVENTS")?;

        let matcher = self.matcher.clone();
        let js = self.jetstream.clone();
        let shutdown = self.shutdown.clone();
        let batch_size = self.buffer_size.min(100);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(workers));

        tokio::spawn(async move {
            info!(
                workers = workers,
                batch_size = batch_size,
                "event consumer started"
            );
            loop {
                tokio::select! {
                    _ = shutdown.notified() => {
                        info!("consumer shutting down");
                        break;
                    }
                    result = consumer.fetch().max_messages(batch_size).messages() => {
                        match result {
                            Ok(mut messages) => {
                                use futures::StreamExt;
                                while let Some(Ok(msg)) = messages.next().await {
                                    let permit = semaphore.clone().acquire_owned().await;
                                    let matcher = matcher.clone();
                                    let js = js.clone();
                                    tokio::spawn(async move {
                                        let _permit = permit;
                                        process_message(&msg, &matcher, &js).await;
                                        if let Err(e) = msg.ack().await {
                                            warn!(error = %e, "failed to ack message");
                                        }
                                    });
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "fetch error, retrying in 1s");
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            }
                        }
                    }
                }
            }
        });

        Ok(())
    }

    /// Signal shutdown and wait for cleanup.
    pub async fn shutdown(&self) {
        self.shutdown.notify_waiters();
        // Give consumer a moment to finish
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        // Flush and close
        if let Err(e) = self.client.flush().await {
            warn!(error = %e, "error flushing NATS on shutdown");
        }
    }
}

/// Process a single NATS message: deserialize the event, run pattern matching, publish results.
async fn process_message(
    msg: &async_nats::Message,
    matcher: &PatternMatcher,
    js: &jetstream::Context,
) {
    // Deserialize the security event
    let event: SecurityEvent = match serde_json::from_slice(&msg.payload) {
        Ok(e) => e,
        Err(e) => {
            debug!(error = %e, "failed to deserialize event, skipping");
            return;
        }
    };

    // Extract text fields from the event data for scanning
    let fields = extract_scannable_fields(&event);
    if fields.is_empty() {
        return;
    }

    // Dual-pass scan: raw fields first, then normalized fields.
    // This mirrors the Go engine's AnalyzeInput dual-pass approach.
    let field_refs: Vec<(&str, &str)> = fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let mut result = matcher.scan(&event.id, &field_refs);

    // Second pass: normalize all fields and scan again for evasion-encoded payloads
    let normalized_fields: Vec<(String, String)> = fields
        .iter()
        .map(|(k, v)| {
            let norm = normalize::normalize(v);
            (format!("{}.normalized", k), norm)
        })
        .filter(|(_, v)| !v.is_empty())
        .collect();

    if !normalized_fields.is_empty() {
        let norm_refs: Vec<(&str, &str)> = normalized_fields
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let norm_result = matcher.scan(&event.id, &norm_refs);

        // Merge normalized matches (deduplicate by pattern name)
        let existing: std::collections::HashSet<String> =
            result.matches.iter().map(|m| m.pattern_name.clone()).collect();
        for m in norm_result.matches {
            if !existing.contains(&m.pattern_name) {
                if m.severity > result.highest_severity {
                    result.highest_severity = m.severity;
                }
                result.matches.push(m);
            }
        }

        // Recalculate aggregate score
        if !result.matches.is_empty() {
            let sum: f64 = result.matches.iter().map(|m| m.severity.score()).sum();
            let max_possible = result.matches.len() as f64;
            result.aggregate_score = (sum / max_possible).min(1.0);
        }
    }

    // Only publish if we found matches
    if result.matches.is_empty() {
        debug!(event_id = %event.id, time_us = result.processing_time_us, "no matches");
        return;
    }

    info!(
        event_id = %event.id,
        match_count = result.matches.len(),
        score = result.aggregate_score,
        severity = %result.highest_severity.as_str(),
        time_us = result.processing_time_us,
        "patterns matched"
    );

    // Publish match result
    let subject = format!(
        "sec.matches.{}.{}",
        event.module,
        result.highest_severity.as_str()
    );

    match serde_json::to_vec(&result) {
        Ok(payload) => {
            if let Err(e) = js.publish(subject, payload.into()).await {
                error!(error = %e, event_id = %event.id, "failed to publish match result");
            }
        }
        Err(e) => {
            error!(error = %e, "failed to serialize match result");
        }
    }
}

/// Extract all string fields from a SecurityEvent's data payload for scanning.
fn extract_scannable_fields(event: &SecurityEvent) -> Vec<(String, String)> {
    let mut fields = Vec::new();

    // Always scan the description
    if !event.description.is_empty() {
        fields.push(("description".to_string(), event.description.clone()));
    }

    // Recursively extract string values from the JSON data
    extract_json_strings("data", &event.data, &mut fields, 0);

    fields
}

/// Recursively extract string values from a JSON value, with depth limiting.
fn extract_json_strings(
    prefix: &str,
    value: &serde_json::Value,
    out: &mut Vec<(String, String)>,
    depth: usize,
) {
    if depth > 5 {
        return; // Prevent stack overflow on deeply nested payloads
    }

    match value {
        serde_json::Value::String(s) => {
            if s.len() > 1 && s.len() < 100_000 {
                out.push((prefix.to_string(), s.clone()));
            }
        }
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                let field_name = format!("{}.{}", prefix, key);
                extract_json_strings(&field_name, val, out, depth + 1);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, val) in arr.iter().enumerate() {
                let field_name = format!("{}[{}]", prefix, i);
                extract_json_strings(&field_name, val, out, depth + 1);
            }
        }
        _ => {} // Skip numbers, bools, nulls
    }
}
