---
name: 1sec-security
description: >
  Install, configure, and manage 1-SEC — an all-in-one cybersecurity platform
  (16 modules, single binary) on Linux servers and VPS instances. Use when the
  user asks to secure a server, install security monitoring, set up intrusion
  detection, harden a VPS, protect an AI agent host, or deploy endpoint defense.
  Covers installation, setup, enforcement presets, module configuration, alert
  management, and ongoing security operations.
license: AGPL-3.0
compatibility: >
  Requires Linux (amd64 or arm64) with curl or wget. Root or sudo recommended
  for full enforcement (iptables, process kill). Optional: GEMINI_API_KEY env
  var for AI-powered cross-module correlation.
metadata:
  author: cutmob
  version: "0.4.11"
  external_connections:
    - domain: api.1-sec.dev
      purpose: "Cloud control plane for centralized management"
      required: false
      enabled_by: "cloud.enabled: true in config"
    - domain: "user-configured"
      purpose: "Webhook notifications (Slack, Discord, Telegram, etc.)"
      required: false
      enabled_by: "webhook_urls in config"
    - domain: generativelanguage.googleapis.com
      purpose: "Gemini API for AI-powered cross-module correlation"
      required: false
      enabled_by: "GEMINI_API_KEY environment variable"
  required_permissions:
    - "Network monitoring (read-only for all modules)"
    - "Log file access (read-only for detection)"
    - "iptables/nftables (optional, for IP blocking enforcement)"
    - "Process management (optional, for kill_process enforcement)"
    - "File system access (optional, for quarantine_file enforcement)"
  data_collection:
    - "System logs (processed locally, not sent externally)"
    - "Network metadata (processed locally, not sent externally)"
    - "Alert metadata (sent to webhooks/cloud API only if configured)"
  source_repository: "https://github.com/1sec-security/1sec"
  security_policy: "See SECURITY.md for vulnerability reporting and supply chain security"
---

# 1-SEC Security Platform — Agent Skill

You are installing and configuring **1-SEC**, an open-source all-in-one
cybersecurity platform. One binary, 16 defense modules, zero config required.

## When to Use This Skill

- User asks to "secure this server" or "install security monitoring"
- User wants intrusion detection, WAF, LLM firewall, or ransomware protection
- User is deploying an AI agent (OpenClaw, Manus, Moltbot, etc.) on a VPS
- User needs to harden a Linux server or VPS
- User mentions 1-SEC, 1sec, or "one sec" in a security context

## Installation Methods

### Quick Install (Recommended for Testing)

```bash
curl -fsSL https://1-sec.dev/get | sh
```

This detects OS/arch, downloads the latest release, and installs to
`/usr/local/bin` (or `~/.local/bin` without root).

### Manual Install with Verification (Recommended for Production)

```bash
# 1. Download release and checksums
VERSION="0.4.11"
wget https://github.com/1sec-security/1sec/releases/download/v${VERSION}/1sec-linux-amd64
wget https://github.com/1sec-security/1sec/releases/download/v${VERSION}/checksums.txt

# 2. Verify checksum
sha256sum -c checksums.txt 2>&1 | grep 1sec-linux-amd64

# 3. Install
chmod +x 1sec-linux-amd64
sudo mv 1sec-linux-amd64 /usr/local/bin/1sec

# 4. Verify installation
1sec --version
```

### Inspect Before Install

```bash
# Download installer script for review
curl -fsSL https://1-sec.dev/get -o install.sh

# Review the script
cat install.sh

# Run after review
sh install.sh
```

## Post-Install Setup

### Option A: Non-interactive (recommended for agents)

```bash
# Install + configure in one shot
1sec setup --non-interactive

# Start with all 16 modules, zero config
1sec up
```

### Option B: AI agent VPS deployment

If this server hosts an AI agent, use the purpose-built `vps-agent` preset.

**Important:** The `vps-agent` preset is designed for maximum security on unattended AI agent hosts. It uses aggressive enforcement settings including:
- Automatic process termination for containment violations
- File quarantine without approval for agent file tampering
- Short cooldown periods and high action rate limits
- Escalation timers that auto-escalate unacknowledged alerts
- Disabled approval gates (no human available to approve)

**We recommend these settings for production AI agent hosts** as they provide the strongest defense against the specific threats targeting autonomous agents (prompt injection, malicious skills, credential theft, memory tampering).

**Recommended Deployment Path:**

```bash
# Install
curl -fsSL https://1-sec.dev/get | sh

# Non-interactive setup (uses env vars for AI keys)
1sec setup --non-interactive

# Apply the vps-agent enforcement preset (start in dry-run for validation)
1sec enforce preset vps-agent --dry-run

# Start the engine
1sec up

# Monitor for 24-48 hours to validate behavior
1sec alerts
1sec enforce history

# Review what would have been blocked
1sec enforce test auth_fortress
1sec enforce test llm_firewall

# Go live with full enforcement (recommended)
1sec enforce dry-run off

# Configure notifications (pick your platform)
# Slack:
1sec config set webhook-url https://hooks.slack.com/services/YOUR/WEBHOOK --template slack
# Discord:
1sec config set webhook-url https://discord.com/api/webhooks/YOUR/WEBHOOK --template discord
# Telegram:
1sec config set webhook-url https://api.telegram.org/botTOKEN/sendMessage --template telegram --param chat_id=CHAT_ID
```

**If you need to reduce enforcement** (not recommended for production):

```yaml
# In 1sec.yaml, override specific actions:
enforcement:
  policies:
    ai_containment:
      actions:
        - action: kill_process
          enabled: false  # Disable if too aggressive
    runtime_watcher:
      min_severity: HIGH  # Raise threshold from MEDIUM
```

### Option C: Interactive setup

```bash
1sec setup
```

Walks through config creation, AI key setup, and API authentication.

## Security & Transparency

### What This Tool Does
- Installs a binary to `/usr/local/bin` or `~/.local/bin`
- Creates config directory at `~/.1sec/`
- Monitors system logs and network activity locally
- Optionally sends alerts to configured webhooks (user-controlled)
- Optionally connects to cloud API for centralized management (opt-in via `cloud.enabled: true`)
- Self-updates daily via the same installer mechanism

### External Connections (All Optional)
- **api.1-sec.dev**: Cloud control plane (only if `cloud.enabled: true` in config)
- **Webhook URLs**: User-configured alert destinations (Slack, Discord, Telegram, etc.)
- **Gemini API**: AI analysis (only if `GEMINI_API_KEY` environment variable is set)

### Source & Provenance
- Source code: https://github.com/1sec-security/1sec
- Release artifacts: https://github.com/1sec-security/1sec/releases
- License: AGPL-3.0
- All releases include SHA256 checksums for verification

## Enforcement Presets

1-SEC ships with `dry_run: true` and the `safe` preset by default.

| Preset      | Behavior |
|-------------|----------|
| `lax`       | Log + webhook only. Never blocks or kills. |
| `safe`      | Default. Blocks only brute force + port scans at CRITICAL. |
| `balanced`  | Blocks IPs on HIGH, kills processes on CRITICAL. |
| `strict`    | Aggressive enforcement on MEDIUM+. |
| `vps-agent` | Purpose-built for AI agent hosts. Aggressive on auth, LLM firewall, containment, runtime, supply chain. |

Recommended progression: `lax` → `safe` → `balanced` → `strict`

The `vps-agent` preset is standalone — use it for AI agent deployments.

### VPS-Agent Preset: Detailed Configuration

The `vps-agent` preset is **purpose-built for unattended AI agent hosts** where no human SOC team is actively monitoring. It addresses the specific threat model of autonomous agents: prompt injection, malicious skill installations, credential exfiltration, and runtime file tampering.

**Current Configuration (Recommended for Maximum Security):**

Critical modules with aggressive enforcement:
- **auth_fortress**: Blocks IPs at MEDIUM severity, 30s cooldown, 60 actions/min
- **llm_firewall**: Drops connections at MEDIUM, 10s cooldown, 100 actions/min
- **ai_containment**: Kills processes at MEDIUM with `skip_approval: true`, 15s cooldown
- **runtime_watcher**: Kills processes and quarantines files at MEDIUM with `skip_approval: true`, 15s cooldown
- **supply_chain**: Quarantines files at MEDIUM with `skip_approval: true`, 30s cooldown

**Escalation timers** (shorter than defaults for autonomous hosts):
- CRITICAL: 3 min timeout, re-notify up to 5 times
- HIGH: 10 min timeout, escalate to CRITICAL, 3 times
- MEDIUM: 20 min timeout, escalate to HIGH, 2 times

**Approval gates**: Disabled by default (no human available to approve)

**What gets auto-enforced:**
- Process kills: Suspicious processes accessing agent files (SOUL.md, MEMORY.md, .env)
- File quarantine: Unauthorized modifications to agent configuration files
- IP blocks: Brute force attempts, port scans, prompt injection sources
- Connection drops: Active prompt injection attempts, command injection

**We recommend these aggressive settings for maximum security on AI agent hosts.** The threat model justifies immediate response without human approval. However, if you need to reduce enforcement for testing or have concerns about false positives, see the deployment path below.

```bash
# Apply a preset
1sec enforce preset balanced

# Preview what a preset does without applying
1sec enforce preset strict --show

# Apply with dry-run safety net
1sec enforce preset balanced --dry-run
```

## Essential Commands

```bash
1sec up                        # Start engine (all 16 modules)
1sec status                    # Engine status
1sec alerts                    # Recent alerts
1sec alerts --severity HIGH    # Filter by severity
1sec modules                   # List all modules
1sec dashboard                 # Real-time TUI dashboard
1sec check                     # Pre-flight diagnostics
1sec doctor                    # Health check with fix suggestions
1sec stop                      # Graceful shutdown
```

## Enforcement Management

```bash
1sec enforce status            # Enforcement engine status
1sec enforce policies          # List response policies
1sec enforce history           # Action execution history
1sec enforce dry-run off       # Go live (disable dry-run)
1sec enforce test <module>     # Simulate alert, preview actions
1sec enforce approvals pending # Pending human approval gates
1sec enforce escalations       # Escalation timer stats
1sec enforce batching          # Alert batcher stats
1sec enforce chains list       # Action chain definitions
```

## AI Analysis (Optional)

The 15 rule-based modules work without any API key. For AI-powered
cross-module correlation, set a Gemini API key:

```bash
# Via environment variable
export GEMINI_API_KEY=your_key_here
1sec up

# Or via CLI
1sec config set-key AIzaSy...

# Multiple keys for load balancing
1sec config set-key key1 key2 key3
```

## The 16 Modules

| # | Module | Covers |
|---|--------|--------|
| 1 | Network Guardian | DDoS, rate limiting, IP reputation, C2 beaconing, port scans |
| 2 | API Fortress | BOLA, schema validation, shadow API discovery |
| 3 | IoT & OT Shield | Device fingerprinting, protocol anomaly, firmware integrity |
| 4 | Injection Shield | SQLi, XSS, SSRF, command injection, template injection |
| 5 | Supply Chain Sentinel | SBOM, typosquatting, dependency confusion, CI/CD |
| 6 | Ransomware Interceptor | Encryption detection, canary files, wiper detection |
| 7 | Auth Fortress | Brute force, credential stuffing, MFA fatigue, AitM |
| 8 | Deepfake Shield | Audio forensics, AI phishing, BEC detection |
| 9 | Identity Fabric | Synthetic identity, privilege escalation |
| 10 | LLM Firewall | 65+ prompt injection patterns, jailbreak detection, multimodal hidden injection scanning |
| 11 | AI Agent Containment | Action sandboxing, scope escalation, OWASP Agentic Top 10 |
| 12 | Data Poisoning Guard | Training data integrity, RAG pipeline validation |
| 13 | Quantum-Ready Crypto | Crypto inventory, PQC readiness, TLS auditing |
| 14 | Runtime Watcher | FIM, container escape, LOLBin, memory injection |
| 15 | Cloud Posture Manager | Config drift, misconfiguration, secrets sprawl |
| 16 | AI Analysis Engine | Two-tier Gemini pipeline for correlation |

## Configuration

Zero-config works out of the box. For customization, generate a config:

```bash
1sec init                      # Generate 1sec.yaml
1sec config --validate         # Validate config
```

Key config sections: `server`, `bus`, `modules`, `enforcement`, `escalation`,
`archive`, `cloud`. See `references/config-reference.md` for details.

## Webhook Notifications

Configure webhook URLs for alert notifications to Slack, Discord, Telegram,
PagerDuty, or Microsoft Teams:

```yaml
# In 1sec.yaml or configs/default.yaml
alerts:
  webhook_urls:
    - "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

# Enforcement webhooks support templates:
# pagerduty, slack, teams, discord, telegram, generic
```

Telegram example:

```yaml
enforcement:
  policies:
    auth_fortress:
      actions:
        - action: webhook
          params:
            url: "https://api.telegram.org/botYOUR_TOKEN/sendMessage"
            template: "telegram"
            chat_id: "-1001234567890"
```

## Docker Deployment

```bash
cd deploy/docker
docker compose up -d
docker compose logs -f
```

## Day-to-Day Operations (Post-Install)

Once 1-SEC is running, the key commands for daily operations:

```bash
1sec status                    # Quick health check
1sec alerts                    # Recent alerts
1sec alerts --severity HIGH    # Filter by severity
1sec enforce status            # Enforcement engine state
1sec enforce history           # What actions were taken
1sec threats --blocked         # Currently blocked IPs
1sec doctor                    # Health check with fix suggestions
```

For the full operations runbook — investigating alerts, handling false
positives, tuning noisy modules, managing webhooks, escalation timers,
and troubleshooting — see `references/operations-runbook.md`.

## Additional References

- `references/operations-runbook.md` — Day-to-day operations, alert investigation, tuning, troubleshooting
- `references/config-reference.md` — Full configuration reference
- `references/vps-agent-guide.md` — Detailed VPS agent deployment guide
- `scripts/install-and-configure.sh` — Automated install + configure script

## Uninstall

```bash
# Stop the engine
1sec stop

# Remove enforcement rules (iptables, etc.)
1sec enforce cleanup

# Remove binary
sudo rm /usr/local/bin/1sec

# Remove data directory
rm -rf ~/.1sec
```
