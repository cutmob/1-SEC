
<div align="center">
  <img src="web/public/og-image.png" alt="1-SEC Social Preview" width="100%">
  <h1>⚡ 1-SEC</h1>
  <p><strong>One binary. Total defense.</strong></p>
  <p>The next generation of rapid-deployment security layers. <br/>Auditable, community-driven, and designed for immediate integration.</p>

  <p>
    <a href="#features">Features</a> •
    <a href="#quick-start">Quick Start</a> •
    <a href="#architecture">Architecture</a> •
    <a href="#documentation">Docs</a> •
    <a href="#license">License</a>
  </p>

  <p>
    <a href="https://github.com/cutmob/1-SEC/blob/main/LICENSE">
      <img src="https://img.shields.io/badge/License-AGPL%20v3-blue.svg?style=flat-square" alt="License">
    </a>
    <a href="https://golang.org/">
      <img src="https://img.shields.io/github/go-mod/go-version/cutmob/1-SEC?style=flat-square&color=blue" alt="Go Version">
    </a>
    <a href="https://github.com/cutmob/1-SEC/releases">
      <img src="https://img.shields.io/github/v/release/cutmob/1-SEC?style=flat-square&color=orange" alt="Release">
    </a>
  </p>
</div>

---

## 🛡️ What is 1-SEC?

**1-SEC** is an open-source (AGPLv3), all-in-one security platform designed for modern infrastructure. It combines 16 specialized defense modules into a single, zero-dependency binary that runs anywhere.

Instead of managing 15 different agents (WAF, IDS, Log Shipper, Compliance, etc.), you run **one** binary that communicates over a high-performance internal event bus.

### Core Philosophy
- **Zero Config by Default**: Secure out of the box. Tune later.
- **Single Binary**: No containers, no JVM, no Python envs. Just `1sec`.
- **Privacy First**: Your data stays on your server. Cloud features are opt-in.
- **Open Core**: The engine is free forever. Paid features are for team management & history.

---

## 🚀 Quick Start

From your terminal:

```bash
curl -fsSL https://1-sec.dev/get | sh
1sec up
```

Or build from source:

```bash
git clone https://github.com/cutmob/1-SEC.git
cd 1-SEC
go build -o 1sec cmd/1sec/main.go
./1sec up
```

---

## 📦 16 Defense Modules

Every module runs concurrently on the internal NATS JetStream bus. Enable or disable any module via YAML config.

| Module | Description | Tier |
| :--- | :--- | :--- |
| **Network Guardian** | DDoS mitigation, rate limiting, IP reputation, geo-fencing, DNS tunneling/DGA detection, C2 beaconing, lateral movement (PtH, Kerberoasting, Golden Ticket, DCSync), port scan detection. | 1 |
| **API Fortress** | BOLA detection, schema validation, shadow API discovery, per-endpoint rate limiting. | 1 |
| **IoT & OT Shield** | Device fingerprinting, protocol anomaly detection (MQTT/CoAP/Modbus), firmware integrity. | 1 |
| **Injection Shield** | SQLi, XSS, SSRF, command injection, template injection, NoSQL injection, path traversal. | 2 |
| **Supply Chain Sentinel** | SBOM generation, typosquatting detection, dependency confusion, CI/CD hardening. | 2 |
| **Ransomware Interceptor** | Encryption detection, canary files, exfiltration monitoring, wiper detection (MBR/GPT), shadow copy deletion, backup destruction, compound attack correlation. | 2 |
| **Auth Fortress** | Brute force, credential stuffing, session hijack, impossible travel, MFA bypass/fatigue, OAuth abuse, password spraying. | 3 |
| **Deepfake Shield** | Synthetic voice/video detection, AI phishing, domain spoofing, BEC detection. | 3 |
| **Identity Fabric Monitor** | Synthetic identity detection, privilege escalation tracking, dormant service accounts. | 3 |
| **LLM Firewall** | 55+ prompt injection patterns, jailbreak detection, output filtering, multi-turn tracking, encoding evasion. Zero LLM calls. | 4 |
| **AI Agent Containment** | Action sandboxing, tool-use monitoring, shadow AI detection, policy enforcement. | 4 |
| **Data Poisoning Guard** | Training data integrity, RAG verification, adversarial input detection, model drift. | 4 |
| **Quantum-Ready Crypto** | Crypto inventory, PQC migration, TLS auditing, certificate monitoring, harvest-now-decrypt-later (HNDL) detection. | 5 |
| **Runtime Watcher** | FIM, container escape detection, LOLBin detection (40+), memory injection (process hollowing, DLL injection), persistence mechanisms, firmware/UEFI, fileless malware. | 6 |
| **Cloud Posture Manager** | Config drift, misconfiguration scanning, secrets sprawl, compliance checks. | 6 |
| **AI Analysis Engine** | Two-tier LLM pipeline: Gemini Flash Lite for triage, Gemini 3 Flash for deep classification and cross-module correlation. | X |

---

## 🖥️ CLI Reference

```
1sec up                Start the engine with all enabled modules
1sec up --modules X,Y  Start only specific modules
1sec up --dry-run      Validate config without starting
1sec status            Show running engine status
1sec alerts            Fetch recent alerts (--severity, --module, --limit, --json)
1sec scan              Submit payload for analysis (stdin or --input file)
1sec modules           List all 16 defense modules (--tier, --json)
1sec config            Show resolved config (--validate, --json)
1sec check             Run pre-flight diagnostics
1sec stop              Gracefully stop a running instance
1sec version           Print version and build info
1sec help <command>    Detailed help for any command
```

---

## 🏗️ Architecture

1-SEC is built on a **Modular Monolith** architecture:

1.  **Core Engine (Go)**: Handles lifecycle, configuration, and the event bus.
2.  **Event Bus (NATS)**: High-performance messaging between modules.
3.  **Modules (Go/Rust)**: Independent workers that consume/produce events.
4.  **Web Dashboard (Next.js)**: Optional UI for visualization and management (located in `/web`).

### Directory Structure

- `/cmd`: Entry points (the CLI).
- `/internal/core`: The engine, config loader, and logger.
- `/internal/modules`: distinct packages for each security domain.
- `/web`: The Next.js dashboard and landing page.

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to set up your development environment.

### Development Prerequisites
- Go 1.26+
- Node.js 20+ (for the dashboard)
- Make (optional)

---

## 📜 License

**AGPLv3**. See [LICENSE](LICENSE) for details.

Copyright © 2026 1-SEC Project.
