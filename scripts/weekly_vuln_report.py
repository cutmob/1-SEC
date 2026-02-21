#!/usr/bin/env python3
"""
Weekly Vulnerability Intelligence Report Generator for 1SEC

Three-phase agentic approach:
  Phase 1: Introspect the codebase — read actual Go source to build a capability map
  Phase 2: Gather threat intel — CISA KEV, NVD, Go Vuln DB, editorial sources via Jina
  Phase 3: Cross-reference — feed both to Gemini for accurate coverage analysis

Requirements:
    pip install google-genai requests python-dotenv

Setup:
    Add GEMINI_API_KEY=your-key to the .env file in the project root.

Usage:
    python scripts/weekly_vuln_report.py
    python scripts/weekly_vuln_report.py --days 3
"""

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

try:
    from google import genai
except ImportError:
    print("Missing dependency: pip install google-genai")
    sys.exit(1)

# Load .env from project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

MODEL = "gemini-flash-lite-latest"

# ── Module source files to introspect ────────────────────────────────────────

MODULE_SOURCE_FILES = {
    "network_guardian": [
        "internal/modules/network/network.go",
    ],
    "api_fortress": [
        "internal/modules/apifortress/apifortress.go",
    ],
    "iot_shield": [
        "internal/modules/iot/iot.go",
    ],
    "injection_shield": [
        "internal/modules/injection/injection.go",
        "internal/modules/injection/patterns.go",
        "internal/modules/injection/analyze.go",
        "internal/modules/injection/filesentinel.go",
    ],
    "supply_chain": [
        "internal/modules/supplychain/supplychain.go",
    ],
    "ransomware": [
        "internal/modules/ransomware/ransomware.go",
    ],
    "auth_fortress": [
        "internal/modules/auth/auth.go",
    ],
    "deepfake_shield": [
        "internal/modules/deepfake/deepfake.go",
    ],
    "identity_monitor": [
        "internal/modules/identity/identity.go",
    ],
    "llm_firewall": [
        "internal/modules/llmfirewall/llmfirewall.go",
    ],
    "ai_containment": [
        "internal/modules/aicontainment/aicontainment.go",
    ],
    "data_poisoning": [
        "internal/modules/datapoisoning/datapoisoning.go",
    ],
    "quantum_crypto": [
        "internal/modules/quantumcrypto/quantumcrypto.go",
    ],
    "runtime_watcher": [
        "internal/modules/runtime/runtime.go",
    ],
    "cloud_posture": [
        "internal/modules/cloudposture/cloudposture.go",
    ],
    "ai_analysis_engine": [
        "internal/modules/aiengine/aiengine.go",
    ],
}

# ── 1SEC direct dependencies (from go.mod) ──────────────────────────────────

ONESEC_DEPS = [
    "github.com/google/uuid",
    "github.com/hashicorp/golang-lru",
    "github.com/nats-io/nats-server",
    "github.com/nats-io/nats.go",
    "github.com/rs/zerolog",
    "github.com/sony/gobreaker",
    "gopkg.in/yaml.v3",
    "golang.org/x/crypto",
    "golang.org/x/sys",
    "golang.org/x/time",
    "github.com/klauspost/compress",
    "github.com/nats-io/jwt",
    "github.com/nats-io/nkeys",
    "github.com/google/go-tpm",
]

# ── Data sources ─────────────────────────────────────────────────────────────

JINA_READER_PREFIX = "https://r.jina.ai/"

EDITORIAL_SOURCES = [
    {"name": "The Hacker News",      "url": "https://thehackernews.com/"},
    {"name": "SecurityWeek",         "url": "https://www.securityweek.com/"},
    {"name": "Krebs on Security",    "url": "https://krebsonsecurity.com/"},
    {"name": "Zero Day Initiative",  "url": "https://www.zerodayinitiative.com/advisories/published/"},
    {"name": "Dark Reading",         "url": "https://www.darkreading.com/"},
    {"name": "The Record",           "url": "https://therecord.media/"},
    {"name": "PromptArmor Threat Intel", "url": "https://www.promptarmor.com/resources/threat-intelligence"},
]

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GO_VULN_DB_URL = "https://vuln.go.dev"


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1: Codebase Introspection
# ═══════════════════════════════════════════════════════════════════════════════

def read_module_sources() -> dict[str, str]:
    """Read actual Go source code for each module, extracting key sections."""
    print("[*] Phase 1: Introspecting codebase...")
    module_code = {}

    for module_name, files in MODULE_SOURCE_FILES.items():
        combined = ""
        for rel_path in files:
            full_path = PROJECT_ROOT / rel_path
            if not full_path.exists():
                print(f"    [!] Missing: {rel_path}")
                continue
            content = full_path.read_text(encoding="utf-8", errors="replace")
            # Extract the most relevant parts: struct definitions, HandleEvent,
            # detection functions, pattern lists. Truncate large files.
            extracted = extract_key_code(content, rel_path)
            combined += f"\n// === {rel_path} ===\n{extracted}\n"

        if combined.strip():
            module_code[module_name] = combined
            print(f"    {module_name}: {len(combined)} chars extracted")

    return module_code


def extract_key_code(content: str, filename: str) -> str:
    """Extract the most detection-relevant parts of a Go source file.
    Keeps struct definitions, function signatures, detection logic,
    and pattern/regex definitions. Flash Lite has a 1M token window
    and cheap input — send generous chunks."""
    lines = content.split("\n")
    relevant = []
    in_relevant_block = False
    brace_depth = 0

    # Keywords that indicate detection-relevant code
    relevance_markers = [
        "type ", "func ", "HandleEvent", "Analyze", "Detect", "Check",
        "patterns", "Pattern", "Regex", "regexp.", "Severity",
        "raiseAlert", "NewAlert", "Description()", "inspect",
        "suspicious", "malicious", "dangerous", "LOLBin",
        "isSensitivePath", "isSuspiciousFile", "compilePatterns",
        "threshold", "Threshold", "Finding", "Detection",
        "alert", "Alert", "monitor", "Monitor", "scan", "Scan",
        "validate", "Validate", "policy", "Policy",
    ]

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Always include package, import, const, type declarations
        if stripped.startswith(("package ", "const ", "type ", "func ")):
            in_relevant_block = True
            brace_depth = 0

        # Check for relevance markers
        if any(marker in line for marker in relevance_markers):
            in_relevant_block = True

        if in_relevant_block:
            relevant.append(line)
            brace_depth += line.count("{") - line.count("}")
            if brace_depth <= 0 and stripped.endswith("}"):
                in_relevant_block = False
                relevant.append("")  # blank line separator

    result = "\n".join(relevant)
    # Flash Lite has 1M token context — be generous per file
    max_chars = 30000
    if len(result) > max_chars:
        result = result[:max_chars] + "\n// ... (truncated)"
    return result


def build_capability_audit_prompt(module_code: dict[str, str]) -> str:
    """Build prompt for Phase 1: capability audit from source code."""
    code_sections = "\n\n".join(
        f"## Module: {name}\n```go\n{code}\n```"
        for name, code in module_code.items()
    )

    return f"""You are a security engineer auditing the 1SEC codebase. Below is the actual
Go source code for each security module. Your job is to produce a precise capability
manifest — what each module ACTUALLY detects based on the code, not what you think it
should detect.

For each module, output a structured entry with:
- module_name
- detection_capabilities: list of specific things it detects (be precise — reference
  actual function names, regex patterns, thresholds, and detection logic from the code)
- event_types_handled: what event types trigger this module
- limitations: what it explicitly does NOT cover (based on code gaps you can see)

Be brutally accurate. If a module only checks for 4 BACnet function codes, say that.
If a regex only catches UNION SELECT but not blind SQLi via boolean, say that.
If a threshold is hardcoded at 10, mention it.

{code_sections}

Output as a structured markdown document with one section per module."""


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2: Threat Intelligence Gathering
# ═══════════════════════════════════════════════════════════════════════════════

def fetch_cisa_kev(days: int = 7) -> list[dict]:
    """Fetch recent entries from CISA Known Exploited Vulnerabilities catalog."""
    print("[*] Fetching CISA KEV catalog...")
    try:
        resp = requests.get(CISA_KEV_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
        recent = [v for v in data.get("vulnerabilities", []) if v.get("dateAdded", "") >= cutoff]
        print(f"    Found {len(recent)} new KEV entries in the last {days} days")
        return recent
    except Exception as e:
        print(f"    [!] CISA KEV fetch failed: {e}")
        return []


def fetch_nvd_recent(days: int = 7) -> list[dict]:
    """Fetch recent CVEs from NVD API v2."""
    print("[*] Fetching NVD recent CVEs...")
    try:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT23:59:59.999"),
            "resultsPerPage": 100,
        }
        resp = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params, timeout=30)
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        critical = []
        for v in vulns:
            cve = v.get("cve", {})
            metrics = cve.get("metrics", {})
            cvss31 = metrics.get("cvssMetricV31", [{}])
            score = cvss31[0].get("cvssData", {}).get("baseScore", 0) if cvss31 else 0
            if score >= 7.0:
                critical.append({
                    "id": cve.get("id", ""),
                    "description": (cve.get("descriptions", [{}])[0].get("value", "") if cve.get("descriptions") else ""),
                    "score": score,
                    "published": cve.get("published", ""),
                })
        print(f"    Found {len(critical)} high/critical CVEs (score >= 7.0) in the last {days} days")
        return critical
    except Exception as e:
        print(f"    [!] NVD fetch failed: {e}")
        return []


def fetch_go_vuln_db() -> list[dict]:
    """Check Go vulnerability database for advisories affecting our dependencies."""
    print("[*] Checking Go vulnerability database...")
    findings = []
    for dep in ONESEC_DEPS:
        try:
            search_url = f"{GO_VULN_DB_URL}/search?q={dep}"
            jina_url = f"{JINA_READER_PREFIX}{search_url}"
            resp = requests.get(jina_url, headers={"Accept": "text/plain"}, timeout=20)
            if resp.status_code == 200:
                content = resp.text[:1500]
                if "GO-" in content and "no results" not in content.lower():
                    findings.append({"package": dep, "content": content})
                    print(f"    [!] Found advisories for {dep}")
        except Exception:
            pass
    if not findings:
        print("    No Go vulnerability advisories found for our dependencies")
    return findings


def fetch_via_jina(url: str, name: str) -> str:
    """Use Jina Reader to extract text content from a URL."""
    print(f"[*] Scraping {name} via Jina Reader...")
    try:
        jina_url = f"{JINA_READER_PREFIX}{url}"
        resp = requests.get(jina_url, headers={"Accept": "text/plain"}, timeout=45)
        resp.raise_for_status()
        content = resp.text[:8000]
        print(f"    Got {len(content)} chars from {name}")
        return content
    except Exception as e:
        print(f"    [!] Jina fetch failed for {name}: {e}")
        return ""


def collect_threat_intel(days: int = 7) -> dict:
    """Phase 2: Gather all threat intelligence."""
    print(f"\n[*] Phase 2: Gathering threat intelligence ({days}-day window)...")
    intel = {
        "cisa_kev": fetch_cisa_kev(days),
        "nvd_critical": fetch_nvd_recent(days),
        "go_vulns": fetch_go_vuln_db(),
        "editorial": {},
    }
    for source in EDITORIAL_SOURCES:
        content = fetch_via_jina(source["url"], source["name"])
        if content:
            intel["editorial"][source["name"]] = content
    return intel


def build_threat_digest_prompt(intel: dict) -> str:
    """Build prompt for Phase 2: structured threat digest."""
    cisa_summary = "\n".join(
        f"- {v.get('cveID', 'N/A')}: {v.get('vulnerabilityName', 'N/A')} "
        f"(vendor: {v.get('vendorProject', 'N/A')}, added: {v.get('dateAdded', 'N/A')})"
        for v in intel["cisa_kev"][:30]
    ) or "No new CISA KEV entries this week."

    nvd_summary = "\n".join(
        f"- {v['id']} (CVSS {v['score']}): {v['description'][:200]}"
        for v in intel["nvd_critical"][:30]
    ) or "No critical NVD CVEs fetched this week."

    editorial_summary = "\n\n".join(
        f"### {name}\n{content[:4000]}"
        for name, content in intel["editorial"].items()
    ) or "No editorial content fetched."

    go_vuln_summary = "\n\n".join(
        f"### {f['package']}\n{f['content'][:800]}"
        for f in intel.get("go_vulns", [])
    ) or "No Go vulnerability advisories found."

    return f"""You are a threat intelligence analyst. Produce a structured digest of this
week's security threats. For each threat/vulnerability, extract:
- CVE ID (if applicable)
- Attack type/category (e.g., SSRF, RCE, privilege escalation, ransomware, etc.)
- Attack vector (network, application layer, file parsing, authentication, etc.)
- Specific techniques used (e.g., path traversal, heap overflow, credential stuffing)
- Affected software/ecosystem
- Real-world exploitation status (actively exploited? proof of concept? theoretical?)

## CISA Known Exploited Vulnerabilities
{cisa_summary}

## NVD Critical/High CVEs
{nvd_summary}

## Security News
{editorial_summary}

## Go Ecosystem Advisories
{go_vuln_summary}

Output as a structured markdown list grouped by attack category. Be factual — only include
what the data actually says, don't speculate."""


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: Cross-Reference Analysis
# ═══════════════════════════════════════════════════════════════════════════════

def build_crossref_prompt(capability_audit: str, threat_digest: str) -> str:
    """Build prompt for Phase 3: cross-reference capabilities against threats."""
    return f"""You are a product intelligence analyst for 1SEC, a real-time security defense
platform. You have two documents:

1. A CAPABILITY AUDIT — an accurate assessment of what each 1SEC module actually detects,
   based on reading the source code. Trust this document completely.
2. A THREAT DIGEST — this week's real-world attacks and vulnerabilities.

Your job: cross-reference these to answer two questions:
- Would running 1SEC have helped defend against these real-world incidents?
- What new attack methods should we build defenses for?

## CAPABILITY AUDIT (from source code analysis)
{capability_audit}

## THREAT DIGEST (this week's intelligence)
{threat_digest}

---

Produce the final report with these sections. For EVERY coverage claim, include a confidence
rating (HIGH / MEDIUM / LOW):
- HIGH = the capability audit shows a specific detection mechanism for this exact attack pattern
- MEDIUM = the audit shows coverage for the general category but this specific variant may slip through
- LOW = only tangential coverage exists

### 1. Executive Summary
3-5 sentences on the week's most important threats and what they mean for 1SEC.

### 2. Where 1SEC Would Have Helped
For each real-world attack this week, map it to specific 1SEC capabilities from the audit.
Reference the actual detection functions, regex patterns, or thresholds. Group by attack
scenario, not by module.

### 3. New Attack Methods — Product Improvement Opportunities
Novel techniques from this week that we should build defenses for. For each:
- The technique and how attackers use it
- Whether any current module catches it (reference the audit)
- Specific detection rule or enhancement proposal
- Effort estimate (rule update / module enhancement / new module)

### 4. Coverage Gaps — Honest Assessment
Where 1SEC would NOT have helped this week. Reference the audit's "limitations" sections.
For each gap, propose what we'd need to build.

### 5. Dependency Alerts
Go ecosystem and 1SEC dependency vulnerabilities.

### 6. Action Items
Prioritized: IMMEDIATE (rule tweaks) / SHORT-TERM (enhancements) / STRATEGIC (new capabilities).

Be specific, reference CVE IDs, and write for engineers building security software.
If a section has nothing notable, say so briefly and move on."""


# ═══════════════════════════════════════════════════════════════════════════════
# Orchestration
# ═══════════════════════════════════════════════════════════════════════════════

def call_gemini(client: genai.Client, prompt: str, phase_name: str) -> str:
    """Make a Gemini API call with logging."""
    print(f"[*] Calling Gemini ({phase_name})...")
    response = client.models.generate_content(
        model=MODEL,
        contents=prompt,
    )
    result = response.text
    print(f"    Got {len(result)} chars from {phase_name}")
    return result


def generate_report(module_code: dict, intel: dict, output_path: str) -> None:
    """Three-phase report generation."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("[!] GEMINI_API_KEY environment variable not set.")
        sys.exit(1)

    client = genai.Client(api_key=api_key)

    # Phase 1: Capability audit
    capability_prompt = build_capability_audit_prompt(module_code)
    capability_audit = call_gemini(client, capability_prompt, "Phase 1: Capability Audit")

    # Phase 2: Threat digest
    threat_prompt = build_threat_digest_prompt(intel)
    threat_digest = call_gemini(client, threat_prompt, "Phase 2: Threat Digest")

    # Phase 3: Cross-reference
    crossref_prompt = build_crossref_prompt(capability_audit, threat_digest)
    final_report = call_gemini(client, crossref_prompt, "Phase 3: Cross-Reference Analysis")

    # Assemble output
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    week_start = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
    week_end = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    sources_used = ", ".join(
        ["CISA KEV", "NVD", "Go Vuln DB"]
        + [s["name"] for s in EDITORIAL_SOURCES]
    )

    full_report = f"""# 1SEC Weekly Vulnerability Intelligence Report

**Period:** {week_start} to {week_end}
**Generated:** {now}
**Sources:** {sources_used}
**Model:** {MODEL}
**Method:** Three-phase agentic analysis (codebase introspection → threat intel → cross-reference)

---

{final_report}

---

<details>
<summary>Phase 1: Capability Audit (from source code)</summary>

{capability_audit}

</details>

<details>
<summary>Phase 2: Threat Digest (raw intelligence)</summary>

{threat_digest}

</details>

---

*Auto-generated by `scripts/weekly_vuln_report.py` — capabilities derived from actual Go source code analysis.*
"""

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(full_report, encoding="utf-8")
    print(f"\n[✓] Report written to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="1SEC Weekly Vulnerability Intelligence Report")
    parser.add_argument("--days", type=int, default=7, help="Look-back window in days (default: 7)")
    parser.add_argument("--output", type=str, default=None, help="Output file path")
    args = parser.parse_args()

    if args.output is None:
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        args.output = f"scripts/reports/vuln-report-{date_str}.md"

    print(f"=== 1SEC Vulnerability Intelligence Report Generator ===")
    print(f"    Look-back: {args.days} days")
    print(f"    Output:    {args.output}")
    print(f"    Model:     {MODEL}")
    print(f"    Method:    Three-phase agentic analysis\n")

    # Phase 1: Read codebase
    module_code = read_module_sources()

    # Phase 2: Gather threat intel
    intel = collect_threat_intel(args.days)

    total_sources = len(intel["editorial"])
    total_vulns = len(intel["cisa_kev"]) + len(intel["nvd_critical"])
    go_alerts = len(intel.get("go_vulns", []))
    print(f"\n[*] Collected {total_vulns} vulnerabilities from {total_sources + 2} sources")
    print(f"[*] Introspected {len(module_code)} modules from source code")
    if go_alerts:
        print(f"[*] {go_alerts} Go dependency advisory alerts found")

    # Phase 3: Generate report
    print(f"\n[*] Phase 3: Cross-reference analysis...")
    generate_report(module_code, intel, args.output)


if __name__ == "__main__":
    main()
