<div align="center">

# 🐛 BugScanner

**An Advanced, Context-Aware Recon & Automated Web Vulnerability Assessment Framework**

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>

---

## 📌 Overview

**BugScanner** is a modular asynchronous reconnaissance and web vulnerability assessment framework for **authorized security testing**. It combines asset discovery, endpoint-aware testing, conservative verification, finding deduplication, explainable risk prioritization, and professional technical/executive reporting.

The platform is deliberately designed around **evidence-backed, non-destructive verification**. It generates human-reviewable reproduction PoCs from findings already collected by the scan; it does not provide credential theft, destructive exploitation, scope expansion, WAF bypass, or internal/cloud metadata access.

---

## 🔥 Platform Capabilities

### 🔍 Phase 1 — Reconnaissance & Discovery
- Subdomain discovery with scope enforcement.
- TCP service discovery and banner collection.
- HTTP technology fingerprinting.
- Endpoint discovery with deterministic asset normalization.
- Explicit target allowlists, wildcard subdomains and CIDR scope support.

### 🛡️ Phase 2 — Context-Aware Vulnerability Assessment
- XSS, SQL injection, CORS, SSRF, open redirect, JWT, IDOR and information-disclosure checks.
- API security signals for REST/GraphQL/OpenAPI/Swagger-style surfaces.
- Adaptive endpoint prioritization based on path, parameters and previously observed evidence.
- Optional Nuclei and business-logic integrations.

### ✅ Phase 3 — Verification & Evidence
- Conservative verification states: `low-confidence`, `medium-confidence`, `high-confidence`, `verified`.
- Evidence signal tracking and independent corroboration.
- False-positive validation and deterministic finding deduplication.
- Safe reproduction material and cURL PoCs generated without executing exploits.
- Explicit exploitability state: `not-reproducible`, `reproducible`, or `verified`.

### 📊 Phase 4 — Risk & Reporting
- Explainable CVSS/evidence-based prioritization with `P0`–`P3` remediation tiers.
- Technical reports containing evidence, reproduction steps, PoC, remediation and references.
- Executive reports focused on business risk and remediation order.
- Machine-readable JSON results with a scan manifest covering scope, coverage, filtering and verification statistics.

### ⚡ Phase 5 — Resilience & Safety
- Adaptive rate limiting that respects server back-pressure such as `429` and `503`.
- TLS verification enabled by default.
- Deterministic scope enforcement before network activity.
- No stealth, credential theft, destructive payload execution, unauthorized target expansion, or internal-resource probing.

---

## 🏗 Architecture

```text
cli.py
  │
  ▼
scanner.py ──────────────── ScanResult / Manifest
  │
  ├── Recon
  │   ├── subdomain.py
  │   ├── portscan.py
  │   ├── fingerprint.py
  │   └── discovery.py
  │
  ├── Vulnerability Modules
  │   ├── xss.py / sqli.py / cors.py / ssrf.py
  │   ├── redirect.py / jwt.py / idor.py
  │   ├── disclosure.py / api_security.py
  │   └── nuclei_wrapper.py / business_logic.py
  │
  └── Finding Pipeline
      ├── deduplication
      ├── safe PoC generation
      ├── evidence verification
      ├── risk prioritization
      └── technical + executive reporting
```

## 🚀 Usage

```bash
python cli.py scan https://target.example
python cli.py scan https://target.example --mode recon
python cli.py scan https://target.example --mode vulns
python cli.py scan https://target.example --no-subdomains --ports extended
python cli.py scan https://target.example --rps 5
```

Only scan systems for which you have explicit authorization. For production use, configure an allowlist in `config/settings.yaml`:

```yaml
scope:
  allowed_targets:
    - target.example
  include_subdomains: true
```

## 📋 Reporting Model

Each finding can contain:

- Severity and CVSS score
- CWE and references
- URL, method and parameter
- Evidence and payload/marker information
- Verification status and confidence
- Independent confirmation count
- Safe cURL reproduction PoC
- Exploitability and impact state
- Remediation guidance
- Risk priority (`P0`–`P3`)

The scan manifest additionally records target, timing, enabled modules, coverage, duplicates, false positives and verification statistics so a manager can distinguish **what was found** from **what was actually verified**.

## 🗺 Roadmap

- Authenticated multi-role differential testing with explicit session inputs.
- Headless DOM analysis for modern SPA route discovery and browser-context verification.
- Stronger request/response provenance and per-module evidence attribution.
- CI quality gates for unit tests, linting and report schema validation.

## ⚠️ Disclaimer

BugScanner is intended only for educational, defensive auditing, authorized penetration testing and permitted bug-bounty activities. Do not scan systems without explicit permission. The project intentionally favors safe, auditable verification over weaponized exploitation.
