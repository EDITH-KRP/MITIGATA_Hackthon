# CyberForge CART
### Controlled Autonomous Red Teaming & Assessment Engine

[![PTES v1.0 Compliant](https://img.shields.io/badge/PTES-v1.0_Compliant-0ea5e9?style=flat-square)](http://www.pentest-standard.org/)
[![Scope Policy](https://img.shields.io/badge/Security-Fail--Closed_PolicyGate-10b981?style=flat-square)](docs/safety.md)
[![Verification Engine](https://img.shields.io/badge/Verification-Deterministic_Playbooks-6366f1?style=flat-square)](src/cart/verify.py)
[![Test Suite](https://img.shields.io/badge/Tests-51_Passing-22c55e?style=flat-square)](tests/test_cart.py)
[![Python Version](https://img.shields.io/badge/Python-3.11_%7C_3.12_%7C_3.13-blue?style=flat-square)](pyproject.toml)
[![Container](https://img.shields.io/badge/Docker-Ready-38bdf8?style=flat-square)](Dockerfile)
[![License](https://img.shields.io/badge/License-Proprietary-64748b?style=flat-square)](AGENTS.md)

---

## Executive Overview

**CyberForge CART** (Controlled Autonomous Red Teaming) is an enterprise-grade autonomous security assessment engine designed for organiser-designated CTF laboratories, hybrid cloud infrastructures, and scoped enterprise perimeters. 

Operating under the strict lifecycle of the **Penetration Testing Execution Standard (PTES)**, CART coordinates bounded, specialized worker agents across three concurrent attack surfaces: **Network Infrastructure**, **Web Applications**, and **Native Compiled Binaries**.

Unlike fragile LLM-only scanners, CART is built on the fundamental principle of **Deterministic State Ownership**: scheduling, scope enforcement, deduplication, evidence hashing, and vulnerability verification are governed entirely by deterministic Python and SQLite state machines. AI and heuristics remain strictly advisory and can never mutate state or promote unverified claims.

---

## Architectural Principles

```
  ┌────────────────────────────────────────────────────────────────────────┐
  │                           CORE PILLARS OF CART                         │
  ├──────────────────────────────────┬─────────────────────────────────────┤
  │ 1. Zero-Trust Scope Safety       │ Fails closed on all outbound probes │
  │ 2. Deterministic State Ownership │ SQLite WAL core; zero LLM drift     │
  │ 3. Evidence Before Claims        │ 100% verified PoCs; no hallucinations│
  │ 4. Full Tri-Surface Auditing     │ Network + Web + Binary Static/ELF   │
  │ 5. Actionable Remediation        │ Git-appliable unified diff patches  │
  └──────────────────────────────────┴─────────────────────────────────────┘
```

1. **Zero-Trust Scope Safety (`PolicyGate`)**:
   Every packet, socket handshake, HTTP probe, or binary file request is evaluated against a cryptographically locked `ScopeManifest` before transmission. If an IP, CIDR prefix, domain, or file hash is not explicitly pre-approved, the gate drops the request immediately and records the violation in the audit log.
2. **Deterministic State Machine**:
   Task dependencies, rate limits, timeouts, and state transitions are executed in deterministic code. The core system runs locally without requiring cloud API keys or external LLM connections.
3. **Evidence-Backed Verification**:
   Vulnerabilities are never confirmed on suspicion. Findings enter the state machine as `CANDIDATE` and must pass deterministic verification playbooks to be promoted to `CONFIRMED`. Unproven items are strictly marked `INCONCLUSIVE` or `REJECTED`.
4. **Tri-Surface Coverage**:
   - **Network**: TCP/UDP discovery, state tracking, service fingerprinting, and cleartext protocol analysis.
   - **Web**: Origin-pinned link crawling, security header inspection, CSRF token validation, reverse-proxy bypass testing (`X-Forwarded-For`), and sensitive file detection.
   - **Binaries**: Static ELF/PE structural analysis, compiler checksec auditing (`NX`, `PIE`, `Canary`, `RELRO`), unsafe libc symbol detection (`strcpy`, `system`, `gets`, `popen`), and XOR algorithm reversing.
5. **Unified Remediation Advisory**:
   Translates confirmed weaknesses directly into concrete mitigation guidance, hardened configuration snippets, and Git-compatible unified diff patches (`.patch`).

---

## System Architecture

### High-Level Architecture Diagram

```mermaid
flowchart TD
    subgraph INGESTION ["1. Target Ingestion & Scope Locking"]
        InputTarget["Target Input (URL / IP / CIDR / Binary)"] --> ManifestGen["Scope Manifest Generator"]
        ManifestGen --> LockedManifest["ScopeManifest (SHA-256 Locked)"]
        LockedManifest --> Gate{"PolicyGate (Fail-Closed Engine)"}
    end

    subgraph ORCHESTRATION ["2. Autonomous Orchestrator"]
        Gate -- In-Scope --> Coordinator["Deterministic Task Coordinator"]
        Gate -- Out-of-Scope --> GateAuditLog[("Scope Audit Decisions Log")]
        Coordinator --> WorkerNet["Network Specialist (Nmap & Sockets)"]
        Coordinator --> WorkerWeb["Web Specialist (Crawler & Header Auditor)"]
        Coordinator --> WorkerBin["Binary Specialist (ELF Parser & Checksec)"]
    end

    subgraph PERSISTENCE ["3. State & Evidence Layer"]
        WorkerNet --> StateStore[("SQLite State Store (WAL Mode)")]
        WorkerWeb --> StateStore
        WorkerBin --> StateStore
        StateStore --> RawEvidence[("Cryptographic Evidence (SHA-256)")]
        StateStore --> CandidateQueue["Candidate Findings Queue"]
    end

    subgraph VERIFICATION ["4. Verification & Correlation"]
        CandidateQueue --> Verifier["Deterministic Verification Service"]
        RawEvidence --> Verifier
        Verifier --> ConfirmedFindings["Confirmed Findings (Zero False-Positives)"]
        ConfirmedFindings --> AttackEngine["Attack Path Graph Engine"]
    end

    subgraph REPORTING ["5. Executive Delivery & UI"]
        ConfirmedFindings --> PatchGen["Unified Diff Patch Generator"]
        ConfirmedFindings --> PTESEngine["PTES Assessment Report Engine"]
        AttackEngine --> DashboardUI["Dark Dashboard UI (Port 8080)"]
        PTESEngine --> DashboardUI
        PatchGen --> DashboardUI
        DashboardUI --> PDFArtifact["Downloadable PTES Assessment PDF"]
    end

    classDef primary fill:#0f172a,stroke:#0284c7,stroke-width:2px,color:#f8fafc;
    classDef gate fill:#1e1b4b,stroke:#818cf8,stroke-width:2px,color:#f8fafc;
    classDef storage fill:#090d16,stroke:#38bdf8,stroke-width:1px,color:#94a3b8;
    class Gate,LockedManifest gate;
    class Coordinator,WorkerNet,WorkerWeb,WorkerBin,Verifier primary;
    class StateStore,RawEvidence,GateAuditLog storage;
```

---

### Verification Lifecycle State Machine

```mermaid
stateDiagram-v2
    [*] --> Ingestion: Target Input Submitted
    Ingestion --> PolicyCheck: Generate Scope Manifest
    
    state PolicyCheck {
        [*] --> Evaluating
        Evaluating --> Denied: Out-of-Scope Target
        Evaluating --> Allowed: Explicitly Allowed
    }
    
    Denied --> ScopeAuditLog: Write Fail-Closed Audit Event
    ScopeAuditLog --> [*]

    Allowed --> Candidate: Specialist Worker Discovers Vulnerability
    Candidate --> VerificationQueued: Submit to Verification Service
    
    state VerificationQueued {
        [*] --> Replaying
        Replaying --> Confirmed: Deterministic PoC Succeeds
        Replaying --> Inconclusive: Partial / Indeterminate Result
        Replaying --> Rejected: Target Defended / False Alarm
    }

    Confirmed --> AttackGraph: Correlate Multi-Stage Pivot
    Inconclusive --> StateStore: Record Observation Only
    Rejected --> StateStore: Discard with Audit Reason

    AttackGraph --> RemediationAdvisor: Generate Unified Diff Patch
    RemediationAdvisor --> PTESReport: Synthesize Executive & Technical Output
    PTESReport --> [*]
```

---

### End-to-End Exploitation Sequence

```mermaid
sequenceDiagram
    autonumber
    participant Judge as Assessor / Judge
    participant WebUI as CART UI (Port 8080)
    participant Scope as PolicyGate
    participant Orch as Autonomous Orchestrator
    participant Target as Scoped Lab Host (10.0.10.25)
    participant Verifier as Verification Service
    participant Store as SQLite WAL Store

    Judge->>WebUI: Launch Assessment on Scoped Target
    WebUI->>Scope: Submit Target (10.0.10.25, TCP 1-65535)
    Scope->>Scope: Compute SHA-256 Manifest & Lock Scope
    Scope->>Orch: Dispatch Approved Scope

    par Tri-Surface Autonomous Sweeps
        Orch->>Target: Network Recon (Discover Ports 80, 8080, 8833)
        Orch->>Target: Web Crawl (Identify application endpoints & robots.txt)
        Orch->>Target: Proxy Header Audit (Bypass boundary via X-Forwarded-For: 10.0.0.1)
    end

    Target-->>Orch: Disclose Internal Knowledge Base & Artifact Repository (/artifacts/auth_service)
    Orch->>Target: Download 'auth_service' Binary
    Orch->>Orch: Reverse Static XOR Algorithm (Passkey: 'Demo_K3y_2026!')
    
    Orch->>Target: Authenticate to Management Console (Port 8833)
    Target-->>Orch: Access Granted, Spawn Worker PID
    Orch->>Target: Issue PIDREQ for /Desktop/flag with calculated CRC
    Target-->>Orch: Disclose Flag: EXAMPLE{c4rt_d3m0_fl4g_pr00f_2026}

    Orch->>Verifier: Queue Flag & PoC for Independent Validation
    Verifier->>Verifier: Replay Verification Playbook against SQLite Contracts
    Verifier->>Store: Promote Finding to CONFIRMED with SHA-256 Evidence
    Store->>WebUI: Stream Real-Time Node to Attack Graph & Report
    WebUI-->>Judge: Display Confirmed Findings, Attack Graph & PDF Export
```

---

## Deployment & Usage

### Option 1: Docker Deployment (Recommended)

CyberForge CART includes a self-contained, multi-stage Docker environment with `nmap`, `binutils`, `readelf`, `curl`, and Python pre-configured.

#### Using Docker Compose
```bash
# 1. Clone repository
git clone https://github.com/EDITH-KRP/MITIGATA_Hackthon.git
cd MITIGATA_Hackthon

# 2. Build and start container in detached mode
docker compose up --build -d

# 3. View live operational logs
docker compose logs -f
```

#### Using Docker CLI Directly

**Linux / macOS (Bash):**
```bash
docker build -t cyberforge-cart .
docker run -d --name cyberforge-cart \
  -p 127.0.0.1:8080:8080 \
  -v "$(pwd)/reports:/app/reports" \
  -v "$(pwd)/cart.db:/app/cart.db" \
  cyberforge-cart
```

**Windows (PowerShell):**
```powershell
docker build -t cyberforge-cart .
docker run -d --name cyberforge-cart `
  -p 127.0.0.1:8080:8080 `
  -v "${PWD}/reports:/app/reports" `
  -v "${PWD}/cart.db:/app/cart.db" `
  cyberforge-cart
```

Open your browser at: **`http://localhost:8080`**

---

### Option 2: Native Host Installation

#### Prerequisites
- Python 3.11 or newer
- `pip` and `virtualenv`
- Optional: `nmap`, GNU `binutils` (`strings`, `readelf`)

```bash
# 1. Clone repository
git clone https://github.com/EDITH-KRP/MITIGATA_Hackthon.git
cd MITIGATA_Hackthon

# 2. Create and activate a clean virtual environment
python -m venv .venv

# On Linux/macOS:
source .venv/bin/activate
# On Windows (PowerShell):
.\.venv\Scripts\Activate.ps1

# 3. Install package with development dependencies
pip install -e .[dev]

# 4. Launch the Interactive Dashboard
python -m cart.cli ui --port 8080
```

---

## Judge Walkthrough & Demonstration Guide

### Step 1: Access Clean Assessment Dashboard
Navigate to `http://localhost:8080`. The dashboard initializes clean with zero metrics until a target assessment is triggered.

### Step 2: Configure & Lock Scope
Use the header launcher to select an authorized target or preset:
- **Preset: Local OWASP Juice Shop**: Target `http://127.0.0.1:3000/` (Local isolated container).
- **Preset: Local Assessment Dashboard**: Target `http://127.0.0.1:8080/` (Self-auditing interface).
- **Preset: Isolated Lab Subnet**: Target `10.0.10.0/24` (Scoped private network).
- **Custom Input**: Enter any authorized lab URL, IP address, or CIDR block. The zero-trust `PolicyGate` will cryptographically lock scope and fail closed on any out-of-bounds destination.

### Step 3: Trigger Autonomous Execution
Click **Launch Assessment**. The orchestrator will:
1. Lock the scope manifest via `PolicyGate`.
2. Concurrently execute network, web, and binary analysis workers.
3. Dynamically capture live evidence, compute SHA-256 hashes, and stream logs to the UI.
4. Execute deterministic verification routines to promote confirmed findings.
5. Derive the multi-stage attack path graph and synthesize code-level remediation diffs.

### Step 4: Export Deliverables
- **Interactive Inspection**: Click on any finding or attack graph node to view technical PoCs, CWE classifications, and raw HTTP/binary excerpts.
- **Executive PDF**: Click **Download PDF** to export a publication-ready PTES v1.0 penetration testing report.
- **Remediation Patches**: Inspect or export unified diff patches directly from `reports/patches/`.

---

## Vulnerability & Weakness Taxonomy

CyberForge CART classifies all discovered weaknesses against standardized CWE and CVSS v3.1 frameworks:

| Vulnerability Type | Default Severity | PTES Phase | Classification | Technical Description |
| :--- | :--- | :--- | :--- | :--- |
| `flag_disclosure_pidreq` | **CRITICAL** (9.8) | Exploitation | CWE-639 / CWE-200 | Arbitrary resource dereference via authenticated PID console protocol |
| `binary_missing_nx_stack` | **HIGH** (9.8) | Vulnerability Analysis | CWE-732 / CWE-119 | Missing `GNU_STACK` ELF header allowing arbitrary stack shellcode execution |
| `binary_unsafe_function` | **HIGH** (9.8) | Vulnerability Analysis | CWE-120 / CWE-676 | Inclusion of dangerous libc functions (`strcpy`, `system`, `gets`, `popen`) |
| `unauthenticated_console_service` | **HIGH** (8.8) | Vulnerability Analysis | CWE-284 / CWE-306 | Cleartext TCP administrative console exposed without TLS or transport encryption |
| `reverse_proxy_ip_spoofing` | **HIGH** (8.6) | Vulnerability Analysis | CWE-290 | Reverse proxy IP trust boundary bypass via `X-Forwarded-For` header spoofing |
| `cleartext_http_authentication` | **HIGH** (8.8) | Vulnerability Analysis | CWE-319 / CWE-523 | Cleartext HTTP Basic Authentication transmitted over unencrypted HTTP |
| `unauthenticated_artifact_vault` | **HIGH** (7.5) | Information Gathering | CWE-552 | Public directory listing exposing compiled internal binaries (`/vault/`) |
| `ctf_planted_flag` | **HIGH** (7.5) | Exploitation | CTF Objective | Static or dynamically disclosed capture-the-flag string literal |
| `binary_missing_stack_canary` | **MEDIUM** (7.5) | Vulnerability Analysis | CWE-121 | Stack smashing protection omitted during compilation (no `__stack_chk_fail`) |
| `binary_no_pie` | **MEDIUM** (7.0) | Vulnerability Analysis | CWE-119 | Position Independent Executable disabled (`ET_EXEC`); ASLR defeated |
| `binary_no_relro` | **MEDIUM** (7.0) | Vulnerability Analysis | CWE-732 | Writable Global Offset Table (GOT) permitting PLT control-flow hijacking |
| `weak_reversible_binary_passkey` | **MEDIUM** (6.5) | Vulnerability Analysis | CWE-259 / CWE-327 | Hardcoded symmetric XOR routine permitting static credential recovery |
| `clickjacking_missing_frame_options` | **MEDIUM** (5.4) | Vulnerability Analysis | CWE-1021 | Missing `X-Frame-Options` and CSP `frame-ancestors` directives |
| `form_missing_csrf_token` | **MEDIUM** (5.4) | Vulnerability Analysis | CWE-352 | State-altering POST HTML forms lacking cryptographic anti-CSRF tokens |
| `missing_security_headers` | **MEDIUM** (5.3) | Vulnerability Analysis | CWE-693 | Absence of defensive response headers (`HSTS`, `CSP`, `X-Content-Type-Options`) |
| `cors_wildcard_misconfiguration` | **MEDIUM** (5.3) | Vulnerability Analysis | CWE-346 / CWE-942 | Permissive `Access-Control-Allow-Origin: *` enabling cross-origin exfiltration |

---

## Repository Structure

```
CyberForge_CART/
├── Dockerfile                  # Production container definition (Python 3.11 + Nmap + Binutils)
├── docker-compose.yml          # Container orchestration with volume mounts & port bindings
├── .dockerignore               # Build context exclusions
├── pyproject.toml              # Build system, package dependencies & pytest configuration
├── README.md                   # System documentation & judge evaluation guide
├── AGENTS.md                   # Operational guardrails and non-negotiable coding rules
├── src/
│   └── cart/
│       ├── cli.py              # CLI entrypoint (preflight, select, run, report, ui)
│       ├── scope.py            # Zero-trust fail-closed PolicyGate & ScopeManifest
│       ├── models.py           # Frozen data contracts (Finding, Evidence, Task, Asset)
│       ├── store.py            # SQLite state database schema & ACID queries
│       ├── orchestrator.py     # Deterministic parallel agent coordinator & scheduler
│       ├── ptes.py             # PTES v1.0 standard phases & state machine definitions
│       ├── verify.py           # Zero false-positive deterministic verification engine
│       ├── attackpath.py       # Evidence-backed attack path graph derivation
│       ├── report.py           # Markdown report synthesis engine
│       ├── advisor.py          # Remediation advisor & unified diff patch synthesizer
│       ├── ui.py               # Modern dark dashboard server & REST API
│       └── workers/
│           ├── network.py      # Network discovery, port scanning & service detection
│           ├── web.py          # Web crawler, reverse-proxy bypass & header auditor
│           └── binary.py       # Static ELF/PE structural analysis & checksec auditor
├── reports/                    # Generated PTES assessment reports, JSONs, and unified patches
├── tests/                      # Automated test suite (unit and end-to-end integration tests)
└── docs/                       # Architectural specifications, build plan, and safety policies
```

---

## Verification & Quality Assurance

All core components—including scope gating, binary parsers, verification playbooks, report synthesis, and data contract immutability—are validated through an automated test suite:

```bash
# Execute test suite
pytest

# Execute code formatting and style linting
ruff check src/cart/
```

```
============================= test session starts =============================
platform win32 -- Python 3.13, pytest-9.2.0
rootdir: S:\CyberForge_CART
configfile: pyproject.toml
testpaths: tests
collected 51 items

tests\test_cart.py ...................................................   [100%]
============================== 51 passed in 1.45s =============================
```

---

## Compliance & Standards

CyberForge CART adheres strictly to:
1. **Penetration Testing Execution Standard (PTES v1.0)** across all 7 operational phases.
2. **Common Weakness Enumeration (CWE)** and **CVSS v3.1** vulnerability scoring.
3. **OWASP Top 10 (2021)** web application security mapping.
4. **Zero-Trust Network Architecture**: Outbound packet delivery prohibited prior to cryptographic scope verification.
