# BAC Detector

**Automated Broken Access Control (BAC) Testing Tool**

> ⚠️ **For authorized security testing only.**  
> Use this tool only against applications you own or have explicit written permission to test.  
> Unauthorized scanning may be illegal.

---

## What is BAC Detector?

BAC Detector is an open-source security testing tool that helps pentesters and AppSec engineers discover broken access control issues in web APIs and REST services.

It focuses specifically on:

- **IDOR (Insecure Direct Object Reference)** — accessing another user's resource by manipulating an ID
- **BOLA (Broken Object Level Authorization)** — API-level variant of IDOR
- **Horizontal privilege escalation** — user A accessing user B's data at the same privilege level
- **Vertical privilege escalation** — low-privileged user accessing admin-only endpoints
- **Graph-based authorization analysis** — cross-endpoint reasoning to find inconsistencies that isolated request-pair checks miss

BAC Detector is **not** a vulnerability scanner, fuzzer, or exploit framework. It is a focused authorization testing tool designed for pentests, bug bounties, and security reviews.

---

## Quick Start

### Prerequisites

- Python 3.11+
- [Poetry](https://python-poetry.org/) (recommended) or pip

### Install

```bash
git clone https://github.com/your-org/bac-detector.git
cd bac-detector
poetry install
```

Or with pip in editable mode:

```bash
pip install -e ".[all]"
```

### Verify the install

```bash
bacdet version
```

### Run against the built-in demo app

The fastest way to see the tool work end-to-end is against the included intentionally-vulnerable demo API:

```bash
bacdet validate-demo
```

This starts the demo app, runs a full scan, and checks that all three intentional flaws are detected.

### Run against a real target

1. Copy the example config and fill in your target and tokens:

```bash
cp examples/config.yaml my-config.yaml
# edit my-config.yaml
```

2. Do a dry run first to confirm discovery works:

```bash
bacdet scan --config my-config.yaml --dry-run
```

3. Run the full scan:

```bash
bacdet scan --config my-config.yaml
```

4. View the report:

```bash
# Markdown report (written automatically after scan)
cat results/report.md

# Re-render as terminal summary
bacdet report --input results/findings.json --format terminal

# Re-render to a new Markdown file
bacdet report --input results/findings.json --format md --output pentest_report.md
```

---

## Configuration

All scan behaviour is driven by a YAML config file. See `examples/config.yaml` for a fully-annotated reference.

### Minimum viable config

```yaml
target:
  base_url: "https://api.example.com"
  openapi_url: "https://api.example.com/openapi.json"

identities:
  - name: alice
    role: user
    auth_mechanism: bearer
    token: "YOUR_ALICE_TOKEN"
    owned_object_ids: ["101", "102"]

  - name: bob
    role: user
    auth_mechanism: bearer
    token: "YOUR_BOB_TOKEN"
    owned_object_ids: ["201"]
```

At least two identity profiles are required.

### Supported auth mechanisms

| Mechanism | Config value | How it works |
|-----------|-------------|--------------|
| Bearer token | `bearer` | Adds `Authorization: Bearer <token>` header |
| Session cookie | `cookie` | Adds cookies to every request |
| Custom header | `header` | Adds arbitrary headers from `custom_headers` |
| No auth | `none` | Sends unauthenticated requests (guest testing) |

### Safety defaults

BAC Detector defaults to the safest possible configuration:

- `read_only: true` — only GET requests are sent
- `dry_run: false` — set to `true` to print requests without sending
- `lab_mode: false` — write operations (POST/PUT/PATCH/DELETE) are disabled
- `requests_per_second: 2.0` — conservative rate limiting
- `request_budget: 500` — hard cap on total requests per scan

---

## Architecture

```
Config + Identities
        │
        ▼
  [ Discovery ]     ← OpenAPI spec, endpoint list
        │
        ▼
  [ Inventory ]     ← Normalized, deduplicated endpoint set
        │
        ▼
  [ Replay Engine ] ← Each endpoint × each identity, rate-limited
        │
        ▼
  [ Auth Matrix ]   ← endpoint × identity × object_id → response
        │
        ▼
  [ Detectors ]     ← IDOR, BOLA, horizontal/vertical escalation
        │
        ▼
  [ Graph Engine ]  ← Cross-endpoint reasoning (optional, see below)
        │
        ▼
  [ Reporters ]     ← JSON findings, Markdown pentest report, terminal summary
```

### Project structure

```
bac_detector/
├── cli/            Command-line interface (Typer)
├── config/         Config loading and validation
├── models/         Pydantic data models (shared by all stages)
├── auth/           Auth profile → request headers/cookies
├── discovery/      Endpoint discovery (OpenAPI, endpoint list)
├── replay/         Request replay engine with rate limiting
├── analyzers/      Authorization matrix and owner baselines
├── comparators/    Response comparison (status, body diff)
├── detectors/      BAC detection logic (IDOR, escalation)
├── graph/          Authorization graph engine (G1–G4)
│   ├── models.py   Graph nodes, edges, inference types
│   ├── builder.py  Builds AuthGraph from matrix + inventory
│   ├── inference.py Action/ownership/tenant inference
│   ├── analyzers.py 6 graph-based detectors
│   └── service.py  Orchestrator: run_graph_analysis()
├── reporters/      JSON, Markdown, terminal output
└── utils/          Logging, HTTP client, URL normalization
demo_app/           Intentionally vulnerable FastAPI app for validation
examples/           Sample configs and endpoint lists
tests/
├── unit/           Unit tests (no network, no server)
└── integration/    End-to-end tests against the demo app
```

---

## Detection Logic

For each discovered endpoint, BAC Detector:

1. Identifies parameters that look like object identifiers (`user_id`, `order_id`, etc.)
2. Replays the request across all configured identities
3. Substitutes object IDs owned by other identities to test cross-user access
4. Compares responses across identities to detect authorization anomalies

### Confidence levels

- **Confirmed** — verified with ownership assertion (identity A accessed an object owned by B, and got the same data back)
- **Potential** — response anomaly detected but not conclusively verified; manual review recommended
- **FP risk** — flagged but high likelihood of false positive

---

## Graph-Based Authorization Analysis

The graph engine is an optional second-pass analysis layer that runs **after** the standard detectors. It builds an authorization graph from the replay results and applies six cross-endpoint analyzers that catch issues request-pair comparisons cannot detect.

Enable it by adding `graph_analysis: enabled: true` to your config:

```yaml
graph_analysis:
  enabled: true
  infer_ownership: true                  # use owner_id/user_id fields in responses
  infer_tenant_boundaries: true          # detect cross-tenant anomalies
  enable_hidden_privilege_path_checks: true
  min_confidence: low                    # low | medium | high
```

### What the graph engine detects

| Analyzer | What it finds |
|----------|--------------|
| **Inconsistent sibling action protection** | Identity denied one action (e.g. GET) but allowed another (e.g. PATCH) on the same resource family |
| **Child-resource exposure** | Parent resource denied but a child sub-resource (e.g. `/orders/{id}/invoice`) is accessible |
| **Hidden privilege path** | Main admin endpoint denied but a specific admin sub-action is reachable for the same identity |
| **Tenant boundary inconsistency** | Same resource returns different `tenant_id` values to different identities, suggesting cross-tenant data leakage |
| **Ownership inconsistency** | Identity gets a 200 but the response body's `owner_id` field belongs to someone else (BOLA confirmed via body) |
| **Partial authorization enforcement** | Some endpoints in a resource family enforce authorization, others do not |

### Graph analysis output

Graph findings appear in the same JSON and Markdown reports as standard findings, with categories prefixed `graph_`:

```
graph_sibling_inconsistency
graph_child_exposure
graph_hidden_privilege_path
graph_tenant_boundary
graph_ownership_inconsistency
graph_partial_authorization
```

The JSON summary includes a `findings_by_category` breakdown so you can see at a glance how many findings came from each detector.

### When to use it

- APIs with nested resources (orders → invoices, users → documents)
- Multi-tenant SaaS applications
- APIs where admin and user functionality share the same path namespace
- Any target where standard IDOR detection returns findings but you suspect deeper structural issues

Graph analysis adds no additional HTTP requests — it reasons over the responses already collected during the replay phase.

---

## Output

Every scan produces:

- `results/findings.json` — machine-readable findings with summary counts by severity and category
- `results/report.md` — Markdown pentest report ready for client deliverables
- Terminal summary — immediate overview after the scan completes

### JSON summary fields

```json
{
  "summary": {
    "total_findings": 7,
    "confirmed_findings": 3,
    "potential_findings": 4,
    "findings_by_severity": { "high": 2, "medium": 4, "low": 1 },
    "findings_by_category": {
      "IDOR": 2,
      "vertical_escalation": 1,
      "graph_child_exposure": 1,
      "graph_ownership_inconsistency": 2,
      "graph_sibling_inconsistency": 1
    }
  }
}
```

---

## Development

```bash
# Run all tests (unit + integration)
poetry run pytest

# Unit tests only (no server startup)
poetry run pytest tests/unit/
# or
poetry run pytest -m unit

# Integration tests only
poetry run pytest -m integration

# Lint
poetry run ruff check .

# Type check
poetry run mypy bac_detector/
```

---

## Implementation Status

| Phase | Status | Description |
|-------|--------|-------------|
| Phase 1 | ✅ Complete | Scaffold, models, config, logging, CLI |
| Phase 2 | ✅ Complete | OpenAPI parser, endpoint list reader, inventory builder |
| Phase 3 | ✅ Complete | Replay engine, baseline capture, auth matrix |
| Phase 4 | ✅ Complete | IDOR/escalation detectors, confidence scoring |
| Phase 5 | ✅ Complete | JSON/Markdown reporters, terminal summary |
| Phase 6 | ✅ Complete | Demo app, integration tests, `validate-demo` command |
| Graph G1–G4 | ✅ Complete | Authorization graph engine with 6 cross-endpoint analyzers |

---

## Legal

This tool is provided for **authorized security testing only**. The authors are not responsible for any unauthorized use.

Only run BAC Detector against:
- Applications you own
- Staging/lab environments you control
- Bug bounty targets that explicitly permit automated testing
- Client environments where you have written authorization

---

## License

MIT License. See [LICENSE](LICENSE) for details.
