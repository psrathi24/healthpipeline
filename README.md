# healthpipeline

A healthcare-native data pipeline that extracts raw clinical and claims data from FHIR APIs, validates and transforms it into structured, agent-ready records, orchestrates those jobs reliably, and serves the output via REST API — so agentic AI systems can reason over clean, trusted data instead of fighting raw input.

Built as a proof of concept targeting **prior authorization denial workflows** at provider organizations.

---

## What this proves

Agentic AI systems in healthcare fail or underperform because they operate on messy, inconsistent, multi-source clinical data. This pipeline solves that by acting as the **data preparation layer between raw FHIR data and any AI agent**.

The capstone demo fetches real FHIR EOB (ExplanationOfBenefit) records, transforms them into structured denial records, serves them via API, and passes them to an LLM that generates prior authorization appeal letters — one per claim, referencing real claim IDs, service dates, procedure codes, and flagging data gaps honestly.

**Messy FHIR data in → agent-ready denial records out → AI-generated appeal letters.**

---

## Architecture

```
FHIR API (HAPI / Synthea)
        │
        ▼
┌─────────────────┐
│  Extraction     │  eob_extractor.py
│  Layer          │  Pulls EOB resources, stores raw JSONB
│                 │  → raw_fhir_responses (PostgreSQL)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Transformation │  eob_transformer.py
│  Layer          │  Validates, normalizes, maps X12 codes
│                 │  → clean_denial_records / quarantine_records
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Orchestration  │  Dagster
│  Layer          │  Schedules extraction → transformation
│                 │  Observability via localhost:3000
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Serving        │  FastAPI + uvicorn
│  Layer          │  REST API at localhost:8000
│                 │  GET /denial/{claim_id}
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Agent          │  appeal_agent.py
│  Layer          │  Calls Groq LLaMA to generate appeal letters
│                 │  from structured denial records
└─────────────────┘
```

---

## Project structure

```
healthpipeline/
├── extractors/
│   ├── fhir_client.py          # FHIR API connector: auth, pagination, retries
│   └── eob_extractor.py        # EOB-specific extraction into raw_fhir_responses
├── transformers/
│   ├── code_mapper.py          # X12/CARC code lookup and canonicalization
│   ├── validator.py            # Denial record validation rules
│   └── eob_transformer.py      # Core transform: JSONB → clean_denial_records
├── pipeline/
│   ├── __init__.py
│   ├── assets.py               # Dagster asset definitions
│   ├── jobs.py                 # Dagster job + nightly schedule
│   └── definitions.py          # Dagster entry point
├── api/
│   ├── __init__.py
│   ├── main.py                 # FastAPI app and endpoints
│   ├── models.py               # Pydantic response models
│   ├── mcp_server.py           # MCP tools and resources (Anthropic MCP SDK)
│   └── run_mcp.py              # MCP server entry point
├── db/
│   ├── schema.sql              # PostgreSQL table definitions
│   ├── db_client.py            # DB connection helpers
│   └── seed_code_mappings.py   # Seeds X12 CARC codes from x12.org
├── agent/
│   └── appeal_agent.py         # Demo agent: fetches denials, generates appeals
├── explore.ipynb               # Exploration notebook (Phase 1–3 analysis)
├── sandbox_1.py                # Phase 1 script: Synthea → PostgreSQL
├── .env.example                # Environment variable template
├── .gitignore
└── README.md
```

---

## Prerequisites

- Python 3.11+ (note: Python 3.14 requires some package workarounds — see below)
- PostgreSQL 15+
- Java 11+ (required for Synthea)
- Git

---

## Setup

### 1. Clone the repo

```bash
git clone https://github.com/YOUR_USERNAME/healthpipeline.git
cd healthpipeline
```

### 2. Create and activate virtual environment

```bash
python3 -m venv venv
source venv/bin/activate  # Mac/Linux
# venv\Scripts\activate   # Windows
```

### 3. Install dependencies

```bash
pip install requests psycopg2-binary python-dotenv tenacity loguru
pip install pandas dbt-postgres
pip install dagster dagster-webserver
pip install fastapi uvicorn
pip install groq
pip install beautifulsoup4
pip install mcp
```

### 4. Configure environment variables

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

```env
FHIR_BASE_URL=https://hapi.fhir.org/baseR4
PGHOST=localhost
PGPORT=5432
PGDATABASE=healthpipeline
PGUSER=your_mac_username
PGPASSWORD=
GROQ_API_KEY=your_groq_api_key_here
```

Get a free Groq API key at [console.groq.com](https://console.groq.com).

### 5. Set up PostgreSQL database

```bash
psql postgres
CREATE DATABASE healthpipeline;
\q
```

Then run the schema:

```bash
psql -d healthpipeline -f db/schema.sql
```

### 6. Seed X12 denial code mappings

```bash
python db/seed_code_mappings.py
```

This scrapes the authoritative CARC code list from x12.org and loads ~300 active denial reason codes into PostgreSQL.

---

## Running the pipeline

### Option A — Run each layer manually (development)

```bash
# 1. Extract EOB records from FHIR API
python extractors/eob_extractor.py

# 2. Transform raw records into clean denial records
python transformers/eob_transformer.py

# 3. Start the API server
uvicorn api.main:app --reload --port 8000

# 4. Run the agent demo
python agent/appeal_agent.py
```

### Option B — Run via Dagster (orchestrated)

```bash
# Set persistent Dagster home (run in same terminal as dagster dev)
mkdir -p .dagster_home
export DAGSTER_HOME=$(pwd)/.dagster_home

# Start Dagster
./venv/bin/dagster dev -m pipeline.definitions
```

Open [http://localhost:3000](http://localhost:3000) → Catalog → Materialize all.

Then in a second terminal:

```bash
uvicorn api.main:app --reload --port 8000
python agent/appeal_agent.py
```

---

## API endpoints

Base URL: `http://localhost:8000`

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/denial/{claim_id}` | Get one denial record by claim ID |
| GET | `/denials` | List recent denial records (params: `limit`, `status`) |

Interactive docs available at [http://localhost:8000/docs](http://localhost:8000/docs).

---

## MCP server

The pipeline is also exposed as a [Model Context Protocol](https://modelcontextprotocol.io) server so agents can call tools instead of HTTP.

From `healthpipeline`:

```bash
python api/run_mcp.py
```

| Tool | Purpose |
|------|---------|
| `get_denial_context` | Full `DenialContext` row for a claim ID |
| `list_pending_denials` | Unworked denials, sorted by appeal deadline |
| `record_outcome` | Insert an appeal outcome for ROI tracking |
| `get_workflow_rules` | Active payer / validation / escalation rules |
| `get_pipeline_health` | Last extraction run and data-quality counts |

| Resource | Purpose |
|----------|---------|
| `kalamon://workflow/prior-auth-denial` | Prior auth denial workflow rules as operational text |
| `kalamon://schema/denial-context` | DenialContext field and flag documentation |

**Example response — `GET /denial/{claim_id}`:**

```json
{
  "claim_id": "131272949",
  "patient_id": "131272944",
  "service_date": "2026-03-20",
  "denial_reason_code": null,
  "canonical_denial_code": null,
  "canonical_denial_description": null,
  "denial_category": null,
  "payer_name": null,
  "total_claim_amount": 26450.0,
  "diagnosis_codes": [],
  "procedure_codes": [],
  "validation_status": "flagged",
  "data_quality_flags": [
    "missing_optional:denial_reason_code",
    "missing_optional:payer_name",
    "missing_optional:diagnosis_codes",
    "missing_optional:procedure_codes"
  ]
}
```

---

## Database schema

| Table | Purpose |
|-------|---------|
| `raw_fhir_responses` | Raw JSONB from FHIR API — one row per resource |
| `clean_denial_records` | Validated, normalized denial records served to agents |
| `quarantine_records` | Records that failed required field validation |
| `extraction_log` | Run history for the extraction layer |
| `code_mappings` | X12 CARC denial code lookup table (~300 active codes) |

---

## Data sources used

| Source | Purpose |
|--------|---------|
| [Synthea](https://github.com/synthetichealth/synthea) | Synthetic patient FHIR data generation |
| [HAPI FHIR public server](https://hapi.fhir.org/baseR4) | Live FHIR R4 API for extraction testing |
| [x12.org CARC codes](https://x12.org/codes/claim-adjustment-reason-codes) | Authoritative X12 denial reason code list |

---

## Known limitations of this PoC

- **Synthea data lacks denial codes** — Synthea generates mostly paid claims. Real payer data will populate `denial_reason_code`, `diagnosis_codes`, and `payer_name` fields that appear null here.
- **Local only** — pipeline runs locally against a local PostgreSQL instance. Production deployment would require cloud PostgreSQL, hosted Dagster, and a deployed FastAPI instance.
- **No authentication** — the API has no auth layer. Production would require OAuth2 or API key authentication.
- **Single resource type** — currently extracts ExplanationOfBenefit only. Real pipeline would add Claim, ClaimResponse, Patient, and Coverage resources.

---

## What this enables

Once connected to real payer data:

- Agents can query clean, validated denial records via the API without touching raw FHIR data
- X12 denial codes are automatically mapped to human-readable categories
- Data quality gaps are surfaced explicitly so agents know what's missing before reasoning
- The pipeline runs nightly via Dagster, keeping denial records fresh
- Any agent — appeal generation, denial prediction, RCM analytics — can consume the same clean data layer

---

## License

Private — not for distribution.