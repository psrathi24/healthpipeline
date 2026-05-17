"""
Fetch recent denial records from the local API and draft prior-auth appeal letters via Groq.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv

_HEALTHPIPELINE_ROOT = Path(__file__).resolve().parent.parent
DENIALS_URL = os.environ.get("DENIALS_API_URL", "http://localhost:8000/denials")
GROQ_MODEL = "llama-3.3-70b-versatile"


def _ensure_groq() -> None:
    try:
        import groq  # noqa: F401
    except ImportError:
        print("Installing groq …", file=sys.stderr)
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "groq"],
        )


def _load_env() -> str:
    load_dotenv(_HEALTHPIPELINE_ROOT / ".env")
    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    if not api_key:
        raise ValueError("GROQ_API_KEY must be set in healthpipeline/.env")
    return api_key


def _fetch_denials(limit: int = 5) -> list[dict]:
    resp = requests.get(DENIALS_URL, params={"limit": limit}, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, list):
        raise ValueError(f"Expected list from {DENIALS_URL}, got {type(data).__name__}")
    return data


def _build_prompt(record: dict) -> str:
    record_json = json.dumps(record, indent=2, default=str)
    flags = record.get("data_quality_flags") or []
    flags_note = (
        "None reported."
        if not flags
        else "\n".join(f"- {f}" for f in flags)
    )
    return f"""You are a healthcare appeals specialist. Using only the denial record below, write a prior authorization appeal letter to the payer.

Requirements:
- Address the payer by name when available in the record.
- Reference claim_id, service_date, diagnosis_codes, procedure_codes, and denial_reason_code when present.
- The record may be incomplete. Acknowledge any gaps listed in data_quality_flags and explain what you are inferring or what additional documentation would strengthen the appeal.
- Use a professional, concise tone suitable for a payer medical director.
- Do not invent clinical facts not supported by the record; state assumptions clearly.
- End with a clear request for overturning the denial or granting prior authorization.

data_quality_flags:
{flags_note}

Denial record (JSON):
{record_json}

Write the full appeal letter body only (no meta-commentary about the prompt)."""


def _generate_appeal(client, record: dict) -> str:
    completion = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[
            {
                "role": "system",
                "content": (
                    "You draft medically accurate prior authorization appeal letters "
                    "from structured denial data. You never fabricate patient identifiers."
                ),
            },
            {"role": "user", "content": _build_prompt(record)},
        ],
        temperature=0.3,
        max_tokens=2048,
    )
    return (completion.choices[0].message.content or "").strip()


def main() -> None:
    _ensure_groq()
    from groq import Groq

    print("DEBUG: starting", file=sys.stderr)

    try:
        client = Groq(api_key=_load_env())
        print("DEBUG: groq client created", file=sys.stderr)
    except Exception as e:
        print(f"DEBUG: failed at client creation: {e}", file=sys.stderr)
        return

    denials = _fetch_denials(limit=5)
    print(f"DEBUG: fetched {len(denials)} records", file=sys.stderr)

    if not denials:
        print("No denial records returned from API.")
        return

    for record in denials:
        claim_id = record.get("claim_id") or "(unknown claim_id)"
        print("=" * 72)
        print(f"claim_id: {claim_id}")
        print("=" * 72)
        try:
            print(_generate_appeal(client, record))
        except Exception as exc:
            print(f"Error generating appeal for {claim_id}: {exc}", file=sys.stderr)
        print()


if __name__ == "__main__":
    main()