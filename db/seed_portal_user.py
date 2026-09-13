"""Seed a portal user for local development. Never commit real passwords."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import psycopg2
from dotenv import load_dotenv
from psycopg2.extras import RealDictCursor

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from api.auth_security import hash_password, validate_password_strength  # noqa: E402

ROLES = ("admin", "billing", "readonly")


def main() -> None:
    load_dotenv(_ROOT / ".env")
    parser = argparse.ArgumentParser(description="Create a Kalamon portal user")
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--role", default="admin", choices=ROLES)
    parser.add_argument("--client-id", default="demo-practice")
    args = parser.parse_args()

    strength = validate_password_strength(args.password)
    if strength:
        raise SystemExit(strength)

    conn = psycopg2.connect(
        host=os.environ.get("PGHOST", "localhost"),
        port=os.environ.get("PGPORT", "5432"),
        dbname=os.environ.get("PGDATABASE", "healthpipeline"),
        user=os.environ.get("PGUSER", os.environ.get("USER", "postgres")),
        password=os.environ.get("PGPASSWORD", ""),
    )
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO portal_users (email, hashed_password, full_name, role, client_id)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (email) DO UPDATE SET
                    hashed_password = EXCLUDED.hashed_password,
                    full_name = EXCLUDED.full_name,
                    role = EXCLUDED.role,
                    client_id = EXCLUDED.client_id,
                    is_active = TRUE,
                    failed_login_attempts = 0,
                    locked_until = NULL,
                    updated_at = NOW()
                RETURNING id, email, role
                """,
                (
                    args.email.strip().lower(),
                    hash_password(args.password),
                    args.name,
                    args.role,
                    args.client_id,
                ),
            )
            row = cur.fetchone()
        conn.commit()
        print(f"Upserted portal user {row['email']} ({row['role']}) id={row['id']}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
