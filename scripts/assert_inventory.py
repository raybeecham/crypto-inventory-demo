#!/usr/bin/env python3
"""Assert the demo CBOM contains the expected crypto findings."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from cbom import load_inventory


EXPECTED_FINDINGS = [
    {"api": "java.security.MessageDigest", "algorithm": "MD5", "risk_level": "HIGH", "risk_reason": "Broken hash"},
    {"api": "java.security.MessageDigest", "algorithm": "SHA-256", "risk_level": "LOW", "pqc_status": "SAFE"},
    {"api": "java.security.Signature", "algorithm": "SHA1withRSA", "risk_level": "HIGH", "pqc_status": "NOT_SAFE"},
    {"api": "java.security.Signature", "algorithm": "SHA256withRSA", "risk_level": "MEDIUM", "pqc_status": "NOT_SAFE"},
    {"api": "javax.crypto.Cipher", "algorithm": "DES", "mode": "CBC", "risk_level": "HIGH"},
    {"api": "javax.crypto.Cipher", "algorithm": "AES", "mode": "ECB", "risk_level": "HIGH"},
    {"api": "javax.crypto.Cipher", "algorithm": "AES", "mode": "GCM", "risk_level": "LOW", "pqc_status": "SAFE"},
    {
        "api": "java.security.KeyPairGenerator",
        "algorithm": "RSA",
        "key_size": 3072,
        "risk_level": "MEDIUM",
        "pqc_status": "NOT_SAFE",
        "harvest_now_decrypt_later_risk": True,
    },
    {"api": "java.security.SecureRandom", "algorithm": "SHA1PRNG", "risk_level": "MEDIUM"},
    {"api": "javax.net.ssl.SSLContext", "protocol": "TLSv1.2", "risk_level": "MEDIUM"},
]


def matches(record: dict[str, Any], expected: dict[str, Any]) -> bool:
    return all(record.get(key) == value for key, value in expected.items())


def describe(expected: dict[str, Any]) -> str:
    return ", ".join(f"{key}={value!r}" for key, value in expected.items())


def assert_inventory(path: Path) -> list[str]:
    records = load_inventory(path)
    failures: list[str] = []

    if len(records) != 11:
        failures.append(f"Expected 11 findings, got {len(records)}")

    critical = [record for record in records if record.get("risk_level") == "CRITICAL"]
    if critical:
        failures.append(f"Expected no CRITICAL findings, got {len(critical)}")

    for expected in EXPECTED_FINDINGS:
        if not any(matches(record, expected) for record in records):
            failures.append(f"Missing finding: {describe(expected)}")

    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", type=Path, help="Path to inventory.json")
    args = parser.parse_args(argv)

    failures = assert_inventory(args.inventory)
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1

    print(f"Inventory assertions passed for {args.inventory}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
