#!/usr/bin/env python3
"""JWT analyzer.

Decodes a JSON Web Token and audits it WITHOUT trusting it. Decoding a
JWT is not verification: anyone can read the header and payload, and
the contents mean nothing until the signature is checked with a key
you trust. This tool shows what is inside a token and flags common
problems:

- alg set to none, or a missing signature
- missing exp claim, an expired token, or an exp absurdly far ahead
- iat in the future
- missing iss or aud claims
- sensitive-looking claim names in the payload (password, secret,
  ssn, credit_card and similar)
- for HS256 tokens, a short list of notoriously common weak secrets
  is tested against the signature with HMAC. If one matches, that is
  a critical finding: the token was signed with a guessable secret.

Zero dependencies: Python 3.9+ standard library only. Use it on tokens
from systems you own or are authorised to test.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time

WEAK_SECRETS = ["secret", "password", "changeme", "secretkey", "jwtsecret", "123456", "key", "default"]

SENSITIVE_CLAIM_HINTS = (
    "password", "passwd", "secret", "ssn", "social_security",
    "credit_card", "creditcard", "card_number", "cvv", "pin",
    "private_key", "api_key", "apikey", "access_token", "refresh_token",
)

# An exp more than about 10 years out is almost always a mistake or a
# deliberate never-expiring token, both worth flagging.
MAX_REASONABLE_LIFETIME_SECONDS = 10 * 365 * 24 * 3600


class TokenError(ValueError):
    """Raised when a token cannot be decoded at all."""


def b64url_decode(segment: str) -> bytes:
    """Decode one base64url segment, tolerating missing padding."""
    if not segment:
        raise TokenError("Empty token segment")
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise TokenError(f"Segment is not valid base64url: {exc}") from exc


def decode_token(token: str) -> dict:
    """Split and decode a JWT without verifying anything.

    Returns a dict with header, payload, signature (bytes), the raw
    signing input, and the original segments.
    """
    token = token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenError(f"A JWT must have 3 dot-separated parts, found {len(parts)}")
    header_segment, payload_segment, signature_segment = parts
    try:
        header = json.loads(b64url_decode(header_segment))
    except json.JSONDecodeError as exc:
        raise TokenError(f"Header is not valid JSON: {exc}") from exc
    try:
        payload = json.loads(b64url_decode(payload_segment))
    except json.JSONDecodeError as exc:
        raise TokenError(f"Payload is not valid JSON: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise TokenError("Header and payload must both be JSON objects")
    signature = b64url_decode(signature_segment) if signature_segment else b""
    return {
        "header": header,
        "payload": payload,
        "signature": signature,
        "signing_input": f"{header_segment}.{payload_segment}".encode("ascii"),
        "has_signature": bool(signature_segment),
    }


def try_weak_secrets(decoded: dict) -> str | None:
    """If this is an HS256 token signed with a known weak secret, return it."""
    if decoded["header"].get("alg") != "HS256" or not decoded["has_signature"]:
        return None
    for secret in WEAK_SECRETS:
        candidate = hmac.new(secret.encode(), decoded["signing_input"], hashlib.sha256).digest()
        if hmac.compare_digest(candidate, decoded["signature"]):
            return secret
    return None


def analyse(decoded: dict, now: int | None = None) -> list[dict]:
    """Return findings as dicts with level (critical, warn, info) and message."""
    now = int(time.time()) if now is None else now
    header, payload = decoded["header"], decoded["payload"]
    findings: list[dict] = []
    add = lambda level, message: findings.append({"level": level, "message": message})

    alg = header.get("alg")
    if alg is None:
        add("critical", "Header has no alg value.")
    elif str(alg).lower() == "none":
        add("critical", "alg is 'none'. The token is unsigned by design and any server accepting it can be forged trivially.")
    if not decoded["has_signature"]:
        add("critical", "Token has no signature segment. It is not signed at all.")

    exp = payload.get("exp")
    if exp is None:
        add("warn", "No exp claim. The token never expires on its own.")
    elif not isinstance(exp, (int, float)):
        add("warn", f"exp claim is not a number: {exp!r}")
    else:
        if exp < now:
            add("warn", f"Token is expired (exp {int(exp)} is in the past).")
        if exp - now > MAX_REASONABLE_LIFETIME_SECONDS:
            add("warn", "exp is more than 10 years in the future. Long-lived tokens are a standing credential if leaked.")

    iat = payload.get("iat")
    if isinstance(iat, (int, float)) and iat > now + 60:
        add("warn", "iat is in the future. The issuing clock or the token is wrong.")

    if "iss" not in payload:
        add("info", "No iss (issuer) claim.")
    if "aud" not in payload:
        add("info", "No aud (audience) claim. Tokens without an audience can be replayed against other services that accept the same key.")

    for key in payload:
        lowered = str(key).lower()
        if any(hint in lowered for hint in SENSITIVE_CLAIM_HINTS):
            add("warn", f"Payload contains a sensitive-looking claim: {key!r}. JWT payloads are only base64 encoded, anyone holding the token can read this.")

    weak = try_weak_secrets(decoded)
    if weak is not None:
        add("critical", f"Signature verifies with the weak secret {weak!r} from the built-in common-secrets list. Anyone can forge tokens for this service.")
    return findings


def build_report(token: str, now: int | None = None) -> dict:
    decoded = decode_token(token)
    return {
        "header": decoded["header"],
        "payload": decoded["payload"],
        "has_signature": decoded["has_signature"],
        "weak_secret_found": try_weak_secrets(decoded),
        "findings": analyse(decoded, now=now),
        "warning": "Decoding is not verification. Unless the weak-secret check matched, this tool has not verified the signature, so do not trust these contents.",
    }


def print_report(report: dict) -> None:
    print("\nWARNING: decoding is not verification.")
    print(report["warning"])
    print("\nHeader:")
    print(json.dumps(report["header"], indent=2))
    print("\nPayload:")
    print(json.dumps(report["payload"], indent=2))
    print("\nFindings:")
    if not report["findings"]:
        print("  No problems found by these checks.")
    for finding in report["findings"]:
        print(f"  [{finding['level'].upper()}] {finding['message']}")
    print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Decode and audit a JWT without trusting it.")
    parser.add_argument("token", help="The JWT, or - to read it from stdin")
    parser.add_argument("--json", action="store_true", help="Print the report as JSON")
    args = parser.parse_args(argv)

    token = sys.stdin.read().strip() if args.token == "-" else args.token
    if not token:
        print("Error: no token supplied", file=sys.stderr)
        return 2
    try:
        report = build_report(token)
    except TokenError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)
    return 1 if any(f["level"] == "critical" for f in report["findings"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
