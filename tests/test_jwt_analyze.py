import base64
import hashlib
import hmac
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from jwt_analyze import TokenError, analyse, build_report, decode_token, try_weak_secrets

NOW = 1_800_000_000  # fixed point in time so tests never rot


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_token(header: dict, payload: dict, secret: str | None) -> str:
    header_part = b64url(json.dumps(header).encode())
    payload_part = b64url(json.dumps(payload).encode())
    signing_input = f"{header_part}.{payload_part}".encode()
    if secret is None:
        signature = ""
    else:
        signature = b64url(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())
    return f"{header_part}.{payload_part}.{signature}"


GOOD_PAYLOAD = {"sub": "1234", "iss": "https://issuer.example", "aud": "api",
                "iat": NOW - 60, "exp": NOW + 3600}


class WeakSecretTests(unittest.TestCase):
    def test_valid_hs256_with_secret_is_flagged_weak(self):
        token = make_token({"alg": "HS256", "typ": "JWT"}, GOOD_PAYLOAD, "secret")
        decoded = decode_token(token)
        self.assertEqual(try_weak_secrets(decoded), "secret")
        findings = analyse(decoded, now=NOW)
        self.assertTrue(any(f["level"] == "critical" and "weak secret" in f["message"] for f in findings))
        self.assertFalse(any("expired" in f["message"] for f in findings))

    def test_strong_secret_is_not_flagged(self):
        token = make_token({"alg": "HS256", "typ": "JWT"}, GOOD_PAYLOAD, "a-long-random-secret-nobody-guesses")
        self.assertIsNone(try_weak_secrets(decode_token(token)))


class ExpiryTests(unittest.TestCase):
    def test_expired_token_is_flagged(self):
        payload = dict(GOOD_PAYLOAD, exp=NOW - 3600, iat=NOW - 7200)
        token = make_token({"alg": "HS256", "typ": "JWT"}, payload, "a-long-random-secret-nobody-guesses")
        findings = analyse(decode_token(token), now=NOW)
        self.assertTrue(any("expired" in f["message"] for f in findings))

    def test_missing_exp_warns(self):
        payload = {k: v for k, v in GOOD_PAYLOAD.items() if k != "exp"}
        token = make_token({"alg": "HS256", "typ": "JWT"}, payload, "a-long-random-secret-nobody-guesses")
        findings = analyse(decode_token(token), now=NOW)
        self.assertTrue(any("never expires" in f["message"] for f in findings))


class AlgNoneTests(unittest.TestCase):
    def test_alg_none_is_critical(self):
        token = make_token({"alg": "none", "typ": "JWT"}, GOOD_PAYLOAD, None)
        findings = analyse(decode_token(token), now=NOW)
        critical = [f["message"] for f in findings if f["level"] == "critical"]
        self.assertTrue(any("none" in m for m in critical))
        self.assertTrue(any("no signature" in m for m in critical))


class MalformedTests(unittest.TestCase):
    def test_two_part_token_raises_clean_error(self):
        with self.assertRaises(TokenError):
            decode_token("only.two")

    def test_garbage_raises_clean_error(self):
        with self.assertRaises(TokenError):
            build_report("not-a-jwt-at-all")

    def test_sensitive_claim_is_flagged(self):
        payload = dict(GOOD_PAYLOAD, password="hunter2")
        token = make_token({"alg": "HS256", "typ": "JWT"}, payload, "a-long-random-secret-nobody-guesses")
        findings = analyse(decode_token(token), now=NOW)
        self.assertTrue(any("password" in f["message"] for f in findings))


if __name__ == "__main__":
    unittest.main()
