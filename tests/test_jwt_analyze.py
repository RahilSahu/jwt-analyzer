import base64
import hashlib
import hmac
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from jwt_analyze import WEAK_SECRETS, TokenError, analyse, build_report, decode_token, try_weak_secrets

NOW = 1_800_000_000  # fixed point in time so tests never rot
STRONG_SECRET = "7f3a9c1e5b8d2046f7a1c9e3b5d7082a4e6f1a3c5e7b9d0f2a4c6"  # random, not a default


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_token(header: dict, payload: dict, secret: str | None, digestmod=hashlib.sha256) -> str:
    header_part = b64url(json.dumps(header).encode())
    payload_part = b64url(json.dumps(payload).encode())
    signing_input = f"{header_part}.{payload_part}".encode()
    if secret is None:
        signature = ""
    else:
        signature = b64url(hmac.new(secret.encode(), signing_input, digestmod).digest())
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


class WeakSecretAlgTests(unittest.TestCase):
    def test_hs384_with_weak_secret_is_caught(self):
        token = make_token({"alg": "HS384", "typ": "JWT"}, GOOD_PAYLOAD, "secret", hashlib.sha384)
        self.assertEqual(try_weak_secrets(decode_token(token)), "secret")
        findings = analyse(decode_token(token), now=NOW)
        self.assertTrue(any(f["level"] == "critical" and "weak secret" in f["message"] for f in findings))

    def test_hs512_with_jwtio_default_is_caught(self):
        token = make_token({"alg": "HS512", "typ": "JWT"}, GOOD_PAYLOAD, "your-256-bit-secret", hashlib.sha512)
        self.assertEqual(try_weak_secrets(decode_token(token)), "your-256-bit-secret")

    def test_hs384_with_random_secret_is_not_flagged(self):
        token = make_token({"alg": "HS384", "typ": "JWT"}, GOOD_PAYLOAD, STRONG_SECRET, hashlib.sha384)
        self.assertIsNone(try_weak_secrets(decode_token(token)))

    def test_hs512_with_random_secret_is_not_flagged(self):
        token = make_token({"alg": "HS512", "typ": "JWT"}, GOOD_PAYLOAD, STRONG_SECRET, hashlib.sha512)
        self.assertIsNone(try_weak_secrets(decode_token(token)))

    def test_weak_secret_list_is_substantial(self):
        self.assertGreaterEqual(len(WEAK_SECRETS), 25)
        self.assertIn("your-256-bit-secret", WEAK_SECRETS)


class HeaderFlagTests(unittest.TestCase):
    def test_kid_header_is_flagged(self):
        token = make_token({"alg": "HS256", "typ": "JWT", "kid": "../../dev/null"}, GOOD_PAYLOAD, STRONG_SECRET)
        findings = analyse(decode_token(token), now=NOW)
        self.assertTrue(any("kid" in f["message"] and "injection" in f["message"] for f in findings))

    def test_no_kid_no_kid_finding(self):
        token = make_token({"alg": "HS256", "typ": "JWT"}, GOOD_PAYLOAD, STRONG_SECRET)
        findings = analyse(decode_token(token), now=NOW)
        self.assertFalse(any("kid" in f["message"] for f in findings))

    def test_missing_typ_is_flagged(self):
        token = make_token({"alg": "HS256"}, GOOD_PAYLOAD, STRONG_SECRET)
        findings = analyse(decode_token(token), now=NOW)
        self.assertTrue(any("typ" in f["message"] for f in findings))

    def test_present_typ_is_not_flagged(self):
        token = make_token({"alg": "HS256", "typ": "JWT"}, GOOD_PAYLOAD, STRONG_SECRET)
        findings = analyse(decode_token(token), now=NOW)
        self.assertFalse(any("typ" in f["message"] for f in findings))


class TemporalTests(unittest.TestCase):
    def test_nbf_in_future_is_flagged_with_date(self):
        payload = dict(GOOD_PAYLOAD, nbf=NOW + 3600)
        token = make_token({"alg": "HS256", "typ": "JWT"}, payload, STRONG_SECRET)
        findings = analyse(decode_token(token), now=NOW)
        nbf = [f["message"] for f in findings if "not valid yet" in f["message"]]
        self.assertTrue(nbf)
        self.assertIn("2027-01-15", nbf[0])

    def test_nbf_in_past_is_not_flagged(self):
        payload = dict(GOOD_PAYLOAD, nbf=NOW - 3600)
        token = make_token({"alg": "HS256", "typ": "JWT"}, payload, STRONG_SECRET)
        findings = analyse(decode_token(token), now=NOW)
        self.assertFalse(any("not valid yet" in f["message"] for f in findings))

    def test_expired_finding_prints_the_date(self):
        payload = dict(GOOD_PAYLOAD, exp=NOW - 3600, iat=NOW - 7200)
        token = make_token({"alg": "HS256", "typ": "JWT"}, payload, STRONG_SECRET)
        findings = analyse(decode_token(token), now=NOW)
        expired = [f["message"] for f in findings if "expired" in f["message"]]
        self.assertTrue(expired)
        self.assertIn("2027-01-15", expired[0])

    def test_iat_in_future_is_flagged_with_date(self):
        payload = dict(GOOD_PAYLOAD, iat=NOW + 7200)
        token = make_token({"alg": "HS256", "typ": "JWT"}, payload, STRONG_SECRET)
        findings = analyse(decode_token(token), now=NOW)
        future = [f["message"] for f in findings if "iat is in the future" in f["message"]]
        self.assertTrue(future)
        self.assertIn("2027-01-15", future[0])

    def test_fully_valid_token_has_no_warn_or_critical(self):
        payload = dict(GOOD_PAYLOAD, nbf=NOW - 3600)
        token = make_token({"alg": "HS256", "typ": "JWT"}, payload, STRONG_SECRET)
        findings = analyse(decode_token(token), now=NOW)
        self.assertEqual([f for f in findings if f["level"] in ("warn", "critical")], [])


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
