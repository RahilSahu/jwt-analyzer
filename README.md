# JWT Analyzer

A small, zero-dependency Python tool that decodes a JSON Web Token and
audits it, without trusting it.

Decoding a JWT is not verification. The header and payload are only
base64url encoded, so anyone holding a token can read them, and the
contents mean nothing until the signature is checked with a trusted
key. This tool makes that distinction loud, shows what is inside the
token, and flags the problems that show up again and again in real
assessments.

## What it flags

- alg set to none, or a token with no signature at all
- A kid (key id) header: if the server uses it to look up the
  verification key without strict validation, kid is an injection
  point for path traversal, SQL injection and command injection
- A missing typ header (optional, but validators use it to tell
  token types apart)
- Missing exp, an expired token, or an exp more than 10 years out,
  with the actual dates printed, not just epoch numbers
- iat in the future, or an nbf (not-before) that has not been
  reached yet
- Missing iss or aud claims
- Sensitive-looking claims in the payload, such as password, secret,
  ssn or credit_card style key names (the payload is public to anyone
  holding the token)
- HS256, HS384 and HS512 tokens signed with a commonly used default
  secret. The tool tests a built-in list of 35 well-known defaults
  ("secret", "changeme", the jwt.io default "your-256-bit-secret",
  and similar tutorial and framework placeholders) against the
  signature with HMAC, and reports a critical finding naming the
  matched secret if one verifies

## Usage

```bash
python3 jwt_analyze.py "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
python3 jwt_analyze.py "eyJ..." --json
echo "eyJ..." | python3 jwt_analyze.py -
```

Exit code is 1 when a critical finding is present, 2 for a malformed
token, and 0 otherwise.

## Requirements

Python 3.9 or newer. No packages to install.

## Tests

The tests build real tokens with base64url and HMAC, including a
weak-secret token, an expired token, and an alg=none token, and run
fully offline:

```bash
python3 -m unittest discover -s tests
```

## Responsible use

Only analyse tokens from systems you own or are authorised to test.
A token is a credential: handle other people's tokens the way you
would handle their passwords, and never share a live token publicly.

## License

MIT, see LICENSE.
