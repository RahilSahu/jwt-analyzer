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
- Missing exp, an expired token, or an exp more than 10 years out
- iat in the future
- Missing iss or aud claims
- Sensitive-looking claims in the payload, such as password, secret,
  ssn or credit_card style key names (the payload is public to anyone
  holding the token)
- HS256 tokens signed with a notoriously common weak secret. The tool
  tests a short built-in list ("secret", "password", "changeme" and a
  few more) against the signature with HMAC, and reports a critical
  finding if one matches

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
