# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a vulnerability

Gatekeeper is a security tool - please hold it to the same standard.

If you find a vulnerability in Gatekeeper itself, **do not open a public
issue**. Email the maintainer directly or use
[GitHub's private vulnerability reporting](https://github.com/sbacaro/gatekeeper/security/advisories/new).

Include:
- A description of the issue and its impact.
- Steps to reproduce or a proof of concept.
- The Gatekeeper version (`git rev-parse HEAD` if running from source).

You can expect an initial response within 7 days. We will credit reporters in
the release notes unless anonymity is requested.

## Scope notes

- Gatekeeper binds its dashboard to `127.0.0.1` only and serves only files
  inside `reports/`. Reports of remote exposure via those mechanisms are
  in scope; local-only access by the running user is by design.
- Findings produced by the scanners about *scanned* projects are not
  Gatekeeper vulnerabilities.
