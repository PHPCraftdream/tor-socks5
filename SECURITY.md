# Security Policy

This document describes how to report security vulnerabilities in
**tor-socks5**, the local SOCKS5 proxy with embedded Tor and
self-managed bridge infrastructure.

## Scope

The following components of this repository are in scope:

- SOCKS5 server and connection handling
- Authentication module
- Bridge fetching (all sources) and candidate pool management
- Bridge probing and stability scoring
- Egress and circuit-selection logic
- Pluggable-transport dispatch (busybox mode, obfs4, webtunnel)
- Service installer
- Configuration parsing and validation

## Out of Scope

Vulnerabilities in upstream dependencies should be reported to their
respective maintainers:

- **arti-client / tor-\* crates** (Tor implementation):
  <https://gitlab.torproject.org/tpo/core/arti/-/issues>
- **ptrs-gesher / lyrebird** (obfs4 and webtunnel transports):
  <https://github.com/PHPCraftdream/ptrs-gesher>
- **Tor protocol or Tor network** issues:
  <https://gitlab.torproject.org/tpo/core/tor/-/issues>

If you are unsure whether a bug belongs here or upstream, err on the
side of reporting it here -- we will triage and redirect if needed.

## How to Report a Vulnerability

- **Preferred method**: use GitHub's private vulnerability reporting.
  Navigate to the repository's **Security** tab and select
  **Report a vulnerability**. Do **not** open a public issue.
- **PGP-encrypted email**: acceptable if you prefer it. A dedicated
  contact address and PGP key will be published here upon the first
  report received through GitHub. Until then, please use the GitHub
  mechanism above.

## What to Include

A good report helps us act quickly. Please provide:

- Affected version -- git SHA, release tag, or branch name.
- Step-by-step reproduction instructions.
- Expected behavior vs. actual behavior.
- Your assessment of impact (confidentiality, integrity, availability).
- Any suggested fix or mitigation, if you have one.

## Response Timeline

This is a small, volunteer-maintained project. The following targets
are best-effort aspirations, not contractual commitments:

- **Initial acknowledgement**: within 7 days of report.
- **Triage and severity assessment**: within 14 days.
- **Fix or mitigation plan**: within 30 days.

If circumstances delay any of these, we will communicate updated
expectations in the private thread.

## Coordinated Disclosure

We ask reporters to allow reasonable time for a fix to ship before
any public disclosure. The standard window is **90 days** from the
initial report, but we are open to adjusting this on a case-by-case
basis depending on severity and complexity.

If you have not received a substantive response within 14 days, you
are free to escalate or disclose at your discretion.

## Supported Versions

Security fixes are provided for:

- The `main` branch (development head).
- The latest published release.

Older releases do not receive backports. Users are encouraged to
stay on the latest release.

## Credit

We are happy to credit reporters in the CHANGELOG and release notes
for responsibly disclosed vulnerabilities. If you prefer to remain
anonymous, let us know in your report and we will respect that.
