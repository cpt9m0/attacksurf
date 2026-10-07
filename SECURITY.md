# Security Policy

attacksurf is a security tool, so we take vulnerabilities in it seriously.

## Supported versions

The project is pre-1.0. Only the latest `main` branch and the most recent release receive
security fixes.

## Reporting a vulnerability

**Please do not open public issues, discussions, or PRs for security vulnerabilities.**

Report privately through GitHub:
**[Report a vulnerability](https://github.com/cpt9m0/attacksurf/security/advisories/new)**
(Security tab → "Report a vulnerability").

Please include:
- affected component and version / commit
- steps to reproduce or a proof of concept
- impact (what an attacker could do)
- any suggested fix

## What to expect

- Acknowledgement within **72 hours**
- An initial assessment within **7 days**
- Coordinated disclosure: we'll agree on a timeline with you (default 90 days max), publish a
  GitHub Security Advisory, and credit you unless you prefer otherwise.

## Scope

In scope: this repository's code, including tenant isolation, authentication, SSRF / scope
bypasses (making attacksurf scan or reach targets it shouldn't), injection, XSS, prompt
injection leading to data exposure, and secrets handling.

Out of scope: findings that require a compromised host or admin access, social engineering,
volumetric DoS, and vulnerabilities in third-party dependencies without a demonstrated impact on
attacksurf (report those upstream).

## Safe harbor

Good-faith research that follows this policy, avoids privacy violations and service disruption,
and only targets your own installation will not lead to legal action from the maintainers.
