# Responsible Use Policy and Terms

**attacksurf** is a defensive external attack surface management (EASM) platform. It is built to
help owners and defenders discover, monitor, and remediate misconfigurations in their own assets.

---

## 1. Authorized Assets Only

- You may only register, verify, and scan domains, IP addresses, websites, repositories, or binaries
  that **you own** or for which you hold **explicit, documented authorization** from the asset owner.
- Do not add or monitor third-party targets to probe external infrastructure, perform competitive
  reconnaissance, or bypass security controls.

## 2. Technical Safeguards Enforced by the Platform

attacksurf enforces authorization and non-exploitation boundaries in code ([security model](security.md)):

- **Passive vs. active separation:** passive checks query public DNS, public Certificate Transparency
  logs, and public RDAP registries. Any active check that connects directly to target services
  (`dns.takeover.http`, `dns.axfr`, and future web/port probes) requires an active, unexpired DNS
  TXT ownership proof (`_attacksurf-verify.<root>`), which is automatically re-checked every 20 hours
  and expires after 24 hours without confirmation.
- **No exploitation:** scanners only observe and report misconfigurations. Takeover checks never
  register, claim, or modify dangling third-party resources; zone-transfer checks count records in the
  first response only and discard zone contents.
- **SSRF & boundary protection:** `ScopeGuard` validates hostnames against the Public Suffix List
  and blocks private, loopback, link-local, metadata, and reserved IP ranges across DNS, HTTP,
  redirects, authoritative nameservers, and custom LLM URLs.

## 3. Prohibited Use

You must **not** use attacksurf (or fork/modify it without removing this policy notice on hosted
services you operate) to:

- Scan or probe targets without ownership or authorization
- Conduct denial-of-service, brute-force, credential stuffing, or fuzzing attacks
- Exploit discovered vulnerabilities or claim dangling cloud services belonging to others
- Bypass `ScopeGuard`, rate limits, or ownership verification controls

## 4. AI Triage & Third-Party LLM Providers

- AI features (per-finding triage and scan exposure summaries) are **optional** and send only
  normalized finding metadata, asset names, and bounded/escaped evidence excerpts inside
  `<scan_data>` blocks — never secrets, API keys, raw uploads, or database identifiers.
- Organization administrators who configure an external LLM provider or Bring-Your-Own-Key (BYOK)
  endpoint are responsible for reviewing that provider's data-handling and privacy terms and
  ensuring compliance with their organization's policies.

## 5. Self-Hosted & Public Instances (AGPL-3.0)

- **Self-hosters** are solely responsible for the targets they configure, the outbound traffic their
  deployment generates, and compliance with applicable laws and network-provider policies.
- **No warranty / limitation of liability:** as stated in the [GNU AGPL v3.0](../LICENSE) license
  (§§ 15–16), attacksurf is provided **"as is"** without warranty of any kind. The authors and
  maintainers are not liable for damages arising from authorized or unauthorized use.
- **Hosted public instances:** operators of a public or multi-tenant instance may suspend or delete
  accounts that scan unauthorized targets or abuse shared quotas, and must keep the AGPL §13
  source-code link intact when distributing modified versions over a network.

## 6. Reporting Abuse or Vulnerabilities

- **Security vulnerabilities in attacksurf itself:** report privately via GitHub Security
  Advisories ([SECURITY.md](../SECURITY.md)). Do not open public issues for exploitable bugs.
- **Abuse from a hosted instance:** contact the instance operator using the contact channel listed on
  that deployment.
