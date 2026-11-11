# 0023. Sandbox proxy reports runtime names for the launcher's runsc check

- Status: accepted
- Date: 2026-11-11

## Context
ADR 0016 says `sandbox-launcher` refuses to start in prod unless `runsc` is a registered Docker
runtime. It also says `sandbox-proxy` allows container create, start, wait, attach, kill and
remove, "and nothing else". The launcher has no Docker socket. The only way it can learn which
runtimes exist is through the proxy, so the two rules can't both hold. A settings-only check
can't tell whether gVisor is actually installed on the host. Docker's full `GET /info` reply
exposes host details the launcher doesn't need: paths, labels, registry, swarm and plugin
settings.

## Decision
- The proxy allows one more call: `GET /info` (with the same optional `/v1.NN` prefix rule),
  with no query string and no body. It is the only `GET` allowed.
- The proxy never relays Docker's reply. It answers only `{"Runtimes": [<sorted names>]}`,
  taken from the keys of Docker's `Runtimes` object. Any other status or shape is answered
  with a 502, and the reason is logged (status code only, never reply contents).
- A successful answer is cached for 60 s, and only one daemon call runs at a time. A client
  looping on `/info` can't make the daemon rebuild its full system info on every request.
  Failures aren't cached, so a repaired daemon is seen on the next request.
- The launcher calls it once at startup (#84, PR 3c). In prod it exits unless `runsc` is
  listed. Outside prod it uses `runc` only when `runsc` is missing **and** the fallback is
  explicitly enabled. Otherwise it exits.
- This amends ADR 0016's list of allowed proxy actions. Everything else in ADR 0016 stands.

## Consequences
- The ADR 0016 startup check becomes a real check against the daemon, not a promise in config.
- Whoever can reach the proxy can learn which runtimes are configured on the host. That is
  harmless next to the create rights the launcher already has, and the proxy is reachable only
  on the internal network.
- The proxy still enforces `runsc` on every create. This check makes a misconfigured host fail
  fast at startup instead of on the first job.
