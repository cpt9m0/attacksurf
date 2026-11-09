# 0020. Publish the instance through a Cloudflare Tunnel

- Status: accepted
- Date: 2026-11-08

## Context
ADR 0004 put Caddy on a single VPS with automatic TLS. The host we have (`lili`, Oracle Cloud
ARM, Ubuntu 24.04) was checked before building anything:

- It holds only a private address (`10.0.1.225/24`); no public IPv4 is configured on any
  interface, and nothing listens on 80/443.
- It is shared: jellyfin, uptime-kuma, a separate `csday` application and its own Cloudflare
  Tunnel already run there.
- The `attacksurf.dev` zone is on Cloudflare, and the repository owner chose to keep the
  orange-cloud proxy on.

Without a public address, Caddy cannot answer ACME HTTP-01, and opening 80/443 would mean
changing the host's networking for one of several tenants. The existing `csday-tunnel.service`
already shows the working pattern for this host.

## Decision
- **`cloudflared` is the only ingress** and publishes no ports: it dials out to Cloudflare, which
  owns DNS and TLS for the zone. The application stack is on a private Docker network.
- **Caddy listens on plain HTTP (`:80`) inside that network.** It does not redirect to HTTPS and
  manages no certificate: the public leg is always TLS at Cloudflare's edge, and `cloudflared`
  itself re-originates TLS to that edge. The zone therefore runs SSL mode **Full**, not Full
  (strict), which would require a certificate at an origin Caddy does not own.
- **`PROXY_COUNT=1`**: one trusted hop (Cloudflare). Requests carry Cloudflare's
  `X-Forwarded-For`; Caddy lists Docker's private ranges as trusted and forwards the chain. The
  app keys rate limits on `CF-Connecting-IP`, falling back to the leftmost `X-Forwarded-For`
  entry, so limits follow the visitor rather than an edge address.
- **Secrets are files on the host**, mounted as Compose secrets and readable only by the uid that
  needs each one. They never enter an image, a Compose file or the repository.

## Consequences
- No inbound ports, no host firewalling changes for one tenant, and TLS renewal happens at
  Cloudflare. Works unchanged if the host's address changes.
- The instance now depends on Cloudflare for availability and TLS; an outage at the edge is an
  outage here. Zone-level settings (SSL mode, Always Use HTTPS, routes) are manual, documented in
  `docs/deployment.md`.
- Full (strict) is not usable while the origin is plain HTTP behind the tunnel. Restoring it means
  giving Caddy its own publicly trusted certificate (DNS-01 again) and having `cloudflared` dial
  `https://caddy:443`.
- A dedicated VPS for the production instance remains an open question: this host is shared with
  unrelated services. Backups, Sentry, log rotation and host hardening stay in #29.
