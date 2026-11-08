# Production image for the Caddy ingress (issue #132).
# The official caddy image has no DNS providers, so the Cloudflare DNS-01 plugin is compiled
# into a custom binary. caddy:build tracks the `caddy` module version; pin it like the other
# images (Dependabot proposes bumps).
ARG CADDY_VERSION=2.11.9

FROM caddy:${CADDY_VERSION}-builder AS builder
RUN xcaddy build \
    --with github.com/caddy-dns/cloudflare@v0.2.4

FROM caddy:${CADDY_VERSION}
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY Caddyfile /etc/caddy/Caddyfile
