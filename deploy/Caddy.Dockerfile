# Production image for the Caddy ingress (issue #132).
# The official image is used as-is: Caddy does not need DNS plugins because Cloudflare terminates
# public TLS in front of the tunnel and the origin leg is plain HTTP on a private network.
# Pinned by digest like the other runtime images; Dependabot proposes bumps.
ARG CADDY_VERSION=2.11.9@sha256:0c2243efcf437ab7f7a978f1027fcf0d4f9be8a75df27b1b3fbc5dbe0ffa8cf0

FROM caddy:${CADDY_VERSION}
COPY Caddyfile /etc/caddy/Caddyfile
