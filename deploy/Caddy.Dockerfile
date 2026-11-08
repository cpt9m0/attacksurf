# Production image for the Caddy ingress (issue #132).
# The official image is used as-is: Caddy does not need DNS plugins because Cloudflare terminates
# public TLS in front of the tunnel and the origin leg is plain HTTP on a private network.
ARG CADDY_VERSION=2.11.9

FROM caddy:${CADDY_VERSION}
COPY Caddyfile /etc/caddy/Caddyfile
