#!/bin/sh
# Entry point for the Caddy ingress (issue #132).
# The Cloudflare plugin only accepts the token through the environment, but the file is a
# secret mount: read it here so it is never written to a compose file or an env file. The
# `exec` keeps Caddy as PID 1 so it receives stop signals directly.
set -eu

if [ -n "${CF_DNS_API_TOKEN_FILE:-}" ]; then
	CF_DNS_API_TOKEN="$(cat "$CF_DNS_API_TOKEN_FILE")"
	export CF_DNS_API_TOKEN
fi

exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
