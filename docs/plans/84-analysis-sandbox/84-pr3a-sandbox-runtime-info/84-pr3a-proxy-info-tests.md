# Plan: tests for PR 3a (sandbox proxy `GET /info`)

## Context
PR 3a (branch `84-sandbox-runtime-info`, uncommitted) adds one read-only proxy call, `GET /info`.
It answers with Docker's runtime names only, keeps a good answer for 60 s, logs why it fails,
and moves the three Docker round trips into one `_docker_call` helper (ADR 0023). The code has
no tests yet (review finding #1). An existing test still lists `GET` among the refused request
types (finding #8). This plan adds the tests you asked for: happy path, boundaries, invalid
input, Docker failures and concurrency. No commit, and **no new test files**: the tests go
into the two existing proxy test files.

## Mocked external dependencies
- **The Docker daemon (the HTTP request over the Unix socket):** the existing `FakeDocker` in
  `tests/unit/sandbox_proxy/test_server.py`, a real Unix-socket server on a background thread
  that records calls and returns scripted replies. Nothing touches real Docker.
- **The cache clock:** no clock mocking, since patching `time.monotonic` would also affect
  threading. `RUNTIMES_CACHE_SECONDS` is set to 0 with `monkeypatch` to force expiry.
- **Reply size limit:** `MAX_DOCKER_INFO_BYTES` is set to a small value with `monkeypatch`, so
  boundary tests send kilobytes instead of 8 MiB.
- **Logs:** `structlog.testing.capture_logs()`, as in `tests/unit/ai/providers/test_anthropic.py`.
- **The database:** not used; the proxy has no database.

## Realistic test data
A trimmed but real-shaped `docker info` reply, as a module constant `DOCKER_INFO`:
`ServerVersion "27.3.1"`, `Name "vps-fra-01"`, `DockerRootDir "/var/lib/docker"`,
`Labels ["com.attacksurf.region=eu-central"]`, `RegistryConfig` with a mirror,
`DefaultRuntime "runc"`, and `Runtimes {"runc": {"path": "runc"}, "io.containerd.runc.v2":
{...}, "runsc": {"path": "/usr/local/bin/runsc", "runtimeArgs": ["--platform=systrap"]}}`.
The existing `IMAGE`, `CREATED` and `FOREIGN` constants are reused.

## Changes to `FakeDocker` (`test_server.py`)
- Add `do_GET`, which records the call and serves `/info` from new attributes:
  - `info_status` (200) and `info_body` (`DOCKER_INFO` as JSON);
  - `drop_info_reply` (close without answering);
  - `info_entered` / `info_release` events, mirroring the existing `create_entered` /
    `create_release`, to hold a request inside "Docker" for the concurrency tests.

## Tests in `tests/unit/sandbox_proxy/test_policy.py` (pure routing, no sockets)
Each group gets a one-line comment.

**Group: the runtime-info call is recognized (ADR 0023)**
- Add rows to `test_allowed_docker_calls_are_recognized`: `GET /info`, `GET /v1.30/info`
  (oldest allowed version), `GET /v1.47/info`, `GET /v1.99/info` (newest the pattern allows),
  each giving `"info"`.
- `test_info_route_keeps_the_versioned_path_and_has_no_container`: `Route("info", None,
  "/v1.47/info")`.
- `test_info_with_an_empty_query_string_is_canonicalized_to_the_bare_path`: `GET /info?`
  gives target `/info`.

**Group: anything else on the info path is denied**
- `test_info_call_variants_are_denied`, parametrized:
  - other methods: `POST /info`, `DELETE /info`;
  - options: `GET /info?format=json`, `GET /info?verbose=1&verbose=1`;
  - fragment: `GET /info#Runtimes`;
  - lookalike paths: `GET /infox`, `GET /info/`, `GET /INFO`, `GET /system/info`;
  - versions: `GET /v1.29/info`, `GET /v2.0/info`;
  - path tricks: `GET /v1.47/../info`, `GET /%69nfo`.

## Tests in `tests/unit/sandbox_proxy/test_server.py` (through the real proxy)

**Group: happy path, runtime names only**
- `test_info_returns_only_the_sorted_runtime_names`: the reply is exactly
  `{"Runtimes": ["io.containerd.runc.v2", "runc", "runsc"]}`.
- `test_info_never_relays_host_details_from_docker`: the reply contains none of
  `/var/lib/docker`, `vps-fra-01`, `/usr/local/bin/runsc`, `systrap` or the label.
- `test_versioned_info_is_forwarded_to_the_same_versioned_path`: Docker sees
  `("GET", "/v1.47/info")`.
- `test_info_forwards_no_client_headers_or_query`: `X-Registry-Auth` and `Cookie` sent by the
  client never reach Docker.

**Group: boundaries**
- `test_info_with_no_registered_runtimes_returns_an_empty_list`: `Runtimes: {}` gives `[]`.
- `test_info_with_only_runsc_registered_returns_just_runsc`.
- `test_info_reply_exactly_at_the_size_limit_is_accepted` /
  `test_info_reply_one_byte_over_the_size_limit_is_refused`: the limit is patched to 4096
  bytes, and padding a label makes the body exactly that size or one byte more.
- `test_info_reply_larger_than_the_general_reply_cap_is_accepted`: a body of about 1.1 MiB,
  above `MAX_DOCKER_REPLY_BYTES`, succeeds (guards review fix #4).

**Group: invalid client requests never reach Docker**
- `test_info_with_query_options_is_denied_before_docker`: 403, and `docker.calls == []`.
- `test_info_with_a_request_body_is_rejected`: `GET /info` with a JSON body gives 403.
- `test_chunked_info_request_is_rejected`: 403.
- Split the existing test to fix review finding #8:
  - `test_methods_other_than_get_post_delete_are_denied`: `HEAD`, `PUT`, `PATCH`, `OPTIONS`;
  - `test_get_is_denied_on_every_path_except_info`: `/containers/json`, `/_ping`, `/version`,
    `/images/json`, `/containers/{CREATED}/json` (even an owned container) and `/info/`.

**Group: Docker fails to answer (error states and logging)**
- `test_docker_error_status_on_info_is_a_gateway_error`, parametrized 404 / 500 / 503: 502
  `"Docker runtimes are unavailable."`, and a log entry `sandbox_proxy_info_failed` with
  `reason="docker_status"` and the status.
- `test_malformed_info_reply_is_a_gateway_error`, parametrized:
  - an HTML `502 Bad Gateway` page;
  - an empty body;
  - `[]`;
  - `{"Runtimes": null}`;
  - `{"Runtimes": ["runsc"]}` (a list, not an object);
  - a JSON body cut off midway.

  Each gives 502 and `reason="invalid_reply"`.
- `test_unreachable_docker_on_info_is_a_gateway_error`: socket removed, giving 502 and
  `reason="docker_unavailable"`.
- `test_docker_hanging_up_on_info_is_a_gateway_error`: `drop_info_reply` gives 502.
- `test_info_failure_logs_never_include_the_daemon_reply`: a 500 whose body contains
  `/var/lib/docker` and a registry token never shows up in the captured logs.
- The existing `test_failed_create_releases_reserved_capacity`,
  `test_uncertain_create_retains_capacity_until_named_cleanup_succeeds` and
  `test_unreachable_docker_is_a_gateway_error` already cover the create and cleanup paths
  that now go through `_docker_call` (fix #5). They stay unchanged as regression guards.

**Group: caching and concurrency**
- `test_repeated_info_calls_within_the_cache_window_reach_docker_once`: 3 requests give 1
  Docker call.
- `test_info_is_fetched_again_after_the_cache_window_expires`: the window is patched to 0, and
  Docker's runtimes change between calls (runsc gets registered). The second reply shows
  `runsc`.
- `test_failed_info_is_not_cached_so_a_repaired_daemon_is_seen_next_time`: first 500, then
  200, giving 502 then 200, with 2 Docker calls.
- `test_cached_runtimes_are_served_while_docker_briefly_fails`: within the window, a later
  500 from Docker still gives the cached 200.
- `test_concurrent_info_requests_share_a_single_docker_call`: the first request is held in
  `FakeDocker` and 8 more are sent from a thread pool. After release, all 9 get 200 and
  Docker saw 1 call.
- `test_slow_info_call_does_not_block_container_creation`: while `/info` is held in Docker,
  a create still returns 201. The cache lock covers runtimes only.

## Proving the tests can fail
The code already exists, so to show the tests can fail, run them against the old proxy
first:
1. `git stash push -- src/attacksurf/sandbox_proxy/`
2. Run the new `/info` tests and confirm they fail (403 or a missing route).
3. `git stash pop`

## Verification
```bash
uv run pytest tests/unit/sandbox_proxy -q
uv run ruff check . && uv run ruff format --check . && uv run pyright \
  && uv run lint-imports && uv run pytest        # full suite with Postgres, coverage >= 80%
```
Confirm coverage of `sandbox_proxy/server.py` and `policy.py` includes `_runtimes`,
`_fetch_runtimes`, `_runtime_names`, `_RuntimeCache` and `_action`
(`--cov-report=term-missing`). Nothing is committed.

## Files
- `tests/unit/sandbox_proxy/test_policy.py` (new rows and tests)
- `tests/unit/sandbox_proxy/test_server.py` (`FakeDocker.do_GET`, `DOCKER_INFO`, new groups,
  and the split method test)
