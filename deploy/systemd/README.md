# Pull-based CD units

`attacksurf-deploy.timer` runs `scripts/deploy.sh` on the host every few minutes, so a merge
to `main` reaches production within one interval. The host pulls; nothing dials in.

- No inbound port is opened.
- No GitHub secret and no self-hosted runner: the box only needs read access to the public
  repository.
- The service runs as **root** because `/etc/attacksurf/*` is mode 600 root-owned and the
  docker socket is root-equivalent.
- `flock` on `/var/lock/attacksurf-deploy.lock` guarantees two deploys never overlap, even if
  a manual run races the timer. The **unit owns the lock**: `scripts/deploy.sh` must not take
  the same file, or the nested `flock` sees the lock held and the deploy silently skips.
- Every line the script prints — including the deployed SHA — goes to the journal under
  `attacksurf-deploy`.

`docs/deployment.md` covers what the script does and how to recover by hand; this file is only
the unit installation.

## Prerequisites

1. `/opt/attacksurf` holds the repository checkout and `deploy/attacksurf.env` symlinks to
   `/etc/attacksurf/attacksurf.env`. `scripts/deploy.sh` must exist and be executable: the
   script bootstraps its own git checkout, but it cannot fetch itself, so on a host where
   `/opt/attacksurf` is still a copied tree copy it once before enabling the timer
   (`sudo install -D -m 755 scripts/deploy.sh /opt/attacksurf/scripts/deploy.sh`).
2. `docker.service` is running and `docker compose -f /opt/attacksurf/compose.prod.yaml ps`
   shows a healthy stack.
3. Branch protection and required CI checks are on for `main`: a timer deploys whatever lands
   there, so CI is the safety gate.

## Install

```bash
sudo install -m 644 deploy/systemd/attacksurf-deploy.tmpfiles.conf /etc/tmpfiles.d/
sudo systemd-tmpfiles --create /etc/tmpfiles.d/attacksurf-deploy.tmpfiles.conf
sudo install -m 644 deploy/systemd/attacksurf-deploy.service \
                     deploy/systemd/attacksurf-deploy.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now attacksurf-deploy.timer
```

The tmpfiles line is not optional: `/run/lock` is world-writable and sticky, and
`fs.protected_regular=2` applies to root too, so a lock file created by a non-root manual run
would make the root unit fail with `Permission denied` on every tick. `systemd-tmpfiles` creates
it root-owned at boot and here.

The service unit deliberately has no `[Install]` section: the timer is the entry point, and
`systemctl start attacksurf-deploy` works for a one-off run without enabling anything.

## Verify

```bash
systemctl list-timers attacksurf-deploy.timer      # NEXT / LAST / PASSED
systemctl status attacksurf-deploy.timer
journalctl -u attacksurf-deploy -n 50 --no-pager   # the deploy log, SHA included
cat /var/lib/attacksurf/deployed-sha               # what the script says is live
docker ps --filter name=attacksurf-prod-web-1 --format '{{.Image}}'
```

A run that finds the lock already held logs nothing and exits 0 — that is the overlap guard
doing its job, not a failed deploy.

## Operate

```bash
sudo systemctl start attacksurf-deploy        # deploy now, same path as the timer
sudo systemctl stop attacksurf-deploy.timer   # pause CD (the unit stays enabled)
sudo systemctl disable --now attacksurf-deploy.timer
```

## Uninstall

```bash
sudo systemctl disable --now attacksurf-deploy.timer
sudo rm /etc/systemd/system/attacksurf-deploy.{service,timer}
sudo systemctl daemon-reload
```

## Troubleshooting

| Symptom | Check |
|---|---|
| Timer active but no runs | `systemctl list-timers --all`; a failed unit still fires on the next tick, so look at `journalctl -u attacksurf-deploy` for the script's error |
| `status=.../FAILURE` right away | `scripts/deploy.sh` missing or not executable, or `docker.service` down (`systemctl status docker`) |
| `flock: cannot open lock file /var/lock/attacksurf-deploy.lock: Permission denied` | the lock file is owned by a non-root user; `sudo install -m 644 -o root -g root /dev/null /var/lock/attacksurf-deploy.lock` (or re-run `systemd-tmpfiles --create`) |
| Deploy skipped every tick | lock held by a stuck run: `sudo fuser -v /var/lock/attacksurf-deploy.lock` |
| Deployed SHA unchanged after a merge | `git -C /opt/attacksurf fetch` by hand; check the script's own log for "already deployed" |
