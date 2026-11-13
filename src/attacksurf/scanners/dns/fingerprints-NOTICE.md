# Takeover fingerprint dataset — attribution and changes

`fingerprints.json` in this directory is derived from the
[can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) dataset by EdOverflow
and contributors, licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), vendored at pinned commit
`5bd4e12837911c8475486f1da922c9b9c706e632` (2025-02-08). This file is the attribution and
change notice the license requires; the dataset is used for detection only.

Changes made to the upstream `fingerprints.json` (76 entries at the pinned commit):

- Kept only the 25 entries marked `"vulnerable": true` that a scanner can act on mechanically:
  at least one CNAME pattern plus an NXDOMAIN signal or a non-empty HTTP fingerprint /
  `http_status`. Dropped as unusable: vulnerable entries with no CNAME pattern (Campaign
  Monitor, Canny, Cargo Collective, Digital Ocean, Getresponse, Pantheon, Pingdom,
  Readthedocs, Short.io) or no detection signal (Smugmug), and SmartJobBoard, whose only
  CNAME pattern is an IP literal. All `Not vulnerable` and `Edge case` entries are dropped.
- Reduced each entry to the fields the scanners use (`service`, `cname`, `fingerprint`,
  `nxdomain`, `http_status`); discussion/documentation links stay upstream.
- IP-literal CNAME patterns were dropped (Worksites): a CNAME target is never an IP literal.
- The synthetic upstream fingerprints `HTTP_STATUS=301` / `HTTP_STATUS=500` (Helprace,
  LaunchRock) are represented by the `http_status` field alone.

Known limitation, deliberate: fingerprints are matched as literal substrings, never as regular
expressions. A few upstream strings contain regex-style artifacts (`.*`, HTML entities) and
are therefore inert until upstream publishes them as plain text; compiling untrusted patterns
would be a ReDoS risk on untrusted response bodies.

To update: re-download `fingerprints.json` at a new pinned commit, re-apply the transform
above, update the commit SHA here, and adjust the pinned entry count in
`tests/unit/scanners/dns/test_takeover.py`.
