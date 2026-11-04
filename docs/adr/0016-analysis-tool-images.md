# 0016. Analysis tools and their images

- Status: accepted
- Date: 2026-11-04

## Context
ADR 0014 runs each analyzer in a no-network sandbox, chosen by image digest from a fixed
allowlist. ADR 0015 adds an extractor and a pack-to-tree step inside that sandbox. This ADR
decides which tools go in, how their images are built and how their data stays current.

Three facts shape it:
- The project is AGPL-3.0-or-later, so bundled tools and rules need compatible licenses.
- The sandbox can't download anything, but several tools normally fetch rules or databases.
- Security tools are themselves supply-chain targets. In March 2026 attackers used stolen
  credentials to publish malicious Trivy releases and images and to move `trivy-action` version
  tags (CVE-2026-33634), which hit anyone who trusted a tag.

## Decision
### Tools
Licenses were checked against each project's repository or PyPI metadata on 2026-11-04.

| Tool | License | Used for | Issues |
|---|---|---|---|
| gitleaks | MIT | Secrets in the tree and fetched history | #92 |
| osv-scanner | Apache-2.0 | Vulnerable dependencies, offline only | #93 |
| Opengrep | LGPL-2.1 | SAST engine, with our own rules | #94 |
| trivy | Apache-2.0 | Terraform and Kubernetes config checks only | #95 |
| LIEF | Apache-2.0 | ELF, PE and Mach-O parsing | #102 |
| androguard | Apache-2.0 | APK parsing | #105 |

Supporting pieces also ship in the images: the ADR 0015 extractor (our own code, AGPL) and `git`
(GPL-2.0-only), which gitleaks needs in order to read history.

- **License compatibility:** all of these can ship alongside the project. Opengrep and `git` run
  only as separate processes and are never linked into our code. LIEF and androguard are
  imported by our analyzer code, which Apache-2.0 allows. Each image carries its tools' license
  texts, and `NOTICE` lists them.
- **SAST rules are ours.** They're written in this repository under the project license. We
  don't use `opengrep/opengrep-rules`: it's archived, adds a Commons Clause that forbids selling
  the software, and describes itself as for research, testing and benchmarking. We don't use the
  Semgrep registry either, because the Semgrep Rules License restricts hosted use (#94).
- **trivy has a narrow job:** `trivy config` with the checks bundled in the image. osv-scanner
  covers dependencies, so no trivy vulnerability database is needed.

### Images
- **One image per analyzer,** each holding one tool plus the shared extractor, with no build
  tools or package managers beyond what the tool needs at run time. A tool exploit therefore
  has no other tool to reach.
- **Built in CI, used by digest.** A `sandbox-images.lock` file maps each analyzer name to its
  image digest, and `sandbox-launcher` and `sandbox-proxy` allow nothing else. `:latest` and
  other tags are never used at run time.
- **Inputs are pinned too:** base images by digest, tool downloads by version and SHA-256
  checksum (never a moved tag or an install script), and Python libraries through a lockfile.
  Actions in the build workflow are pinned to commit SHAs, and that job holds only the
  permission needed to push images.
- **The two-week rule applies** (`security.md`): a tool version is eligible once its release is
  at least two weeks old. Versions named in an advisory are never used, including trivy v0.69.4
  to v0.69.6.
- **Upgrades go through a reviewed PR** that changes the pin and passes the analyzer's fixtures.

### Data
- **Nothing is fetched at run time.** Every tool runs in its offline mode, and an attempted
  update would fail anyway because the sandbox has no network.
- **Rules and checks** change with the tool version, through the same PR as any upgrade.
- **The OSV database is baked into the osv-scanner image,** which CI rebuilds daily with the
  same pinned tool and updates `sandbox-images.lock`. The two-week rule covers tool code, not
  this data. Each result records the database's date, and an image older than seven days fails
  the job rather than reporting a misleadingly clean result.

### Rejected
- **Downloading databases when a job starts:** this needs network access in the sandbox, which
  ADR 0014 forbids.
- **A shared OSV volume, synced by a passive task** (as first drafted in #93): it needs a second
  bind, which ADR 0014's proxy policy refuses, and lets a process outside the sandbox change
  what analyzers read without a new digest.
- **One image with every tool:** a single exploit would reach every tool, and the image would
  need rebuilding for any change.
- **`opengrep-rules` and Semgrep registry rules:** their licenses, as above.

## Consequences
- #93 changes: its daily sync becomes the CI image rebuild. The issue text needs updating.
- #94 has to write and maintain its own rules, so coverage starts small and grows on purpose.
- CI gains an image build workflow and a daily job. Each OSV refresh changes
  `sandbox-images.lock`, so the deploy has to pick up a new digest daily, or the seven-day
  limit will start failing dependency scans.
- Advisory data carries the licenses of its sources. #93 records the required attribution in
  `NOTICE`.
- The project doesn't currently have a `NOTICE` file; the first analyzer image adds it. If images
  are ever published outside the project, the LGPL and GPL source obligations must be met then.
- The tool list covers what is planned today. iOS (#107) and component detection (#104) may add
  tools, each subject to the same license and pinning rules.
- Residual risk: a malicious release that stays undetected past two weeks would still enter an
  image. The sandbox limits what it can reach: no network, no credentials, one job's input.
