<!--
HOW TO USE THIS TEMPLATE
Copy to docs/plans/<issue#>-<slug>/<issue#>-<slug>.md (one folder per issue; a split PR gets its
own subfolder, e.g. <issue#>-pr<N>-<slug>/NN-<slug>.md, one file per commit). One plan = one commit. Replace every <placeholder>, delete every HTML comment and any
section that truly does not apply (say "None" rather than leaving it empty). Keep the section
order: readers rely on it. Plans hold the *intent and checks* for the commit, not the code itself.
-->

# Plan: <PR label, e.g. "PR 3b">, commit <N>: `<type>(<scope>): <subject>`

<!-- Subject = the Conventional Commit subject: imperative, <= 72 chars, types and scopes from
AGENTS.md ("Issues, commits, PRs"). -->

Branch `<issue#>-<slug>` · `Refs #<issue>` · follows `<short-sha> <previous commit subject>`
(commit <N-1> of <PR label>; see `<relative path to the split plan or epic doc>`).

## Purpose

<!-- Two paragraphs: the same idea told twice, for two readers. -->

**In plain words.** <3-6 sentences, no jargon, no file or function names. What problem does this
commit solve, what does it add, and what can it NOT do (the guarantee or limit that matters)?
A newcomer should understand why the commit exists after reading only this paragraph.>

**Technical.** <What is added or changed, by name: module paths, public functions with
signatures, the contract or ADR/rule it implements (`ADR <NNNN>`, `AGENTS.md` rule <N>). State
what it depends on, what it deliberately does NOT import or touch (layer rules), and how the
change is proven correct (which test or check catches drift).>

## Context
<Where the project stands: what earlier commits produced (name the types and functions this
commit builds on), what is missing today, and which later commit needs this one. Say why this is
a separate commit (what it keeps isolated, e.g. "pure module, no I/O, so it is tested alone").>

## Decisions
<!-- One numbered item per non-obvious choice a reviewer could question. Format: **bold
decision**, then the reason and the rejected alternative if there was one. Include the exact
signature when it differs from an earlier sketch. Always end with the scope-of-docs decision. -->
1. **<Decision>.** <Why; what the earlier plan or sketch said and how this differs.>
   `<exact signature or value if relevant>`
2. **<Decision about duplicated or shared constants / config>.** <Where they live, why they are
   not imported, and which test guards them.>
3. **<Decision about boundaries: what is in/out of the interface>.** <What the caller can and
   cannot influence.>
4. **<Decision about coupling to another component>.** <How it mirrors that component's rule.>
5. **<Defensive checks>.** <Which invalid inputs are rejected locally and why a clear local error
   beats a downstream failure.>
6. **<Something deliberately left out>.** <Which later commit owns it.>
7. **<Docs in this commit or not>.** <e.g. "No docs in this commit. Commit <N> of <PR label>
   carries `AGENTS.md`, `docs/architecture.md`, `CHANGELOG.md` and `STATE.md`." Otherwise list the
   docs updated here per the `finish-task` skill.>

## Requirements
<!-- Concrete, checkable statements about WHAT the code must be/do (structure and behavior).
Each is a checkbox a reviewer can tick by reading the diff. Be exact: key names, values, error
types. Acceptance criteria below prove these; do not repeat them here. -->
- [ ] `<path/to/new_module.py>` exists, <purity/layer constraints: no I/O, imports only X>.
- [ ] `<function>` returns <exact shape: type, keys, values, ordering>.
- [ ] <Field-by-field or rule-by-rule mapping from inputs to outputs>.
- [ ] <Fixed values that must never be configurable>.
- [ ] <Conditional behavior: "X only when Y">.
- [ ] `<ExceptionType>` (message without <sensitive input>) for <invalid input 1>, <invalid input
      2>, <invalid input 3>.
- [ ] <Isolation/immutability: fresh objects per call, no shared mutable state>.
- [ ] <Anything copied from another layer is covered by a parity test>.
- [ ] No change to <list of files/packages that must stay untouched> (<reason, e.g. the existing
      import contract already covers the new module>).

## Acceptance criteria
<!-- How we KNOW the requirements hold: observable outcomes tied to tests or commands. Bold the
kind of check, then the proof. Cover happy path, contract with neighbors, tightness (golden),
guards for future additions, negatives, isolation and the quality gate. -->
- [ ] **Contract:** <inputs, including the extremes> produce output that <the neighboring
      component's real validator> accepts, under <the exact configuration used in the test>.
- [ ] **Contract (<special case>):** <passes when X, rejected when not X (proves the condition)>.
- [ ] **Contract (<negative case>):** <output never contains Y when Z>.
- [ ] **Tight fit:** an exact-body (golden) test pins every key and value, so any added or
      changed field is a visible test diff.
- [ ] **Catalog/registry guard:** every <registered item> builds output that passes the contract
      (vacuous while empty); keeps future additions honest.
- [ ] **Negative:** <invalid inputs> raise `<ExceptionType>`; the message does not contain
      <the input>.
- [ ] **Isolation:** `uv run lint-imports` passes; <module> imports nothing its contract forbids;
      <other package> is imported in tests only.
- [ ] **Gate:** `ruff check`, `ruff format --check`, `pyright`, `lint-imports` and full `pytest`
      pass with coverage >= 80%; the commit passes the hooks without `--no-verify`.

## Changes

### 1. `<src/attacksurf/path/to/module.py>` (~<N> lines)
- Module docstring: <what it is the single place for; why anything is duplicated>.
- Constants: `<NAME>`, `<NAME>`, `<NAME>`.
- `<public_function(...)>` as above, composed of small helpers (`<_helper_a>`, `<_helper_b>`) so
  each output field is traceable to an input. Reuses `<existing types>` from `<module>`; no new
  <dataclasses/abstractions>.

### 2. Tests, `<tests/unit/path/test_module.py>` (written first)
Style follows `<existing test file to imitate>` (its `<fixture>` is the reference for <golden
data>). The file is split into <N> sections by scenario type, each under a comment banner, so a
reader can see what is covered at a glance. <How shared fixtures/objects are built.>

#### A. Happy path (valid input → the exact output, accepted by <neighbor>)
| Test | Given | Expect |
|---|---|---|
| `test_<default_case>_<builds_the_exact_output>` | <default inputs> | <full output equals the golden value (pins every key and value)> |
| `test_<output>_is_accepted_by_<neighbor>` (param `<a>`, `<b>`) | <same, configuration variant> | `<validator>` does not raise |
| `test_each_<input>_lands_in_its_own_<field>` (param, one per input field) | <one custom value> | <only the mapped field(s) change> |
| `test_<source_fields>_come_from_<source>` | <specific source values> | <exact derived fields; forbidden keys absent> |
| `test_<special_case>_gets_<extra>` | <special input> | <extra present, validator passes> |
| `test_<other_cases>_never_get_<extra>` | <ordinary input> | <extra absent> |
| `test_output_is_json_serializable` | <any valid output> | `json.loads(json.dumps(x)) == x` |
| `test_each_call_returns_fresh_objects` | <two calls, mutate one> | <other output and source unchanged> |
| `test_<upstream_result>_feeds_the_<function>` | <real result of the previous commit's function> | <passes the validator> |
| `test_every_<registry_item>_builds_an_accepted_<output>` (param over `<REGISTRY>`) | <each real item> | passes; vacuous while empty, guards future additions |

#### B. Boundary cases (edges of what is allowed)
| Test | Given | Expect |
|---|---|---|
| `test_<inputs>_at_each_<ceiling>_are_accepted` (param per field + all at once) | <values exactly at the maximum> | <validator passes (note any special formatting)> |
| `test_<inputs>_at_the_minimum_are_accepted` (param per field) | <each input = minimum> | <built and accepted> |
| `test_single_item_<collection>_is_kept` | <one-element input> | <one-element output> |
| `test_<condition>_matches_the_name_exactly` (param `<exact>`, `<near miss 1>`, `<near miss 2>`) | <near-miss values> | <special behavior absent> |
| `test_<input>_with_<allowed unusual characters>_is_accepted` | <e.g. dots, hyphens, underscores> | <passes through unchanged and validates> |
| `test_<deeply nested / long>_input_is_accepted` | <large but legal input> | <passes> |

<One line on what is NOT a case here and where it is covered instead (e.g. "One above a ceiling
is rejected earlier by `<type>`, so it can never reach `<function>`").>

#### C. Invalid inputs (must raise `<ExceptionType>`, message never echoes the input)
| Test | Given | Expect |
|---|---|---|
| `test_<invalid_input_1>_is_rejected` (param `<value>`, `<value>`) | <what is wrong with it> | `<ExceptionType>` |
| `test_<invalid_input_2>_is_rejected` (param `<value>`, `<value>`, `<value>`) | <what it could smuggle in> | `<ExceptionType>` |
| `test_unknown_<option>_is_rejected` (param `""`, `"<unknown>"`, `"<wrong case>"`, `"<trailing space>"`) | <value outside the allowed set> | `<ExceptionType>` |
| `test_error_messages_do_not_echo_inputs` | <each case above> | `str(exc)` contains none of the input values |

#### D. Neighbor rejection and drift guards (the contract, including its error side)
| Test | Given | Expect |
|---|---|---|
| `test_<special_output>_is_refused_when_<neighbor config lacks X>` | <output + config missing or wrong X> | `<RejectionError>` (proves the output depends on the right X) |
| `test_output_is_refused_for_<value not on the allowlist>` | <config lists a different value> | `<RejectionError>` |
| `test_output_is_refused_when_<setting is not allowed>` | <config allows only another setting> | `<RejectionError>` |
| `test_output_is_refused_outside_<allowed area>` | <config area differs> | `<RejectionError>` |
| `test_copied_constants_match_<neighbor>` | `<CONST_A>`, `<CONST_B>` vs `<neighbor module>` | equal |

<One or two sentences on what section D proves (e.g. "the builder cannot silently widen X: the
neighbor keeps refusing anything the builder is not meant to produce"), and a note on which
tests may import both sides while source modules stay isolated.>

## Order of work (red → green)
1. Write `<test file>`; run `uv run pytest <test file>`. Confirm it fails for the expected reason
   (e.g. the missing module), not for a typo.
2. Implement `<module>` until the file passes.
3. Full gate:
   ```bash
   uv run ruff check . && uv run ruff format --check . && uv run pyright \
     && uv run lint-imports && uv run pytest
   ```
4. Run the `finish-task` sync (or record why docs are deferred, see Decisions) and the
   `pre-pr-check` self-review.
5. Commit on `<branch>` with subject `<type>(<scope>): <subject>`, a body explaining *why* (<the
   reason in one clause>), footer `Refs #<issue>` (or `Closes #<issue>` on the last commit), and
   the Co-Authored-By trailer. Never `--no-verify`.

## Reused code
- `<path/to/module.py>`: `<Name>`, `<Name>`, `<Name>`.
- `<path/to/other_module.py>`: `<Name>` (<where it is used, e.g. "in one integration test">).
- `<path/to/neighbor/module.py>`: `<Name>`, `<Name>`, `<CONST_*>` (tests only; never imported by
  source).

## Verification
- `uv run pytest <tests dir> -q` green, then the full suite with coverage >= 80%.
- `uv run lint-imports` passes. Scratch-only negative check (revert afterwards): add
  `<forbidden import>` to `<module>` and confirm the `<contract name>` contract fails.
- Mutation check (scratch only): <change one safety-relevant value, or drop one field, in the
  implementation> and confirm the contract test fails with `<RejectionError>`.
- Optional manual smoke: <the quickest real-world check, e.g. a shell one-liner or a `run` of the
  app>.

## Notes for later commits
- **Commit <N+1> (`<module>`):** <how it relates: independent / depends on this>.
- **<Later PR or commit that consumes this>:** <exactly how it will call this code, what
  failure mapping it needs, where its inputs come from>.
- **<Deploy/config PR>:** <any constraint this commit puts on infrastructure or configuration>.
