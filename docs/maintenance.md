# Maintenance

How this repository stays current with the Matrix specification, the
proposals it serves ahead of the spec, and the clients and suites it is
measured against — and what a maintainer does when one of them moves.

The principle throughout: **every claim is held to the code by a gate, and
every upstream is watched by a job.** Nothing here is a checklist a person
remembers; each item is a script that runs in CI or on a schedule, prints
what it found, and fails or files an issue. What remains for a person is the
judgement — whether to bump a pin, whether a new endpoint is in scope, what
to do when a proposal dies.

## 1. The gates, per pull request

`ci.yml` runs these on every push. Each one answers "does a generated
artefact still tell the truth about the code":

| Gate | Holds | Regenerate with |
|---|---|---|
| `coverage-dashboard.py --check` | `docs/dashboard.md`: the endpoints the router serves, per milestone | `just regen` |
| `spec-drift.py --check` | `docs/spec-gaps.md`: what the pinned spec defines that the router does not serve | `just regen` |
| `msc-ledger.py --check` | `docs/mscs.md`, and that `/versions`' flags and the `unstable/` routes are all owned by a served entry in `contrib/msc/ledger.toml` with a test naming the MSC | `just regen` after editing the ledger |
| `upstream-pins.py --check` | that every hand-pinned upstream can still be read from its file | fix the regex or the file |
| `openapi-check.py` | every response the scripted client gets validates against the pinned spec's schema | `scripts/openapi-allowlist.txt` for an explained divergence |
| `readme-numbers.py --check` | the README's headline counts are the gated ones | `just regen` |
| `config-drift.py` | the example config names every setting | edit `spindle.example.toml` |
| `untested-routes.py` | (report) routes nothing names in a test, rig or evidence page | write the test |
| `tests/surface.rs` | `/versions` advertises nothing unbuilt | build it, then advertise it |

`just lint`, `just test` and `just regen` before pushing reproduce the lot.

## 2. The ratchets, nightly

Three external suites run against a fresh build every night from
`compliance.yml`, and each has an allowlist that may only grow:

| Suite | Pin | Allowlist | Check |
|---|---|---|---|
| Complement | `scripts/complement.sh` | `complement/allowlist.txt` | `scripts/complement-check.py` |
| matrix-rust-sdk integration tests | `contrib/rust-sdk/run.sh` | `contrib/rust-sdk/allowlist.txt` | `scripts/rust-sdk-check.py` |
| Element Call Playwright | `contrib/element-call/run.sh` | `contrib/element-call/allowlist.txt` | `scripts/element-call-check.py` |

A test that passes and is not listed is printed as a **candidate**. Promoting
it is a reviewed commit that names the run it passed in, never automatic —
so a flaky test cannot teach everyone to ignore the gate. A listed test that
fails is a **regression** and fails the job. The procedure:

1. Read the job's tail: the `candidate` and `REGRESSED` lines.
2. For a regression, the fix goes in first; the allowlist is not edited to
   make it pass. (A test that upstream changed under the same name is the
   one exception, and the commit says so.)
3. For candidates, add them under a header naming the run id and the
   Spindle commit, one pull request per run.

The remaining failures in each suite are triaged on the tracking issue
(#112 for the SDK suite). Each is a real gap or a real defect; the
`sdk_findings` tests in `crates/spindle-server/tests/` are the unit-sized
reproductions of what the suite found.

## 3. The weekly upkeep report

`upkeep.yml` runs on Mondays and edits one issue labelled `upkeep`. Locally,
`just upkeep` prints the same three reports:

**Pins behind upstream** (`upstream-pins.py --upstream`). Every upstream
this repository pins by hand, read from the file that uses it, against the
newest tag or the branch head. Dependabot covers Cargo, the actions, the
Docker bases and the Go module; this covers the rest.

**MSCs against the proposals** (`msc-ledger.py --upstream`). Each ledger
entry's pull request on `matrix-spec-proposals`: open, merged or closed,
with its labels. Two findings matter. A *served* MSC that has landed
upstream while the ledger records no `stable` version means the stable
spelling exists and clients will start sending it — see §5. A *planned* MSC
closed unmerged is one to stop planning for.

**What a spec pin bump would bring** (`spec-drift.py` against matrix-spec
`main`). The operations that differ between the pinned spec and today's
main, so the size of the next release's work is known before the bump.

Nothing in the report is acted on automatically. Bumping a pin is §4.

## 4. Bumping a pin

Every pin bump is its own pull request, and the pull request's job is to
show what the bump changed. What to expect from each:

| Pin | What moves with it | What to read before merging |
|---|---|---|
| `SPEC_PIN` in `scripts/openapi-check.py` | `docs/spec-gaps.md` is rewritten; `openapi-check` validates against new schemas | The diff of `spec-gaps.md` *is* the release's new work. File an issue per group that is in scope. A schema failure is a real divergence: fix it or allowlist it with a reason. |
| `RUST_SDK_REV` | The nightly suite runs the new tests | Run `compliance.yml` by dispatch on the branch and read the tail: new candidates are promoted with the bump, regressions block it. |
| `COMPLEMENT_REV` | Same, for Complement | Same; the protected subset runs on the pull request, the whole suite on main. |
| `ELEMENT_TAG`, `ELEMENT_CALL_REV` | The browser and call suites | The E2E jobs on the pull request. A new spec Element Call requires appears as a failing spec, and the fix goes in before or with the bump. |
| `SYNAPSE_VERSION` and the other benchmark versions | The next sitting's field | Nothing gates it; the sitting's sidecar records the versions, and the page keeps groups apart, so an older sitting is never compared against a newer field. |

Two pins are deliberately not automated: `rust-toolchain.toml` (the MSRV
moves on its own decision, #193) and `ruma` (ADR-0002: the room-version,
redaction and authorization rules are taken from ruma and a bump is read as
a protocol change, not a dependency update).

## 5. Absorbing a spec release

A Matrix spec release (v1.N) reaches this repository as a `SPEC_PIN` bump,
and the bump's `spec-gaps.md` diff lists what it added under `### Not
served, added in v1.N`. For each group:

1. **Decide scope.** A homeserver serves what it serves; the page's job is
   to be honest about it. Third-party identity lookups and MSISDN tokens,
   for instance, are listed and not planned. File an issue for what is in
   scope, and say why the rest is not in the issue that tracks the release.
2. **Serve it.** A route arrives with the test that would have failed
   without it (CONTRIBUTING). `just regen` moves it from `spec-gaps.md` to
   `dashboard.md`; the OpenAPI check validates its responses on the next
   run.
3. **Claim it.** `crates/spindle-server/src/surface.rs` lists the spec
   versions `/versions` advertises, each with the routes that make the claim
   honest; `tests/surface.rs` fails if one is missing. Advertising v1.N is
   the last step, after everything the version requires is served — a
   client plans against `/versions`, and a longer list buys nothing but
   failures further from the cause.
4. **Retire the unstable spelling** of anything the release stabilised
   (§6).

## 6. Adding, stabilising and retiring an MSC

Spindle serves proposals ahead of the spec when a client it targets needs
them: Element X's sliding sync, MatrixRTC's delayed and sticky events. Each
one goes through the same life:

1. **Add.** Serve it under the `unstable/org.matrix.mscNNNN` prefix the
   proposal names, advertise the flag in `surface::UNSTABLE_FEATURES` only
   if the endpoint answers, and add the entry to `contrib/msc/ledger.toml`
   with `status = "served"` and the test that proves it. `msc-ledger.py
   --check` refuses a flag or a route the ledger does not own, and a served
   entry with no test naming the MSC.
2. **Stabilise.** When the weekly report says the proposal merged, the
   stable spelling exists. Serve both — the stable path and the unstable
   one, with the same handler, as `auth_metadata` does — record the spec
   version in the entry's `stable` field, and keep the flag until the
   clients that check it have moved. A proposal that has merged but that
   no spec release names yet gets `merged = true` instead: there is no
   stable spelling to adopt, and the report stops asking until there is.
3. **Retire.** The unstable route and flag go once no pinned client sends
   them; the entry stays, with its `stable` version, so the page still says
   what was served and when.

A proposal that dies upstream is marked `declined` or `superseded` with a
note saying what replaced it, never deleted: the ledger is a record, not a
list of the present.

## 7. What is deliberately not automated

- **Bumps.** Every one above is a reviewed pull request. The suites are how
  a newer client tells this server what it now expects, and that is a thing
  to read, not to merge.
- **Promotion.** A passing test enters an allowlist by a commit naming the
  run, so the ratchet cannot learn to ignore a flake.
- **Claims.** `/versions`, the dashboard, the MSC page and the spec-gaps
  page are generated from or checked against the router; none is typed.
- **Scope.** The spec-gaps page lists everything unserved and gates on
  nothing but its own accuracy. Which of it to build is the roadmap's
  decision, made in an issue where the reasons are written down.
