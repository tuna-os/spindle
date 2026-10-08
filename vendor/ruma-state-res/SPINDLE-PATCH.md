# Spindle's local Ruma patch

Base: ruma-state-res 0.18.0, from crates.io. Registry checksum:

```text
08294aac3a4cc6b20e29c7822a2cd13c13541b1175ec260065503ac37c8207ed
```

Upstream: https://github.com/ruma/ruma. License: MIT; see LICENSE.

The extension adds `resolve_with_candidate_policy`.
Its predicate can skip a candidate during iterative auth checks.
The patch preserves the event order and the rules for auth dependencies.
The usual `resolve` function uses a predicate that always returns true.

Spindle uses the extension to preserve Synapse's rejection decisions for
imported history. The operator chose this policy.
For new events, the resolver keeps Ruma's usual behavior.
The policy is explicit: Synapse keeps old rejections where the Matrix
algorithm can reconsider an event that failed at a former state.

We keep the source and upstream tests here so a reviewer can compare the
change with the release. Run them with:

```sh
cargo test --manifest-path vendor/ruma-state-res/Cargo.toml
```
