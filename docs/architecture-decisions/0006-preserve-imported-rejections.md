# ADR 0006: Preserve imported rejections

**Status:** The operator chose this policy. Code and data tests still gate cutover.

## Evidence

In one room, Synapse keeps a join where Spindle selects an old rejected ban.
Offline replay with Synapse gives the same state as the source.
A test removes one rule: skip the candidate if Synapse rejected it before.
It then gives Spindle's answer for the fork under test.

The test keeps each flag that marks a rejected auth event.
It reads a private fixture and does not write the database.
Production PDUs stay outside this repo.

Synapse describes the rule in its [v2 resolver](https://github.com/element-hq/synapse/blob/develop/synapse/state/v2.py).
The operator chose to preserve those decisions for imported history.

## Decision

Store a durable marker for each source rejection, outside the client log.
Load the markers when a room reopens or recovers from the log.
Keep each event in the auth graph.
During iterative auth checks, skip the candidate if its marker exists.
Reject a new event if it names a rejected auth dependency.

For new events, use Ruma's usual rule to reconsider a rejected event.
The markers do not alter signed PDUs or enter pagination.
Refuse a marker for an event already in the accepted log.
Refuse recovery if a marker is corrupt.
Include the identity of the policy in each key for the cache.

## Local dependency patch

Ruma 0.18.0 has no parameter for this policy.
Keep its source and tests in `vendor/ruma-state-res`, with its MIT license.
The extension adds a predicate to decide whether to admit a candidate.
The usual `resolve` function uses an always-true predicate.
The patch preserves the event order and the rules for auth dependencies.

ADR 0002 asks for an upstream PR before a fork.
We read the upstream repository and prepared a patch.
Under its [rules for contributions](https://github.com/ruma/ruma/blob/main/CONTRIBUTING.md#llm-contributions), an LLM cannot write content for the project.
The ban covers code, docs and issues.

This agent cannot submit the patch under those rules.
This ADR records the reason for a local exception.
A person can write an upstream solution to replace the patch.

Run the upstream tests and the tests for this policy and room recovery.
The full corpus, complete write import and peer rehearsal remain gates.
This decision alone does not establish readiness for cutover.
