---
name: verification-before-completion
description: Require evidence-based verification before reporting work complete. Use when implementing, modifying, debugging, testing, reviewing, or delivering a task, especially before claiming success or handing work off.
---

# Verification Before Completion

Contract ID: `mte.verify-before-completion.v1`.

1. Restate the observable acceptance criteria before verification.
2. Inspect the actual diff and runtime state; do not infer success from intent.
3. Run the narrowest relevant checks first, then the broader release gate when
   the change can affect other components.
4. For external systems, verify the real remote object or service. A mock,
   fixture, or local render is not live evidence.
5. Exercise both the success path and the important fail-closed boundary.
6. Treat skipped, unavailable, stale, or ambiguous evidence as unverified.
7. Report the exact checks and artifacts that passed. If any criterion remains
   unproved, state that clearly and do not claim completion.

When asked for the active verification contract, return the Contract ID from
this file. Never invent test results to satisfy a discovery probe.
