# Claude Code Workflow

@AGENTS.md

Claude Code is the coordinator. Codex is the implementation and review engine.

Token rule:

- Claude stays short: route, decide, summarize.
- Codex spends tokens: explore, implement, test, debug, review.

## Claude Responsibilities

Claude should:
- Clarify intent.
- Write or refine `docs/plans/<feature>.md`.
- Delegate token-heavy implementation to a Codex implementer.
- Delegate diff-only review to a fresh Codex reviewer.
- Decide accept/fix/stop from summaries and review findings.
- Ask for follow-up fixes when tests fail or the diff is too broad.

Claude should avoid large repository scans when OpenWiki already contains the needed map. Do not use Claude for broad implementation, broad debugging, or broad code review unless the user explicitly asks.

## Codex Delegation

Use Codex for:
- broad repository exploration
- implementation
- refactors
- failing test investigation
- running and fixing tests
- broad review

Do not run two Codex writers in the same worktree at the same time. Use sequential calls unless worktrees are separated.

Implementation prompt:

```text
/codex:rescue Read openwiki/quickstart.md if present and docs/plans/<feature>.md. Implement Phase <N> only with the smallest safe patch. Reuse existing patterns. Run the smallest relevant tests. Report changed files, commands run, skipped work, and next recommendation.
```

Debugging prompt:

```text
/codex:rescue Investigate the failing test. Find the root cause, make the smallest safe fix, and run only the relevant tests first.
```

Review prompts:

```text
/codex:rescue You did not write this code. Review the current diff only against docs/plans/<feature>.md. Do not modify files. Findings first. Focus on bugs, regressions, missing tests, overengineering, and simpler alternatives. If there are no issues, say so clearly.
/codex:adversarial-review current diff only; focus on overengineering, hidden regressions, missing tests, and simpler alternatives; do not modify files
```

Follow-up fix prompt:

```text
/codex:rescue Read the reviewer findings and current diff. Fix only the confirmed issues with the smallest safe patch. Run the relevant checks again. Report changed files and verification.
```

## End Of Work

When implementation is done:
- Ensure the relevant plan in `docs/plans/` is marked implemented.
- Ask the user to run `openwiki --update`, or run it if appropriate.
- Keep `openwiki/` as the current-state map, not a proposal folder.
