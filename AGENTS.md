# Agent Workflow

Codex is the primary coding agent for implementation, exploration, tests, and fixes.
Claude Code, when present, is the coordinator only. Keep Claude's token use small.

## Context Order

Before broad or non-trivial work:
- Read `openwiki/quickstart.md` if it exists.
- Read the relevant linked OpenWiki page for the touched area.
- If the work is unclear or not trivial, create or update `docs/plans/<feature>.md` before editing implementation files.

Use OpenWiki as current-state documentation only. Do not put proposed or not-yet-implemented behavior in `openwiki/` as if it already exists.

Use `docs/plans/` for proposed work. Each plan should include:
- Goal
- Success criteria
- In-scope and out-of-scope notes
- Affected areas
- Implementation steps
- Test commands
- Ready-to-send prompts for:
  - Codex implementer
  - Codex reviewer

## GJC

Use GJC only for requirements interviews and plan shaping when the task is early-stage or ambiguous.

Prefer non-interactive planning calls:

```powershell
gjc -p "Read openwiki/quickstart.md if present. Interview the user requirements for <feature> and produce a concise implementation-plan draft."
```

Do not let GJC edit implementation files unless the user explicitly asks.

## Implementation Rules

- Prefer the smallest safe patch.
- Reuse existing project patterns.
- Avoid new dependencies unless clearly necessary.
- Do not rewrite unrelated code.
- Do not change formatting across untouched files.
- Run the smallest relevant tests first; broaden only when the change risk justifies it.
- Report changed files and verification results.

## Implementer And Reviewer Split

Do not let the same agent role both implement and approve its own work.

Default sequence:

1. Codex Implementer changes files and runs relevant checks.
2. Fresh Codex Reviewer reviews the current diff only.
3. Claude or the user decides whether to accept, request fixes, or stop.

The reviewer must not edit files. Review only the diff against the plan.

Implementer prompt:

```text
Read openwiki/quickstart.md if present and docs/plans/<feature>.md. Implement Phase <N> only with the smallest safe patch. Reuse existing patterns. Run the smallest relevant checks. Report changed files, commands run, skipped work, and next recommendation.
```

Reviewer prompt:

```text
You did not write this code. Review the current diff only against docs/plans/<feature>.md. Do not modify files. Findings first. Focus on bugs, regressions, missing tests, overengineering, and simpler alternatives. If there are no issues, say so clearly.
```

## Documentation Loop

After implementation is accepted:
- Mark the matching `docs/plans/<feature>.md` as implemented.
- Run or ask the user to run:

```powershell
openwiki --update
```

OpenWiki should then reflect the actual implemented state.
