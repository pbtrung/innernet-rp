---
description: Commit staged/modified changes with a detailed message and push, no AI co-author attribution
---

# Commit and Push

## Steps

1. Run `git status` and `git diff` (and `git diff --staged` if anything is already staged) to see all changes.
2. Lint, typecheck, and format whatever's actually touched, before staging anything (this project's own local convention -- there is no CI):
   - Any `*.rs` (or `Cargo.toml`) changed: `cargo +nightly fmt --all`, then
     `cargo clippy --workspace --locked --all-targets -- -D warnings`, then
     `cargo test --workspace --locked`.
     - `imports_granularity = "Crate"` in `rustfmt.toml` requires the
       `nightly` toolchain; use `cargo +nightly fmt` if nightly is
       installed, otherwise plain `cargo fmt`.
     - If IPv6-related code changed, also run
       `cargo test --workspace --locked --features v6-test`.
   - If formatting rewrote a file, or any check reports an error, fix it and
     re-run before continuing.
3. If nothing is staged, stage all relevant modified/new files with `git add`.
4. Write a **detailed** commit message:
   - Subject line: concise summary of the change (imperative mood, e.g. "Add", "Fix", "Refactor").
   - Body: explain _what_ changed and _why_, as bullet points if there are multiple distinct changes.
   - Base the message only on the actual diff — do not include conversational back-and-forth, dead ends, or trial-and-error from the session.
5. Create the commit using a HEREDOC so formatting is preserved, e.g.:
   ```bash
   git commit -m "$(cat <<'EOF'
   Short summary of the change

   - Detail one
   - Detail two
   - Why this change was made
   EOF
   )"
   ```
6. **Do not** add any AI attribution — no `🤖 Generated with Claude Code` line, no `Co-Authored-By: Claude` trailer, no mention of Claude/AI anywhere in the message.
7. Push the commit to the current branch's remote (`git push`, or `git push -u origin <branch>` if it has no upstream yet).
8. Confirm success by showing `git log -1` and `git status` after pushing.

## Rules

- Never include Claude/AI co-authorship or attribution in the commit message.
- Always push after committing — don't stop at just the local commit.
- If the push fails (e.g. diverged branch), report the error and ask before force-pushing or rebasing.
- Never pass `--fix` to clippy or fmt as a substitute for understanding a warning — fix the underlying issue, and only accept an auto-fix after reviewing the diff it produces.
