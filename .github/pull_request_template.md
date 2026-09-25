## Summary

<!-- What does this PR do, in one or two sentences? -->

## Changes

<!-- List the key changes made in this PR. -->

-

## Test plan

<!-- How was this verified? Check off what applies and note commands/output where useful. -->

- [ ] `cargo fmt --all`
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] `cargo test --lib --bins`
- [ ] `cargo check --all-targets`
- [ ] Manual testing (describe below)

## Checklist

- [ ] Commit messages follow [conventional commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`, `perf:`, `ci:`)
- [ ] No customer or tenant names, secrets, credentials, or internal hostnames in code, commits, or this description
- [ ] No emojis, em-dashes, or AI-attribution lines anywhere in this PR
- [ ] Tests added or updated for the change
- [ ] Documentation updated (README, docs/, doc comments) if applicable
- [ ] Ran `cargo audit` / considered Gitleaks implications for any new dependency or config surface
- [ ] Branch is rebased on latest `main`

## Related issues

<!-- e.g. Closes #123 -->
