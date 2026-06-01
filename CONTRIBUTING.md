# Contributing to Pick

Thank you for your interest in contributing to Pick! This document provides guidelines for contributing to the project.

---

## Code of Conduct

Pick is an open-source project maintained by Strike48. We expect all contributors to be respectful, professional, and collaborative.

---

## Getting Started

### Prerequisites

- Rust 1.92+ (required by egui dependencies)
- `cargo` and `rustup`
- `libpcap-dev` (for packet capture features)
- `libssl-dev` (for TLS)
- `protobuf-compiler` (for Protocol Buffers)

See [RUNNING.md](RUNNING.md) for detailed setup instructions.

### Development Environment

```bash
# Clone the repository
git clone https://github.com/Strike48-public/pick.git
cd pick

# Copy environment template
cp .env.example .env

# Run in development mode
./run-pentest.sh headless dev
```

---

## How to Contribute

### 1. Fork and Branch

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/YOUR-USERNAME/pick.git
cd pick

# Add upstream remote
git remote add upstream https://github.com/Strike48-public/pick.git

# Create a feature branch
git checkout -b feat/your-feature-name
```

### 2. Make Changes

- Write clear, focused commits
- Follow Rust best practices (see Code Quality section below)
- Add tests for new functionality
- Update documentation as needed

### 3. Test Your Changes

**Required before creating a PR:**

```bash
# Format code
cargo fmt --all

# Run clippy (zero warnings required)
cargo clippy --all-targets -- -D warnings

# Run tests
cargo test --lib --bins

# Check compilation
cargo check --all-targets
```

### 4. Commit Your Changes

Follow [conventional commits](https://www.conventionalcommits.org/) format:

```
<type>: <description>

<optional body>
```

**Types:**
- `feat:` New feature
- `fix:` Bug fix
- `refactor:` Code refactoring (no functional changes)
- `docs:` Documentation changes
- `test:` Adding or updating tests
- `chore:` Maintenance tasks (dependencies, CI, etc.)
- `perf:` Performance improvements
- `ci:` CI/CD changes

**Example:**
```bash
git commit -m "feat: add nmap timeout validation

Validates nmap timeout parameters to prevent infinite hangs.
Adds unit tests for timeout edge cases."
```

**Important:**
- Never include customer/tenant names in commits (PII)
- Never include secrets or credentials
- No emojis or em-dashes in commit messages
- No AI attribution lines (Co-Authored-By: Claude, etc.)

### 5. Push and Create Pull Request

```bash
# Push to your fork
git push origin feat/your-feature-name

# Create PR via GitHub CLI (or web interface)
gh pr create --base main --head YOUR-USERNAME:feat/your-feature-name
```

---

## Code Quality Standards

### Rust Style

- Use `rustfmt` for formatting (run `cargo fmt --all`)
- Use `clippy` for linting with zero warnings (`cargo clippy -- -D warnings`)
- Follow Rust naming conventions:
  - `snake_case` for functions, variables, modules
  - `PascalCase` for types, traits, enums
  - `SCREAMING_SNAKE_CASE` for constants

### Error Handling

- Use `Result<T, E>` and `?` for error propagation
- Never use `unwrap()` in production code
- Add context to errors with `.context()` or `.with_context()`

### Testing

- **Minimum 80% test coverage** required
- Write unit tests in `#[cfg(test)]` modules
- Integration tests go in `tests/` directory
- Use descriptive test names that explain the scenario

```rust
#[test]
fn rejects_invalid_timeout_zero() {
    let result = validate_timeout(0);
    assert!(result.is_err());
}
```

### Documentation

- Add doc comments (`///`) for public APIs
- Update README.md if adding new features
- Update CHANGELOG.md (if it exists)
- Create or update docs/ files for significant features

---

## Pull Request Guidelines

### Before Submitting

- [ ] All tests pass (`cargo test`)
- [ ] Code is formatted (`cargo fmt --all`)
- [ ] Clippy passes with zero warnings (`cargo clippy -- -D warnings`)
- [ ] Documentation is updated
- [ ] Commit messages follow conventional commits
- [ ] No PII, secrets, or customer names in code/commits
- [ ] Branch is rebased on latest `main`

### PR Description

Include:
- **Summary** - What does this PR do?
- **Motivation** - Why is this change needed?
- **Testing** - How was this tested?
- **Related Issues** - Link to GitHub issues if applicable

### Review Process

1. Automated CI checks must pass
2. Maintainer review required
3. Address review feedback
4. Approval from maintainer
5. Squash and merge to `main`

---

## Security Guidelines

### Never Commit

- API keys, passwords, tokens
- Customer or tenant names (PII)
- Real Strike48 instance URLs (use examples)
- `.env` files (use `.env.example` templates)

### Gitleaks

We use Gitleaks to scan for secrets. If you accidentally commit a secret:

1. Use interactive rebase to remove it from ALL commits
2. Rotate the exposed secret immediately
3. Never push secrets to GitHub

### Security Issues

Report security vulnerabilities to: **security@strike48.com**

Do NOT open public GitHub issues for security vulnerabilities.

---

## Getting Help

- **Questions?** Open a [GitHub Discussion](https://github.com/Strike48-public/pick/discussions)
- **Bug reports?** Open a [GitHub Issue](https://github.com/Strike48-public/pick/issues)
- **Documentation:** See [docs/README.md](docs/README.md)

---

## License

By contributing to Pick, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to Pick!**
