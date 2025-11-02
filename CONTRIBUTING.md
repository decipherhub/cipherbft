# Contributing to CipherBFT

Thank you for your interest in contributing to CipherBFT! This document provides guidelines and instructions for contributing.

## Code of Conduct

Be respectful, constructive, and professional in all interactions.

## Development Workflow

### 1. Fork and Clone

```bash
git clone https://github.com/your-username/cipherbft.git
cd cipherbft
```

### 2. Create a Feature Branch

```bash
git checkout -b feature/my-new-feature
```

### 3. Make Changes

- Write clear, documented code
- Follow Rust API guidelines
- Add tests for new functionality
- Run quality checks before committing

### 4. Quality Checks

```bash
# Format code
cargo fmt

# Run linter
cargo clippy --all-targets --all-features -- -D warnings

# Run tests
cargo test

# Run all checks
cargo check-all
```

### 5. Commit Changes

Follow conventional commits:

```
feat: add new feature
fix: bug fix
refactor: code refactoring
perf: performance improvement
test: add tests
docs: documentation update
style: formatting
chore: build/tooling changes
```

**Max 30 characters per commit message** (Constitutional Principle X)

### 6. Push and Create Pull Request

```bash
git push origin feature/my-new-feature
```

Then create a PR on GitHub.

## Code Standards

### Rust Best Practices (Principle I)

- Use `Result<T, E>` for fallible operations
- Use traits for polymorphism
- **No `unwrap()` in production code** (use `expect()` with clear messages in tests only)
- Use `Option<T>` appropriately

### Code Quality (Principle II)

- Zero warnings policy
- Clippy pedantic + nursery lints enabled
- rustfmt applied to all code
- 80%+ test coverage
- All public APIs documented with rustdoc

### Testing Standards (Principle III - NON-NEGOTIABLE)

- **TDD workflow**: Write tests before implementation
- Unit tests for all business logic
- Integration tests for ABCI communication
- Byzantine fault injection tests
- Network partition tests
- Property-based tests with proptest
- Benchmarks for performance-critical code

### Documentation

- Module-level documentation
- Rustdoc for all public types and functions
- Usage examples in rustdoc comments
- Inline comments for complex logic

### Performance

- Use async/await for I/O
- Avoid blocking in async context
- Use `Bytes` for zero-copy message passing
- Profile hot paths

### Security

- Validate all inputs at boundaries
- Use constant-time crypto operations
- Verify all signatures
- Handle Byzantine behavior gracefully

## Pull Request Process

1. **Update tests**: Ensure all tests pass
2. **Update docs**: If changing public APIs
3. **Update CHANGELOG.md**: Note your changes
4. **Request review**: Tag maintainers
5. **Address feedback**: Respond to review comments
6. **Squash commits**: Before merge (if requested)

## Testing

### Run All Tests

```bash
cargo test
```

### Run Specific Tests

```bash
# Crate tests
cargo test -p consensus

# Integration tests
cargo test --test integration

# Single test
cargo test test_name
```

### Coverage

```bash
cargo install cargo-tarpaulin
cargo tarpaulin --out Html
open tarpaulin-report.html
```

## Benchmarks

```bash
# Run all benchmarks
cargo bench

# Specific benchmark
cargo bench --bench consensus_bench
```

## Release Process

(For maintainers only)

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Create git tag: `git tag -a v0.1.0 -m "Release v0.1.0"`
4. Push tag: `git push origin v0.1.0`
5. CI will build and publish release artifacts

## Questions?

- Open an issue for bugs or feature requests
- Join discussions in GitHub Discussions
- Check documentation in `specs/` directory

Thank you for contributing!
