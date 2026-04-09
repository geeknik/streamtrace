# Contributing to StreamTrace

StreamTrace is an open forensic runtime. Contributions that improve evidence integrity, ingestion breadth, correlation accuracy, or investigation workflow are welcome.

---

## Getting Started

### Prerequisites

- **Rust 1.75+** -- install via [rustup](https://rustup.rs/)
- **Node.js 22+** -- for the SolidJS frontend
- **Docker and Docker Compose** -- for TimescaleDB
- **psql** (optional) -- for direct database inspection

### Setup

```bash
# Clone
git clone https://github.com/geeknik/streamtrace
cd streamtrace

# Start database
docker compose up timescaledb -d

# Copy environment config
cp .env.example .env
# Edit .env if needed (see comments in the file)

# Build and test
cargo build --workspace
cargo test --workspace

# Run the API server
cargo run --bin streamtrace

# In a separate terminal, start the frontend
cd frontend && npm install && npm run dev
```

The API will be available at `http://localhost:8080`.
The frontend will be available at `http://localhost:3000` (dev server) or `http://localhost:3000` (via Docker).

**Signing key for Phase 3 testing.** To test evidence bundle signing and verification locally, set `ST_SIGNING_KEY_HEX` in your `.env` file. Generate a key with `openssl rand -hex 32`. Without this variable, an ephemeral key is generated on each startup and bundles signed in one session cannot be verified after restart. See `.env.example` for details.

---

## Project Structure

StreamTrace is a Cargo workspace with 10 crates. See [ARCHITECTURE.md](ARCHITECTURE.md) for the full dependency graph and design rationale.

```
crates/
  st-common/      Shared types, forensic event model, errors, config
  st-crypto/      BLAKE3/SHA-256 hashing, integrity verification
  st-store/       PostgreSQL/TimescaleDB access layer
  st-parser/      Pluggable parser framework (JSON, CSV, syslog)
  st-ingest/      Ingestion pipeline orchestration
  st-index/       Timeline queries, full-text search
  st-correlate/   Cross-system event correlation
  st-cases/       Case management and evidence export
  st-api/         REST API (axum), auth, rate limiting
  st-server/      Binary entry point, config, graceful shutdown
frontend/         SolidJS + TypeScript UI
config/           Default configuration (TOML)
docker/           Dockerfiles and database init scripts
```

---

## Development Workflow

1. **Fork** the repository and create a branch from `main`.
2. **Implement** your change in the appropriate crate.
3. **Test** your change (see Testing below).
4. **Run checks** before committing:

```bash
# Format
cargo fmt --all

# Lint (treat warnings as errors)
cargo clippy --workspace -- -D warnings

# Test
cargo test --workspace
```

5. **Commit** with a clear message describing what and why.
6. **Open a pull request** against `main`.

### Commit Messages

Use the format: `<crate>: <description>`

Examples:
- `st-parser: add syslog RFC 5424 parser`
- `st-store: fix chunk pruning for cross-day queries`
- `st-api: add rate limit headers to response`

### API Testing

All `/v1/` endpoints require authentication via the `Authorization: Bearer <token>` header. Health check endpoints (`/healthz`, `/readyz`) are unauthenticated.

Example -- ingest an event with a bearer token:

```bash
curl -X POST http://localhost:8080/v1/ingest/events \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "auth.login",
    "occurred_at": "2026-04-09T12:00:00Z",
    "actor": {"id": "alice"},
    "network": {"src_ip": "203.0.113.10"}
  }'
```

Example -- query the timeline (requires read permission):

```bash
curl http://localhost:8080/v1/timeline \
  -H "Authorization: Bearer dev-token"
```

In development mode, a `dev-token` API key is seeded automatically. Do not use this token in production.

---

## Coding Standards

### Rust

- **Edition**: Rust 2021. Use workspace dependencies from the root `Cargo.toml`.
- **Doc comments**: All public types, functions, and modules must have `///` doc comments.
- **No unsafe**: Do not use `unsafe` without a comment justifying why it is necessary and why it is sound. Expect scrutiny.
- **Error handling**: Use `thiserror` for library errors, `anyhow` only in the binary crate (`st-server`). No `.unwrap()` in library code except in tests.
- **Types**: Use explicit types. Avoid `impl Trait` in return position for public APIs.
- **Functions**: Keep functions small and deterministic. Separate business logic from I/O.
- **Immutability**: Prefer immutable bindings. Use `mut` only when necessary.

### SQL

- **Parameterized binds only.** Never interpolate values into SQL strings. All queries use `$1`, `$2`, etc.
- **Explicit columns.** No `SELECT *`. List the columns you need.
- **Migrations.** Schema changes go in the migration system, not in application code.

### Security

- **Input validation at trust boundaries.** Every value that crosses a trust boundary (HTTP request, database result used in a different context) must be validated.
- **No secrets in code.** Load from environment or secret management.
- **No `eval`, `exec`, or dynamic code generation.**
- **Fail closed.** On error, deny access. Do not fall through to a permissive default.

### Frontend (SolidJS + TypeScript)

- **TypeScript strict mode.** No `any` types without justification.
- **Signals over stores** for simple state. Stores for complex nested state.
- **No direct DOM manipulation.** Use SolidJS reactivity.

---

## Testing

### Required for all PRs

- **Unit tests** for all public functions and types.
- **Negative tests** for malformed input, boundary conditions, and error paths.
- **Integration tests** for changes that cross crate boundaries.

### Running tests

```bash
# All tests
cargo test --workspace

# Specific crate
cargo test -p st-parser

# With output
cargo test --workspace -- --nocapture
```

### Property-based testing

The workspace includes `proptest` as a dependency. Use it for parser and validation code:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn parse_never_panics(input in any::<Vec<u8>>()) {
        let _ = Parser::parse(&input);
    }
}
```

---

## What We Are Looking For

### Parsers for new log formats

The `st-parser` crate has a pluggable parser trait. Adding support for new formats (AWS CloudTrail, Azure Activity Log, Kubernetes audit log, Nginx access log, etc.) directly increases StreamTrace's usefulness.

### Correlation strategies

The `st-correlate` crate extracts linkable keys from events. New strategies for identifying relationships (e.g., correlating deploy events with error spikes by time proximity) are valuable.

### Performance improvements

Ingestion throughput, query latency, and memory usage are all important. Profile before optimizing. Include benchmarks with your PR.

### Real-world testing

If you use StreamTrace with real (anonymized) data, reports on what works, what breaks, and what's missing are extremely valuable.

---

## Security Vulnerabilities

**Do not open public issues for security vulnerabilities.**

If you discover a security issue, report it responsibly:

1. Email the maintainers directly (see the repository contact information).
2. Include a description of the vulnerability, reproduction steps, and potential impact.
3. Allow reasonable time for a fix before public disclosure.

We take security seriously. StreamTrace handles forensic evidence -- integrity and confidentiality are non-negotiable.

---

## License

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](LICENSE).
