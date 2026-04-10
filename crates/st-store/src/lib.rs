//! `st-store` -- database access layer for StreamTrace.
//!
//! Wraps sqlx operations for PostgreSQL + TimescaleDB, providing typed
//! methods for raw events, normalized events, correlation keys, cases,
//! API keys, entity graph, sequence patterns, legal holds, and audit logging.
//!
//! All queries use parameterized binds. No user-supplied values are ever
//! interpolated into SQL strings.

pub mod api_keys;
pub mod audit;
pub mod cases;
pub mod correlation_keys;
pub mod entities;
pub mod events;
pub mod holds;
pub mod raw_events;
pub mod sequences;

use std::time::Duration;

use sqlx::postgres::{PgPool, PgPoolOptions};
use st_common::config::DatabaseConfig;
use st_common::error::{StError, StResult};
use st_common::types::Severity;

// Re-export transaction-related types so downstream crates (st-ingest,
// st-cases, st-api) can reference them without adding sqlx directly.
pub use sqlx::Postgres;
pub type Transaction<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

/// Central database handle. All store operations are methods on this struct.
#[derive(Debug, Clone)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    /// Creates a new connection pool and returns a `Database` handle.
    ///
    /// Applies pool sizing and timeout settings from `config`.
    pub async fn connect(database_url: &str, config: &DatabaseConfig) -> StResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .acquire_timeout(Duration::from_secs(config.connect_timeout_secs))
            .idle_timeout(Duration::from_secs(config.idle_timeout_secs))
            .connect(database_url)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to connect to database");
                StError::Database(format!("connection failed: {e}"))
            })?;

        tracing::info!(
            max_connections = config.max_connections,
            min_connections = config.min_connections,
            "database connection pool established"
        );

        Ok(Self { pool })
    }

    /// Returns a reference to the underlying connection pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Begins a new database transaction.
    ///
    /// The returned transaction will automatically roll back on drop unless
    /// explicitly committed via [`Transaction::commit`]. All `_tx` store
    /// functions accept this transaction handle.
    pub async fn begin(&self) -> StResult<Transaction<'_>> {
        self.pool.begin().await.map_err(|e| {
            tracing::error!(error = %e, "failed to begin transaction");
            StError::Database(format!("begin transaction failed: {e}"))
        })
    }

    /// Runs sqlx migrations from the workspace `migrations/` directory.
    ///
    /// Uses the runtime `Migrator` API (not the `migrate!` macro) to avoid
    /// pulling in `sqlx-macros-core` which transitively depends on `sqlx-mysql`
    /// and the vulnerable `rsa` crate (RUSTSEC-2023-0071).
    pub async fn migrate(&self) -> StResult<()> {
        let migrator = sqlx::migrate::Migrator::new(std::path::Path::new("migrations"))
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to load migrations");
                StError::Database(format!("migration load failed: {e}"))
            })?;

        migrator.run(&self.pool).await.map_err(|e| {
            tracing::error!(error = %e, "database migration failed");
            StError::Database(format!("migration failed: {e}"))
        })?;

        tracing::info!("database migrations applied successfully");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Severity <-> i16 conversion helpers used across submodules
// ---------------------------------------------------------------------------

/// Convert a database `SMALLINT` to a [`Severity`] enum variant.
///
/// Returns `Severity::Info` for unrecognized values (fail-safe default).
fn severity_from_i16(val: i16) -> Severity {
    match val {
        0 => Severity::Info,
        1 => Severity::Low,
        2 => Severity::Medium,
        3 => Severity::High,
        4 => Severity::Critical,
        _ => {
            tracing::warn!(value = val, "unknown severity value, defaulting to Info");
            Severity::Info
        }
    }
}

/// Convert a [`Severity`] enum variant to a database `SMALLINT`.
fn severity_to_i16(sev: Severity) -> i16 {
    sev as i16
}

/// Map a sqlx error to [`StError::Database`].
fn map_sqlx_err(e: sqlx::Error) -> StError {
    tracing::error!(error = %e, "database query failed");
    StError::Database(e.to_string())
}
