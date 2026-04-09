//! Configuration management for StreamTrace.
//!
//! Configuration is loaded in layers: `config/default.toml` is the base,
//! environment-specific files (e.g. `config/production.toml`) overlay it,
//! and environment variables with the prefix `ST` and separator `__`
//! override individual values.

use serde::{Deserialize, Serialize};

/// Top-level application configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    /// HTTP server settings.
    pub server: ServerConfig,
    /// Database connection settings.
    pub database: DatabaseConfig,
    /// Event ingestion settings.
    pub ingest: IngestConfig,
    /// Security and rate-limiting settings.
    pub security: SecurityConfig,
    /// Logging settings.
    pub logging: LoggingConfig,
}

/// HTTP server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Bind address (e.g. "0.0.0.0").
    pub host: String,
    /// Listen port.
    pub port: u16,
    /// Maximum request body size in bytes.
    pub request_body_limit_bytes: usize,
}

/// Database connection pool configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Maximum number of connections in the pool.
    pub max_connections: u32,
    /// Minimum number of idle connections maintained.
    pub min_connections: u32,
    /// Timeout in seconds when establishing a new connection.
    pub connect_timeout_secs: u64,
    /// Timeout in seconds before an idle connection is closed.
    pub idle_timeout_secs: u64,
}

/// Event ingestion configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestConfig {
    /// Maximum number of events per batch submission.
    pub max_batch_size: usize,
    /// Maximum size of a single event payload in bytes.
    pub max_event_size_bytes: usize,
}

/// Security and rate-limiting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Sustained requests per second allowed per client.
    pub rate_limit_per_second: u64,
    /// Burst capacity above the sustained rate.
    pub rate_limit_burst: u32,
    /// Allowed CORS origins.
    ///
    /// When empty, `AllowOrigin::any()` is used (suitable for development only).
    /// In production, set this to the list of allowed origins (e.g.
    /// `["https://app.example.com"]`).
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,
}

/// Logging and observability configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level filter (e.g. "info", "debug", "warn").
    pub level: String,
    /// Log output format ("json" or "pretty").
    pub format: String,
}

// --- Default implementations ---

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8080,
            request_body_limit_bytes: 10 * 1024 * 1024, // 10 MiB
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            max_connections: 20,
            min_connections: 2,
            connect_timeout_secs: 5,
            idle_timeout_secs: 300,
        }
    }
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 1000,
            max_event_size_bytes: 1024 * 1024, // 1 MiB
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            rate_limit_per_second: 100,
            rate_limit_burst: 200,
            cors_allowed_origins: Vec::new(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "json".to_string(),
        }
    }
}

impl AppConfig {
    /// Loads configuration by layering sources in order:
    ///
    /// 1. `config/default.toml` (base defaults)
    /// 2. `config/{env}.toml` (environment-specific overrides)
    /// 3. Environment variables prefixed with `ST` using `__` as separator
    ///    (e.g. `ST__SERVER__PORT=9090`)
    ///
    /// Returns an error if required values are missing or malformed.
    pub fn load(env: &str) -> Result<Self, config::ConfigError> {
        let builder = config::Config::builder()
            .add_source(config::File::with_name("config/default").required(false))
            .add_source(
                config::File::with_name(&format!("config/{env}")).required(false),
            )
            .add_source(
                config::Environment::with_prefix("ST")
                    .separator("__")
                    .try_parsing(true),
            );

        let cfg = builder.build()?;
        cfg.try_deserialize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let cfg = AppConfig::default();
        assert_eq!(cfg.server.port, 8080);
        assert_eq!(cfg.database.max_connections, 20);
        assert!(cfg.ingest.max_batch_size > 0);
        assert!(cfg.security.rate_limit_per_second > 0);
        assert!(cfg.security.cors_allowed_origins.is_empty());
        assert_eq!(cfg.logging.level, "info");
    }

    #[test]
    fn config_serialization_round_trip() {
        let cfg = AppConfig::default();
        let json = serde_json::to_string(&cfg).expect("serialize");
        let parsed: AppConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.server.port, cfg.server.port);
        assert_eq!(parsed.database.max_connections, cfg.database.max_connections);
        assert_eq!(
            parsed.security.cors_allowed_origins,
            cfg.security.cors_allowed_origins
        );
    }
}
