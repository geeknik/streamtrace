//! StreamTrace server entry point.
//!
//! Initializes logging, loads configuration, connects to the database,
//! runs migrations, and starts the HTTP server with graceful shutdown.

use std::sync::Arc;

use clap::Parser;
use st_api::{AppState, create_router_with_config};
use st_cases::CaseManager;
use st_common::config::AppConfig;
use st_crypto::SigningKeyPair;
use st_index::EventIndex;
use st_ingest::IngestPipeline;
use st_parser::ParserRegistry;
use st_store::Database;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// StreamTrace forensic runtime server.
#[derive(Parser, Debug)]
#[command(name = "streamtrace", about = "StreamTrace forensic runtime server")]
struct Args {
    /// Configuration environment (e.g. "development", "production").
    #[arg(long, default_value = "development")]
    config_env: String,

    /// Override the listen port from configuration.
    #[arg(long)]
    port: Option<u16>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Load layered configuration.
    let mut config = AppConfig::load(&args.config_env)
        .unwrap_or_else(|e| {
            eprintln!("warning: failed to load config ({e}), using defaults");
            AppConfig::default()
        });

    // Apply CLI overrides.
    if let Some(port) = args.port {
        config.server.port = port;
    }

    // Initialize tracing subscriber.
    init_tracing(&config);

    // Database URL must come from the environment, never from config files.
    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| anyhow::anyhow!("DATABASE_URL environment variable is required"))?;

    tracing::info!(
        env = %args.config_env,
        host = %config.server.host,
        port = config.server.port,
        "starting StreamTrace server"
    );

    // Connect to the database.
    let db = Database::connect(&database_url, &config.database).await?;

    // Run pending migrations.
    db.migrate().await?;

    let db = Arc::new(db);

    // Seed a development API key if ST_ENV is "development" and no keys exist.
    if args.config_env == "development" {
        seed_dev_api_key(&db).await;
    }

    // Initialize the parser registry with all built-in parsers.
    let parsers = Arc::new(ParserRegistry::with_defaults());

    // Create the ingestion pipeline.
    let ingest = Arc::new(IngestPipeline::new(
        Arc::clone(&db),
        parsers,
        config.ingest.clone(),
    ));

    // Create the event index.
    let index = Arc::new(EventIndex::new(Arc::clone(&db)));

    // Create the case manager.
    let cases = Arc::new(CaseManager::new(Arc::clone(&db)));

    // Load or generate the Ed25519 signing key for evidence bundles.
    let signing_key = Arc::new(load_signing_key()?);
    tracing::info!(
        public_key_hex = %signing_key.public_key_info().public_key_hex,
        "Ed25519 signing key ready for evidence bundles"
    );

    // Build application state and router.
    let state = AppState {
        db,
        ingest,
        index,
        cases,
        signing_key,
    };
    let router = create_router_with_config(
        state,
        config.server.request_body_limit_bytes,
        &config.security.cors_allowed_origins,
        config.security.rate_limit_per_second,
    );

    // Bind the TCP listener.
    let bind_addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;

    tracing::info!(addr = %bind_addr, "server listening");

    // Serve with graceful shutdown.
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("server shut down gracefully");
    Ok(())
}

/// Seed a development API key if none exist in the database.
///
/// Creates a key with token `st-dev-token-streamtrace-00000000` that has all
/// permissions. Only runs in development mode.
async fn seed_dev_api_key(db: &Database) {
    let token = "st-dev-token-streamtrace-00000000";
    let prefix = &token[..8]; // "dev-toke"

    // Check if a key with this prefix already exists.
    match db.validate_api_key(prefix, token).await {
        Ok(Some(_)) => {
            tracing::info!("development API key already exists (prefix: {prefix})");
            return;
        }
        Ok(None) | Err(_) => {}
    }

    // Hash the token and create the key.
    match st_api::auth::hash_api_key_token(token) {
        Ok(hash) => {
            let permissions = &[
                st_common::types::Permission::Read,
                st_common::types::Permission::Write,
                st_common::types::Permission::Admin,
            ];
            match db.create_api_key("development", &hash, prefix, permissions).await {
                Ok(_key) => {
                    tracing::info!(
                        token = token,
                        "development API key seeded -- use 'Authorization: Bearer {token}'"
                    );
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to seed development API key");
                }
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to hash development API key");
        }
    }
}

/// Load a signing key from the `ST_SIGNING_KEY_HEX` environment variable,
/// or generate a fresh ephemeral key if the variable is not set.
///
/// When the env var is present it must contain exactly 64 hex characters
/// (32 bytes). This allows production deployments to persist a stable key
/// across restarts so that previously-generated evidence bundles remain
/// verifiable.
fn load_signing_key() -> anyhow::Result<SigningKeyPair> {
    match std::env::var("ST_SIGNING_KEY_HEX") {
        Ok(hex_str) => {
            let bytes = hex::decode(hex_str.trim()).map_err(|e| {
                anyhow::anyhow!("ST_SIGNING_KEY_HEX contains invalid hex: {e}")
            })?;
            let secret: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
                anyhow::anyhow!(
                    "ST_SIGNING_KEY_HEX must be exactly 32 bytes (64 hex chars), got {} bytes",
                    v.len()
                )
            })?;
            tracing::info!("signing key loaded from ST_SIGNING_KEY_HEX environment variable");
            Ok(SigningKeyPair::from_bytes(&secret))
        }
        Err(_) => {
            tracing::warn!(
                "ST_SIGNING_KEY_HEX not set -- using ephemeral signing key; \
                 evidence bundles will not survive restart"
            );
            Ok(SigningKeyPair::generate())
        }
    }
}

/// Initialize the tracing subscriber based on the logging configuration.
///
/// - `"json"` format: structured JSON output suitable for log aggregation.
/// - Any other value: human-readable pretty output for development.
fn init_tracing(config: &AppConfig) {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.logging.level));

    let registry = tracing_subscriber::registry().with(env_filter);

    match config.logging.format.as_str() {
        "json" => {
            registry
                .with(tracing_subscriber::fmt::layer().json())
                .init();
        }
        _ => {
            registry
                .with(tracing_subscriber::fmt::layer().pretty())
                .init();
        }
    }
}

/// Wait for a SIGTERM or SIGINT signal for graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install CTRL+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {
            tracing::info!("received SIGINT, initiating shutdown");
        }
        () = terminate => {
            tracing::info!("received SIGTERM, initiating shutdown");
        }
    }
}
