//! Application configuration loaded from environment variables.

use crate::errors::{IndexerError, Result};

#[derive(Debug, Clone)]
pub struct Config {
    /// Soroban/Horizon RPC endpoint (e.g. https://soroban-testnet.stellar.org)
    pub rpc_url: String,
    /// The PIFP contract address (Strkey format)
    pub contract_id: String,
    /// Path to the SQLite database file
    pub database_url: String,
    /// Port for the REST API server
    pub api_port: u16,
    /// How often (in seconds) to poll the RPC for new events
    pub poll_interval_secs: u64,
    /// Maximum number of events to fetch per RPC request
    pub events_per_page: u32,
    /// Ledger to start from if no cursor is saved
    pub start_ledger: u32,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Config {
            rpc_url: env_var("RPC_URL")
                .unwrap_or_else(|_| "https://soroban-testnet.stellar.org".to_string()),
            contract_id: env_var("CONTRACT_ID").map_err(|_| {
                IndexerError::Config("CONTRACT_ID environment variable is required".to_string())
            })?,
            database_url: env_var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite:./pifp_events.db".to_string()),
            api_port: env_var("API_PORT")
                .unwrap_or_else(|_| "3001".to_string())
                .parse()
                .map_err(|_| IndexerError::Config("Invalid API_PORT".to_string()))?,
            poll_interval_secs: env_var("POLL_INTERVAL_SECS")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .map_err(|_| IndexerError::Config("Invalid POLL_INTERVAL_SECS".to_string()))?,
            events_per_page: env_var("EVENTS_PER_PAGE")
                .unwrap_or_else(|_| "100".to_string())
                .parse()
                .map_err(|_| IndexerError::Config("Invalid EVENTS_PER_PAGE".to_string()))?,
            start_ledger: env_var("START_LEDGER")
                .unwrap_or_else(|_| "0".to_string())
                .parse()
                .map_err(|_| IndexerError::Config("Invalid START_LEDGER".to_string()))?,
        })
    }
}

fn env_var(key: &str) -> Result<String> {
    std::env::var(key).map_err(|_| IndexerError::Config(format!("Missing env var: {key}")))
}
