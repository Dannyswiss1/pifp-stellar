//! Long-running background task that polls the Soroban RPC and writes
//! decoded PIFP events to the database.

use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use sqlx::SqlitePool;
use tracing::{error, info};

use crate::config::Config;
use crate::db;
use crate::rpc;

pub struct IndexerState {
    pub pool: SqlitePool,
    pub config: Config,
    pub client: Client,
}

/// Spawn the indexer loop as a background [`tokio`] task.
pub async fn run(state: Arc<IndexerState>) {
    info!("Indexer starting — contract: {}", state.config.contract_id);

    // Load the cursor from the DB; fall back to config start_ledger.
    let last_ledger = db::get_last_ledger(&state.pool).await.unwrap_or(0);
    let cursor_str = db::get_cursor_string(&state.pool).await.unwrap_or(None);

    let mut current_ledger = if last_ledger > 0 {
        last_ledger as u32
    } else {
        state.config.start_ledger
    };
    let mut cursor: Option<String> = cursor_str;

    info!("Resuming from ledger {current_ledger}");

    loop {
        match poll_once(
            &state.pool,
            &state.client,
            &state.config,
            current_ledger,
            cursor.as_deref(),
        )
        .await
        {
            Ok((next_ledger, next_cursor)) => {
                current_ledger = next_ledger;
                cursor = next_cursor;
            }
            Err(e) => {
                error!("Indexer poll error: {e}");
            }
        }

        tokio::time::sleep(Duration::from_secs(state.config.poll_interval_secs)).await;
    }
}

/// Perform a single poll iteration.
///
/// Returns `(next_start_ledger, next_cursor)`.
async fn poll_once(
    pool: &SqlitePool,
    client: &Client,
    config: &Config,
    start_ledger: u32,
    cursor: Option<&str>,
) -> crate::errors::Result<(u32, Option<String>)> {
    let (raw_events, next_cursor, latest_ledger) = rpc::fetch_events(
        client,
        &config.rpc_url,
        &config.contract_id,
        start_ledger,
        cursor,
        config.events_per_page,
    )
    .await?;

    if !raw_events.is_empty() {
        let decoded = rpc::decode_events(&raw_events, &config.contract_id);
        let inserted = db::insert_events(pool, &decoded).await?;
        info!(
            "Polled {} raw events → {} new records stored",
            raw_events.len(),
            inserted
        );
    }

    // Advance the ledger cursor:
    // - If there is a next_cursor string, keep the same start_ledger so the next
    //   call paginates within the same ledger range.
    // - Otherwise advance to the latest known ledger.
    let next_ledger = latest_ledger
        .map(|l| (l as u32).max(start_ledger))
        .unwrap_or(start_ledger);

    // Persist cursor so restarts are deterministic.
    db::save_cursor(pool, next_ledger as i64, next_cursor.as_deref()).await?;

    Ok((next_ledger, next_cursor))
}
