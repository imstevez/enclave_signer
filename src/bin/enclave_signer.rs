use anyhow::Result;
use axum::routing::{get, post};
use axum::{Router, serve};
use enclave_signer::enclave_state::EnclaveState;
use enclave_signer::handler::{generate, info, pcrs, sign};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    info!("Starting...");

    let state = EnclaveState::new()?;

    let app = Router::new()
        .route("/ping", get(info))
        .route("/api/v1/generate", post(generate))
        .route("/api/v1/sign", post(sign))
        .route("/api/v1/pcrs", get(pcrs))
        .with_state(Arc::new(state.clone()));

    let listener = TcpListener::bind(&state.listen_address).await?;

    info!("Listening on {}", &state.listen_address);

    serve(listener, app).await?;

    Ok(())
}
