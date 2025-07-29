use crate::enclave_state::EnclaveState;
use crate::helper;
use crate::helper::{
    address_checksum, build_kms_recipient, clear_vec, decrypt, encrypt, generate_evm_account,
    sign_message,
};
use crate::response::Res;
use anyhow::anyhow;
use aws_sdk_kms::types::DataKeySpec;
use aws_smithy_types::Blob;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;

pub async fn hello() -> &'static str {
    info!("Receive ping req");
    "pong"
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateReq {
    pub kms_key_id: String,
    pub kms_key_region: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateRes {
    pub address: String,
    pub public_key: String,
    pub encrypted_private_key: String,
    pub encrypted_data_key: String,
}

pub async fn generate(
    State(state): State<Arc<EnclaveState>>,
    Json(req): Json<GenerateReq>,
) -> (StatusCode, Json<Res<GenerateRes>>) {
    info!("Receive generate req: {:?}", req);

    let doc = match state.attest() {
        Err(err) => return Res::internal_err(anyhow!("attest document: {}", err)),
        Ok(doc) => doc,
    };

    let kms_cli = match state.kms_cli(&req.kms_key_region).await {
        Err(err) => return Res::internal_err(anyhow!("kms cli: {}", err)),
        Ok(cli) => cli,
    };

    let kms_res = match kms_cli
        .generate_data_key()
        .key_id(&req.kms_key_id)
        .key_spec(DataKeySpec::Aes256)
        .recipient(build_kms_recipient(&doc))
        .send()
        .await
    {
        Err(err) => return Res::internal_err(anyhow!("kms generate data key: {}", err)),
        Ok(value) => value,
    };

    let key_rec = match kms_res.ciphertext_for_recipient {
        None => return Res::internal_err(anyhow!("ciphertext for recipient is empty")),
        Some(value) => value,
    };

    let key = match state.decrypt(&key_rec.into_inner()) {
        Err(err) => return Res::internal_err(anyhow!("decrypt recipient: {}", err)),
        Ok(value) => value,
    };

    let key_enc = match kms_res.ciphertext_blob {
        None => return Res::internal_err(anyhow!("ciphertext is empty")),
        Some(value) => value.into_inner(),
    };

    let (address, public, private) = match generate_evm_account() {
        Err(err) => return Res::internal_err(anyhow!("generate evm account: {}", err)),
        Ok(value) => value,
    };

    let private_enc = match encrypt(&private, &key) {
        Err(err) => return Res::internal_err(anyhow!("encrypt private key: {}", err)),
        Ok(value) => value,
    };

    clear_vec(key);
    clear_vec(private);

    Res::ok(GenerateRes {
        address: address_checksum(&address),
        public_key: hex::encode(&public),
        encrypted_private_key: hex::encode(&private_enc),
        encrypted_data_key: hex::encode(&key_enc),
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignReq {
    pub kms_key_id: String,
    pub kms_key_region: String,
    pub message: String,
    pub encrypted_private_key: String,
    pub encrypted_data_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignRes {
    pub signature: String,
}

pub async fn sign(
    State(state): State<Arc<EnclaveState>>,
    Json(req): Json<SignReq>,
) -> (StatusCode, Json<Res<SignRes>>) {
    info!("Receive sign req: {:?}", req);

    let doc = match state.attest() {
        Err(err) => return Res::internal_err(anyhow!("attest document: {}", err)),
        Ok(doc) => doc,
    };

    let kms_cli = match state.kms_cli(&req.kms_key_region).await {
        Err(err) => return Res::internal_err(anyhow!("kms cli: {}", err)),
        Ok(cli) => cli,
    };

    let key_enc = match hex::decode(req.encrypted_data_key) {
        Err(err) => return Res::internal_err(anyhow!("encrypted data key decode: {}", err)),
        Ok(value) => value,
    };

    let kms_res = match kms_cli
        .decrypt()
        .key_id(&req.kms_key_id)
        .ciphertext_blob(Blob::from(key_enc))
        .recipient(build_kms_recipient(&doc))
        .send()
        .await
    {
        Err(err) => return Res::internal_err(anyhow!("encrypted data key decrypt: {}", err)),
        Ok(value) => value,
    };

    let key_rec = match kms_res.ciphertext_for_recipient {
        None => return Res::internal_err(anyhow!("data key recipient is empty")),
        Some(value) => value.into_inner(),
    };

    let key = match state.decrypt(&key_rec) {
        Err(err) => return Res::internal_err(anyhow!("recipient data key decrypt: {}", err)),
        Ok(value) => value,
    };

    let private_enc = match hex::decode(req.encrypted_private_key) {
        Err(err) => return Res::internal_err(anyhow!("encrypted private key decode: {}", err)),
        Ok(value) => value,
    };

    let private = match decrypt(&private_enc, &key) {
        Err(err) => return Res::internal_err(anyhow!("decrypt private key: {}", err)),
        Ok(value) => value,
    };

    clear_vec(key);

    let signature = match sign_message(&private, &req.message).await {
        Err(err) => return Res::internal_err(anyhow!("sign message: {}", err)),
        Ok(value) => value,
    };

    clear_vec(private);

    Res::ok(SignRes {
        signature: hex::encode(signature),
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PCR {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PCRsRep {
    pub pcrs: Vec<PCR>,
}

pub async fn pcrs(State(state): State<Arc<EnclaveState>>) -> (StatusCode, Json<Res<PCRsRep>>) {
    info!("Receive pcrs req");

    let doc = match state.attest() {
        Err(err) => return Res::internal_err(anyhow!("attest document: {}", err)),
        Ok(doc) => doc,
    };

    let doc_t = match helper::parse_attestation_doc(&doc) {
        Err(err) => return Res::internal_err(anyhow!("parse attestation document: {}", err)),
        Ok(doc_t) => doc_t,
    };

    let mut pcrs: Vec<PCR> = Vec::new();
    doc_t.pcrs.iter().for_each(|(key, val)| {
        pcrs.push(PCR {
            key: format!("PCR-{}", key),
            value: hex::encode(val).to_string(),
        })
    });

    Res::ok(PCRsRep { pcrs })
}
