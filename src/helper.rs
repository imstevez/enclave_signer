use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use anyhow::{Result, anyhow};
use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use aws_sdk_kms::types::KeyEncryptionMechanism::RsaesOaepSha256;
use aws_sdk_kms::types::RecipientInfo;
use aws_smithy_types::Blob;
use ethers::core::k256::ecdsa::{SigningKey, VerifyingKey};
use ethers::signers::{LocalWallet, Signer};
use ethers::utils;
use solana_sdk::signature::{Keypair, SeedDerivable, Signer as SolSigner};

pub fn parse_attestation_doc(doc: &[u8]) -> Result<AttestationDoc> {
    let doc_cose =
        aws_nitro_enclaves_cose::CoseSign1::from_bytes(doc).map_err(|e| anyhow!(e.to_string()))?;

    let doc_payload: Vec<u8> = doc_cose
        .get_payload::<aws_nitro_enclaves_cose::crypto::Openssl>(None)
        .map_err(|e| anyhow!(e.to_string()))?;

    serde_cbor::from_slice(&doc_payload).map_err(|e| anyhow!(e.to_string()))
}

pub fn build_kms_recipient(doc: &[u8]) -> RecipientInfo {
    RecipientInfo::builder()
        .attestation_document(Blob::from(doc))
        .key_encryption_algorithm(RsaesOaepSha256)
        .build()
}

pub fn generate_evm_account() -> Result<(String, Vec<u8>, Vec<u8>)> {
    let mut rng = rand::thread_rng();

    let signing_key = SigningKey::random(&mut rng);
    let verifying_key = VerifyingKey::from(&signing_key);

    let address = utils::public_key_to_address(&verifying_key);
    let address = eth_checksum::checksum(&hex::encode(address.as_bytes()));
    let public = verifying_key.to_encoded_point(false).as_bytes().to_vec();
    let private = signing_key.to_bytes().to_vec();

    Ok((address, public, private))
}

pub fn generate_sol_account() -> Result<(String, Vec<u8>, Vec<u8>)> {
    let keypair = Keypair::new();
    let address = keypair.pubkey().to_string();
    let public = keypair.pubkey().to_bytes().to_vec();
    let private = keypair.to_bytes().to_vec();
    Ok((address, public, private))
}

pub fn encrypt(content: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)?;

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let nonce = Nonce::from_slice(&nonce);

    let ciphertext = cipher.encrypt(nonce, content).map_err(|e| anyhow!(e))?;

    let mut result = Vec::new();
    result.extend_from_slice(nonce);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

pub fn decrypt(content: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if content.len() < 12 {
        return Err(anyhow!("content too short"));
    }

    let nonce = Nonce::from_slice(&content[..12]);
    let ciphertext = &content[12..];

    let cipher = Aes256Gcm::new_from_slice(key)?;

    cipher.decrypt(nonce, ciphertext).map_err(|e| anyhow!(e))
}

pub async fn sign_evm_message(private: &[u8], message: &str) -> Result<Vec<u8>> {
    let wallet = LocalWallet::from_bytes(private)?;

    let message_bytes = if let Ok(bytes) = hex::decode(message.trim_start_matches("0x")) {
        bytes
    } else {
        message.as_bytes().to_vec()
    };

    let signature = wallet.sign_message(&message_bytes).await?;

    Ok(signature.to_vec())
}

pub async fn sign_sol_message(private: &[u8], message: &str) -> Result<Vec<u8>> {
    let keypair = Keypair::from_seed(private).map_err(|e| anyhow!(e.to_string()))?;

    let message_bytes = if let Ok(bytes) = hex::decode(message.trim_start_matches("0x")) {
        bytes
    } else {
        message.as_bytes().to_vec()
    };

    let signature = keypair.sign_message(&message_bytes);

    Ok(signature.as_array().to_vec())
}

pub fn clear_vec(mut vec: Vec<u8>) {
    vec.fill(0)
}

#[test]
fn test_generate_evm_account() {
    let (address, public, private) = generate_evm_account().unwrap();
    println!(
        "address: {}\n public: 0x{}\n private: 0x{}\n",
        &address,
        hex::encode(public),
        hex::encode(private)
    );
}

#[test]
fn test_generate_sol_account() {
    let (address, public, private) = generate_sol_account().unwrap();
    println!(
        "address: {}\n public: 0x{}\n private: 0x{}\n",
        address,
        hex::encode(public),
        hex::encode(private)
    );
}

#[tokio::test]
async fn test_sign_sol() -> Result<()> {
    let prv =
        "51Y9KYpmMu1fw8Mjv2vhySjcGK7mSEwRbvrh63novRiaiLcPt62usSHcDcdUyKNo7462Az3jbSuTVcuZH9CiPWdh";
    let keypair = Keypair::from_base58_string(&prv);
    let keypair_bytes = keypair.to_bytes().to_vec();

    let msg = "hello";

    let sig_o = keypair.sign_message(msg.as_bytes()).as_array().to_vec();

    let sig = sign_sol_message(&keypair_bytes, msg).await?;

    assert_eq!(sig, sig_o);

    Ok(())
}

#[tokio::test]
async fn test_sign_evm() {
    let prv = "29483cab4ee87b490ba40c50459137922240a2c5e240fbd50118c5150976a0ae";
    let prv_bytes = hex::decode(prv.trim_start_matches("0x")).unwrap();
    let message = "hello";
    let sig = sign_evm_message(&prv_bytes, message).await.unwrap();
    println!("sig: {}", hex::encode(sig));
}

#[test]
fn test_encrypt_decrypt() {
    let key_hex = "ac4565203d02b1325f6b974a718583c15200c3147e8a6f7763a84ec64768df09";
    println!("key_hex: {}", key_hex);
    let key_bytes = hex::decode(key_hex).unwrap();

    let prv_hex = "29483cab4ee87b490ba40c50459137922240a2c5e240fbd50118c5150976a0ae";
    println!("prv_hex: {}", prv_hex);
    let prv_bytes = hex::decode(prv_hex.trim_start_matches("0x")).unwrap();

    let prv_enc_bytes = encrypt(&prv_bytes, &key_bytes).unwrap();
    let prv_enc_hex = hex::encode(&prv_enc_bytes);
    println!("prv_enc_hex: {}", prv_enc_hex);

    let prv_bytes_dec = decrypt(&prv_enc_bytes, &key_bytes).unwrap();
    assert_eq!(&prv_bytes_dec, &prv_bytes);

    let prv_hex_dec = hex::encode(&prv_bytes_dec);
    assert_eq!(prv_hex_dec, prv_hex);

    println!("prv_hex_dec: {}", &prv_hex_dec);
}
