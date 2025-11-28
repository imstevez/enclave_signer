use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use anyhow::{Result, anyhow};
use aws_nitro_enclaves_cose::{CoseSign1, crypto::Openssl};
use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use aws_sdk_kms::types::KeyEncryptionMechanism::RsaesOaepSha256;
use aws_sdk_kms::types::RecipientInfo;
use aws_smithy_types::Blob;
use ethers::core::k256::ecdsa::{SigningKey, VerifyingKey};
use ethers::signers::{LocalWallet, Signer};
use ethers::types::H256;
use ethers::utils;
use ethers::utils::rlp;
use solana_sdk::signature::{Keypair, SeedDerivable, Signer as SolSigner};

pub fn to_err<T: ToString>(e: T) -> anyhow::Error {
    anyhow!(e.to_string())
}

pub fn parse_attestation_doc(doc: &[u8]) -> Result<AttestationDoc> {
    let doc_cose = CoseSign1::from_bytes(doc).map_err(to_err)?;
    let doc_payload: Vec<u8> = doc_cose.get_payload::<Openssl>(None).map_err(to_err)?;
    serde_cbor::from_slice(&doc_payload).map_err(to_err)
}

pub fn build_kms_recipient(doc: &[u8]) -> RecipientInfo {
    RecipientInfo::builder()
        .attestation_document(Blob::from(doc))
        .key_encryption_algorithm(RsaesOaepSha256)
        .build()
}

pub fn generate_evm_account() -> Result<(String, Vec<u8>, Vec<u8>)> {
    let sig_key = SigningKey::random(&mut rand::thread_rng());
    let ver_key = VerifyingKey::from(&sig_key);

    let address = utils::to_checksum(&utils::public_key_to_address(&ver_key), None);
    let public = ver_key.to_encoded_point(false).as_bytes().to_vec();
    let private = sig_key.to_bytes().to_vec();

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

    let ciphertext = cipher.encrypt(nonce, content).map_err(to_err)?;

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

    cipher.decrypt(nonce, ciphertext).map_err(to_err)
}

pub async fn sign_evm_message(private: &[u8], message: &str) -> Result<Vec<u8>> {
    let wallet = LocalWallet::from_bytes(private)?;

    let message_bytes = match hex::decode(message.strip_prefix("0x").unwrap_or(message)) {
        Ok(bytes) => bytes,
        Err(_) => message.as_bytes().to_vec(),
    };

    let signature = wallet.sign_message(&message_bytes).await?;

    Ok(signature.to_vec())
}

pub async fn sign_evm_data(private: &[u8], data: &str) -> Result<Vec<u8>> {
    let wallet = LocalWallet::from_bytes(private)?;

    let data_bytes = hex::decode(data.strip_prefix("0x").unwrap_or(data))?;

    let signature = wallet.sign_message(&data_bytes).await?;

    Ok(signature.to_vec())
}

pub async fn sign_evm_hash(private: &[u8], hash: &str) -> Result<Vec<u8>> {
    let wallet = LocalWallet::from_bytes(private)?;

    let hash_bytes = hex::decode(hash.strip_prefix("0x").unwrap_or(hash))?;

    let hash = H256::from_slice(&hash_bytes);

    let signature = wallet.sign_hash(hash)?;

    Ok(signature.to_vec())
}

pub async fn sign_evm_transaction(private: &[u8], transaction: &str) -> Result<Vec<u8>> {
    let wallet = LocalWallet::from_bytes(private)?;

    let transaction_bytes = hex::decode(transaction.strip_prefix("0x").unwrap_or(transaction))?;

    let tx = rlp::decode(&transaction_bytes)?;

    let signature = wallet.sign_transaction(&tx).await?;

    Ok(signature.to_vec())
}

pub async fn sign_sol_message(private: &[u8], message: &str) -> Result<Vec<u8>> {
    let keypair = Keypair::from_seed(private).map_err(|e| anyhow!(e.to_string()))?;

    let message_bytes = message.as_bytes().to_vec();

    let signature = keypair.try_sign_message(&message_bytes)?;

    Ok(signature.as_array().to_vec())
}

pub async fn sign_sol_data(private: &[u8], data: &str) -> Result<Vec<u8>> {
    let keypair = Keypair::from_seed(private).map_err(|e| anyhow!(e.to_string()))?;

    let data_bytes = hex::decode(data.strip_prefix("0x").unwrap_or(data))?;

    let signature = keypair.try_sign_message(&data_bytes)?;

    Ok(signature.as_array().to_vec())
}

pub fn clear_vec(mut vec: Vec<u8>) {
    vec.fill(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::abi::ethereum_types;
    use solana_sdk::pubkey::Pubkey;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_generate_evm_account() {
        let (address, public, private) = generate_evm_account().unwrap();
        println!(
            "address: {address}\npublic: {}\nprivate: {}\n",
            hex::encode(&public),
            hex::encode(&private)
        );

        let address_from_result = ethereum_types::Address::from_slice(
            &hex::decode(address.trim_start_matches("0x")).unwrap(),
        );

        let address_from_public =
            utils::public_key_to_address(&VerifyingKey::from_sec1_bytes(&public).unwrap());

        assert_eq!(address_from_result, address_from_public);

        let message = "hello";

        let signature = LocalWallet::from_bytes(&private)
            .unwrap()
            .sign_message(message)
            .await
            .unwrap();

        signature.verify(message, address_from_result).unwrap();
    }

    #[test]
    fn test_generate_sol_account() {
        let (address, public, private) = generate_sol_account().unwrap();
        println!(
            "address: {}\npublic: {}\nprivate: {}\n",
            address,
            hex::encode(&public),
            hex::encode(&private)
        );

        let address_from_result = Pubkey::from_str(&address).unwrap();

        let address_from_public = Pubkey::try_from(public.clone()).unwrap();

        assert_eq!(address_from_result, address_from_public);

        let message = "hello";

        let signature = Keypair::from_seed(&private)
            .unwrap()
            .sign_message(message.as_bytes());

        assert!(signature.verify(&public, message.as_bytes()));
    }

    #[tokio::test]
    async fn test_sign_evm_message() {
        let message = "hello";
        let private = "f32cc086c921c7758002afec8114da49cc86086e14ee69c20ba204deed1ebd2d";
        let signature = "6a73266a8fd50dccd19389e1fd8ff6c6fac6760138d52feb38540d43c5ed314733b332c3675745483a89a8b18af2b16aceeaf68cff65051808d53566b067054c1b";

        let signature_target = hex::decode(signature).unwrap();
        let signature_result = sign_evm_message(&hex::decode(private).unwrap(), message)
            .await
            .unwrap();

        assert_eq!(signature_result, signature_target);
    }

    #[tokio::test]
    async fn test_sign_evm_hash() {
        let hash = "0xfe546e16fc3aecb9db7990f2e1904299bb697b02c43d3dd4c2a8f2d88561357f";
        let private = "fbd19a3c3501904fe81a1593fb10fe948a5523dae77e8ea5ea36e816578a3160";

        let signature_result = sign_evm_hash(&hex::decode(private).unwrap(), hash)
            .await
            .unwrap();

        println!("result: {}", hex::encode(signature_result));
    }

    #[tokio::test]
    async fn test_sign_sol_message() {
        let message = "hello";
        let private = "51Y9KYpmMu1fw8Mjv2vhySjcGK7mSEwRbvrh63novRiaiLcPt62usSHcDcdUyKNo7462Az3jbSuTVcuZH9CiPWdh";
        let signature = "c26e4a56027369a56052cda5f062c4a4569d657dbdc33086b2069d830c3ac5e41407e71707826a15f25bcecf371fb2dbc9a4589614fba51edf2a964d862c1b06";

        let signature_target = hex::decode(signature).unwrap();
        let signature_result =
            sign_sol_message(&Keypair::from_base58_string(private).to_bytes(), message)
                .await
                .unwrap();

        assert_eq!(signature_result, signature_target);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = "ac4565203d02b1325f6b974a718583c15200c3147e8a6f7763a84ec64768df09";
        let key = hex::decode(key).unwrap();

        let cnt = "29483cab4ee87b490ba40c50459137922240a2c5e240fbd50118c5150976a0ae";
        let cnt = hex::decode(cnt).unwrap();

        let cnt_enc = encrypt(&cnt, &key).unwrap();
        let cnt_dec = decrypt(&cnt_enc, &key).unwrap();

        assert_eq!(&cnt_dec, &cnt);
    }
}
