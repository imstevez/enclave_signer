use anyhow::{Result, anyhow};
use aws_config::BehaviorVersion;
use aws_nitro_enclaves_nsm_api::{api, driver};
use aws_sdk_kms::config::{Credentials, SharedCredentialsProvider};
use openssl::cms::CmsContentInfo;
use openssl::pkey::{PKey, Private};
use rsa::RsaPrivateKey;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use serde::Deserialize;
use serde_bytes::ByteBuf;
use std::env;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct EnclaveState {
    pub nsm_fd: i32,
    pub recipient_private: PKey<Private>,
    pub recipient_public: Vec<u8>,
    pub aws_metadata_host: String,
    pub listen_address: String,
}

impl Drop for EnclaveState {
    fn drop(&mut self) {
        driver::nsm_exit(self.nsm_fd);
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct AwsCredentials {
    code: String,
    access_key_id: String,
    secret_access_key: String,
    token: String,
}

impl EnclaveState {
    pub fn new() -> Result<Self> {
        let nsm_fd = driver::nsm_init();
        if nsm_fd < 0 {
            return Err(anyhow!("nsm_init() failed"));
        }

        const BITS: usize = 2048;
        let mut rng = rand::thread_rng();
        let recipient_private = RsaPrivateKey::new(&mut rng, BITS)?;

        let recipient_public = recipient_private
            .to_public_key()
            .to_public_key_der()?
            .as_bytes()
            .to_vec();

        let recipient_private_do = recipient_private.to_pkcs8_der()?.as_bytes().to_vec();
        let recipient_private = PKey::private_key_from_der(&recipient_private_do)?;

        const DEFAULT_AWS_METADATA_HOST: &str = "127.0.0.1:7001";
        let aws_metadata_host =
            env::var("AWS_METADATA_HOST").unwrap_or(DEFAULT_AWS_METADATA_HOST.to_owned());

        const DEFAULT_LISTEN_ADDRESS: &str = "127.0.0.1:8002";
        let listen_address =
            env::var("LISTEN_ADDRESS").unwrap_or(DEFAULT_LISTEN_ADDRESS.to_owned());

        Ok(EnclaveState {
            nsm_fd,
            recipient_private,
            recipient_public,
            aws_metadata_host,
            listen_address,
        })
    }

    pub fn attest(&self) -> Result<Vec<u8>> {
        let nonce = Uuid::new_v4().as_bytes().to_vec();
        let req = api::Request::Attestation {
            user_data: None,
            public_key: Some(ByteBuf::from(self.recipient_public.clone())),
            nonce: Some(ByteBuf::from(nonce)),
        };
        let res = driver::nsm_process_request(self.nsm_fd, req);
        match res {
            api::Response::Attestation { document: doc } => Ok(doc),
            api::Response::Error(e) => Err(anyhow!(format!("code: {:?}", e))),
            _ => Err(anyhow::anyhow!("unknown response")),
        }
    }

    pub fn decrypt(&self, content: &[u8]) -> Result<Vec<u8>> {
        let cms = CmsContentInfo::from_der(content)?;
        cms.decrypt_without_cert_check(&self.recipient_private)
            .map_err(|e| anyhow!(e))
    }

    pub async fn kms_cli(&self, region: &str) -> Result<aws_sdk_kms::Client> {
        let creds = self.aws_creds().await?;

        let creds = Credentials::new(
            creds.access_key_id,
            creds.secret_access_key,
            Some(creds.token),
            None,
            "enclave",
        );

        let creds_provider = SharedCredentialsProvider::new(creds);
        let region = aws_config::Region::new(region.to_string());

        let cfg = aws_config::SdkConfig::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(region)
            .credentials_provider(creds_provider)
            .build();

        let cli = aws_sdk_kms::Client::new(&cfg);

        Ok(cli)
    }

    async fn aws_creds(&self) -> Result<AwsCredentials> {
        let token_url = format!("http://{}/latest/api/token", self.aws_metadata_host);
        let res = match reqwest::Client::new()
            .put(token_url)
            .header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
            .send()
            .await
        {
            Ok(res) => res,
            Err(e) => return Err(anyhow!("get creds token: {}", e)),
        };
        if res.status() != 200 {
            return Err(anyhow!("get creds token: {}", res.status()));
        }
        let token = res.text().await?;

        let role_url = format!(
            "http://{}/latest/meta-data/iam/security-credentials",
            self.aws_metadata_host
        );
        let res = match reqwest::Client::new()
            .get(role_url)
            .header("X-aws-ec2-metadata-token", &token)
            .send()
            .await
        {
            Err(e) => return Err(anyhow!("get creds role: {}", e)),
            Ok(res) => res,
        };
        if res.status() != 200 {
            return Err(anyhow!("get creds role: {}", res.status()));
        }
        let role = res.text().await?;

        let creds_url = format!(
            "http://{}/latest/meta-data/iam/security-credentials/{}",
            self.aws_metadata_host, role
        );
        let res = match reqwest::Client::new()
            .get(creds_url)
            .header("X-aws-ec2-metadata-token", &token)
            .send()
            .await
        {
            Err(e) => return Err(anyhow!("get creds: {}", e)),
            Ok(res) => res,
        };
        if res.status() != 200 {
            return Err(anyhow!("get creds: {}", res.status()));
        }
        let creds: AwsCredentials = res.json().await?;
        if creds.code != "Success" {
            return Err(anyhow!("get creds: {}", creds.code));
        }

        Ok(creds)
    }
}
