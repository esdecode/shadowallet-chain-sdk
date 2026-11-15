use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use crate::DecredError;
use crate::net::{DecredNet, VerifiedNet};

/// JSON-RPC client for a dcrd node (HTTP POST, basic auth). dcrd normally serves TLS with a self-signed certificate:
/// pass its `rpc.cert` as `ca_pem` (the certificate is trusted explicitly, never "accept any"). A plain `http://` URL
/// is for a local `--notls` development node only.
pub struct DcrdRpc {
    url: String,
    user: String,
    pass: String,
    client: reqwest::Client,
}

impl DcrdRpc {
    pub fn new(
        url: &str,
        user: &str,
        pass: &str,
        ca_pem: Option<&[u8]>,
    ) -> Result<Self, DecredError> {
        let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(60));
        if let Some(pem) = ca_pem {
            let der = pem_to_der(pem)?;
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let verifier = Arc::new(PinnedCert {
                der,
                provider: provider.clone(),
            });
            let config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| DecredError::Rpc(e.to_string()))?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth();
            builder = builder.use_preconfigured_tls(config);
        }
        let client = builder
            .build()
            .map_err(|e| DecredError::Rpc(e.to_string()))?;
        Ok(Self {
            url: url.to_string(),
            user: user.to_string(),
            pass: pass.to_string(),
            client,
        })
    }

    /// Raw JSON-RPC call for development tooling (for example `generate` on a private simnet).
    pub async fn raw(&self, method: &str, params: Value) -> Result<Value, DecredError> {
        self.call(method, params).await
    }

    pub(crate) async fn call(&self, method: &str, params: Value) -> Result<Value, DecredError> {
        let body =
            json!({"jsonrpc": "1.0", "id": "shadowallet", "method": method, "params": params});
        let resp = self
            .client
            .post(&self.url)
            .basic_auth(&self.user, Some(&self.pass))
            .json(&body)
            .send()
            .await
            .map_err(|e| DecredError::Rpc(e.to_string()))?;
        let value: Value = resp
            .json()
            .await
            .map_err(|e| DecredError::Rpc(e.to_string()))?;
        if let Some(err) = value.get("error").filter(|e| !e.is_null()) {
            let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
            let message = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("error");
            return Err(DecredError::Rpc(format!("{code}: {message}")));
        }
        Ok(value.get("result").cloned().unwrap_or(Value::Null))
    }

    /// Prove which network the node serves: chain name from `getblockchaininfo` and the genesis hash. Mainnet nodes
    /// are refused here, so a signing-capable `VerifiedNet` cannot exist for mainnet.
    pub async fn verify_network(&self, net: DecredNet) -> Result<VerifiedNet, DecredError> {
        let info = self.call("getblockchaininfo", json!([])).await?;
        let chain = info
            .get("chain")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let genesis = self.call("getblockhash", json!([0])).await?;
        VerifiedNet::verify(net, &chain, genesis.as_str().unwrap_or_default())
    }

    /// Raw identity for read-only display (never grants signing).
    pub async fn identity(&self) -> Result<(String, String), DecredError> {
        let info = self.call("getblockchaininfo", json!([])).await?;
        let genesis = self.call("getblockhash", json!([0])).await?;
        Ok((
            info.get("chain")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            genesis.as_str().unwrap_or_default().to_string(),
        ))
    }

    pub async fn block_count(&self) -> Result<u64, DecredError> {
        self.call("getblockcount", json!([]))
            .await?
            .as_u64()
            .ok_or_else(|| DecredError::Rpc("bad block count".into()))
    }

    pub(crate) async fn block_hash(&self, height: u64) -> Result<String, DecredError> {
        let v = self.call("getblockhash", json!([height])).await?;
        v.as_str()
            .map(str::to_string)
            .ok_or_else(|| DecredError::Rpc("bad block hash".into()))
    }

    /// A block with its full regular transactions (`rawtx`).
    pub(crate) async fn block(&self, hash: &str) -> Result<Value, DecredError> {
        self.call("getblock", json!([hash, true, true])).await
    }

    pub(crate) async fn mempool_txids(&self) -> Result<Vec<String>, DecredError> {
        let v = self.call("getrawmempool", json!([false])).await?;
        Ok(v.as_array()
            .into_iter()
            .flatten()
            .filter_map(|t| t.as_str().map(str::to_string))
            .collect())
    }

    pub(crate) async fn raw_tx(&self, txid: &str) -> Result<Value, DecredError> {
        self.call("getrawtransaction", json!([txid, 1])).await
    }

    pub(crate) async fn send_raw(&self, hex: &str) -> Result<String, DecredError> {
        let v = self.call("sendrawtransaction", json!([hex, false])).await?;
        v.as_str()
            .map(str::to_string)
            .ok_or_else(|| DecredError::Rpc("no txid returned".into()))
    }
}

/// Trusts exactly one certificate: the node's own `rpc.cert`. dcrd's self-signed certificate is flagged as a CA, which
/// the standard web-PKI verifier refuses for a server, so the usual root-store route cannot be used. Pinning the exact
/// DER bytes is stricter than a CA trust anchor: any other certificate, including one signed by this one, is refused.
/// Handshake signatures are still verified against the pinned certificate's key.
#[derive(Debug)]
struct PinnedCert {
    der: Vec<u8>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.der.as_slice() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// First certificate of a PEM file as DER bytes.
fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>, DecredError> {
    use base64::Engine as _;
    let text =
        std::str::from_utf8(pem).map_err(|_| DecredError::Rpc("rpc.cert is not text".into()))?;
    let body: String = text
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END CERTIFICATE-----"))
        .map(str::trim)
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|_| DecredError::Rpc("rpc.cert is not valid PEM".into()))
}
