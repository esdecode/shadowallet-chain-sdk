//! Minimal, testable Solana JSON-RPC client.
//!
//! The wire layer is abstracted behind [`Transport`] so protocol tests run
//! deterministically without a network. Reads are retried a bounded number of
//! times on transport-level failures only; `sendTransaction` is never retried.
//! Every response is shape-validated before use.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};

use crate::error::SolanaError;
use crate::network::SolanaNetwork;
use crate::pubkey::{Pubkey, TOKEN_2022_PROGRAM, TOKEN_PROGRAM};

const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_RETRIES: u32 = 2;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Defensive cap on token accounts accepted from a single response.
const MAX_TOKEN_ACCOUNTS: usize = 512;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Raw JSON-RPC transport: POST a request body, return the response body.
pub trait Transport: Send + Sync {
    fn post(&self, body: String) -> BoxFuture<'_, Result<Vec<u8>, SolanaError>>;
}

#[derive(Debug, Clone)]
pub struct HttpTransport {
    client: reqwest::Client,
    url: String,
}

impl HttpTransport {
    pub fn new(url: &str) -> Result<Self, SolanaError> {
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err(SolanaError::Transport("rpc url must be http(s)".into()));
        }
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| SolanaError::Transport(e.to_string()))?;
        Ok(Self {
            client,
            url: url.to_owned(),
        })
    }
}

impl Transport for HttpTransport {
    fn post(&self, body: String) -> BoxFuture<'_, Result<Vec<u8>, SolanaError>> {
        Box::pin(async move {
            let response = self
                .client
                .post(&self.url)
                .header("content-type", "application/json")
                .body(body)
                .send()
                .await
                .map_err(|e| SolanaError::Transport(e.without_url().to_string()))?;
            let status = response.status();
            if status.as_u16() == 429 || status.is_server_error() {
                return Err(SolanaError::Transport(format!("retryable http {status}")));
            }
            let bytes = response
                .bytes()
                .await
                .map_err(|e| SolanaError::Transport(e.without_url().to_string()))?;
            if bytes.len() > MAX_RESPONSE_BYTES {
                return Err(SolanaError::InvalidResponse("response too large".into()));
            }
            if !status.is_success() {
                return Err(SolanaError::InvalidResponse(format!("http {status}")));
            }
            Ok(bytes.to_vec())
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountInfo {
    pub lamports: u64,
    pub owner: Pubkey,
    pub data: Vec<u8>,
    pub executable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenAccount {
    pub address: Pubkey,
    pub mint: Pubkey,
    pub owner: Pubkey,
    pub token_program: Pubkey,
    pub amount: u64,
    pub decimals: u8,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxStatus {
    pub slot: u64,
    pub confirmations: Option<u64>,
    pub failed: bool,
    pub error: Option<String>,
    pub confirmation_status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureInfo {
    pub signature: String,
    pub slot: u64,
    pub block_time: Option<i64>,
    pub failed: bool,
    pub confirmation_status: Option<String>,
}

/// Net effect of a confirmed transaction on one owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxEffect {
    pub signature: String,
    pub slot: u64,
    pub block_time: Option<i64>,
    pub fee: u64,
    pub failed: bool,
    /// Lamport balance delta of the owner's system account (includes the fee
    /// when the owner is the fee payer).
    pub native_delta: i128,
    /// `(mint, raw amount delta)` for token accounts owned by the owner.
    pub token_deltas: Vec<(Pubkey, i128)>,
}

#[derive(Clone)]
pub struct SolanaRpc {
    transport: Arc<dyn Transport>,
    network: SolanaNetwork,
    next_id: Arc<AtomicU64>,
}

impl std::fmt::Debug for SolanaRpc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SolanaRpc")
            .field("network", &self.network)
            .finish()
    }
}

fn invalid(what: &str) -> SolanaError {
    SolanaError::InvalidResponse(what.to_owned())
}

fn as_u64(value: &Value, what: &str) -> Result<u64, SolanaError> {
    value.as_u64().ok_or_else(|| invalid(what))
}

fn pubkey_of(value: &Value, what: &str) -> Result<Pubkey, SolanaError> {
    let text = value.as_str().ok_or_else(|| invalid(what))?;
    Pubkey::from_base58(text).map_err(|_| invalid(what))
}

fn decode_account(value: &Value) -> Result<AccountInfo, SolanaError> {
    let data = value
        .get("data")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("account data"))?;
    Ok(AccountInfo {
        lamports: as_u64(&value["lamports"], "lamports")?,
        owner: pubkey_of(&value["owner"], "owner")?,
        data: B64.decode(data).map_err(|_| invalid("account data b64"))?,
        executable: value["executable"].as_bool().unwrap_or(false),
    })
}

impl SolanaRpc {
    pub fn new(transport: Arc<dyn Transport>, network: SolanaNetwork) -> Self {
        Self {
            transport,
            network,
            next_id: Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn http(url: &str, network: SolanaNetwork) -> Result<Self, SolanaError> {
        Ok(Self::new(Arc::new(HttpTransport::new(url)?), network))
    }

    pub fn network(&self) -> SolanaNetwork {
        self.network
    }

    async fn call(
        &self,
        method: &str,
        params: Value,
        idempotent: bool,
    ) -> Result<Value, SolanaError> {
        let mut attempt = 0u32;
        loop {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let body =
                json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string();
            match self.transport.post(body).await {
                Ok(bytes) => return Self::parse_response(&bytes, id),
                Err(SolanaError::Transport(message)) if idempotent && attempt < MAX_RETRIES => {
                    let _ = message;
                    attempt += 1;
                    tokio::time::sleep(Duration::from_millis(150 * (1 << attempt))).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn parse_response(bytes: &[u8], id: u64) -> Result<Value, SolanaError> {
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| invalid("response is not json"))?;
        if value["id"].as_u64() != Some(id) {
            return Err(invalid("response id mismatch"));
        }
        if let Some(error) = value.get("error") {
            let code = error["code"].as_i64().unwrap_or(0);
            let message: String = error["message"]
                .as_str()
                .unwrap_or("unknown")
                .chars()
                .take(300)
                .collect();
            return Err(SolanaError::Rpc { code, message });
        }
        value
            .get("result")
            .cloned()
            .ok_or_else(|| invalid("missing result"))
    }

    pub async fn get_genesis_hash(&self) -> Result<String, SolanaError> {
        let result = self.call("getGenesisHash", json!([]), true).await?;
        result
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| invalid("genesis hash"))
    }

    /// Bind this client to its declared network. A public network must report
    /// its well-known genesis hash; `Localnet` must NOT report any public one.
    pub async fn verify_network(&self) -> Result<(), SolanaError> {
        let genesis = self.get_genesis_hash().await?;
        match self.network.genesis_hash() {
            Some(expected) if expected == genesis => Ok(()),
            Some(_) => Err(SolanaError::WrongNetwork(format!(
                "rpc is not {}",
                self.network.id()
            ))),
            None => {
                let public = SolanaNetwork::ALL
                    .iter()
                    .filter_map(|n| n.genesis_hash())
                    .any(|g| g == genesis);
                if public {
                    Err(SolanaError::WrongNetwork(
                        "localnet endpoint reports a public cluster genesis".into(),
                    ))
                } else {
                    Ok(())
                }
            }
        }
    }

    pub async fn get_balance(&self, address: &Pubkey) -> Result<u64, SolanaError> {
        let result = self
            .call(
                "getBalance",
                json!([address.to_base58(), {"commitment": "confirmed"}]),
                true,
            )
            .await?;
        as_u64(&result["value"], "balance")
    }

    pub async fn get_account_info(
        &self,
        address: &Pubkey,
    ) -> Result<Option<AccountInfo>, SolanaError> {
        let result = self
            .call(
                "getAccountInfo",
                json!([address.to_base58(), {"encoding": "base64", "commitment": "confirmed"}]),
                true,
            )
            .await?;
        match &result["value"] {
            Value::Null => Ok(None),
            value => decode_account(value).map(Some),
        }
    }

    /// Returns `(blockhash, last_valid_block_height)`.
    pub async fn get_latest_blockhash(&self) -> Result<([u8; 32], u64), SolanaError> {
        let result = self
            .call(
                "getLatestBlockhash",
                json!([{"commitment": "confirmed"}]),
                true,
            )
            .await?;
        let text = result["value"]["blockhash"]
            .as_str()
            .ok_or_else(|| invalid("blockhash"))?;
        let bytes = bs58::decode(text)
            .into_vec()
            .map_err(|_| invalid("blockhash"))?;
        let hash: [u8; 32] = bytes.try_into().map_err(|_| invalid("blockhash length"))?;
        Ok((
            hash,
            as_u64(&result["value"]["lastValidBlockHeight"], "height")?,
        ))
    }

    /// Faucet request. Only meaningful on `Localnet`/`Devnet`/`Testnet`; the
    /// call is refused on mainnet.
    pub async fn request_airdrop(
        &self,
        address: &Pubkey,
        lamports: u64,
    ) -> Result<String, SolanaError> {
        if self.network.is_mainnet() {
            return Err(SolanaError::WrongNetwork("no faucet on mainnet".into()));
        }
        let result = self
            .call(
                "requestAirdrop",
                json!([address.to_base58(), lamports]),
                false,
            )
            .await?;
        result
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| invalid("airdrop signature"))
    }

    pub async fn get_block_height(&self) -> Result<u64, SolanaError> {
        let result = self
            .call("getBlockHeight", json!([{"commitment": "confirmed"}]), true)
            .await?;
        as_u64(&result, "block height")
    }

    /// `None` means the node no longer recognizes the message's blockhash.
    pub async fn get_fee_for_message(&self, message: &[u8]) -> Result<Option<u64>, SolanaError> {
        let result = self
            .call(
                "getFeeForMessage",
                json!([B64.encode(message), {"commitment": "confirmed"}]),
                true,
            )
            .await?;
        match &result["value"] {
            Value::Null => Ok(None),
            value => as_u64(value, "fee").map(Some),
        }
    }

    pub async fn get_minimum_balance_for_rent_exemption(
        &self,
        data_len: u64,
    ) -> Result<u64, SolanaError> {
        let result = self
            .call("getMinimumBalanceForRentExemption", json!([data_len]), true)
            .await?;
        as_u64(&result, "rent")
    }

    pub async fn get_signature_statuses(
        &self,
        signatures: &[String],
    ) -> Result<Vec<Option<TxStatus>>, SolanaError> {
        if signatures.is_empty() || signatures.len() > 256 {
            return Err(SolanaError::InvalidTransaction(
                "bad signature batch".into(),
            ));
        }
        let result = self
            .call(
                "getSignatureStatuses",
                json!([signatures, {"searchTransactionHistory": true}]),
                true,
            )
            .await?;
        let values = result["value"]
            .as_array()
            .ok_or_else(|| invalid("statuses"))?;
        if values.len() != signatures.len() {
            return Err(invalid("status count"));
        }
        values
            .iter()
            .map(|v| {
                if v.is_null() {
                    return Ok(None);
                }
                let err = &v["err"];
                Ok(Some(TxStatus {
                    slot: as_u64(&v["slot"], "slot")?,
                    confirmations: v["confirmations"].as_u64(),
                    failed: !err.is_null(),
                    error: (!err.is_null()).then(|| err.to_string().chars().take(200).collect()),
                    confirmation_status: v["confirmationStatus"].as_str().map(str::to_owned),
                }))
            })
            .collect()
    }

    /// Submit a signed transaction. Never retried: a lost response must be
    /// reconciled by signature status, not by blind resubmission.
    pub async fn send_transaction(&self, raw: &[u8]) -> Result<String, SolanaError> {
        let result = self
            .call(
                "sendTransaction",
                json!([B64.encode(raw), {
                    "encoding": "base64",
                    "preflightCommitment": "confirmed",
                    "skipPreflight": false,
                    "maxRetries": 0
                }]),
                false,
            )
            .await?;
        result
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| invalid("signature"))
    }

    /// Token accounts owned by `owner` under the SPL Token and Token-2022
    /// programs. Amounts and decimals come from the node's parsed account
    /// state; untrusted token metadata is never consulted.
    pub async fn get_token_accounts_by_owner(
        &self,
        owner: &Pubkey,
    ) -> Result<Vec<TokenAccount>, SolanaError> {
        let mut accounts = Vec::new();
        for program in [*TOKEN_PROGRAM, *TOKEN_2022_PROGRAM] {
            let result = self
                .call(
                    "getTokenAccountsByOwner",
                    json!([owner.to_base58(), {"programId": program.to_base58()},
                           {"encoding": "jsonParsed", "commitment": "confirmed"}]),
                    true,
                )
                .await?;
            let values = result["value"]
                .as_array()
                .ok_or_else(|| invalid("token accounts"))?;
            for v in values {
                if accounts.len() >= MAX_TOKEN_ACCOUNTS {
                    break;
                }
                let info = &v["account"]["data"]["parsed"]["info"];
                let amount = info["tokenAmount"]["amount"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    .ok_or_else(|| invalid("token amount"))?;
                let decimals = info["tokenAmount"]["decimals"]
                    .as_u64()
                    .and_then(|d| u8::try_from(d).ok())
                    .ok_or_else(|| invalid("token decimals"))?;
                let account = TokenAccount {
                    address: pubkey_of(&v["pubkey"], "token account")?,
                    mint: pubkey_of(&info["mint"], "mint")?,
                    owner: pubkey_of(&info["owner"], "token owner")?,
                    token_program: program,
                    amount,
                    decimals,
                    state: info["state"].as_str().unwrap_or("unknown").to_owned(),
                };
                if &account.owner != owner {
                    return Err(invalid("token account owner mismatch"));
                }
                accounts.push(account);
            }
        }
        Ok(accounts)
    }

    pub async fn get_token_account_balance(
        &self,
        account: &Pubkey,
    ) -> Result<(u64, u8), SolanaError> {
        let result = self
            .call(
                "getTokenAccountBalance",
                json!([account.to_base58(), {"commitment": "confirmed"}]),
                true,
            )
            .await?;
        let amount = result["value"]["amount"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| invalid("token balance"))?;
        let decimals = result["value"]["decimals"]
            .as_u64()
            .and_then(|d| u8::try_from(d).ok())
            .ok_or_else(|| invalid("token decimals"))?;
        Ok((amount, decimals))
    }

    pub async fn get_signatures_for_address(
        &self,
        address: &Pubkey,
        limit: u32,
        before: Option<&str>,
    ) -> Result<Vec<SignatureInfo>, SolanaError> {
        let mut options = json!({"limit": limit.clamp(1, 100), "commitment": "confirmed"});
        if let Some(before) = before {
            options["before"] = json!(before);
        }
        let result = self
            .call(
                "getSignaturesForAddress",
                json!([address.to_base58(), options]),
                true,
            )
            .await?;
        result
            .as_array()
            .ok_or_else(|| invalid("signatures"))?
            .iter()
            .map(|v| {
                Ok(SignatureInfo {
                    signature: v["signature"]
                        .as_str()
                        .ok_or_else(|| invalid("signature"))?
                        .to_owned(),
                    slot: as_u64(&v["slot"], "slot")?,
                    block_time: v["blockTime"].as_i64(),
                    failed: !v["err"].is_null(),
                    confirmation_status: v["confirmationStatus"].as_str().map(str::to_owned),
                })
            })
            .collect()
    }

    /// Derive the exact balance effect of a transaction on `owner` from the
    /// ledger's pre/post balances. Nothing is inferred beyond those fields.
    pub async fn get_transaction_effect(
        &self,
        signature: &str,
        owner: &Pubkey,
    ) -> Result<Option<TxEffect>, SolanaError> {
        let result = self
            .call(
                "getTransaction",
                json!([signature, {"encoding": "json", "commitment": "confirmed",
                                   "maxSupportedTransactionVersion": 0}]),
                true,
            )
            .await?;
        if result.is_null() {
            return Ok(None);
        }
        let meta = &result["meta"];
        let keys: Vec<Pubkey> = result["transaction"]["message"]["accountKeys"]
            .as_array()
            .ok_or_else(|| invalid("account keys"))?
            .iter()
            .map(|k| pubkey_of(k, "account key"))
            .collect::<Result<_, _>>()?;
        let pre = meta["preBalances"]
            .as_array()
            .ok_or_else(|| invalid("pre"))?;
        let post = meta["postBalances"]
            .as_array()
            .ok_or_else(|| invalid("post"))?;
        if pre.len() != keys.len() || post.len() != keys.len() {
            return Err(invalid("balance array length"));
        }
        let mut native_delta = 0i128;
        if let Some(index) = keys.iter().position(|k| k == owner) {
            native_delta =
                i128::from(as_u64(&post[index], "post")?) - i128::from(as_u64(&pre[index], "pre")?);
        }
        let mut token_deltas: Vec<(Pubkey, i128)> = Vec::new();
        let sum =
            |field: &str, sign: i128, out: &mut Vec<(Pubkey, i128)>| -> Result<(), SolanaError> {
                for entry in meta[field].as_array().into_iter().flatten() {
                    if entry["owner"].as_str() != Some(&owner.to_base58()) {
                        continue;
                    }
                    let mint = pubkey_of(&entry["mint"], "mint")?;
                    let amount = entry["uiTokenAmount"]["amount"]
                        .as_str()
                        .and_then(|s| s.parse::<u64>().ok())
                        .ok_or_else(|| invalid("token amount"))?;
                    match out.iter_mut().find(|(m, _)| *m == mint) {
                        Some((_, total)) => *total += sign * i128::from(amount),
                        None => out.push((mint, sign * i128::from(amount))),
                    }
                }
                Ok(())
            };
        sum("postTokenBalances", 1, &mut token_deltas)?;
        sum("preTokenBalances", -1, &mut token_deltas)?;
        token_deltas.retain(|(_, d)| *d != 0);
        Ok(Some(TxEffect {
            signature: signature.to_owned(),
            slot: as_u64(&result["slot"], "slot")?,
            block_time: result["blockTime"].as_i64(),
            fee: as_u64(&meta["fee"], "fee")?,
            failed: !meta["err"].is_null(),
            native_delta,
            token_deltas,
        }))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Scripted transport: pops queued responses and records requests.
    struct Scripted {
        responses: Mutex<Vec<Result<String, SolanaError>>>,
        requests: Mutex<Vec<Value>>,
    }

    impl Scripted {
        fn new(responses: Vec<Result<String, SolanaError>>) -> Arc<Self> {
            Arc::new(Self {
                responses: Mutex::new(responses.into_iter().rev().collect()),
                requests: Mutex::new(Vec::new()),
            })
        }
    }

    impl Transport for Scripted {
        fn post(&self, body: String) -> BoxFuture<'_, Result<Vec<u8>, SolanaError>> {
            Box::pin(async move {
                let request: Value = serde_json::from_str(&body).unwrap();
                let id = request["id"].clone();
                self.requests.lock().unwrap().push(request);
                let next = self.responses.lock().unwrap().pop().unwrap();
                next.map(|result| {
                    let mut value: Value = serde_json::from_str(&result).unwrap();
                    value["id"] = id;
                    value["jsonrpc"] = json!("2.0");
                    value.to_string().into_bytes()
                })
            })
        }
    }

    fn rpc(t: &Arc<Scripted>) -> SolanaRpc {
        SolanaRpc::new(t.clone(), SolanaNetwork::Localnet)
    }

    fn ok(result: Value) -> Result<String, SolanaError> {
        Ok(json!({"result": result}).to_string())
    }

    #[tokio::test]
    async fn balance_and_request_shape() {
        let t = Scripted::new(vec![ok(json!({"context": {"slot": 1}, "value": 42}))]);
        let balance = rpc(&t).get_balance(&Pubkey([3; 32])).await.unwrap();
        assert_eq!(balance, 42);
        let req = t.requests.lock().unwrap()[0].clone();
        assert_eq!(req["method"], "getBalance");
        assert_eq!(req["params"][0], Pubkey([3; 32]).to_base58());
    }

    #[tokio::test]
    async fn rpc_error_and_malformed_responses_are_rejected() {
        let t = Scripted::new(vec![
            Ok(json!({"error": {"code": -32002, "message": "boom"}}).to_string()),
            ok(json!({"value": "not a number"})),
            ok(json!({"value": null})),
        ]);
        let r = rpc(&t);
        assert!(matches!(
            r.get_balance(&Pubkey([3; 32])).await,
            Err(SolanaError::Rpc { code: -32002, .. })
        ));
        assert!(matches!(
            r.get_balance(&Pubkey([3; 32])).await,
            Err(SolanaError::InvalidResponse(_))
        ));
        assert_eq!(r.get_account_info(&Pubkey([3; 32])).await.unwrap(), None);
    }

    #[tokio::test]
    async fn reads_retry_boundedly_and_send_never_retries() {
        let flaky = || Err(SolanaError::Transport("down".into()));
        let t = Scripted::new(vec![flaky(), flaky(), ok(json!({"value": 7}))]);
        assert_eq!(rpc(&t).get_balance(&Pubkey([3; 32])).await.unwrap(), 7);
        assert_eq!(t.requests.lock().unwrap().len(), 3);

        let t = Scripted::new(vec![flaky(), flaky(), flaky()]);
        assert!(rpc(&t).get_balance(&Pubkey([3; 32])).await.is_err());
        assert_eq!(t.requests.lock().unwrap().len(), 3); // 1 + MAX_RETRIES

        let t = Scripted::new(vec![flaky(), ok(json!("sig"))]);
        assert!(rpc(&t).send_transaction(&[1, 2, 3]).await.is_err());
        assert_eq!(t.requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn network_binding() {
        let local = Scripted::new(vec![ok(json!(
            "SomeFreshLocalGenesis111111111111111111111111"
        ))]);
        assert!(rpc(&local).verify_network().await.is_ok());

        // A "localnet" client talking to a mainnet node is refused.
        let mainnet = SolanaNetwork::MainnetBeta.genesis_hash().unwrap();
        let t = Scripted::new(vec![ok(json!(mainnet))]);
        assert!(matches!(
            rpc(&t).verify_network().await,
            Err(SolanaError::WrongNetwork(_))
        ));

        // A "devnet" client talking to mainnet is refused.
        let t = Scripted::new(vec![ok(json!(mainnet))]);
        let devnet = SolanaRpc::new(t, SolanaNetwork::Devnet);
        assert!(matches!(
            devnet.verify_network().await,
            Err(SolanaError::WrongNetwork(_))
        ));
    }

    #[tokio::test]
    async fn token_accounts_are_parsed_and_owner_checked() {
        let owner = Pubkey([4; 32]);
        let entry = |owner_key: &Pubkey| {
            json!({"pubkey": Pubkey([5; 32]).to_base58(), "account": {"data": {"parsed": {"info": {
                "mint": Pubkey([6; 32]).to_base58(),
                "owner": owner_key.to_base58(),
                "state": "initialized",
                "tokenAmount": {"amount": "1500", "decimals": 6}
            }}}}})
        };
        let t = Scripted::new(vec![
            ok(json!({"value": [entry(&owner)]})),
            ok(json!({"value": []})),
        ]);
        let accounts = rpc(&t).get_token_accounts_by_owner(&owner).await.unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].amount, 1500);
        assert_eq!(accounts[0].decimals, 6);
        assert_eq!(accounts[0].token_program, *TOKEN_PROGRAM);

        let t = Scripted::new(vec![ok(json!({"value": [entry(&Pubkey([9; 32]))]}))]);
        assert!(rpc(&t).get_token_accounts_by_owner(&owner).await.is_err());
    }

    #[tokio::test]
    async fn transaction_effect_from_balances() {
        let owner = Pubkey([4; 32]);
        let other = Pubkey([5; 32]);
        let tx = json!({
            "slot": 10, "blockTime": 1700000000,
            "transaction": {"message": {"accountKeys": [owner.to_base58(), other.to_base58()]}},
            "meta": {"fee": 5000, "err": null,
                     "preBalances": [10000, 0], "postBalances": [4000, 1000],
                     "preTokenBalances": [], "postTokenBalances": []}
        });
        let t = Scripted::new(vec![ok(tx)]);
        let effect = rpc(&t)
            .get_transaction_effect("sig", &owner)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(effect.native_delta, -6000);
        assert_eq!(effect.fee, 5000);
        assert!(!effect.failed);
    }
}
