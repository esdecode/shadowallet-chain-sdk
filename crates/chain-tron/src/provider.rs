//! TRON full-node HTTP access (`/wallet/*`) plus optional TronGrid history (`/v1/*`).
//! Every answer is treated as untrusted: sizes are bounded, shapes are checked, and the network
//! identity (genesis block id) is verified before any data is used.

use std::time::Duration;

use serde_json::{Value, json};

use crate::tokens::{
    TokenMeta, TokenTrust, decode_abi_string, decode_decimals, is_verified_symbol, sanitize_label,
    verified,
};
use crate::tx::BlockRef;
use crate::{TronAddress, TronError, TronNetwork};

const MAX_BODY: usize = 2 * 1024 * 1024;

#[derive(Clone)]
pub struct TronProvider {
    pub network: TronNetwork,
    url: String,
    client: reqwest::Client,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ChainParams {
    /// Sun burned per bandwidth byte when no bandwidth is available.
    pub bandwidth_fee_sun: u64,
    /// Sun burned per energy unit when no energy is available.
    pub energy_fee_sun: u64,
    /// Sun charged when a transfer activates a new account.
    pub new_account_fee_sun: u64,
    pub max_fee_limit_sun: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Resources {
    pub free_bandwidth_available: u64,
    pub staked_bandwidth_available: u64,
    pub energy_available: u64,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NowBlock {
    pub block: BlockRef,
    pub timestamp_ms: u64,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ConstantCall {
    pub result: Vec<u8>,
    pub energy_used: u64,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TxInfo {
    pub block_number: u64,
    /// `true` unless the receipt says the execution failed (REVERT, OUT_OF_ENERGY, ...).
    pub success: bool,
    pub failure: Option<String>,
    pub fee_sun: u64,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IncomingTransfer {
    pub txid: String,
    pub from: String,
    pub kind: &'static str,
    pub contract: Option<String>,
    pub symbol: Option<String>,
    pub decimals: Option<u8>,
    pub amount_raw: String,
    pub time_ms: u64,
}

fn rpc_err(e: impl std::fmt::Display) -> TronError {
    TronError::Rpc(e.to_string())
}

fn u64_of(v: &Value) -> Option<u64> {
    v.as_u64()
}

impl TronProvider {
    /// Connect and verify the node serves the expected network (genesis block id).
    pub async fn connect(network: TronNetwork, url: &str) -> Result<Self, TronError> {
        let url = url.trim_end_matches('/').to_owned();
        if !(url.starts_with("https://") || url.starts_with("http://")) {
            return Err(TronError::Rpc("node URL must be http(s)".to_owned()));
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(rpc_err)?;
        let provider = Self {
            network,
            url,
            client,
        };
        let genesis = provider
            .post("/wallet/getblockbynum", json!({"num": 0}))
            .await?;
        let id = genesis
            .get("blockID")
            .and_then(Value::as_str)
            .ok_or_else(|| TronError::Rpc("node returned no genesis block".to_owned()))?;
        if !id.eq_ignore_ascii_case(network.genesis_block_id) {
            return Err(TronError::Network(format!(
                "network identity mismatch: expected {} genesis {}, node reported {id}",
                network.name, network.genesis_block_id
            )));
        }
        Ok(provider)
    }

    async fn request(&self, path: &str, body: Option<Value>) -> Result<Value, TronError> {
        let mut attempt = 0;
        loop {
            let url = format!("{}{path}", self.url);
            let builder = match &body {
                Some(b) => self.client.post(&url).json(b),
                None => self.client.get(&url),
            };
            let response = builder.send().await.map_err(rpc_err)?;
            let status = response.status();
            let bytes = response.bytes().await.map_err(rpc_err)?;
            if bytes.len() > MAX_BODY {
                return Err(TronError::Rpc("node response exceeds 2 MiB".to_owned()));
            }
            let text = String::from_utf8_lossy(&bytes);
            let limited = status.as_u16() == 429
                || text.contains("allowed_rps")
                || text.contains("rate limit");
            if limited && attempt < 5 {
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(1_200)).await;
                continue;
            }
            if limited {
                return Err(TronError::Rpc("rate limited by the node".to_owned()));
            }
            let value: Value = serde_json::from_slice(&bytes)
                .map_err(|e| TronError::Rpc(format!("malformed node JSON (HTTP {status}): {e}")))?;
            if !status.is_success() {
                return Err(TronError::Rpc(format!("HTTP {status}: {}", short(&value))));
            }
            return Ok(value);
        }
    }

    async fn post(&self, path: &str, body: Value) -> Result<Value, TronError> {
        self.request(path, Some(body)).await
    }

    pub async fn now_block(&self) -> Result<NowBlock, TronError> {
        let v = self.post("/wallet/getnowblock", json!({})).await?;
        let id = v
            .get("blockID")
            .and_then(Value::as_str)
            .and_then(|s| hex::decode(s).ok())
            .filter(|b| b.len() == 32)
            .ok_or_else(|| TronError::Rpc("getnowblock: bad blockID".to_owned()))?;
        let header = v
            .pointer("/block_header/raw_data")
            .ok_or_else(|| TronError::Rpc("getnowblock: no header".to_owned()))?;
        let number = header
            .get("number")
            .and_then(u64_of)
            .ok_or_else(|| TronError::Rpc("getnowblock: no number".to_owned()))?;
        let timestamp_ms = header
            .get("timestamp")
            .and_then(u64_of)
            .ok_or_else(|| TronError::Rpc("getnowblock: no timestamp".to_owned()))?;
        let mut block_id = [0u8; 32];
        block_id.copy_from_slice(&id);
        // The block id embeds the block number: a node that disagrees with itself is not trusted.
        if u64::from_be_bytes([
            block_id[0],
            block_id[1],
            block_id[2],
            block_id[3],
            block_id[4],
            block_id[5],
            block_id[6],
            block_id[7],
        ]) != number
        {
            return Err(TronError::Rpc(
                "getnowblock: block id does not match its number".to_owned(),
            ));
        }
        Ok(NowBlock {
            block: BlockRef { number, block_id },
            timestamp_ms,
        })
    }

    /// TRX balance in sun; `None` means the account is not activated yet.
    pub async fn balance_sun(&self, address: &TronAddress) -> Result<Option<u64>, TronError> {
        let v = self
            .post(
                "/wallet/getaccount",
                json!({"address": hex::encode(address.0)}),
            )
            .await?;
        if v.as_object().is_none_or(|o| o.is_empty()) {
            return Ok(None);
        }
        Ok(Some(v.get("balance").and_then(u64_of).unwrap_or(0)))
    }

    pub async fn resources(&self, address: &TronAddress) -> Result<Resources, TronError> {
        let v = self
            .post(
                "/wallet/getaccountresource",
                json!({"address": hex::encode(address.0)}),
            )
            .await?;
        let g = |k: &str| v.get(k).and_then(u64_of).unwrap_or(0);
        Ok(Resources {
            free_bandwidth_available: g("freeNetLimit").saturating_sub(g("freeNetUsed")),
            staked_bandwidth_available: g("NetLimit").saturating_sub(g("NetUsed")),
            energy_available: g("EnergyLimit").saturating_sub(g("EnergyUsed")),
        })
    }

    pub async fn chain_params(&self) -> Result<ChainParams, TronError> {
        let v = self.post("/wallet/getchainparameters", json!({})).await?;
        let list = v
            .get("chainParameter")
            .and_then(Value::as_array)
            .ok_or_else(|| TronError::Rpc("getchainparameters: no list".to_owned()))?;
        let find = |key: &str| {
            list.iter()
                .find(|p| p.get("key").and_then(Value::as_str) == Some(key))
                .and_then(|p| p.get("value"))
                .and_then(u64_of)
        };
        let need = |key: &str| {
            find(key).ok_or_else(|| TronError::Rpc(format!("getchainparameters: {key} missing")))
        };
        Ok(ChainParams {
            bandwidth_fee_sun: need("getTransactionFee")?,
            energy_fee_sun: need("getEnergyFee")?,
            new_account_fee_sun: need("getCreateNewAccountFeeInSystemContract")?,
            max_fee_limit_sun: find("getMaxFeeLimit").unwrap_or(15_000_000_000),
        })
    }

    /// Does `address` hold deployed contract code?
    pub async fn is_contract(&self, address: &TronAddress) -> Result<bool, TronError> {
        let v = self
            .post(
                "/wallet/getcontract",
                json!({"value": hex::encode(address.0)}),
            )
            .await?;
        Ok(v.get("bytecode")
            .and_then(Value::as_str)
            .is_some_and(|b| !b.is_empty()))
    }

    /// Simulated (read-only) contract call. A revert or an error answer is an `Err`.
    pub async fn constant_call(
        &self,
        owner: &TronAddress,
        contract: &TronAddress,
        selector: &str,
        parameter_hex: &str,
    ) -> Result<ConstantCall, TronError> {
        let v = self
            .post(
                "/wallet/triggerconstantcontract",
                json!({
                    "owner_address": hex::encode(owner.0),
                    "contract_address": hex::encode(contract.0),
                    "function_selector": selector,
                    "parameter": parameter_hex,
                }),
            )
            .await?;
        let ok = v
            .pointer("/result/result")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !ok {
            return Err(TronError::Rpc(format!(
                "constant call {selector} failed: {}",
                short(&v)
            )));
        }
        if let Some(ret) = v
            .pointer("/transaction/ret/0/ret")
            .and_then(Value::as_str)
            .filter(|r| *r != "SUCCESS")
        {
            return Err(TronError::Rpc(format!(
                "constant call {selector} would fail: {ret}"
            )));
        }
        let first = v
            .get("constant_result")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(Value::as_str)
            .ok_or_else(|| TronError::Rpc(format!("constant call {selector}: no result")))?;
        Ok(ConstantCall {
            result: hex::decode(first)
                .map_err(|_| TronError::Rpc("constant call: bad hex".to_owned()))?,
            energy_used: v.get("energy_used").and_then(u64_of).unwrap_or(0),
        })
    }

    /// `balanceOf(owner)` as the raw 32-byte word.
    pub async fn trc20_balance(
        &self,
        contract: &TronAddress,
        owner: &TronAddress,
    ) -> Result<[u8; 32], TronError> {
        let mut param = vec![0u8; 12];
        param.extend_from_slice(&owner.body());
        let call = self
            .constant_call(owner, contract, "balanceOf(address)", &hex::encode(param))
            .await?;
        if call.result.len() != 32 {
            return Err(TronError::Token(
                "balanceOf returned an unexpected size".to_owned(),
            ));
        }
        let mut word = [0u8; 32];
        word.copy_from_slice(&call.result);
        Ok(word)
    }

    /// Read and validate token metadata. Unknown tokens are `Custom`, never `Verified`; a verified
    /// token whose on-chain metadata disagrees with the registry is refused outright.
    pub async fn token_meta(
        &self,
        contract: &TronAddress,
        probe_owner: &TronAddress,
    ) -> Result<TokenMeta, TronError> {
        if !self.is_contract(contract).await? {
            return Err(TronError::Token("the address holds no contract".to_owned()));
        }
        let decimals = decode_decimals(
            &self
                .constant_call(probe_owner, contract, "decimals()", "")
                .await?
                .result,
        )?;
        let symbol = sanitize_label(
            &decode_abi_string(
                &self
                    .constant_call(probe_owner, contract, "symbol()", "")
                    .await?
                    .result,
            )?,
            12,
        )?;
        let name = sanitize_label(
            &decode_abi_string(
                &self
                    .constant_call(probe_owner, contract, "name()", "")
                    .await?
                    .result,
            )?,
            48,
        )?;
        let trust = match verified(self.network.name, contract) {
            Some(v) => {
                if v.decimals != decimals || v.symbol != symbol {
                    return Err(TronError::Token(format!(
                        "verified token {} reports {symbol}/{decimals} on chain: refusing",
                        v.symbol
                    )));
                }
                TokenTrust::Verified
            }
            None => TokenTrust::Custom {
                lookalike: is_verified_symbol(self.network.name, &symbol),
            },
        };
        Ok(TokenMeta {
            contract: *contract,
            symbol,
            name,
            decimals,
            trust,
        })
    }

    /// Broadcast a serialized transaction. `Ok(txid)` only if the node accepted it.
    pub async fn broadcast_hex(&self, serialized: &[u8]) -> Result<String, TronError> {
        let v = self
            .post(
                "/wallet/broadcasthex",
                json!({"transaction": hex::encode(serialized)}),
            )
            .await?;
        if v.get("result").and_then(Value::as_bool) == Some(true) {
            return v
                .get("txid")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| TronError::Rpc("broadcast accepted without a txid".to_owned()));
        }
        let code = v.get("code").and_then(Value::as_str).unwrap_or("");
        // DUP_TRANSACTION_ERROR means the node already has it: that is not a rejection.
        if code == "DUP_TRANSACTION_ERROR" {
            return Err(TronError::Rpc(
                "broadcast ambiguous: DUP_TRANSACTION_ERROR".to_owned(),
            ));
        }
        Err(TronError::Rejected(format!(
            "{code}: {}",
            decode_message(&v)
        )))
    }

    /// Execution info for an included transaction, `None` while it is unknown to the node.
    pub async fn tx_info(&self, txid: &str) -> Result<Option<TxInfo>, TronError> {
        let v = self
            .post("/wallet/gettransactioninfobyid", json!({"value": txid}))
            .await?;
        if v.as_object().is_none_or(|o| o.is_empty()) {
            return Ok(None);
        }
        let Some(block_number) = v.get("blockNumber").and_then(u64_of) else {
            return Ok(None);
        };
        let receipt = v.get("receipt").cloned().unwrap_or(Value::Null);
        let receipt_result = receipt.get("result").and_then(Value::as_str);
        let top_result = v.get("result").and_then(Value::as_str);
        let failure = match (top_result, receipt_result) {
            (Some("FAILED"), _) => Some(format!("FAILED {}", decode_message(&v))),
            (_, Some(r)) if r != "SUCCESS" => Some(r.to_owned()),
            _ => None,
        };
        Ok(Some(TxInfo {
            block_number,
            success: failure.is_none(),
            failure,
            fee_sun: v.get("fee").and_then(u64_of).unwrap_or(0),
        }))
    }

    /// Is the transaction still known to the node (pool or chain)?
    pub async fn tx_known(&self, txid: &str) -> Result<bool, TronError> {
        let v = self
            .post("/wallet/gettransactionbyid", json!({"value": txid}))
            .await?;
        Ok(v.as_object().is_some_and(|o| !o.is_empty()))
    }

    /// Incoming transfers from the TronGrid index (TRX and TRC-20). Provider-reported and not
    /// authoritative: the amounts and token labels are display-only.
    pub async fn incoming_history(
        &self,
        address: &TronAddress,
        limit: u32,
    ) -> Result<Vec<IncomingTransfer>, TronError> {
        let b58 = address.to_base58();
        let limit = limit.clamp(1, 50);
        let mut out = Vec::new();
        let trx = self
            .request(&format!("/v1/accounts/{b58}/transactions?only_to=true&only_confirmed=false&limit={limit}"), None)
            .await?;
        for item in trx
            .get("data")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(c) = item.pointer("/raw_data/contract/0") else {
                continue;
            };
            if c.get("type").and_then(Value::as_str) != Some("TransferContract") {
                continue;
            }
            if item.pointer("/ret/0/contractRet").and_then(Value::as_str) != Some("SUCCESS") {
                continue;
            }
            let v = &c["parameter"]["value"];
            let (Some(txid), Some(amount), Some(from)) = (
                item.get("txID").and_then(Value::as_str),
                v.get("amount").and_then(u64_of),
                v.get("owner_address")
                    .and_then(Value::as_str)
                    .and_then(|s| TronAddress::parse(s).ok()),
            ) else {
                continue;
            };
            out.push(IncomingTransfer {
                txid: txid.to_owned(),
                from: from.to_base58(),
                kind: "trx",
                contract: None,
                symbol: Some("TRX".to_owned()),
                decimals: Some(6),
                amount_raw: amount.to_string(),
                time_ms: item.get("block_timestamp").and_then(u64_of).unwrap_or(0),
            });
        }
        let trc = self
            .request(
                &format!("/v1/accounts/{b58}/transactions/trc20?only_to=true&limit={limit}"),
                None,
            )
            .await?;
        for item in trc
            .get("data")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if item.get("type").and_then(Value::as_str) != Some("Transfer") {
                continue;
            }
            let (Some(txid), Some(from), Some(value), Some(token)) = (
                item.get("transaction_id").and_then(Value::as_str),
                item.get("from").and_then(Value::as_str),
                item.get("value").and_then(Value::as_str),
                item.pointer("/token_info/address").and_then(Value::as_str),
            ) else {
                continue;
            };
            if !value.bytes().all(|b| b.is_ascii_digit()) || value.is_empty() {
                continue;
            }
            out.push(IncomingTransfer {
                txid: txid.to_owned(),
                from: from.to_owned(),
                kind: "trc20",
                contract: Some(token.to_owned()),
                symbol: item
                    .pointer("/token_info/symbol")
                    .and_then(Value::as_str)
                    .and_then(|s| sanitize_label(s, 12).ok()),
                decimals: item
                    .pointer("/token_info/decimals")
                    .and_then(u64_of)
                    .and_then(|d| u8::try_from(d).ok())
                    .filter(|d| *d <= 36),
                amount_raw: value.to_owned(),
                time_ms: item.get("block_timestamp").and_then(u64_of).unwrap_or(0),
            });
        }
        out.sort_by_key(|t| std::cmp::Reverse(t.time_ms));
        Ok(out)
    }
}

fn short(v: &Value) -> String {
    let s = v.to_string();
    s.chars().take(300).collect()
}

/// The node's `message` field is hex-encoded text.
fn decode_message(v: &Value) -> String {
    v.get("message")
        .and_then(Value::as_str)
        .and_then(|m| hex::decode(m).ok())
        .map(|b| {
            String::from_utf8_lossy(&b)
                .chars()
                .filter(|c| !c.is_control())
                .take(200)
                .collect()
        })
        .unwrap_or_default()
}
