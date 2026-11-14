#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! L2 and testnet fee handling against an in-process mock JSON-RPC node: the OP-stack L1 data fee is read from the
//! GasPriceOracle and counted in the balance check; Arbitrum's estimate gets a safety margin; absurd or malformed oracle
//! answers fail closed; the new public-testnet profiles are consistent.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use shadowallet_chain_evm::{
    ARBITRUM_SEPOLIA, Address, BASE_SEPOLIA, BSC_TESTNET, EvmChain, EvmError, EvmProvider,
    FeeModel, POLYGON_AMOY, PROFILES, SEPOLIA, U256, prepare_native_transfer_with_nonce,
};

const HEADER_END: &[u8] = &[13, 10, 13, 10]; // CR LF CR LF

#[derive(Clone)]
struct Node {
    chain_id: u64,
    estimate: u64,
    balance: U256,
    /// bytes answered to `eth_call` (the GasPriceOracle)
    oracle: Vec<u8>,
}

fn serve(node: Node) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let methods: Arc<Mutex<Vec<String>>> = Arc::default();
    let seen = methods.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let (node, seen) = (node.clone(), seen.clone());
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 16384];
                let mut n = 0;
                let mut body_start = None;
                let mut want = 0usize;
                loop {
                    let r = stream.read(&mut buf[n..]).unwrap_or(0);
                    if r == 0 {
                        break;
                    }
                    n += r;
                    if body_start.is_none()
                        && let Some(i) = buf[..n].windows(4).position(|w| w == HEADER_END)
                    {
                        let head = String::from_utf8_lossy(&buf[..i]).to_lowercase();
                        want = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse().ok())
                            .unwrap_or(0);
                        body_start = Some(i + 4);
                    }
                    if let Some(b) = body_start
                        && n >= b + want
                    {
                        break;
                    }
                }
                let b = body_start.unwrap_or(0);
                let req: Value = serde_json::from_slice(&buf[b..n]).unwrap_or(Value::Null);
                let method = req["method"].as_str().unwrap_or("").to_owned();
                seen.lock().unwrap().push(method.clone());
                let result = match method.as_str() {
                    "eth_chainId" => json!(format!("0x{:x}", node.chain_id)),
                    "eth_getBlockByNumber" => {
                        json!({"baseFeePerGas": "0x3b9aca00", "number": "0x10"})
                    }
                    "eth_maxPriorityFeePerGas" => json!("0x3b9aca00"),
                    "eth_gasPrice" => json!("0x3b9aca00"),
                    "eth_estimateGas" => json!(format!("0x{:x}", node.estimate)),
                    "eth_getBalance" => json!(format!("0x{:x}", node.balance)),
                    "eth_getTransactionCount" => json!("0x0"),
                    "eth_call" => json!(format!("0x{}", hex::encode(&node.oracle))),
                    _ => Value::Null,
                };
                let body = json!({"jsonrpc": "2.0", "id": req["id"], "result": result}).to_string();
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .as_bytes(),
                );
            });
        }
    });
    (url, methods)
}

fn word(v: u128) -> Vec<u8> {
    let mut w = vec![0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

const ETH: u128 = 1_000_000_000_000_000_000;

fn node(chain: EvmChain, estimate: u64, balance: u128, oracle: Vec<u8>) -> Node {
    Node {
        chain_id: chain.chain_id,
        estimate,
        balance: U256::from(balance),
        oracle,
    }
}

async fn prepare(
    chain: EvmChain,
    n: Node,
) -> (
    Result<shadowallet_chain_evm::UnsignedEvmTransaction, EvmError>,
    Arc<Mutex<Vec<String>>>,
) {
    let (url, seen) = serve(n);
    let provider = EvmProvider::connect(chain, &url).await.unwrap();
    let r = prepare_native_transfer_with_nonce(
        &provider,
        Address::from([1u8; 20]),
        Address::from([2u8; 20]),
        U256::from(ETH / 100),
        0,
    )
    .await;
    (r, seen)
}

#[test]
fn the_new_test_network_profiles_are_consistent() {
    for (chain, id, fee) in [
        (POLYGON_AMOY, 80_002, FeeModel::Eip1559),
        (BSC_TESTNET, 97, FeeModel::Legacy),
        (ARBITRUM_SEPOLIA, 421_614, FeeModel::ArbitrumNitro),
        (BASE_SEPOLIA, 84_532, FeeModel::OpStack),
    ] {
        assert_eq!(chain.chain_id, id);
        assert_eq!(chain.fee_model, fee);
        assert_eq!(EvmChain::by_id(id).unwrap().name, chain.name);
        assert_eq!(EvmChain::by_name(chain.name).unwrap().chain_id, id);
    }
    // names and ids are unique, and a test network never shares an id with a mainnet profile
    let mut ids: Vec<u64> = PROFILES.iter().map(|p| p.chain_id).collect();
    let before = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), before);
    assert_eq!(SEPOLIA.chain_id, 11_155_111);
}

#[tokio::test]
async fn op_stack_l1_data_fee_is_read_buffered_and_counted_in_the_balance_check() {
    // oracle: 0.0001 ETH
    let (r, seen) = prepare(
        BASE_SEPOLIA,
        node(BASE_SEPOLIA, 21_000, ETH, word(ETH / 10_000)),
    )
    .await;
    let tx = r.unwrap();
    assert_eq!(tx.l1_data_fee_wei, U256::from(ETH / 10_000 + ETH / 40_000)); // +25 %
    assert!(
        seen.lock().unwrap().iter().any(|m| m == "eth_call"),
        "the oracle was asked"
    );

    // gas cost is tiny, so a balance just below value + L1 fee must be refused, one just above accepted
    let value = ETH / 100;
    let exact = value + ETH / 10_000 + ETH / 40_000;
    let (low, _) = prepare(
        BASE_SEPOLIA,
        node(
            BASE_SEPOLIA,
            21_000,
            exact + 20_000_000_000_000 - 1,
            word(ETH / 10_000),
        ),
    )
    .await;
    // (gas: 21 000 x (2 x 1 gwei + 1 gwei) = 6.3e13 wei) -> not enough once gas is counted
    assert!(matches!(low, Err(EvmError::InsufficientFunds)), "{low:?}");
    let (ok, _) = prepare(
        BASE_SEPOLIA,
        node(
            BASE_SEPOLIA,
            21_000,
            exact + 100_000_000_000_000,
            word(ETH / 10_000),
        ),
    )
    .await;
    assert!(ok.is_ok());
}

#[tokio::test]
async fn an_absurd_or_malformed_l1_fee_answer_fails_closed() {
    // above the 0.01 ETH bound
    let (r, _) = prepare(
        BASE_SEPOLIA,
        node(BASE_SEPOLIA, 21_000, 10 * ETH, word(ETH / 10)),
    )
    .await;
    assert!(matches!(r, Err(EvmError::FeeRejected)), "{r:?}");
    // an answer that is not one 32-byte word
    let (r, _) = prepare(
        BASE_SEPOLIA,
        node(BASE_SEPOLIA, 21_000, 10 * ETH, vec![1, 2, 3]),
    )
    .await;
    assert!(matches!(r, Err(EvmError::UnsupportedFeeModel)), "{r:?}");
}

#[tokio::test]
async fn arbitrum_estimate_gets_a_quarter_margin_and_needs_no_oracle() {
    let (r, seen) = prepare(
        ARBITRUM_SEPOLIA,
        node(ARBITRUM_SEPOLIA, 120_000, ETH, vec![]),
    )
    .await;
    let tx = r.unwrap();
    assert_eq!(tx.gas_limit, 150_000, "estimate 120 000 + 25 %");
    assert_eq!(tx.l1_data_fee_wei, U256::zero());
    assert!(!seen.lock().unwrap().iter().any(|m| m == "eth_call"));
}

#[tokio::test]
async fn a_node_that_reports_another_chain_id_is_refused() {
    let (url, _) = serve(node(SEPOLIA, 21_000, ETH, vec![]));
    assert!(EvmProvider::connect(BASE_SEPOLIA, &url).await.is_err());
}

#[tokio::test]
async fn polygon_amoy_uses_the_plain_eip1559_model() {
    let (r, _) = prepare(POLYGON_AMOY, node(POLYGON_AMOY, 21_000, ETH, vec![])).await;
    let tx = r.unwrap();
    assert_eq!(tx.l1_data_fee_wei, U256::zero());
    assert_eq!(tx.gas_limit, 21_000);
}

#[tokio::test]
async fn bsc_testnet_uses_a_legacy_gas_price() {
    let (r, _) = prepare(BSC_TESTNET, node(BSC_TESTNET, 21_000, ETH, vec![])).await;
    let tx = r.unwrap();
    assert!(tx.gas_price.is_some());
    assert_eq!(tx.chain_id, 97);
}
