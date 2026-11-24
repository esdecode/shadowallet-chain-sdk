//! HTTP transport for the Monero daemon RPC with optional SOCKS5 proxy support (Tor, Orbot, I2P gateways).
//!
//! With a `socks5h://` proxy the host name (including `.onion`) is resolved by the proxy, so the device never
//! looks it up itself and a Tor circuit hides the wallet's IP address from the node. A proxy hides the IP address
//! only: the node still sees which blocks and decoy outputs are requested.

use std::sync::Arc;
use std::time::Duration;

use monero_daemon_rpc::HttpTransport;
use monero_wallet::interface::InterfaceError;

/// Requests allowed in flight at once (matches the scan window in `sync.rs`).
const MAX_IN_FLIGHT: usize = 4;

#[derive(Clone)]
pub struct ProxyTransport {
    client: reqwest::Client,
    base: String,
    in_flight: Arc<tokio::sync::Semaphore>,
}

impl ProxyTransport {
    /// `url` is the daemon's base URL (`http(s)://host:port`). `proxy`, when set, must be a `socks5h://` or
    /// `socks5://` URL; anything else is refused (an HTTP proxy would see the traffic).
    pub fn new(url: &str, proxy: Option<&str>) -> Result<Self, InterfaceError> {
        Self::new_with_timeout(url, proxy, 60)
    }

    /// Like [`new`](Self::new) with an explicit per-request bound in seconds (tests use a short one).
    pub fn new_with_timeout(
        url: &str,
        proxy: Option<&str>,
        timeout_secs: u64,
    ) -> Result<Self, InterfaceError> {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("Mozilla/5.0");
        if let Some(p) = proxy {
            if !(p.starts_with("socks5h://") || p.starts_with("socks5://")) {
                return Err(InterfaceError::InternalError(
                    "the proxy must be a socks5h:// or socks5:// URL".to_owned(),
                ));
            }
            builder = builder.proxy(
                reqwest::Proxy::all(p)
                    .map_err(|e| InterfaceError::InternalError(format!("proxy: {e}")))?,
            );
        } else {
            builder = builder.no_proxy();
        }
        let client = builder
            .build()
            .map_err(|e| InterfaceError::InternalError(format!("client: {e}")))?;
        Ok(Self {
            client,
            base: url.trim_end_matches('/').to_owned(),
            in_flight: Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT)),
        })
    }
}

impl HttpTransport for ProxyTransport {
    fn post(
        &self,
        route: &str,
        body: Vec<u8>,
        response_size_limit: Option<usize>,
    ) -> impl Send + std::future::Future<Output = Result<Vec<u8>, InterfaceError>> {
        let url = format!("{}/{route}", self.base);
        let client = self.client.clone();
        let gate = self.in_flight.clone();
        async move {
            // bounded concurrency: each response is read in full by its own request, public nodes see at most this many
            let _permit = gate
                .acquire()
                .await
                .map_err(|_| InterfaceError::InternalError("transport closed".to_owned()))?;
            let mut response = client
                .post(url)
                .body(body)
                .send()
                .await
                .map_err(|e| InterfaceError::InterfaceError(format!("request failed: {e}")))?;
            if !response.status().is_success() {
                return Err(InterfaceError::InterfaceError(format!(
                    "HTTP {}",
                    response.status()
                )));
            }
            let mut out = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|e| InterfaceError::InterfaceError(format!("read failed: {e}")))?
            {
                out.extend_from_slice(&chunk);
                if response_size_limit.is_some_and(|l| out.len() > l) {
                    return Err(InterfaceError::InvalidInterface(
                        "response exceeds the size limit".to_owned(),
                    ));
                }
            }
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_socks5_proxies_are_accepted() {
        assert!(
            ProxyTransport::new("http://x.onion:18089", Some("socks5h://127.0.0.1:9050")).is_ok()
        );
        assert!(ProxyTransport::new("http://x:1", Some("socks5://127.0.0.1:9050")).is_ok());
        assert!(ProxyTransport::new("http://x:1", Some("http://127.0.0.1:8080")).is_err());
        assert!(ProxyTransport::new("http://x:1", Some("127.0.0.1:9050")).is_err());
        assert!(ProxyTransport::new("http://x:1", None).is_ok());
    }
}
