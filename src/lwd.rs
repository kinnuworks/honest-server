//! Talks to a lightwalletd or Zaino server the way a wallet does.

use std::time::Duration;

use anyhow::{Context, Result};
use hyper_util::rt::TokioIo;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint, Uri};

pub mod rpc {
    tonic::include_proto!("cash.z.wallet.sdk.rpc");
}

use rpc::compact_tx_streamer_client::CompactTxStreamerClient;
pub use rpc::{CompactBlock, LightdInfo};

pub type Client = CompactTxStreamerClient<Channel>;

/// Where to send traffic: straight out, or through a local Tor SOCKS port.
#[derive(Clone, Debug)]
pub enum Route {
    Direct,
    Tor(String),
}

/// `server` is "host:port". Port 443 and anything with "https" use TLS;
/// a "http://" prefix forces plaintext (for local test servers).
pub async fn connect(server: &str, route: &Route) -> Result<Client> {
    let (scheme, hostport) = match server.split_once("://") {
        Some((s, rest)) => (s.to_string(), rest.to_string()),
        None => ("https".to_string(), server.to_string()),
    };
    let host = hostport.rsplit_once(':').map(|(h, _)| h).unwrap_or(&hostport).to_string();
    let uri = format!("{scheme}://{hostport}");
    let mut ep = Endpoint::from_shared(uri.clone())?
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(120));
    if scheme == "https" {
        ep = ep.tls_config(ClientTlsConfig::new().with_native_roots().domain_name(host))?;
    }
    let channel = match route {
        Route::Direct => ep.connect().await.with_context(|| format!("could not reach {server}"))?,
        Route::Tor(proxy) => {
            let proxy = proxy.clone();
            let connector = tower::service_fn(move |uri: Uri| {
                let proxy = proxy.clone();
                async move {
                    let host = uri.host().unwrap_or_default().to_string();
                    let port = uri.port_u16().unwrap_or(443);
                    let s = tokio_socks::tcp::Socks5Stream::connect(proxy.as_str(), (host.as_str(), port))
                        .await
                        .map_err(std::io::Error::other)?;
                    Ok::<_, std::io::Error>(TokioIo::new(s.into_inner()))
                }
            });
            ep.connect_with_connector(connector)
                .await
                .with_context(|| format!("could not reach {server} over Tor"))?
        }
    };
    Ok(CompactTxStreamerClient::new(channel).max_decoding_message_size(64 * 1024 * 1024))
}

pub async fn info(c: &mut Client) -> Result<LightdInfo> {
    Ok(c.get_lightd_info(rpc::Empty {}).await?.into_inner())
}

pub async fn tip(c: &mut Client) -> Result<(u64, Vec<u8>)> {
    let b = c.get_latest_block(rpc::ChainSpec {}).await?.into_inner();
    Ok((b.height, b.hash))
}

/// Compact blocks for `start..=end`, shielded pools only, the default request
/// a wallet makes while syncing.
pub async fn blocks(c: &mut Client, start: u64, end: u64) -> Result<Vec<CompactBlock>> {
    let range = rpc::BlockRange {
        start: Some(rpc::BlockId { height: start, hash: vec![] }),
        end: Some(rpc::BlockId { height: end, hash: vec![] }),
        pool_types: vec![],
    };
    let mut stream = c.get_block_range(range).await?.into_inner();
    let mut out = Vec::new();
    while let Some(b) = stream.message().await? {
        out.push(b);
    }
    Ok(out)
}
