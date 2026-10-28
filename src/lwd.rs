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
    let host = match hostport.rsplit_once(':') {
        Some((h, port)) => {
            if port.parse::<u16>().is_err() {
                anyhow::bail!("\"{port}\" isn't a port number");
            }
            h.to_string()
        }
        None => hostport.clone(),
    };
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
            // Tor gives each distinct SOCKS username its own circuit, so every
            // check leaves from a different exit and can't be linked to the others.
            let circuit = format!("{:016x}", rand_u64());
            let connector = tower::service_fn(move |uri: Uri| {
                let proxy = proxy.clone();
                let circuit = circuit.clone();
                async move {
                    let host = uri.host().unwrap_or_default().to_string();
                    let port = uri.port_u16().unwrap_or(443);
                    let s = tokio_socks::tcp::Socks5Stream::connect_with_password(
                        proxy.as_str(),
                        (host.as_str(), port),
                        &circuit,
                        "x",
                    )
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

fn rand_u64() -> u64 {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    u64::from_le_bytes(crate::p2p::dsha256(&t.to_le_bytes())[..8].try_into().unwrap())
}

/// Turns a connection or call error into one plain sentence.
pub fn plain_error(server: &str, e: &anyhow::Error) -> String {
    let text = format!("{e:#}").to_lowercase();
    let why = if text.contains("isn't a port number") {
        "the part after the colon isn't a port number"
    } else if text.contains("503") || text.contains("service unavailable") {
        "it's temporarily unavailable (HTTP 503)"
    } else if text.contains("dns") || text.contains("resolve") || text.contains("lookup") || text.contains("name or service") {
        "the name doesn't resolve"
    } else if text.contains("refused") {
        "the connection was refused (nothing listening on that port)"
    } else if text.contains("deadline") || text.contains("timed out") || text.contains("timeout") {
        "it didn't answer in time"
    } else if text.contains("tls") || text.contains("certificate") || text.contains("handshake") {
        "the TLS handshake failed"
    } else if text.contains("compression flag") || text.contains("405") || text.contains("404") || text.contains("unimplemented") || text.contains("content-type") {
        "it answered, but it isn't a Zcash light-wallet server"
    } else if text.contains("h2 protocol") || text.contains("http2") || text.contains("frame") {
        "it doesn't speak gRPC over HTTP/2 the way a light-wallet server should"
    } else if text.contains("reset") || text.contains("closed") || text.contains("broken pipe") {
        "it closed the connection"
    } else {
        "it couldn't be reached"
    };
    format!("Couldn't check {server}: {why}.")
}

/// Checks that `server` is a reachable light-wallet server, within 20 seconds.
pub async fn reach(server: &str, route: &Route) -> Result<(), String> {
    let attempt = async {
        let mut c = connect(server, route).await?;
        info(&mut c).await
    };
    match tokio::time::timeout(Duration::from_secs(20), attempt).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(plain_error(server, &e)),
        Err(_) => Err(format!("Couldn't check {server}: it didn't answer in time.")),
    }
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
