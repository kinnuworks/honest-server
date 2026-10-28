//! A minimal Zcash peer-to-peer client: handshake, getheaders and getdata.
//!
//! It only asks peers for headers and blocks. Everything a peer sends back is
//! checked in `verify`, so a peer that lies just gets dropped.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const MAGIC: [u8; 4] = [0x24, 0xe9, 0x27, 0x64];
/// NU7 peers on mainnet require protocol version 170190 (ZIP 259).
const PROTOCOL_VERSION: i32 = 170_190;
const USER_AGENT: &[u8] = b"/honest-server:0.1.0/";
const MAX_PAYLOAD: usize = 4 * 1024 * 1024;
const MSG_BLOCK: u32 = 2;

pub const SEEDS: &[&str] = &[
    "mainnet.seeder.zfnd.org",
    "dnsseed.z.cash",
    "dnsseed.str4d.xyz",
    "mainnet.seeder.shieldedinfra.net",
];

pub fn dsha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}

fn write_compact_size(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

pub fn read_compact_size(data: &[u8], pos: &mut usize) -> Result<u64> {
    let first = *data.get(*pos).ok_or_else(|| anyhow!("truncated compact size"))?;
    let (value, len) = match first {
        0xfd => (u16::from_le_bytes(slice::<2>(data, *pos + 1)?) as u64, 3),
        0xfe => (u32::from_le_bytes(slice::<4>(data, *pos + 1)?) as u64, 5),
        0xff => (u64::from_le_bytes(slice::<8>(data, *pos + 1)?), 9),
        n => (n as u64, 1),
    };
    *pos += len;
    Ok(value)
}

fn slice<const N: usize>(data: &[u8], at: usize) -> Result<[u8; N]> {
    data.get(at..at + N)
        .ok_or_else(|| anyhow!("truncated message"))?
        .try_into()
        .map_err(|_| anyhow!("truncated message"))
}

fn frame(command: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + payload.len());
    out.extend_from_slice(&MAGIC);
    let mut cmd = [0u8; 12];
    cmd[..command.len()].copy_from_slice(command.as_bytes());
    out.extend_from_slice(&cmd);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&dsha256(payload)[..4]);
    out.extend_from_slice(payload);
    out
}

fn net_addr() -> [u8; 26] {
    // services, then an IPv4-mapped zero address and port 8233
    let mut a = [0u8; 26];
    a[18] = 0xff;
    a[19] = 0xff;
    a[24..26].copy_from_slice(&8233u16.to_be_bytes());
    a
}

fn version_payload() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    p.extend_from_slice(&0u64.to_le_bytes());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    p.extend_from_slice(&now.to_le_bytes());
    p.extend_from_slice(&net_addr());
    p.extend_from_slice(&net_addr());
    p.extend_from_slice(&rand_nonce().to_le_bytes());
    write_compact_size(&mut p, USER_AGENT.len() as u64);
    p.extend_from_slice(USER_AGENT);
    p.extend_from_slice(&0i32.to_le_bytes());
    p.push(0); // no transaction relay
    p
}

fn rand_nonce() -> u64 {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let h = dsha256(&t.to_le_bytes());
    u64::from_le_bytes(h[..8].try_into().unwrap())
}

pub struct Peer {
    pub addr: SocketAddr,
    pub user_agent: String,
    pub version: i32,
    pub start_height: i32,
    stream: TcpStream,
    buf: Vec<u8>,
}

impl Peer {
    pub async fn connect(addr: SocketAddr) -> Result<Peer> {
        let stream = timeout(Duration::from_secs(6), TcpStream::connect(addr))
            .await
            .context("connect timeout")??;
        let mut peer = Peer {
            addr,
            user_agent: String::new(),
            version: 0,
            start_height: 0,
            stream,
            buf: Vec::new(),
        };
        peer.send("version", &version_payload()).await?;
        let mut got_version = false;
        let mut got_verack = false;
        while !(got_version && got_verack) {
            let (cmd, payload) = peer.recv(Duration::from_secs(10)).await?;
            match cmd.as_str() {
                "version" => {
                    peer.version = i32::from_le_bytes(slice::<4>(&payload, 0)?);
                    let mut pos = 80;
                    let len = read_compact_size(&payload, &mut pos)? as usize;
                    let ua = payload.get(pos..pos + len).ok_or_else(|| anyhow!("bad version"))?;
                    peer.user_agent = String::from_utf8_lossy(ua).into_owned();
                    peer.start_height = i32::from_le_bytes(slice::<4>(&payload, pos + len)?);
                    got_version = true;
                    peer.send("verack", &[]).await?;
                }
                "verack" => got_verack = true,
                _ => {}
            }
        }
        Ok(peer)
    }

    async fn send(&mut self, command: &str, payload: &[u8]) -> Result<()> {
        timeout(Duration::from_secs(10), self.stream.write_all(&frame(command, payload)))
            .await
            .context("send timeout")??;
        Ok(())
    }

    /// Reads the next message, answering pings on the way.
    async fn recv(&mut self, wait: Duration) -> Result<(String, Vec<u8>)> {
        loop {
            if let Some(msg) = self.take_message()? {
                if msg.0 == "ping" {
                    let payload = msg.1.clone();
                    self.send("pong", &payload).await?;
                    continue;
                }
                return Ok(msg);
            }
            let mut chunk = vec![0u8; 64 * 1024];
            let n = timeout(wait, self.stream.read(&mut chunk))
                .await
                .context("peer went quiet")??;
            if n == 0 {
                bail!("peer closed the connection");
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    fn take_message(&mut self) -> Result<Option<(String, Vec<u8>)>> {
        if self.buf.len() < 24 {
            return Ok(None);
        }
        if self.buf[..4] != MAGIC {
            bail!("wrong network magic");
        }
        let len = u32::from_le_bytes(self.buf[16..20].try_into().unwrap()) as usize;
        if len > MAX_PAYLOAD {
            bail!("message too large");
        }
        if self.buf.len() < 24 + len {
            return Ok(None);
        }
        let cmd = String::from_utf8_lossy(&self.buf[4..16])
            .trim_end_matches('\0')
            .to_string();
        let payload = self.buf[24..24 + len].to_vec();
        if dsha256(&payload)[..4] != self.buf[20..24] {
            bail!("bad checksum");
        }
        self.buf.drain(..24 + len);
        Ok(Some((cmd, payload)))
    }

    /// Asks for the headers that follow `locator` (hashes in internal byte order,
    /// newest first). Returns raw 1487-byte headers.
    pub async fn get_headers(&mut self, locator: &[[u8; 32]]) -> Result<Vec<Vec<u8>>> {
        let mut p = Vec::new();
        p.extend_from_slice(&(PROTOCOL_VERSION as u32).to_le_bytes());
        write_compact_size(&mut p, locator.len() as u64);
        for h in locator {
            p.extend_from_slice(h);
        }
        p.extend_from_slice(&[0u8; 32]);
        self.send("getheaders", &p).await?;
        loop {
            let (cmd, payload) = self.recv(Duration::from_secs(20)).await?;
            if cmd != "headers" {
                continue;
            }
            let mut pos = 0;
            let count = read_compact_size(&payload, &mut pos)?;
            let mut headers = Vec::new();
            for _ in 0..count {
                let start = pos;
                pos += 140;
                let sol_len = read_compact_size(&payload, &mut pos)? as usize;
                pos += sol_len;
                if pos > payload.len() {
                    bail!("truncated headers");
                }
                headers.push(payload[start..pos].to_vec());
                let _tx_count = read_compact_size(&payload, &mut pos)?;
            }
            return Ok(headers);
        }
    }

    /// Asks the peer for addresses of other peers (IPv4 on port 8233 only).
    pub async fn get_addrs(&mut self) -> Result<Vec<SocketAddr>> {
        self.send("getaddr", &[]).await?;
        loop {
            let (cmd, payload) = self.recv(Duration::from_secs(10)).await?;
            if cmd != "addr" {
                continue;
            }
            let mut pos = 0;
            let n = read_compact_size(&payload, &mut pos)? as usize;
            let mut out = Vec::new();
            for i in 0..n {
                let e = payload.get(pos + i * 30..pos + (i + 1) * 30).ok_or_else(|| anyhow!("truncated addr"))?;
                let ip = &e[12..28];
                let port = u16::from_be_bytes([e[28], e[29]]);
                if ip[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] && port == 8233 {
                    out.push(SocketAddr::from(([ip[12], ip[13], ip[14], ip[15]], port)));
                }
            }
            // A one-entry addr is usually the peer announcing itself; wait for the list.
            if n > 1 {
                return Ok(out);
            }
        }
    }

    /// Fetches full blocks by hash (internal byte order). Blocks the peer
    /// doesn't have are left out.
    pub async fn get_blocks(&mut self, hashes: &[[u8; 32]]) -> Result<Vec<Vec<u8>>> {
        let mut p = Vec::new();
        write_compact_size(&mut p, hashes.len() as u64);
        for h in hashes {
            p.extend_from_slice(&MSG_BLOCK.to_le_bytes());
            p.extend_from_slice(h);
        }
        self.send("getdata", &p).await?;
        let mut blocks = Vec::new();
        let mut answered = 0;
        while answered < hashes.len() {
            let (cmd, payload) = self.recv(Duration::from_secs(30)).await?;
            match cmd.as_str() {
                "block" => {
                    blocks.push(payload);
                    answered += 1;
                }
                "notfound" => {
                    let mut pos = 0;
                    answered += read_compact_size(&payload, &mut pos)? as usize;
                }
                _ => {}
            }
        }
        Ok(blocks)
    }
}

/// Resolves the DNS seeders and returns candidate peer addresses.
pub async fn seed_addresses() -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for seed in SEEDS {
        if let Ok(Ok(addrs)) =
            timeout(Duration::from_secs(5), tokio::net::lookup_host((*seed, 8233))).await
        {
            for a in addrs {
                if a.is_ipv4() && !out.contains(&a) {
                    out.push(a);
                }
            }
        }
    }
    out
}

/// Connects to up to `want` peers in parallel and keeps the ones that finish
/// the handshake and advertise at least `min_version`.
pub async fn connect_peers(want: usize, min_version: i32) -> Vec<Peer> {
    let mut tried: Vec<SocketAddr> = Vec::new();
    let mut candidates = seed_addresses().await;
    let mut peers: Vec<Peer> = Vec::new();
    // Seeds first, then up to two rounds of addresses learned from peers.
    for _round in 0..3 {
        let batch: Vec<SocketAddr> = candidates.drain(..).filter(|a| !tried.contains(a)).collect();
        if batch.is_empty() {
            break;
        }
        tried.extend(&batch);
        let mut set = tokio::task::JoinSet::new();
        for a in batch {
            set.spawn(async move { Peer::connect(a).await });
        }
        let mut found = Vec::new();
        while let Some(res) = set.join_next().await {
            if let Ok(Ok(p)) = res {
                found.push(p);
            }
        }
        for (i, mut p) in found.into_iter().enumerate() {
            if i < 4 && peers.len() < want {
                if let Ok(more) = p.get_addrs().await {
                    candidates.extend(more.into_iter().filter(|a| !tried.contains(a)));
                }
            }
            if p.version >= min_version && peers.len() < want {
                peers.push(p);
            }
        }
        candidates.sort();
        candidates.dedup();
        if peers.len() >= want {
            break;
        }
    }
    peers
}
