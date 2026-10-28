//! One check of one server: Complete, Current and NU7.

use std::collections::HashMap;

use anyhow::{bail, Result};
use serde::Serialize;

use crate::compare::{self, display_hex, Mismatch, Tally};
use crate::lwd::{self, CompactBlock, Route};
use crate::p2p::{self, Peer};
use crate::verify::{self, VerifiedBlock};

pub const NU7_HEIGHT: u64 = 3_543_405;
/// A server this many blocks behind the peers is still "current".
const TIP_TOLERANCE: u64 = 3;
/// Blocks a peer must also have before we compare them: skip the very tip,
/// which may not have reached every peer yet.
const TIP_MARGIN: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Fail,
    Unverified,
}

#[derive(Debug, Default, Serialize)]
pub struct ServerInfo {
    pub software: String,
    pub node: String,
    pub reported_upgrade: String,
    pub reported_upgrade_height: u64,
    pub consensus_branch_id: String,
}

#[derive(Debug, Serialize)]
pub struct CheckResult {
    pub server: String,
    pub route: String,
    pub checked_at: u64,
    pub info: ServerInfo,
    pub server_tip: u64,
    pub network_tip: Option<u64>,
    pub range: Option<(u64, u64)>,
    pub complete: Status,
    pub current: Status,
    pub nu7: Status,
    pub tally: Tally,
    pub unverified_blocks: Vec<u64>,
    pub mismatches: Vec<Mismatch>,
    pub notes: Vec<String>,
    /// Only for the test row: what a consistency-only check says.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consistency_only: Option<ConsistencyResult>,
}

#[derive(Debug, Serialize)]
pub struct ConsistencyResult {
    pub status: Status,
    pub detail: String,
}

/// Full blocks from peers, verified once and shared by every server check.
pub struct Reference {
    pub peers: Vec<Peer>,
    cache: HashMap<[u8; 32], Option<(VerifiedBlock, usize)>>,
    network_tip: Option<(u64, [u8; 32])>,
}

impl Reference {
    pub async fn new(want_peers: usize) -> Result<Reference> {
        // Peers come and go, and some refuse new connections for a while, so
        // try a few times before giving up.
        let mut peers = Vec::new();
        for attempt in 0..4 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
            for p in p2p::connect_peers(want_peers, 170_190).await {
                if !peers.iter().any(|q: &Peer| q.addr == p.addr) {
                    peers.push(p);
                }
            }
            if peers.len() >= 3 {
                break;
            }
        }
        if peers.len() < 2 {
            bail!("could not reach two NU7-ready Zcash peers; check that outbound port 8233 is open");
        }
        Ok(Reference { peers, cache: HashMap::new(), network_tip: None })
    }

    pub fn peer_summary(&self) -> Vec<String> {
        self.peers.iter().map(|p| format!("{} ({})", p.user_agent, p.start_height)).collect()
    }

    /// Peers drop idle connections, so reconnect when fewer than three are left.
    async fn top_up(&mut self) {
        if self.peers.len() >= 3 {
            return;
        }
        let have: Vec<_> = self.peers.iter().map(|p| p.addr).collect();
        for p in p2p::connect_peers(6, 170_190).await {
            if !have.contains(&p.addr) {
                self.peers.push(p);
            }
        }
    }

    /// Fetches the blocks with these hashes from at least two peers. A block
    /// counts as verified when two peers serve it and it passes every check.
    async fn fetch(&mut self, wanted: &[(u64, [u8; 32])]) {
        self.top_up().await;
        let todo: Vec<(u64, [u8; 32])> =
            wanted.iter().filter(|(_, h)| !self.cache.contains_key(h)).cloned().collect();
        if todo.is_empty() {
            return;
        }
        let mut agree: HashMap<[u8; 32], (Option<VerifiedBlock>, usize)> = HashMap::new();
        let mut pool = std::mem::take(&mut self.peers);
        let mut alive = Vec::new();
        // Ask three peers at once; if some blocks still lack two verifying
        // peers, ask the next three for just those.
        loop {
            let missing: Vec<[u8; 32]> = todo
                .iter()
                .map(|(_, h)| *h)
                .filter(|h| agree.get(h).map(|(_, n)| *n < 2).unwrap_or(true))
                .collect();
            if missing.is_empty() || pool.is_empty() {
                break;
            }
            let batch: Vec<Peer> = pool.drain(..pool.len().min(3)).collect();
            let mut set = tokio::task::JoinSet::new();
            for mut peer in batch {
                let missing = missing.clone();
                set.spawn(async move {
                    let mut got = Vec::new();
                    let mut ok = true;
                    for chunk in missing.chunks(16) {
                        match tokio::time::timeout(std::time::Duration::from_secs(25), peer.get_blocks(chunk)).await {
                            Ok(Ok(blocks)) => got.extend(blocks),
                            _ => {
                                ok = false;
                                break;
                            }
                        }
                    }
                    (peer, ok, got)
                });
            }
            while let Some(res) = set.join_next().await {
                let Ok((peer, ok, got)) = res else { continue };
                if ok {
                    alive.push(peer);
                }
                for raw in got {
                    // Match the block to the hash we asked for by its header.
                    let Ok(hd) = zcash_primitives::block::BlockHeader::read(&raw[..]) else { continue };
                    let Some((height, hash)) = todo.iter().find(|(_, h)| hd.hash().0 == *h) else { continue };
                    if let Ok(vb) = verify::verify_block(&raw, hash, *height as u32) {
                        let e = agree.entry(*hash).or_insert((None, 0));
                        e.1 += 1;
                        if e.0.is_none() {
                            e.0 = Some(vb);
                        }
                    }
                }
                // Don't wait for a slow peer once every block has two.
                if todo.iter().all(|(_, h)| agree.get(h).map(|(_, n)| *n >= 2).unwrap_or(false)) {
                    set.abort_all();
                    break;
                }
            }
        }
        alive.extend(pool);
        self.peers = alive;
        for (_, h) in &todo {
            let entry = match agree.remove(h) {
                Some((Some(vb), n)) if n >= 2 => Some((vb, n)),
                _ => None,
            };
            self.cache.insert(*h, entry);
        }
    }

    /// Walks the peers' header chain forward from `from` and returns the
    /// height and hash of the last header they agree on.
    async fn tip_after(&mut self, from_height: u64, from_hash: [u8; 32]) -> Option<(u64, [u8; 32])> {
        self.top_up().await;
        let mut pool = std::mem::take(&mut self.peers);
        let mut set = tokio::task::JoinSet::new();
        for peer in pool.drain(..pool.len().min(4)) {
            set.spawn(walk_headers(peer, from_height, from_hash));
        }
        let mut best: Option<(u64, [u8; 32])> = None;
        let mut confirmations = 0;
        while let Some(res) = set.join_next().await {
            let Ok((peer, tip)) = res else { continue };
            self.peers.push(peer);
            if let Some(t) = tip {
                confirmations += 1;
                if best.map(|(h, _)| t.0 > h).unwrap_or(true) {
                    best = Some(t);
                }
                if confirmations >= 2 {
                    set.abort_all();
                    break;
                }
            }
        }
        self.peers.extend(pool);
        if confirmations >= 2 {
            if let Some(b) = best {
                if self.network_tip.map(|(h, _)| b.0 > h).unwrap_or(true) {
                    self.network_tip = Some(b);
                }
            }
            best
        } else {
            None
        }
    }
}

/// Follows one peer's headers forward from a block. Returns the peer's tip if
/// the block is on its chain and every header verifies, or None.
async fn walk_headers(mut peer: Peer, from_height: u64, from_hash: [u8; 32]) -> (Peer, Option<(u64, [u8; 32])>) {
    let mut height = from_height;
    let mut hash = from_hash;
    for _ in 0..40 {
        let headers = match tokio::time::timeout(std::time::Duration::from_secs(15), peer.get_headers(&[hash])).await {
            Ok(Ok(h)) => h,
            _ => return (peer, None),
        };
        // An empty answer means the block we asked from is the peer's tip.
        if headers.is_empty() {
            return (peer, Some((height, hash)));
        }
        for raw in &headers {
            match verify::verify_header(raw) {
                Ok(vh) if vh.prev == hash => {
                    height += 1;
                    hash = vh.hash;
                }
                // Headers that don't continue from our block: it isn't on this peer's chain.
                _ => return (peer, None),
            }
        }
        if headers.len() < 160 {
            return (peer, Some((height, hash)));
        }
    }
    (peer, Some((height, hash)))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Runs the full check against `server`, comparing `window` recent blocks.
pub async fn check(server: &str, route: &Route, window: u64, reference: &mut Reference) -> CheckResult {
    let mut r = CheckResult {
        server: server.to_string(),
        route: match route {
            Route::Direct => "direct".into(),
            Route::Tor(_) => "tor".into(),
        },
        checked_at: now(),
        info: ServerInfo::default(),
        server_tip: 0,
        network_tip: None,
        range: None,
        complete: Status::Unverified,
        current: Status::Unverified,
        nu7: Status::Unverified,
        tally: Tally::default(),
        unverified_blocks: vec![],
        mismatches: vec![],
        notes: vec![],
        consistency_only: None,
    };
    let blocks = match fetch_server(server, route, window, &mut r).await {
        Ok(b) => b,
        Err(e) => {
            r.notes.push(format!("couldn't verify: {e:#}"));
            return r;
        }
    };
    judge(&mut r, &blocks, reference).await;
    r
}

/// Reads the server's info, tip and the compact blocks for the window, in the
/// same order a wallet does when it starts a sync.
async fn fetch_server(server: &str, route: &Route, window: u64, r: &mut CheckResult) -> Result<Vec<CompactBlock>> {
    let mut c = lwd::connect(server, route).await?;
    let info = lwd::info(&mut c).await?;
    r.info = ServerInfo {
        software: format!("{} {}", info.vendor, info.version).trim().to_string(),
        node: info.zcashd_subversion.trim_matches('/').to_string(),
        reported_upgrade: info.upgrade_name.clone(),
        reported_upgrade_height: info.upgrade_height,
        consensus_branch_id: info.consensus_branch_id.clone(),
    };
    if info.chain_name != "main" {
        bail!("server is on {} chain, not mainnet", info.chain_name);
    }
    let (tip, _) = lwd::tip(&mut c).await?;
    r.server_tip = tip;
    let end = tip.saturating_sub(TIP_MARGIN);
    let start = end.saturating_sub(window.saturating_sub(1));
    let blocks = lwd::blocks(&mut c, start, end).await?;
    if blocks.is_empty() {
        bail!("server returned no blocks for {start}..={end}");
    }
    r.range = Some((blocks.first().unwrap().height, blocks.last().unwrap().height));
    Ok(blocks)
}

/// Compares the server's blocks with the reference and fills in the verdicts.
pub async fn judge(r: &mut CheckResult, blocks: &[CompactBlock], reference: &mut Reference) {
    let (nu7, why) = nu7_status(r);
    r.nu7 = nu7;
    if let Some(why) = why {
        r.notes.push(why);
    }

    let wanted: Vec<(u64, [u8; 32])> = blocks
        .iter()
        .filter_map(|b| b.hash.as_slice().try_into().ok().map(|h| (b.height, h)))
        .collect();
    reference.fetch(&wanted).await;

    let mut mismatches = Vec::new();
    let mut tally = Tally::default();
    let mut unverified = Vec::new();
    for b in blocks {
        let Ok(hash) = <[u8; 32]>::try_from(b.hash.as_slice()) else {
            unverified.push(b.height);
            continue;
        };
        match reference.cache.get(&hash) {
            Some(Some((full, _))) => mismatches.extend(compare::compare_block(full, b, &mut tally)),
            _ => unverified.push(b.height),
        }
    }
    r.complete = if !mismatches.is_empty() {
        Status::Fail
    } else if tally.blocks == 0 {
        Status::Unverified
    } else {
        Status::Pass
    };
    if !unverified.is_empty() {
        r.notes.push(format!(
            "{} of {} blocks couldn't be verified: two peers didn't serve a matching block",
            unverified.len(),
            blocks.len()
        ));
    }
    r.mismatches = mismatches;
    r.tally = tally;
    r.unverified_blocks = unverified;

    // Current: walk the peers' headers forward from the server's last block.
    let last = blocks.last().unwrap();
    if let Ok(hash) = <[u8; 32]>::try_from(last.hash.as_slice()) {
        match reference.tip_after(last.height, hash).await {
            Some((net_tip, _)) => {
                r.network_tip = Some(net_tip);
                let behind = net_tip.saturating_sub(r.server_tip);
                if behind > TIP_TOLERANCE {
                    r.current = Status::Fail;
                    r.notes.push(format!("{behind} blocks behind the network"));
                } else {
                    r.current = Status::Pass;
                }
            }
            None => {
                if reference.cache.get(&hash).map(|c| c.is_none()).unwrap_or(true) {
                    r.notes.push(format!(
                        "couldn't verify: peers don't know block {} {}; the server may be on a fork",
                        last.height,
                        display_hex(&hash)
                    ));
                }
            }
        }
    }
}

/// First node releases that follow NU7 on mainnet (Zebra 7.0.0 and Zakura
/// 1.7.0 release notes, 2026-10-22).
const NU7_READY: &[(&str, [u32; 3])] = &[("Zebra", [7, 0, 0]), ("Zakura", [1, 7, 0])];

fn parse_version(v: &str) -> Option<([u32; 3], bool)> {
    let pre = v.contains('-');
    let core = v.split(['-', '+']).next()?;
    let mut parts = core.split('.').map(|p| p.parse::<u32>().ok());
    Some(([parts.next()??, parts.next()??, parts.next().flatten().unwrap_or(0)], pre))
}

/// NU7 readiness from what the server reports: an active NU7 branch, the
/// node's release, or the announced upgrade. A missing answer is grey.
fn nu7_status(r: &CheckResult) -> (Status, Option<String>) {
    if r.server_tip >= NU7_HEIGHT {
        return if r.info.consensus_branch_id.eq_ignore_ascii_case("77190ad9") {
            (Status::Pass, None)
        } else {
            (Status::Fail, Some(format!("past block {NU7_HEIGHT} but not on the NU7 branch")))
        };
    }
    if let Some((name, ver)) = r.info.node.split_once(':') {
        if let Some(&(_, ready)) = NU7_READY.iter().find(|(n, _)| *n == name) {
            if let Some((v, pre)) = parse_version(ver) {
                if v < ready || (v == ready && pre) {
                    return (
                        Status::Fail,
                        Some(format!(
                            "node runs {name} {ver}; {name} {}.{}.{} is the first release that follows NU7 on mainnet",
                            ready[0], ready[1], ready[2]
                        )),
                    );
                }
                return (Status::Pass, None);
            }
        }
    }
    if r.info.reported_upgrade.eq_ignore_ascii_case("NU7") && r.info.reported_upgrade_height == NU7_HEIGHT {
        return (Status::Pass, None);
    }
    (Status::Unverified, Some("couldn't verify NU7: the server doesn't say which node it runs or what upgrade comes next".into()))
}

/// The labelled test row: real data from `base`, with one shielded note
/// removed and the tree sizes patched so the chain still adds up.
pub async fn test_row(base: &str, route: &Route, window: u64, reference: &mut Reference) -> Option<CheckResult> {
    let mut r = CheckResult {
        server: format!("test server (real data from {base}, one note removed)"),
        route: "test".into(),
        checked_at: now(),
        info: ServerInfo::default(),
        server_tip: 0,
        network_tip: None,
        range: None,
        complete: Status::Unverified,
        current: Status::Unverified,
        nu7: Status::Unverified,
        tally: Tally::default(),
        unverified_blocks: vec![],
        mismatches: vec![],
        notes: vec![],
        consistency_only: None,
    };
    let blocks = fetch_server(base, route, window, &mut r).await.ok()?;
    let (altered, desc) = compare::drop_one_note(&blocks)?;
    r.notes.push(format!("Test: {desc}."));
    r.consistency_only = Some(match compare::consistency_only(&altered) {
        Ok(()) => ConsistencyResult { status: Status::Pass, detail: "heights, links and tree sizes all add up".into() },
        Err(e) => ConsistencyResult { status: Status::Fail, detail: e },
    });
    judge(&mut r, &altered, reference).await;
    r.server = "test server (one note removed)".into();
    Some(r)
}
