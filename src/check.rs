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
const TIP_MARGIN: u64 = 2;

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
    /// Over Tor: how many separate exits got blocks that matched the verified ones.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exits: Option<ExitCheck>,
    /// The blocks before the window, checked through the note trees.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history: Option<crate::history::HistoryCheck>,
    /// Only for the test row: what a consistency-only check says.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consistency_only: Option<ConsistencyResult>,
}

#[derive(Debug, Serialize)]
pub struct ExitCheck {
    pub exits: usize,
    pub matched: usize,
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

    /// Compares a compact block with its verified full block. None if the
    /// reference couldn't verify that block.
    pub fn compare(&self, b: &CompactBlock) -> Option<Vec<Mismatch>> {
        let hash = <[u8; 32]>::try_from(b.hash.as_slice()).ok()?;
        match self.cache.get(&hash) {
            Some(Some((full, _))) => Some(compare::compare_block(full, b, &mut Tally::default())),
            _ => None,
        }
    }

    /// The verified full block with this hash, if the reference has one.
    pub fn verified(&self, hash: &[u8; 32]) -> Option<&VerifiedBlock> {
        self.cache.get(hash).and_then(|c| c.as_ref()).map(|(b, _)| b)
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
    pub async fn fetch(&mut self, wanted: &[(u64, [u8; 32])]) {
        self.top_up().await;
        let todo: Vec<(u64, [u8; 32])> =
            wanted.iter().filter(|(_, h)| !self.cache.contains_key(h)).cloned().collect();
        if todo.is_empty() {
            return;
        }
        // For each block: the verified copy and the distinct peers that served it.
        let mut agree: HashMap<[u8; 32], (Option<VerifiedBlock>, Vec<std::net::SocketAddr>)> = HashMap::new();
        let mut pool = std::mem::take(&mut self.peers);
        let mut alive: Vec<Peer> = Vec::new();
        let mut rounds = 0;
        // Ask three peers at once; if some blocks still lack two verifying
        // peers, ask the next three for just those. When the peers run out,
        // connect new ones, up to two more times.
        loop {
            let missing: Vec<[u8; 32]> = todo
                .iter()
                .map(|(_, h)| *h)
                .filter(|h| agree.get(h).map(|(_, p)| p.len() < 2).unwrap_or(true))
                .collect();
            if missing.is_empty() {
                break;
            }
            if pool.is_empty() {
                if rounds >= 2 {
                    break;
                }
                rounds += 1;
                let have: Vec<_> = alive.iter().map(|p| p.addr).collect();
                for p in p2p::connect_peers(6, 170_190).await {
                    if !have.contains(&p.addr) {
                        pool.push(p);
                    }
                }
                if pool.is_empty() {
                    break;
                }
            }
            let batch: Vec<Peer> = pool.drain(..pool.len().min(3)).collect();
            let mut set = tokio::task::JoinSet::new();
            for mut peer in batch {
                let missing = missing.clone();
                set.spawn(async move {
                    let mut got = Vec::new();
                    let mut ok = true;
                    for chunk in missing.chunks(8) {
                        match tokio::time::timeout(std::time::Duration::from_secs(25), peer.get_blocks(chunk)).await {
                            Ok(Ok(blocks)) => got.extend(blocks),
                            other => {
                                if std::env::var_os("HONEST_DEBUG").is_some() {
                                    let why = match other { Err(_) => "timed out".to_string(), Ok(Err(e)) => format!("{e:#}"), _ => String::new() };
                                    eprintln!("peer {}: chunk failed: {why}", peer.addr);
                                }
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
                let from = peer.addr;
                if std::env::var_os("HONEST_DEBUG").is_some() {
                    eprintln!("peer {from}: {} blocks, {}", got.len(), if ok { "ok" } else { "timed out or failed" });
                }
                if ok {
                    alive.push(peer);
                }
                for raw in got {
                    // Match the block to the hash we asked for by its header.
                    let Ok(hd) = zcash_primitives::block::BlockHeader::read(&raw[..]) else { continue };
                    let Some((height, hash)) = todo.iter().find(|(_, h)| hd.hash().0 == *h) else { continue };
                    let e = agree.entry(*hash).or_insert((None, Vec::new()));
                    if e.1.contains(&from) {
                        continue;
                    }
                    match verify::verify_block(&raw, hash, *height as u32) {
                        // The second peer must send the same fields, anchors
                        // included: from v6 on, anchors are authorizing data,
                        // which the txids don't commit to.
                        Ok(vb) => match &e.0 {
                            None => {
                                e.0 = Some(vb);
                                e.1.push(from);
                            }
                            Some(first) if first.txs == vb.txs && first.header == vb.header => e.1.push(from),
                            Some(_) => {
                                if std::env::var_os("HONEST_DEBUG").is_some() {
                                    eprintln!("block {height} from {from} disagrees with the first peer's copy");
                                }
                            }
                        },
                        Err(err) => {
                            if std::env::var_os("HONEST_DEBUG").is_some() {
                                eprintln!("block {height} from {from} rejected: {err:#}");
                            }
                        }
                    }
                }
                // Don't wait for a slow peer once every block has two.
                if todo.iter().all(|(_, h)| agree.get(h).map(|(_, p)| p.len() >= 2).unwrap_or(false)) {
                    set.abort_all();
                    break;
                }
            }
        }
        alive.extend(pool);
        self.peers = alive;
        for (_, h) in &todo {
            let entry = match agree.remove(h) {
                Some((Some(vb), p)) if p.len() >= 2 => Some((vb, p.len())),
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

/// Runs the full check against `server`, comparing `window` recent blocks and
/// checking `history` blocks before them through the note trees.
pub async fn check(server: &str, route: &Route, window: u64, history: u64, reference: &mut Reference) -> CheckResult {
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
        exits: None,
        history: None,
    };
    let blocks = match fetch_server(server, route, window, &mut r).await {
        Ok(b) => b,
        Err(e) => {
            r.notes.push(lwd::plain_error(server, &e));
            return r;
        }
    };
    judge(&mut r, &blocks, reference).await;
    if let (Route::Tor(_), Some((start, end))) = (route, r.range) {
        cross_check_exits(&mut r, server, route, start, end, reference).await;
    }
    // The history check builds on the verified window, so it runs only when
    // every block in the window matched.
    if history > 0 && r.complete == Status::Pass {
        let h = crate::history::check(server, route, &blocks, reference, history, false).await;
        if h.status == Status::Fail {
            r.complete = Status::Fail;
            r.notes.push(format!("Older blocks: {}", h.detail));
        } else if h.status == Status::Unverified {
            r.notes.push(format!("Older blocks: {}", h.detail));
        }
        r.history = Some(h);
    }
    r
}

/// Extra Tor circuits used per server, on top of the first one.
const EXTRA_EXITS: usize = 2;

/// Fetches the same block range through more Tor circuits (each leaves from a
/// different exit) and compares every copy with the verified blocks. A server
/// that lies only to some clients would give some exits a different answer.
async fn cross_check_exits(r: &mut CheckResult, server: &str, route: &Route, start: u64, end: u64, reference: &mut Reference) {
    let mut agreed = 1;
    for exit in 2..=EXTRA_EXITS + 1 {
        let fetched = async {
            let mut c = lwd::connect(server, route).await?;
            lwd::blocks(&mut c, start, end).await
        }
        .await;
        let Ok(blocks) = fetched else {
            r.notes.push(format!("Tor exit {exit} couldn't reach the server"));
            continue;
        };
        let mut found = Vec::new();
        for b in &blocks {
            let Ok(hash) = <[u8; 32]>::try_from(b.hash.as_slice()) else { continue };
            if let Some(Some((full, _))) = reference.cache.get(&hash) {
                found.extend(compare::compare_block(full, b, &mut Tally::default()));
            }
        }
        if blocks.len() as u64 != end - start + 1 {
            r.notes.push(format!("Tor exit {exit} got {} blocks, the first exit got {}", blocks.len(), end - start + 1));
        } else if found.is_empty() {
            agreed += 1;
        }
        for mut m in found {
            m.what = format!("{} (through Tor exit {exit})", m.what);
            r.mismatches.push(m);
        }
    }
    r.exits = Some(ExitCheck { exits: EXTRA_EXITS + 1, matched: agreed });
    if !r.mismatches.is_empty() {
        r.complete = Status::Fail;
    }
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
    // Pass only when every block in the window was verified and matched.
    r.complete = if !mismatches.is_empty() {
        Status::Fail
    } else if tally.blocks == 0 || !unverified.is_empty() {
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
pub async fn test_row(base: &str, route: &Route, window: u64, history: u64, reference: &mut Reference) -> Option<CheckResult> {
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
        exits: None,
        history: None,
    };
    let blocks = fetch_server(base, route, window, &mut r).await.ok()?;
    // Only alter blocks the reference has verified, so the change can be checked.
    let wanted: Vec<(u64, [u8; 32])> = blocks
        .iter()
        .filter_map(|b| b.hash.as_slice().try_into().ok().map(|h| (b.height, h)))
        .collect();
    reference.fetch(&wanted).await;
    let verified: Vec<CompactBlock> = blocks
        .iter()
        .filter(|b| {
            <[u8; 32]>::try_from(b.hash.as_slice())
                .map(|h| matches!(reference.cache.get(&h), Some(Some(_))))
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    if verified.len() < 2 || verified.len() != blocks.len() {
        return None;
    }
    let (altered, desc) = compare::drop_one_note(&blocks)?;
    r.notes.push(format!("Test: {desc}."));
    r.consistency_only = Some(match compare::consistency_only(&altered) {
        Ok(()) => ConsistencyResult { status: Status::Pass, detail: "heights, links and tree sizes all add up".into() },
        Err(e) => ConsistencyResult { status: Status::Fail, detail: e },
    });
    judge(&mut r, &altered, reference).await;
    // The same lie further back: one note removed from the blocks before the
    // window, which only the history check can see.
    if history > 0 {
        r.history = Some(crate::history::check(base, route, &blocks, reference, history, true).await);
    }
    r.server = "test server (one note removed)".into();
    Some(r)
}

/// Runs the mutation self-test on real blocks from `server`: every change in
/// `mutate::run`, against the verified full blocks.
pub async fn selftest(server: &str, route: &Route, window: u64, reference: &mut Reference) -> Option<crate::mutate::MutationReport> {
    let mut r = blank(server);
    let blocks = fetch_server(server, route, window, &mut r).await.ok()?;
    let wanted: Vec<(u64, [u8; 32])> = blocks
        .iter()
        .filter_map(|b| b.hash.as_slice().try_into().ok().map(|h| (b.height, h)))
        .collect();
    reference.fetch(&wanted).await;
    let mut report = crate::mutate::MutationReport::default();
    for b in &blocks {
        let Ok(hash) = <[u8; 32]>::try_from(b.hash.as_slice()) else { continue };
        if let Some(Some((full, _))) = reference.cache.get(&hash) {
            crate::mutate::run(full, b, &mut report);
        }
    }
    (report.blocks > 0).then_some(report)
}

fn blank(server: &str) -> CheckResult {
    CheckResult {
        server: server.to_string(),
        route: String::new(),
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
        exits: None,
        history: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(node: &str, upgrade: &str, height: u64, tip: u64, branch: &str) -> CheckResult {
        let mut r = blank("test");
        r.info.node = node.into();
        r.info.reported_upgrade = upgrade.into();
        r.info.reported_upgrade_height = height;
        r.info.consensus_branch_id = branch.into();
        r.server_tip = tip;
        r
    }

    #[test]
    fn versions_parse() {
        assert_eq!(parse_version("7.0.0"), Some(([7, 0, 0], false)));
        assert_eq!(parse_version("7.0.0-rc.0"), Some(([7, 0, 0], true)));
        assert_eq!(parse_version("1.7.0+gc572f8"), Some(([1, 7, 0], false)));
        assert_eq!(parse_version("6.4"), Some(([6, 4, 0], false)));
        assert_eq!(parse_version("x"), None);
    }

    #[test]
    fn nu7_readiness_follows_the_node_release() {
        let tip = 3_533_800;
        assert_eq!(nu7_status(&with("Zebra:6.4.2", "NU6.3", 3_428_143, tip, "37a5165b")).0, Status::Fail);
        assert_eq!(nu7_status(&with("Zebra:7.0.0-rc.0", "NU7", NU7_HEIGHT, tip, "37a5165b")).0, Status::Fail);
        assert_eq!(nu7_status(&with("Zebra:7.0.0", "NU7", NU7_HEIGHT, tip, "37a5165b")).0, Status::Pass);
        assert_eq!(nu7_status(&with("Zakura:1.7.0", "NU7", NU7_HEIGHT, tip, "37a5165b")).0, Status::Pass);
        assert_eq!(nu7_status(&with("Zakura:1.6.9", "", 0, tip, "37a5165b")).0, Status::Fail);
    }

    #[test]
    fn unknown_node_falls_back_to_the_reported_upgrade() {
        let tip = 3_533_800;
        assert_eq!(nu7_status(&with("", "NU7", NU7_HEIGHT, tip, "")).0, Status::Pass);
        assert_eq!(nu7_status(&with("", "", 0, tip, "")).0, Status::Unverified);
        assert_eq!(nu7_status(&with("MagicBean:6.20.0", "", 0, tip, "")).0, Status::Unverified);
    }

    #[test]
    fn after_activation_the_branch_id_decides() {
        let after = NU7_HEIGHT + 10;
        assert_eq!(nu7_status(&with("Zebra:7.0.0", "", 0, after, "77190ad9")).0, Status::Pass);
        assert_eq!(nu7_status(&with("Zebra:7.0.0", "", 0, after, "37a5165b")).0, Status::Fail);
    }
}
