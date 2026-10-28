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
        let peers = p2p::connect_peers(want_peers, 170_190).await;
        if peers.len() < 2 {
            bail!("could not reach two NU7-ready Zcash peers");
        }
        Ok(Reference { peers, cache: HashMap::new(), network_tip: None })
    }

    pub fn peer_summary(&self) -> Vec<String> {
        self.peers.iter().map(|p| format!("{} ({})", p.user_agent, p.start_height)).collect()
    }

    /// Fetches the blocks with these hashes from at least two peers. A block
    /// counts as verified when two peers serve it and it passes every check.
    async fn fetch(&mut self, wanted: &[(u64, [u8; 32])]) {
        let todo: Vec<(u64, [u8; 32])> =
            wanted.iter().filter(|(_, h)| !self.cache.contains_key(h)).cloned().collect();
        if todo.is_empty() {
            return;
        }
        let hashes: Vec<[u8; 32]> = todo.iter().map(|(_, h)| *h).collect();
        let mut agree: HashMap<[u8; 32], (Option<VerifiedBlock>, usize)> = HashMap::new();
        let mut alive = Vec::new();
        for mut peer in std::mem::take(&mut self.peers) {
            let mut ok = true;
            for chunk in hashes.chunks(16) {
                match peer.get_blocks(chunk).await {
                    Ok(blocks) => {
                        for raw in blocks {
                            // Match the block to the hash we asked for by its header.
                            let Some((height, hash)) = todo.iter().find(|(_, h)| {
                                zcash_primitives::block::BlockHeader::read(&raw[..])
                                    .map(|hd| hd.hash().0 == *h)
                                    .unwrap_or(false)
                            }) else { continue };
                            if let Ok(vb) = verify::verify_block(&raw, hash, *height as u32) {
                                let e = agree.entry(*hash).or_insert((None, 0));
                                e.1 += 1;
                                if e.0.is_none() {
                                    e.0 = Some(vb);
                                }
                            }
                        }
                    }
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                alive.push(peer);
            }
            // Stop once every block has two verifying peers; keep the rest for later.
            if agree.values().filter(|(_, n)| *n >= 2).count() == hashes.len() {
                break;
            }
        }
        // Put back peers we didn't get to.
        alive.extend(std::mem::take(&mut self.peers));
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
        let mut best: Option<(u64, [u8; 32])> = None;
        let mut confirmations = 0;
        for peer in self.peers.iter_mut() {
            let mut height = from_height;
            let mut hash = from_hash;
            let mut linked = false;
            for _ in 0..40 {
                let Ok(headers) = peer.get_headers(&[hash]).await else { break };
                if headers.is_empty() {
                    linked = true;
                    break;
                }
                let mut ok = true;
                for raw in &headers {
                    match verify::verify_header(raw) {
                        Ok(vh) if vh.prev == hash => {
                            height += 1;
                            hash = vh.hash;
                        }
                        _ => {
                            ok = false;
                            break;
                        }
                    }
                }
                if !ok {
                    break;
                }
                linked = true;
                if headers.len() < 160 {
                    break;
                }
            }
            if linked {
                confirmations += 1;
                if best.map(|(h, _)| height > h).unwrap_or(true) {
                    best = Some((height, hash));
                }
                if confirmations >= 2 {
                    break;
                }
            }
        }
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
