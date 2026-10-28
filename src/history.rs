//! The history check. Only a short window of recent blocks can be fetched in
//! full from peers, so older blocks are checked another way: the server's own
//! note commitments for the blocks before the window are rebuilt into the
//! Sapling, Orchard and Ironwood trees, starting from the server's tree state.
//! Two things are then compared:
//!
//! - the rebuilt root at the end of the range with the server's own tree state
//!   there. A server that drops a note from its blocks but reports the real
//!   tree state contradicts itself;
//! - the roots with the anchors that transactions in the verified window prove
//!   their spends against. Consensus requires every anchor to be the root of
//!   the real tree after some earlier block, so a match proves that every
//!   commitment the server sent up to that block is the real one, in order.
//!   This also catches a server that fakes its tree states to match.

use std::collections::HashMap;

use anyhow::{anyhow, bail, Result};
use incrementalmerkletree::frontier::Frontier;
use incrementalmerkletree::Hashable;
use orchard::tree::MerkleHashOrchard;
use serde::Serialize;
use zcash_primitives::merkle_tree::{read_commitment_tree, HashSer};

use crate::check::{Reference, Status};
use crate::lwd::{self, CompactBlock, Route};
use crate::verify::VerifiedBlock;

/// Roots are kept for this many blocks before the window. Wallets prove
/// spends against a root a few blocks old, and transactions expire after 40
/// blocks (120 from NU7), so real anchors fall well inside it.
const KEEP_ROOTS: u64 = 300;

/// With this many anchors and none matching, the pool can't count as checked.
/// It isn't a failure either: some real transactions use roots older than
/// the kept range, so only a contradiction fails.
const MIN_ANCHORS_TO_DOUBT: usize = 3;

/// Blocks fetched per request, to stay under the server's message limits.
const CHUNK: u64 = 500;

#[derive(Debug, Serialize, Clone)]
pub struct HistoryCheck {
    pub status: Status,
    /// The blocks whose commitments were rebuilt from the server's data.
    pub from: u64,
    pub to: u64,
    pub sapling: PoolCheck,
    pub orchard: PoolCheck,
    pub ironwood: PoolCheck,
    pub detail: String,
    /// Set only in test mode: the block a note was removed from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_dropped_at: Option<u64>,
}

#[derive(Debug, Serialize, Clone, Default)]
pub struct PoolCheck {
    pub status: Option<Status>,
    /// Commitments the server sent for `from..=to`.
    pub notes: u64,
    /// Whether the rebuilt root at `to` equals the server's own tree state.
    pub matches_own_state: Option<bool>,
    /// Distinct anchors used by transactions in the verified window.
    pub anchors: usize,
    pub matched: usize,
    /// The latest block whose rebuilt root a real transaction uses.
    pub proven_to: Option<u64>,
}

struct Rebuild<H> {
    tree: Frontier<H, 32>,
    roots: HashMap<[u8; 32], u64>,
    notes: u64,
    anchors: Vec<[u8; 32]>,
}

fn root_bytes<H: Hashable + HashSer + Clone>(tree: &Frontier<H, 32>) -> Option<[u8; 32]> {
    let mut bytes = Vec::with_capacity(32);
    tree.root().write(&mut bytes).ok()?;
    bytes.as_slice().try_into().ok()
}

fn read_tree<H: Hashable + HashSer + Clone>(state_hex: &str) -> Result<Frontier<H, 32>> {
    if state_hex.is_empty() {
        return Ok(Frontier::empty());
    }
    let bytes = hex::decode(state_hex)?;
    Ok(read_commitment_tree::<H, _, 32>(&bytes[..])?.to_frontier())
}

impl<H: Hashable + HashSer + Clone> Rebuild<H> {
    fn new(state_hex: &str) -> Result<Self> {
        Ok(Rebuild { tree: read_tree(state_hex)?, roots: HashMap::new(), notes: 0, anchors: Vec::new() })
    }

    fn append(&mut self, leaf: H) {
        self.tree.append(leaf);
        self.notes += 1;
    }

    fn keep_root(&mut self, height: u64) {
        if let Some(b) = root_bytes(&self.tree) {
            self.roots.insert(b, height);
        }
    }

    fn anchor(&mut self, a: [u8; 32]) {
        if !self.anchors.contains(&a) {
            self.anchors.push(a);
        }
    }

    /// `own_state` is the server's tree state at `to`; `notes` is the count
    /// for `from..=to`, taken before the window was added.
    fn judge(&self, notes: u64, at_to: Option<[u8; 32]>, own_state: &str) -> PoolCheck {
        let own = read_tree::<H>(own_state).ok().and_then(|t| root_bytes(&t));
        let matches_own_state = match (at_to, own) {
            (Some(a), Some(b)) => Some(a == b),
            _ => None,
        };
        let heights: Vec<u64> = self.anchors.iter().filter_map(|a| self.roots.get(a).copied()).collect();
        let matched = heights.len();
        let status = if matches_own_state == Some(false) {
            Some(Status::Fail)
        } else if matched > 0 {
            Some(Status::Pass)
        } else {
            None
        };
        PoolCheck { status, notes, matches_own_state, anchors: self.anchors.len(), matched, proven_to: heights.into_iter().max() }
    }
}

fn sapling_leaf(b: &[u8]) -> Result<sapling_crypto::Node> {
    let a = <[u8; 32]>::try_from(b)?;
    Option::from(sapling_crypto::Node::from_bytes(a)).ok_or_else(|| anyhow!("server sent an invalid Sapling note commitment"))
}

fn orchard_leaf(b: &[u8]) -> Result<MerkleHashOrchard> {
    let a = <[u8; 32]>::try_from(b)?;
    Option::from(MerkleHashOrchard::from_bytes(&a)).ok_or_else(|| anyhow!("server sent an invalid Orchard or Ironwood note commitment"))
}

/// Checks the `depth` blocks before `window`, which must already be verified.
/// With `drop_note`, one note commitment is removed from the middle of the
/// server's history first, to show what a lie there looks like.
pub async fn check(server: &str, route: &Route, window: &[CompactBlock], reference: &Reference, depth: u64, drop_note: bool) -> HistoryCheck {
    let to = window.first().map(|b| b.height).unwrap_or(1).saturating_sub(1);
    let from = to.saturating_sub(depth.saturating_sub(1)).max(1);
    match run(server, route, window, reference, from, to, drop_note).await {
        Ok(h) => h,
        Err(e) => HistoryCheck {
            status: Status::Unverified,
            from,
            to,
            sapling: PoolCheck::default(),
            orchard: PoolCheck::default(),
            ironwood: PoolCheck::default(),
            detail: format!("couldn't check the {} blocks before the window: {}", to + 1 - from, lwd::plain_error(server, &e)),
            test_dropped_at: None,
        },
    }
}

async fn run(server: &str, route: &Route, window: &[CompactBlock], reference: &Reference, from: u64, to: u64, drop_note: bool) -> Result<HistoryCheck> {
    let mut c = lwd::connect(server, route).await?;
    let start_state = lwd::tree_state(&mut c, from - 1).await?;
    let end_state = lwd::tree_state(&mut c, to).await?;
    if start_state.height != from - 1 || end_state.height != to {
        bail!("asked for the tree states at blocks {} and {to}, got {} and {}", from - 1, start_state.height, end_state.height);
    }
    let mut sapling = Rebuild::<sapling_crypto::Node>::new(&start_state.sapling_tree)?;
    let mut orchard = Rebuild::<MerkleHashOrchard>::new(&start_state.orchard_tree)?;
    let mut ironwood = Rebuild::<MerkleHashOrchard>::new(&start_state.ironwood_tree)?;
    let keep_from = to.saturating_sub(KEEP_ROOTS);

    let mut old = Vec::new();
    let mut start = from;
    while start <= to {
        let end = (start + CHUNK - 1).min(to);
        old.extend(lwd::blocks(&mut c, start, end).await?);
        start = end + 1;
    }
    for (i, b) in old.iter().enumerate() {
        if b.height != from + i as u64 {
            bail!("the server skipped blocks: expected block {}, got {}", from + i as u64, b.height);
        }
    }
    if old.len() as u64 != to + 1 - from {
        bail!("the server sent {} of {} blocks", old.len(), to + 1 - from);
    }

    // Test mode: the first Orchard note in the second half of the range.
    let drop_at = if drop_note {
        old[old.len() / 2..].iter().find(|b| b.vtx.iter().any(|t| !t.actions.is_empty())).map(|b| b.height)
    } else {
        None
    };
    for b in &old {
        let mut dropped = drop_at != Some(b.height);
        for tx in &b.vtx {
            for o in &tx.outputs {
                sapling.append(sapling_leaf(&o.cmu)?);
            }
            for a in &tx.actions {
                if !dropped {
                    dropped = true;
                    continue;
                }
                orchard.append(orchard_leaf(&a.cmx)?);
            }
            for a in &tx.ironwood_actions {
                ironwood.append(orchard_leaf(&a.cmx)?);
            }
        }
        if b.height >= keep_from {
            sapling.keep_root(b.height);
            orchard.keep_root(b.height);
            ironwood.keep_root(b.height);
        }
    }
    let counts = (sapling.notes, orchard.notes, ironwood.notes);
    let at_to = (root_bytes(&sapling.tree), root_bytes(&orchard.tree), root_bytes(&ironwood.tree));

    // The window: commitments from the verified full blocks, then the anchors
    // their transactions use.
    for cb in window {
        let full: &VerifiedBlock = match <[u8; 32]>::try_from(cb.hash.as_slice()).ok().and_then(|h| reference.verified(&h)) {
            Some(f) => f,
            None => bail!("block {} in the window isn't verified", cb.height),
        };
        for tx in &full.txs {
            for o in &tx.sapling_outputs {
                sapling.append(sapling_leaf(&o.cmu)?);
            }
            for a in &tx.orchard_actions {
                orchard.append(orchard_leaf(&a.cmx)?);
            }
            for a in &tx.ironwood_actions {
                ironwood.append(orchard_leaf(&a.cmx)?);
            }
            for a in &tx.sapling_anchors {
                sapling.anchor(*a);
            }
            if let Some(a) = tx.orchard_anchor {
                orchard.anchor(a);
            }
            if let Some(a) = tx.ironwood_anchor {
                ironwood.anchor(a);
            }
        }
        sapling.keep_root(cb.height);
        orchard.keep_root(cb.height);
        ironwood.keep_root(cb.height);
    }

    let s = sapling.judge(counts.0, at_to.0, &end_state.sapling_tree);
    let o = orchard.judge(counts.1, at_to.1, &end_state.orchard_tree);
    let i = ironwood.judge(counts.2, at_to.2, &end_state.ironwood_tree);
    let blocks = to + 1 - from;
    let pools = [("Sapling", &s), ("Orchard", &o), ("Ironwood", &i)];
    let describe = |name: &str, p: &PoolCheck| -> String {
        match (p.status, p.matches_own_state) {
            (Some(Status::Fail), _) => format!("{name}: the {} notes the server sent don't rebuild to its own tree state at block {to}, so a note was left out, added or changed", p.notes),
            (Some(Status::Pass), _) => format!("{name}: {} notes, rebuilt tree matches a real anchor at block {}", p.notes, p.proven_to.unwrap_or(to)),
            _ if p.anchors > 0 => format!("{name}: {} notes add up to the server's own tree state; none of the {} anchors in the verified blocks is a root from the last {KEEP_ROOTS} blocks", p.notes, p.anchors),
            _ => format!("{name}: {} notes add up to the server's own tree state; no {name} spend in the verified blocks to prove it against", p.notes),
        }
    };
    let status = if pools.iter().any(|(_, p)| p.status == Some(Status::Fail)) {
        Status::Fail
    } else if pools.iter().any(|(_, p)| p.status == Some(Status::Pass))
        && !pools.iter().any(|(_, p)| p.matched == 0 && p.anchors >= MIN_ANCHORS_TO_DOUBT)
    {
        Status::Pass
    } else {
        Status::Unverified
    };
    let detail = format!(
        "{blocks} earlier blocks ({from}-{to}) checked through the note trees. {}.",
        pools.iter().map(|(n, p)| describe(n, p)).collect::<Vec<_>>().join("; ")
    );
    Ok(HistoryCheck { status, from, to, sapling: s, orchard: o, ironwood: i, detail, test_dropped_at: drop_at })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BEFORE: &str = include_str!("../tests/fixtures/treestate-3533760.json");
    const AFTER: &str = include_str!("../tests/fixtures/treestate-3533761.json");

    fn state(json: &str, pool: &str) -> String {
        let v: serde_json::Value = serde_json::from_str(json).unwrap();
        v[pool].as_str().unwrap_or("").to_string()
    }

    /// Every pool's tree at block 3,533,760 plus the commitments of the real
    /// block 3,533,761, in order, minus `skip` leading notes per pool.
    fn rebuild(skip: usize) -> [Option<[u8; 32]>; 3] {
        let full = crate::compare::tests::full();
        let mut s = Rebuild::<sapling_crypto::Node>::new(&state(BEFORE, "sapling")).unwrap();
        let mut o = Rebuild::<MerkleHashOrchard>::new(&state(BEFORE, "orchard")).unwrap();
        let mut i = Rebuild::<MerkleHashOrchard>::new(&state(BEFORE, "ironwood")).unwrap();
        let (mut ns, mut no, mut ni) = (0, 0, 0);
        for tx in &full.txs {
            for n in &tx.sapling_outputs {
                ns += 1;
                if ns > skip {
                    s.append(sapling_leaf(&n.cmu).unwrap());
                }
            }
            for a in &tx.orchard_actions {
                no += 1;
                if no > skip {
                    o.append(orchard_leaf(&a.cmx).unwrap());
                }
            }
            for a in &tx.ironwood_actions {
                ni += 1;
                if ni > skip {
                    i.append(orchard_leaf(&a.cmx).unwrap());
                }
            }
        }
        assert!(ns + no + ni > 0, "the fixture block has shielded notes");
        [root_bytes(&s.tree), root_bytes(&o.tree), root_bytes(&i.tree)]
    }

    fn real_after() -> [Option<[u8; 32]>; 3] {
        [
            root_bytes(&read_tree::<sapling_crypto::Node>(&state(AFTER, "sapling")).unwrap()),
            root_bytes(&read_tree::<MerkleHashOrchard>(&state(AFTER, "orchard")).unwrap()),
            root_bytes(&read_tree::<MerkleHashOrchard>(&state(AFTER, "ironwood")).unwrap()),
        ]
    }

    #[test]
    fn rebuilt_trees_match_the_real_tree_state() {
        assert_eq!(rebuild(0), real_after());
    }

    #[test]
    fn one_missing_note_changes_the_root() {
        let (got, real) = (rebuild(1), real_after());
        let full = crate::compare::tests::full();
        let has = [
            full.txs.iter().any(|t| !t.sapling_outputs.is_empty()),
            full.txs.iter().any(|t| !t.orchard_actions.is_empty()),
            full.txs.iter().any(|t| !t.ironwood_actions.is_empty()),
        ];
        for p in 0..3 {
            if has[p] {
                assert_ne!(got[p], real[p], "pool {p}");
            } else {
                assert_eq!(got[p], real[p], "pool {p}");
            }
        }
    }

    #[test]
    fn verdict_fails_only_on_a_contradiction() {
        let r = Rebuild::<MerkleHashOrchard>::new(&state(BEFORE, "orchard")).unwrap();
        let before = root_bytes(&r.tree);
        // Our rebuilt root equals the server's own state: no contradiction.
        assert_eq!(r.judge(0, before, &state(BEFORE, "orchard")).status, None);
        // The server's own state at the end disagrees with the rebuild.
        let p = r.judge(0, before, &state(AFTER, "ironwood"));
        assert_eq!(p.status, Some(Status::Fail));
        assert_eq!(p.matches_own_state, Some(false));
    }
}
