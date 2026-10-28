//! Self-test: make every single change we can think of to a real compact
//! block and count how many the comparison catches.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::compare::{compare_block, Tally};
use crate::lwd::rpc::{CompactBlock, CompactOrchardAction, CompactTx};
use crate::verify::VerifiedBlock;

#[derive(Debug, Default, Serialize)]
pub struct MutationReport {
    pub blocks: usize,
    pub tried: usize,
    pub caught: usize,
    /// Kind of change -> (tried, caught)
    pub by_kind: BTreeMap<String, (usize, usize)>,
    /// Up to 20 changes that slipped through, if any.
    pub missed: Vec<String>,
}

impl MutationReport {
    fn record(&mut self, kind: &str, caught: bool, what: impl FnOnce() -> String) {
        self.tried += 1;
        let e = self.by_kind.entry(kind.to_string()).or_insert((0, 0));
        e.0 += 1;
        if caught {
            self.caught += 1;
            e.1 += 1;
        } else if self.missed.len() < 20 {
            self.missed.push(what());
        }
    }
}

fn flip(v: &mut [u8], at: usize) {
    if !v.is_empty() {
        let i = at.min(v.len() - 1);
        v[i] ^= 0x01;
    }
}

/// Every pool list of notes in a compact transaction, by name.
fn action_lists(tx: &mut CompactTx) -> [(&'static str, &mut Vec<CompactOrchardAction>); 2] {
    [("Orchard", &mut tx.actions), ("Ironwood", &mut tx.ironwood_actions)]
}

/// Runs every mutation of `compact` against `full`. The unchanged block must
/// match first, or nothing is counted.
pub fn run(full: &VerifiedBlock, compact: &CompactBlock, report: &mut MutationReport) -> bool {
    if !compare_block(full, compact, &mut Tally::default()).is_empty() {
        return false;
    }
    report.blocks += 1;
    let h = compact.height;
    let mut check = |kind: &str, changed: CompactBlock, what: String, report: &mut MutationReport| {
        let caught = !compare_block(full, &changed, &mut Tally::default()).is_empty();
        report.record(kind, caught, || format!("block {h}: {what}"));
    };

    for ti in 0..compact.vtx.len() {
        let tx = &compact.vtx[ti];
        let shielded = !(tx.spends.is_empty() && tx.outputs.is_empty() && tx.actions.is_empty() && tx.ironwood_actions.is_empty());
        if !shielded {
            continue;
        }
        // Whole transaction: drop it, change its txid, move it to another index.
        let mut c = compact.clone();
        c.vtx.remove(ti);
        check("drop a transaction", c, format!("dropped tx {ti}"), report);
        for at in [0, 31] {
            let mut c = compact.clone();
            flip(&mut c.vtx[ti].txid, at);
            check("change a txid byte", c, format!("tx {ti} txid byte {at}"), report);
        }
        let mut c = compact.clone();
        c.vtx[ti].index += 10_000;
        check("move a transaction", c, format!("tx {ti} index moved"), report);

        // Sapling spends.
        for si in 0..tx.spends.len() {
            for at in [0, 31] {
                let mut c = compact.clone();
                flip(&mut c.vtx[ti].spends[si].nf, at);
                check("change a Sapling nullifier", c, format!("tx {ti} spend {si} byte {at}"), report);
            }
            let mut c = compact.clone();
            c.vtx[ti].spends.remove(si);
            check("drop a Sapling spend", c, format!("tx {ti} spend {si}"), report);
        }
        // Sapling outputs.
        for oi in 0..tx.outputs.len() {
            for at in [0, 31] {
                let mut c = compact.clone();
                flip(&mut c.vtx[ti].outputs[oi].cmu, at);
                check("change a Sapling note commitment", c, format!("tx {ti} output {oi} cmu byte {at}"), report);
                let mut c = compact.clone();
                flip(&mut c.vtx[ti].outputs[oi].ephemeral_key, at);
                check("change a Sapling ephemeral key", c, format!("tx {ti} output {oi} epk byte {at}"), report);
            }
            for at in [0, 51] {
                let mut c = compact.clone();
                flip(&mut c.vtx[ti].outputs[oi].ciphertext, at);
                check("change a Sapling ciphertext", c, format!("tx {ti} output {oi} ciphertext byte {at}"), report);
            }
            let mut c = compact.clone();
            c.vtx[ti].outputs.remove(oi);
            check("drop a Sapling output", c, format!("tx {ti} output {oi}"), report);
        }
        if tx.outputs.len() >= 2 && tx.outputs[0] != tx.outputs[1] {
            let mut c = compact.clone();
            c.vtx[ti].outputs.swap(0, 1);
            check("reorder notes", c, format!("tx {ti} outputs 0 and 1 swapped"), report);
        }
        if let Some(first) = tx.outputs.first().cloned() {
            let mut c = compact.clone();
            c.vtx[ti].outputs.push(first);
            check("add a note", c, format!("tx {ti} output duplicated"), report);
        }
        // Orchard and Ironwood actions.
        for pool in 0..2 {
            let len = { let mut t = tx.clone(); action_lists(&mut t)[pool].1.len() };
            for ai in 0..len {
                for field in ["nullifier", "note commitment", "ephemeral key", "ciphertext"] {
                    for at in [0, 31] {
                        let mut c = compact.clone();
                        let (name, list) = { let [a, b] = action_lists(&mut c.vtx[ti]); if pool == 0 { a } else { b } };
                        let a = &mut list[ai];
                        match field {
                            "nullifier" => flip(&mut a.nullifier, at),
                            "note commitment" => flip(&mut a.cmx, at),
                            "ephemeral key" => flip(&mut a.ephemeral_key, at),
                            _ => flip(&mut a.ciphertext, if at == 0 { 0 } else { 51 }),
                        }
                        let kind = format!("change an {name} {field}");
                        check(&kind, c, format!("tx {ti} {name} action {ai} {field} byte {at}"), report);
                    }
                }
                let mut c = compact.clone();
                let (name, list) = { let [a, b] = action_lists(&mut c.vtx[ti]); if pool == 0 { a } else { b } };
                list.remove(ai);
                let kind = format!("drop an {name} action");
                check(&kind, c, format!("tx {ti} {name} action {ai}"), report);
            }
            if len >= 2 {
                let mut c = compact.clone();
                let (name, list) = { let [a, b] = action_lists(&mut c.vtx[ti]); if pool == 0 { a } else { b } };
                if list[0] != list[1] {
                    list.swap(0, 1);
                    check("reorder notes", c, format!("tx {ti} {name} actions 0 and 1 swapped"), report);
                }
            }
        }
    }
    // A shielded transaction that isn't in the block.
    if let Some(t) = compact.vtx.iter().find(|t| !t.spends.is_empty() || !t.outputs.is_empty() || !t.actions.is_empty() || !t.ironwood_actions.is_empty()) {
        let mut c = compact.clone();
        let mut fake = t.clone();
        fake.index = 10_000;
        flip(&mut fake.txid, 0);
        c.vtx.push(fake);
        check("add a fake transaction", c, "fake tx appended".into(), report);
    }
    true
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_change_to_a_real_block_is_caught() {
        let (full, compact) = crate::compare::tests_support::real_pair();
        let mut r = super::MutationReport::default();
        assert!(super::run(&full, &compact, &mut r));
        assert!(r.tried > 100, "fixture gives many mutations ({})", r.tried);
        assert_eq!(r.caught, r.tried, "missed: {:?}", r.missed);
    }

    #[test]
    fn every_change_to_a_block_with_sapling_spends_is_caught() {
        let f = crate::compare::tests::load(include_bytes!("../tests/fixtures/block-3533755.bin"), 3_533_755);
        let c = crate::compare::tests::honest(&f);
        let mut r = super::MutationReport::default();
        assert!(super::run(&f, &c, &mut r));
        assert!(r.by_kind.contains_key("change a Sapling nullifier"));
        assert_eq!(r.caught, r.tried, "missed: {:?}", r.missed);
    }

    #[test]
    fn a_block_that_already_mismatches_is_not_counted() {
        let f = crate::compare::tests::full();
        let mut c = crate::compare::tests::honest(&f);
        // Remove a shielded transaction, so the unchanged block already mismatches.
        let i = c.vtx.iter().position(|t| !t.ironwood_actions.is_empty()).unwrap();
        c.vtx.remove(i);
        let mut r = super::MutationReport::default();
        assert!(!super::run(&f, &c, &mut r));
        assert_eq!(r.tried, 0);
    }
}
