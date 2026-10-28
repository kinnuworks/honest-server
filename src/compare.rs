//! Compares a server's compact blocks with verified full blocks.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::lwd::rpc::{CompactBlock, CompactOrchardAction, CompactTx};
use crate::verify::{ActionData, ShieldedTx, VerifiedBlock};

#[derive(Clone, Debug, Serialize)]
pub struct Mismatch {
    pub height: u64,
    /// Transaction id in the usual display order (byte-reversed hex).
    pub txid: String,
    pub tx_index: u64,
    pub what: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Tally {
    pub blocks: usize,
    pub shielded_txs: usize,
    pub commitments: usize,
    pub nullifiers: usize,
}

pub fn display_hex(bytes: &[u8]) -> String {
    let mut b = bytes.to_vec();
    b.reverse();
    hex::encode(b)
}

fn compact_is_shielded(tx: &CompactTx) -> bool {
    !(tx.spends.is_empty() && tx.outputs.is_empty() && tx.actions.is_empty() && tx.ironwood_actions.is_empty())
}

/// Every shielded transaction in `full` must appear in `compact` with the
/// same txid and identical fields, and nothing extra may appear.
pub fn compare_block(full: &VerifiedBlock, compact: &CompactBlock, tally: &mut Tally) -> Vec<Mismatch> {
    let mut out = Vec::new();
    let h = compact.height;
    let expected: BTreeMap<u64, &ShieldedTx> = full
        .txs
        .iter()
        .filter(|t| t.is_shielded())
        .map(|t| (t.index as u64, t))
        .collect();
    let served: BTreeMap<u64, &CompactTx> =
        compact.vtx.iter().filter(|t| compact_is_shielded(t)).map(|t| (t.index, t)).collect();

    let miss = |idx: u64, txid: &[u8], what: String| Mismatch { height: h, txid: display_hex(txid), tx_index: idx, what };

    for (idx, exp) in &expected {
        let Some(got) = served.get(idx) else {
            out.push(miss(*idx, &exp.txid, "shielded transaction missing from the compact block".into()));
            continue;
        };
        if got.txid != exp.txid {
            out.push(miss(*idx, &exp.txid, format!("txid differs: server sent {}", display_hex(&got.txid))));
            continue;
        }
        let before = out.len();
        // Sapling spends: nullifiers.
        if got.spends.len() != exp.sapling_nullifiers.len() {
            out.push(miss(*idx, &exp.txid, format!(
                "Sapling spends: block has {}, server sent {}", exp.sapling_nullifiers.len(), got.spends.len())));
        } else {
            for (i, (s, nf)) in got.spends.iter().zip(&exp.sapling_nullifiers).enumerate() {
                if s.nf != nf {
                    out.push(miss(*idx, &exp.txid, format!("Sapling spend {i}: nullifier differs")));
                }
            }
        }
        // Sapling outputs: note commitment, ephemeral key, compact ciphertext.
        if got.outputs.len() != exp.sapling_outputs.len() {
            out.push(miss(*idx, &exp.txid, format!(
                "Sapling outputs: block has {}, server sent {}", exp.sapling_outputs.len(), got.outputs.len())));
        } else {
            for (i, (o, e)) in got.outputs.iter().zip(&exp.sapling_outputs).enumerate() {
                if o.cmu != e.cmu {
                    out.push(miss(*idx, &exp.txid, format!("Sapling output {i}: note commitment differs")));
                }
                if o.ephemeral_key != e.epk {
                    out.push(miss(*idx, &exp.txid, format!("Sapling output {i}: ephemeral key differs")));
                }
                if o.ciphertext != e.ciphertext {
                    out.push(miss(*idx, &exp.txid, format!("Sapling output {i}: compact ciphertext differs")));
                }
            }
        }
        compare_actions(&mut out, h, *idx, &exp.txid, "Orchard", &got.actions, &exp.orchard_actions);
        compare_actions(&mut out, h, *idx, &exp.txid, "Ironwood", &got.ironwood_actions, &exp.ironwood_actions);
        if out.len() == before {
            tally.shielded_txs += 1;
            tally.commitments += exp.sapling_outputs.len() + exp.orchard_actions.len() + exp.ironwood_actions.len();
            tally.nullifiers += exp.sapling_nullifiers.len() + exp.orchard_actions.len() + exp.ironwood_actions.len();
        }
    }
    for (idx, got) in &served {
        if !expected.contains_key(idx) {
            out.push(miss(*idx, &got.txid, "server sent a shielded transaction the block does not contain".into()));
        }
    }
    tally.blocks += 1;
    out
}

fn compare_actions(
    out: &mut Vec<Mismatch>,
    h: u64,
    idx: u64,
    txid: &[u8; 32],
    pool: &str,
    got: &[CompactOrchardAction],
    exp: &[ActionData],
) {
    let miss = |what: String| Mismatch { height: h, txid: display_hex(txid), tx_index: idx, what };
    if got.len() != exp.len() {
        out.push(miss(format!("{pool} actions: block has {}, server sent {}", exp.len(), got.len())));
        return;
    }
    for (i, (a, e)) in got.iter().zip(exp).enumerate() {
        if a.nullifier != e.nullifier {
            out.push(miss(format!("{pool} action {i}: nullifier differs")));
        }
        if a.cmx != e.cmx {
            out.push(miss(format!("{pool} action {i}: note commitment differs")));
        }
        if a.ephemeral_key != e.epk {
            out.push(miss(format!("{pool} action {i}: ephemeral key differs")));
        }
        if a.ciphertext != e.ciphertext {
            out.push(miss(format!("{pool} action {i}: compact ciphertext differs")));
        }
    }
}

/// What a checker that only looks at the server's own answers can see:
/// heights in order, each block linking to the one before, and note
/// commitment tree sizes that grow by exactly the outputs in each block.
pub fn consistency_only(blocks: &[CompactBlock]) -> Result<(), String> {
    for w in blocks.windows(2) {
        let (a, b) = (&w[0], &w[1]);
        if b.height != a.height + 1 {
            return Err(format!("height jumps from {} to {}", a.height, b.height));
        }
        if b.prev_hash != a.hash {
            return Err(format!("block {} does not link to block {}", b.height, a.height));
        }
        let (Some(ma), Some(mb)) = (&a.chain_metadata, &b.chain_metadata) else { continue };
        let count = |f: fn(&CompactTx) -> usize| b.vtx.iter().map(f).sum::<usize>() as u32;
        if mb.sapling_commitment_tree_size != ma.sapling_commitment_tree_size + count(|t| t.outputs.len()) {
            return Err(format!("Sapling tree size at block {} doesn't add up", b.height));
        }
        if mb.orchard_commitment_tree_size != ma.orchard_commitment_tree_size + count(|t| t.actions.len()) {
            return Err(format!("Orchard tree size at block {} doesn't add up", b.height));
        }
        if mb.ironwood_commitment_tree_size != ma.ironwood_commitment_tree_size + count(|t| t.ironwood_actions.len()) {
            return Err(format!("Ironwood tree size at block {} doesn't add up", b.height));
        }
    }
    Ok(())
}

/// Builds the test server's answer from real data: one shielded action (or
/// output) removed, and the tree sizes adjusted so the chain still looks
/// consistent. Returns the altered blocks and a description of the change.
pub fn drop_one_note(blocks: &[CompactBlock]) -> Option<(Vec<CompactBlock>, String)> {
    let mut out = blocks.to_vec();
    // Prefer a transaction with two or more notes in a pool, so the change
    // is one missing note rather than a missing transaction.
    for min in [2usize, 1] {
    for bi in (0..out.len()).rev() {
        for ti in 0..out[bi].vtx.len() {
            let tx = &mut out[bi].vtx[ti];
            let (pool, removed) = if tx.ironwood_actions.len() >= min {
                tx.ironwood_actions.pop();
                ("Ironwood", 2)
            } else if tx.actions.len() >= min {
                tx.actions.pop();
                ("Orchard", 1)
            } else if tx.outputs.len() >= min {
                tx.outputs.pop();
                ("Sapling", 0)
            } else {
                continue;
            };
            let desc = format!(
                "dropped one {pool} note from transaction {} in block {}",
                display_hex(&tx.txid), out[bi].height
            );
            for later in out.iter_mut().skip(bi) {
                if let Some(m) = later.chain_metadata.as_mut() {
                    match removed {
                        2 => m.ironwood_commitment_tree_size -= 1,
                        1 => m.orchard_commitment_tree_size -= 1,
                        _ => m.sapling_commitment_tree_size -= 1,
                    }
                }
            }
            return Some((out, desc));
        }
    }
    }
    None
}

#[cfg(test)]
pub mod tests_support {
    pub fn real_pair() -> (crate::verify::VerifiedBlock, super::CompactBlock) {
        let f = super::tests::full();
        let c = super::tests::honest(&f);
        (f, c)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::lwd::rpc::{ChainMetadata, CompactSaplingOutput, CompactSaplingSpend};
    use crate::verify::{verify_block, VerifiedBlock};

    const RAW: &[u8] = include_bytes!("../tests/fixtures/block-3533761.bin");

    pub fn full() -> VerifiedBlock {
        let hash = zcash_primitives::block::BlockHeader::read(RAW).unwrap().hash().0;
        verify_block(RAW, &hash, 3_533_761).unwrap()
    }

    /// The compact block an honest server would send for `full`.
    pub fn honest(full: &VerifiedBlock) -> CompactBlock {
        let action = |a: &crate::verify::ActionData| CompactOrchardAction {
            nullifier: a.nullifier.to_vec(),
            cmx: a.cmx.to_vec(),
            ephemeral_key: a.epk.to_vec(),
            ciphertext: a.ciphertext.clone(),
        };
        CompactBlock {
            height: 3_533_761,
            vtx: full
                .txs
                .iter()
                .map(|t| CompactTx {
                    index: t.index as u64,
                    txid: t.txid.to_vec(),
                    spends: t.sapling_nullifiers.iter().map(|n| CompactSaplingSpend { nf: n.to_vec() }).collect(),
                    outputs: t
                        .sapling_outputs
                        .iter()
                        .map(|o| CompactSaplingOutput {
                            cmu: o.cmu.to_vec(),
                            ephemeral_key: o.epk.to_vec(),
                            ciphertext: o.ciphertext.clone(),
                        })
                        .collect(),
                    actions: t.orchard_actions.iter().map(action).collect(),
                    ironwood_actions: t.ironwood_actions.iter().map(action).collect(),
                    ..Default::default()
                })
                .collect(),
            chain_metadata: Some(ChainMetadata::default()),
            ..Default::default()
        }
    }

    #[test]
    fn honest_block_matches() {
        let f = full();
        let mut tally = Tally::default();
        assert!(compare_block(&f, &honest(&f), &mut tally).is_empty());
        assert!(tally.commitments > 0 && tally.nullifiers > 0);
    }

    #[test]
    fn dropped_note_is_caught_and_consistency_check_misses_it() {
        let f = full();
        let prev = CompactBlock {
            height: 3_533_760,
            hash: vec![1; 32],
            chain_metadata: Some(ChainMetadata::default()),
            ..Default::default()
        };
        let mut cur = honest(&f);
        cur.prev_hash = prev.hash.clone();
        let count = |f: fn(&CompactTx) -> usize| cur.vtx.iter().map(f).sum::<usize>() as u32;
        cur.chain_metadata = Some(ChainMetadata {
            sapling_commitment_tree_size: count(|t| t.outputs.len()),
            orchard_commitment_tree_size: count(|t| t.actions.len()),
            ironwood_commitment_tree_size: count(|t| t.ironwood_actions.len()),
        });
        let (altered, _) = drop_one_note(&[prev, cur]).unwrap();
        assert!(consistency_only(&altered).is_ok(), "the lie is consistent");
        let mismatches = compare_block(&f, &altered[1], &mut Tally::default());
        assert_eq!(mismatches.len(), 1);
    }

    #[test]
    fn changed_nullifier_is_caught() {
        let f = full();
        let mut c = honest(&f);
        let tx = c.vtx.iter_mut().find(|t| !t.ironwood_actions.is_empty() || !t.actions.is_empty()).unwrap();
        let a = tx.ironwood_actions.first_mut().or(tx.actions.first_mut()).unwrap();
        a.nullifier[0] ^= 1;
        let m = compare_block(&f, &c, &mut Tally::default());
        assert!(m.iter().any(|m| m.what.contains("nullifier differs")));
    }

    #[test]
    fn extra_transaction_is_caught() {
        let f = full();
        let mut c = honest(&f);
        c.vtx.push(CompactTx {
            index: 999,
            txid: vec![9; 32],
            spends: vec![CompactSaplingSpend { nf: vec![0; 32] }],
            ..Default::default()
        });
        let m = compare_block(&f, &c, &mut Tally::default());
        assert!(m.iter().any(|m| m.what.contains("does not contain")));
    }
}
