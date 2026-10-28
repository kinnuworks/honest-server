//! Checks a block from a peer before anything is compared with it: Equihash,
//! the difficulty target, the merkle root over librustzcash txids and the
//! height in the coinbase. Then it pulls out every shielded field a compact
//! block is supposed to carry.

use std::io::Cursor;

use anyhow::{anyhow, bail, Result};
use zcash_primitives::block::BlockHeader;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, MainNetwork};

use crate::p2p::{dsha256, read_compact_size};

/// Header bytes covered by Equihash: everything before the nonce.
const EQUIHASH_INPUT_LEN: usize = 108;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedHeader {
    pub hash: [u8; 32],
    pub prev: [u8; 32],
    pub time: u32,
}

/// Verifies a raw header (version through solution).
pub fn verify_header(raw: &[u8]) -> Result<VerifiedHeader> {
    let header = BlockHeader::read(&raw[..])?;
    if raw.len() < EQUIHASH_INPUT_LEN + 32 {
        bail!("header too short");
    }
    equihash::is_valid_solution(200, 9, &raw[..EQUIHASH_INPUT_LEN], &header.nonce, &header.solution)
        .map_err(|e| anyhow!("Equihash solution is invalid: {e:?}"))?;
    if !meets_target(&header.hash().0, header.bits) {
        bail!("block hash is above its difficulty target");
    }
    Ok(VerifiedHeader {
        hash: header.hash().0,
        prev: header.prev_block.0,
        time: header.time,
    })
}

/// True if `hash` (internal byte order) is at or below the compact target `bits`.
fn meets_target(hash: &[u8; 32], bits: u32) -> bool {
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x007f_ffff;
    if bits & 0x0080_0000 != 0 || mantissa == 0 || exponent > 32 {
        return false;
    }
    // Build the 256-bit target, big-endian.
    let mut target = [0u8; 32];
    let m = mantissa.to_be_bytes(); // [0, b1, b2, b3]
    for i in 0..3 {
        let pos = 32i32 - exponent as i32 + i as i32;
        if (0..32).contains(&pos) {
            target[pos as usize] = m[1 + i];
        }
    }
    let mut be = *hash;
    be.reverse();
    be <= target
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShieldedTx {
    pub index: usize,
    pub txid: [u8; 32],
    pub sapling_nullifiers: Vec<[u8; 32]>,
    pub sapling_outputs: Vec<NoteData>,
    pub orchard_actions: Vec<ActionData>,
    pub ironwood_actions: Vec<ActionData>,
}

impl ShieldedTx {
    pub fn is_shielded(&self) -> bool {
        !(self.sapling_nullifiers.is_empty()
            && self.sapling_outputs.is_empty()
            && self.orchard_actions.is_empty()
            && self.ironwood_actions.is_empty())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteData {
    pub cmu: [u8; 32],
    pub epk: [u8; 32],
    pub ciphertext: Vec<u8>, // first 52 bytes of enc_ciphertext
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionData {
    pub nullifier: [u8; 32],
    pub cmx: [u8; 32],
    pub epk: [u8; 32],
    pub ciphertext: Vec<u8>,
}

pub const COMPACT_CIPHERTEXT_LEN: usize = 52;

pub struct VerifiedBlock {
    pub height: u32,
    pub header: VerifiedHeader,
    pub txs: Vec<ShieldedTx>,
}

/// Parses and checks a full block that a peer sent for `expected_hash`.
pub fn verify_block(raw: &[u8], expected_hash: &[u8; 32], height: u32) -> Result<VerifiedBlock> {
    let mut cur = Cursor::new(raw);
    let header = BlockHeader::read(&mut cur)?;
    let header_len = cur.position() as usize;
    let vh = verify_header(&raw[..header_len])?;
    if &vh.hash != expected_hash {
        bail!("peer sent a different block than the one asked for");
    }

    let mut pos = header_len;
    let n_tx = read_compact_size(raw, &mut pos)?;
    cur.set_position(pos as u64);
    let branch = BranchId::for_height(&MainNetwork, BlockHeight::from_u32(height));
    let mut txids = Vec::new();
    let mut txs = Vec::new();
    for index in 0..n_tx as usize {
        let start = cur.position() as usize;
        let tx = Transaction::read(&mut cur, branch)?;
        if index == 0 {
            let got = coinbase_height(&raw[start..cur.position() as usize])?;
            if got != height {
                bail!("coinbase says height {got}, expected {height}");
            }
        }
        let txid: [u8; 32] = *tx.txid().as_ref();
        txids.push(txid);
        txs.push(extract(index, txid, &tx));
    }
    if cur.position() as usize != raw.len() {
        bail!("trailing bytes after the last transaction");
    }
    if merkle_root(&txids) != header.merkle_root {
        bail!("merkle root does not match the transactions");
    }
    Ok(VerifiedBlock { height, header: vh, txs })
}

fn extract(index: usize, txid: [u8; 32], tx: &Transaction) -> ShieldedTx {
    let mut out = ShieldedTx { index, txid, ..Default::default() };
    if let Some(b) = tx.sapling_bundle() {
        for s in b.shielded_spends() {
            out.sapling_nullifiers.push(s.nullifier().0);
        }
        for o in b.shielded_outputs() {
            out.sapling_outputs.push(NoteData {
                cmu: o.cmu().to_bytes(),
                epk: o.ephemeral_key().0,
                ciphertext: o.enc_ciphertext()[..COMPACT_CIPHERTEXT_LEN].to_vec(),
            });
        }
    }
    let actions = |b: &orchard::Bundle<_, _>| -> Vec<ActionData> {
        b.actions()
            .iter()
            .map(|a| ActionData {
                nullifier: a.nullifier().to_bytes(),
                cmx: a.cmx().to_bytes(),
                epk: a.encrypted_note().epk_bytes,
                ciphertext: a.encrypted_note().enc_ciphertext.as_ref()[..COMPACT_CIPHERTEXT_LEN]
                    .to_vec(),
            })
            .collect()
    };
    if let Some(b) = tx.orchard_bundle() {
        out.orchard_actions = actions(b);
    }
    if let Some(b) = tx.ironwood_bundle() {
        out.ironwood_actions = actions(b);
    }
    out
}

/// Bitcoin-style merkle root: pairs of txids hashed with SHA-256d, the last
/// one repeated when a level has an odd count.
pub fn merkle_root(txids: &[[u8; 32]]) -> [u8; 32] {
    if txids.is_empty() {
        return [0u8; 32];
    }
    let mut level = txids.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        level = level
            .chunks(2)
            .map(|p| {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&p[0]);
                buf[32..].copy_from_slice(&p[1]);
                dsha256(&buf)
            })
            .collect();
    }
    level[0]
}

/// Reads the BIP 34 height from a raw coinbase transaction.
fn coinbase_height(raw_tx: &[u8]) -> Result<u32> {
    let header = u32::from_le_bytes(raw_tx[..4].try_into()?);
    let version = header & 0x7fff_ffff;
    let overwintered = header >> 31 == 1;
    // v5 and v6 put the transparent bundle after the version group, branch,
    // lock time and expiry; v3 and v4 after the version group id.
    let mut pos = match (overwintered, version) {
        (true, v) if v >= 5 => 20,
        (true, _) => 8,
        (false, _) => 4,
    };
    let n_in = read_compact_size(raw_tx, &mut pos)?;
    if n_in == 0 {
        bail!("coinbase has no input");
    }
    pos += 36; // null outpoint
    let _script_len = read_compact_size(raw_tx, &mut pos)?;
    let push = *raw_tx.get(pos).ok_or_else(|| anyhow!("empty coinbase script"))? as usize;
    if !(1..=4).contains(&push) {
        // Heights 1-16 use small-integer opcodes; mainnet is far past them.
        bail!("unexpected coinbase height encoding");
    }
    let bytes = raw_tx.get(pos + 1..pos + 1 + push).ok_or_else(|| anyhow!("truncated coinbase"))?;
    let mut h = [0u8; 4];
    h[..push].copy_from_slice(bytes);
    Ok(u32::from_le_bytes(h))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real mainnet blocks fetched over P2P. 3,533,761 has Sapling, Orchard
    // and Ironwood activity; 3,533,600 holds only the coinbase.
    pub const BLOCK_3533761: &[u8] = include_bytes!("../tests/fixtures/block-3533761.bin");
    const BLOCK_3533600: &[u8] = include_bytes!("../tests/fixtures/block-3533600.bin");
    // 3,533,755 carries Sapling spends.
    pub const BLOCK_3533755: &[u8] = include_bytes!("../tests/fixtures/block-3533755.bin");

    fn hash_of(raw: &[u8]) -> [u8; 32] {
        BlockHeader::read(raw).unwrap().hash().0
    }

    #[test]
    fn real_blocks_verify() {
        for (raw, h) in [(BLOCK_3533761, 3_533_761), (BLOCK_3533600, 3_533_600)] {
            let b = verify_block(raw, &hash_of(raw), h).expect("real block verifies");
            assert_eq!(b.height, h);
        }
        let b = verify_block(BLOCK_3533761, &hash_of(BLOCK_3533761), 3_533_761).unwrap();
        assert!(b.txs.iter().any(|t| !t.ironwood_actions.is_empty()), "fixture has Ironwood actions");
    }

    #[test]
    fn wrong_height_is_rejected() {
        assert!(verify_block(BLOCK_3533761, &hash_of(BLOCK_3533761), 3_533_760).is_err());
    }

    #[test]
    fn wrong_hash_is_rejected() {
        assert!(verify_block(BLOCK_3533761, &hash_of(BLOCK_3533600), 3_533_761).is_err());
    }

    #[test]
    fn changed_transaction_byte_is_rejected() {
        // Flip a byte near the end, inside the last transaction.
        let mut raw = BLOCK_3533761.to_vec();
        let i = raw.len() - 100;
        raw[i] ^= 1;
        assert!(verify_block(&raw, &hash_of(BLOCK_3533761), 3_533_761).is_err());
    }

    #[test]
    fn bad_equihash_solution_is_rejected() {
        let mut raw = BLOCK_3533761[..1487].to_vec();
        raw[1000] ^= 1;
        assert!(verify_header(&raw).is_err());
        assert!(verify_header(&BLOCK_3533761[..1487]).is_ok());
    }

    #[test]
    fn merkle_root_of_one_txid_is_the_txid() {
        let t = [7u8; 32];
        assert_eq!(merkle_root(&[t]), t);
    }

    #[test]
    fn sapling_spend_block_verifies_with_its_nullifiers() {
        let b = verify_block(BLOCK_3533755, &hash_of(BLOCK_3533755), 3_533_755).unwrap();
        let spends: usize = b.txs.iter().map(|t| t.sapling_nullifiers.len()).sum();
        assert_eq!(spends, 5, "block 3,533,755 has 5 Sapling spends");
    }

    #[test]
    fn every_fixture_header_has_valid_proof_of_work() {
        for raw in [BLOCK_3533600, BLOCK_3533755, BLOCK_3533761] {
            let h = verify_header(&raw[..1487]).unwrap();
            assert_eq!(h.hash, hash_of(raw));
        }
    }

    #[test]
    fn headers_link_to_their_parent() {
        // 3,533,600 and 3,533,761 are far apart; a header's prev is never itself.
        let h = verify_header(&BLOCK_3533761[..1487]).unwrap();
        assert_ne!(h.prev, h.hash);
    }

    #[test]
    fn merkle_root_duplicates_the_last_txid_on_odd_levels() {
        let (a, b, c) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let pair = |x: [u8; 32], y: [u8; 32]| {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&x);
            buf[32..].copy_from_slice(&y);
            dsha256(&buf)
        };
        assert_eq!(merkle_root(&[a, b, c]), pair(pair(a, b), pair(c, c)));
        assert_eq!(merkle_root(&[a, b]), pair(a, b));
    }

    #[test]
    fn target_check_accepts_real_and_rejects_bad_bits() {
        let raw = &BLOCK_3533761[..1487];
        let hd = BlockHeader::read(raw).unwrap();
        assert!(meets_target(&hd.hash().0, hd.bits));
        // An impossible target (exponent 3, mantissa 1) and a negative one.
        assert!(!meets_target(&hd.hash().0, 0x0300_0001));
        assert!(!meets_target(&hd.hash().0, 0x1d80_ffff));
        // An all-zero hash meets any positive target.
        assert!(meets_target(&[0u8; 32], hd.bits));
    }

    #[test]
    fn truncated_block_is_rejected() {
        let raw = &BLOCK_3533761[..BLOCK_3533761.len() - 10];
        assert!(verify_block(raw, &hash_of(BLOCK_3533761), 3_533_761).is_err());
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut raw = BLOCK_3533600.to_vec();
        raw.push(0);
        assert!(verify_block(&raw, &hash_of(BLOCK_3533600), 3_533_600).is_err());
    }

    /// A small deterministic generator, so failures can be reproduced.
    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    /// Since NU5 a txid commits to a transaction's effects (nullifiers, note
    /// commitments, keys, ciphertexts) but not to its signatures and proofs,
    /// which the header commits to through the chain history root. So a flipped
    /// bit may pass only if every field the comparison uses is unchanged.
    #[test]
    fn random_bit_flips_never_change_the_compared_fields_unnoticed() {
        let hash = hash_of(BLOCK_3533761);
        let honest = verify_block(BLOCK_3533761, &hash, 3_533_761).unwrap();
        let mut rng = 0x5eed_u64;
        let (mut rejected, mut auth_only) = (0, 0);
        for _ in 0..2000 {
            let mut raw = BLOCK_3533761.to_vec();
            let i = (xorshift(&mut rng) as usize) % raw.len();
            raw[i] ^= 1u8 << (xorshift(&mut rng) % 8);
            match verify_block(&raw, &hash, 3_533_761) {
                Err(_) => rejected += 1,
                Ok(b) => {
                    assert_eq!(b.txs, honest.txs, "byte {i} changed a compared field and was accepted");
                    auth_only += 1;
                }
            }
        }
        assert_eq!(rejected + auth_only, 2000);
        assert!(rejected > 0);
    }

    #[test]
    fn random_bytes_never_crash_the_parsers() {
        let mut rng = 0xfeed_u64;
        for _ in 0..3000 {
            let len = (xorshift(&mut rng) % 2000) as usize;
            let junk: Vec<u8> = (0..len).map(|_| xorshift(&mut rng) as u8).collect();
            let _ = verify_block(&junk, &[0u8; 32], 3_533_761);
            let _ = verify_header(&junk);
            let mut buf = junk.clone();
            let _ = crate::p2p::parse_message(&mut buf);
            let mut pos = 0;
            let _ = crate::p2p::read_compact_size(&junk, &mut pos);
        }
    }
}
