# Honest Server

Catch light servers that lie.

Honest Server checks Zcash light-wallet servers (lightwalletd and Zaino) against full blocks it fetches straight from Zcash peers, and shows any shielded note, nullifier or block a server leaves out, changes or serves late. For the 2,000 blocks before those, it rebuilds the server's note commitment trees and checks them against the anchors real transactions use.

A shielded wallet can't see the chain itself. It only decrypts what its server sends, so a server that drops one note hides a payment, and the wallet has no way to notice.

![A real check of zec.rocks, then the same data with one note removed](docs/demo.gif)

**Live table:** https://honest-server.vercel.app

**Try it in 30 seconds.** Download a binary for Linux or macOS from [Releases](https://github.com/kinnuworks/honest-server/releases/latest), or build it (needs Rust, nothing else):

```bash
cargo install --git https://github.com/kinnuworks/honest-server
honest-server check zec.rocks:443
honest-server check zec.rocks:443 --test-drop-note
```

The first command checks the server for real. The second takes the same real data, removes one shielded note from the recent blocks and patches the tree sizes so the chain still adds up, then removes one from about 1,000 blocks earlier, and shows that Honest Server catches both.

`honest-server selftest zec.rocks:443` goes further: it makes every single change it can to the server's real blocks and counts how many the check catches. In the hourly run of Oct 28 2026 at 19:40 UTC (the one in the demo video), it tried 1,358 changes to 24 mainnet blocks across Sapling, Orchard and Ironwood (Zcash's three shielded pools) and caught all 1,358. The number changes every run, because it depends on how many notes the latest blocks hold; the live page shows the newest count.

## Protect your wallet

`honest-server proxy` runs a light-wallet server on your own machine. Point your wallet's custom server setting at it (the wallet has to accept a plain local address such as `http://127.0.0.1:9067`):

```bash
honest-server proxy zec.rocks:443
```

It forwards every call to the real server over Tor whenever a Tor proxy is running on `127.0.0.1:9050` (or the one you name with `--tor`), so the server sees a Tor exit instead of your IP. If no Tor is running it says so and connects directly; `--direct` skips Tor on purpose. At start-up it runs the full check once, the 2,000 earlier blocks included, through the same route, and won't start if the server fails it. Over Tor the server can't tell that check from your wallet's own calls. Before it hands your wallet any block from the last 100, it checks the block against the verified blocks from Zcash peers, in batches of 16. A block that doesn't match is refused, and your wallet gets an error naming the block, the transaction and the field, instead of silently missing a payment. When your wallet asks for one of its own transactions, to read the memo, the proxy answers from the verified peer blocks if the transaction is in one, so the server never sees which transactions are yours (for older ones it still has to ask the server). `--strict` also refuses blocks that two peers couldn't confirm. `--test-drop-note` removes one real note before the check, so you can see a refusal:

```
REFUSED Honest Server refused block 3533812 from the server: transaction 1df0be5bbff4d19c...: Ironwood actions: block has 2, server sent 1
```

Tested with two real wallets on mainnet. ECC's `zcash-devtool`, a stock build that takes `-s 127.0.0.1:9067` as it is, synced a fresh wallet through the proxy over Tor; with `--test-drop-note` its sync stopped with the proxy's refusal ("Ironwood actions: block has 2, server sent 1"). Zingo's `zingo-cli` did the same, built with its test feature because its release forces the Nym mixnet. Both transcripts are in [docs/wallet-demo.md](docs/wallet-demo.md).

While the wallet syncs, older blocks, outside the window, pass through unchecked unless you ask for spot checks: `--sample 50` checks about one in 50, chosen by a secret the proxy picks at start-up, so the server can't tell which of its blocks will be checked. It's off by default because peers would see which older heights you fetch (see Privacy).

## What it checks

For each server, over a window of recent blocks (24 by default):

- **Complete.** Every Sapling spend and output and every Orchard and Ironwood action the block contains is in the server's compact block, at the same transaction and position, with the same nullifier, note commitment, ephemeral key and first 52 bytes of ciphertext. Nothing extra appears.
- **History.** For the 2,000 blocks before the window (about 1.7 days; `--history` sets it), it rebuilds the Sapling, Orchard and Ironwood note commitment trees from the server's own compact blocks, starting from the server's tree state. The rebuilt root has to equal the server's own tree state at the end of the range. It also has to match an anchor: the tree root that a transaction in the verified window proves its spends against. Consensus only accepts real roots as anchors, so one match proves every note commitment the server sent up to that block, and one note left out, added or changed anywhere changes every later root. On zec.rocks on Oct 28 2026 that was 759 Sapling, 339 Orchard and 20,274 Ironwood notes, with Sapling and Ironwood matching real anchors. It takes about 9 seconds.
- **Current.** The server's tip matches the chain the peers follow. A server behind by more than three blocks, or on a fork, fails.
- **NU7.** The server's node follows NU7, the next Zcash network upgrade, at block 3,543,405. Zebra 6.4 nodes stop at block 3,540,768, and nodes that aren't upgraded fork off at NU7.

Anything it can't confirm shows as "couldn't verify", never as a failure: a server it can't reach, a block two peers won't serve, a server that doesn't say which node it runs.

## Where the reference blocks come from

The reference doesn't depend on any company or API. Honest Server speaks the Zcash peer-to-peer protocol itself and, for every block it compares:

1. asks peers for the block with the hash the server reported;
2. checks the header's Equihash proof of work and difficulty target;
3. parses every transaction with librustzcash (`zcash_primitives` 0.31, which reads v4, v5 and v6 transactions, Ironwood included) and recomputes the merkle root from the transaction IDs;
4. checks the height in the coinbase;
5. counts the block only if two peers serve it, both copies pass all of the above, and they agree on every field it uses, anchors included.

For "Current" it walks the peers' headers forward from the server's last block, verifying each header, until the peers' tip.

## Privacy

Who sees what:

- **The light server you check** sees a Tor exit when you pass `--tor` (and, for the proxy, whenever Tor is running locally). Without Tor it sees your IP, as it would for any wallet. It sees the same calls a wallet makes to sync: server info, latest block, a block range, tree states. Behind the proxy it doesn't see your wallet ask for its own transactions in recent blocks; those come from the peer blocks.
- **Zcash peers** see your IP fetching recent blocks, the same as any node that syncs. Tor exits generally don't carry Zcash's port 8233, so peers are reached directly. The tool announces itself with the user agent of the most common node release (`/Zebra:7.0.0/`), so peers can't pick it out from ordinary nodes. With `--sample`, the proxy also fetches some of your wallet's older blocks from peers, which shows them roughly which heights you sync, so it's off by default.
- **Us:** the local check and the proxy send nothing to us. They need no keys, addresses or wallet data.
- **The public table** probes each server over Tor through three exits and publishes no IP addresses. The web page loads nothing from third parties: no analytics, fonts served from the site itself.

## Limits

- It compares a window of recent blocks field by field (24 by default, 60 at most). Zcash nodes cap how many blocks one address can download, so bigger windows from one machine stall. The 2,000 blocks before the window are checked through the note trees, which catches a note left out, added or changed, but not a changed nullifier or ciphertext. Older blocks aren't checked.
- From transaction version 6, anchors are authorizing data that the transaction IDs don't commit to. The history check trusts an anchor only when two peers send the same block with the same anchor. It fails a server only when the server's notes contradict its own tree state, which doesn't depend on anchors.
- The public table probes from one machine through three Tor exits per server. A server that singles out one particular wallet (by its address or its sync pattern) could still pass; the local check, run from your own connection, is how you catch that.
- It can't see what a server logs about the wallets that connect to it. The proxy keeps the server from learning your recent transactions, but a wallet's other calls (transparent address lookups, sending) still go to the server.
- It doesn't test transaction submission or mempool calls. It reads tree states only for the history check.
- It doesn't verify signatures or proofs. Since NU5 a transaction ID commits to what a transaction does (nullifiers, commitments, keys, ciphertexts), which is what compact blocks carry and what Honest Server compares; signatures and proofs are committed through the chain history root, which it doesn't track. A test flips 2,000 random bits in a real block: every flip that changes a compared field is rejected.
- NU7 readiness comes from the node release the server reports (Zebra 7.0.0 and Zakura 1.7.0 are the first that follow NU7). A server can misreport its version.

## Tests

46 tests run in CI on Linux and macOS, on three real mainnet blocks (3,533,600, 3,533,755 with Sapling spends, 3,533,761 with Ironwood actions): blocks verify; a wrong height, hash, transaction byte, trailing byte or Equihash solution is rejected; every kind of change to a compact block is caught; the P2P message parser rejects bad checksums, other networks and oversized messages; the NU7 rule follows node releases; the note trees rebuilt from real tree states and a real block match the real tree state, and one missing note changes the root; the proxy answers a request for a transaction in a verified block from that block, in either byte order, and sends anything else to the server. A second CI job runs `check` and `selftest` against a real server and real peers on every push.

## Exit codes

`check` exits 0 when every check passes, 1 when any check fails, and 3 when something couldn't be verified and nothing failed (including a server it can't reach). `selftest` exits 1 if any change slips through.

## Commands

```bash
honest-server check <host:port> [--blocks 24] [--tor 127.0.0.1:9050] [--json] [--test-drop-note]
honest-server table --servers servers.txt --out web/results.json [--tor 127.0.0.1:9050]
honest-server selftest <host:port> [--blocks 24]
honest-server proxy <host:port> [--listen 127.0.0.1:9067] [--tor 127.0.0.1:9050 | --direct] [--window 100] [--sample 50] [--strict] [--test-drop-note]
honest-server peers
```

`servers.txt` lists the servers Zodl and Zingo ship as defaults plus community servers. `web/` is the static page that shows `results.json`.

## Deploy note

The table needs a machine that can open outbound connections on port 8233 (Zcash peers) and 443 (servers), with Tor running. A scheduled job runs `honest-server table` and publishes `web/`.

## License

MIT
