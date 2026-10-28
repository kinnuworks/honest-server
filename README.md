# Honest Server

Catch light servers that lie.

Honest Server checks Zcash light-wallet servers (lightwalletd and Zaino) against full blocks it fetches straight from Zcash peers, and shows any shielded note, nullifier or block a server leaves out, changes or serves late.

A shielded wallet can't see the chain itself. It only decrypts what its server sends, so a server that drops one note hides a payment, and the wallet has no way to notice.

![A real check of zec.rocks, then the same data with one note removed](docs/demo.gif)

**Live table:** https://honest-server.vercel.app

**Try it in 30 seconds** (needs Rust; nothing else):

```bash
cargo install --git https://github.com/kinnuworks/honest-server
honest-server check zec.rocks:443
honest-server check zec.rocks:443 --test-drop-note
```

The first command checks the server for real. The second takes the same real data, removes one shielded note and patches the tree sizes so the chain still adds up, then shows that Honest Server catches it.

`honest-server selftest zec.rocks:443` goes further: it makes every single change it can to the server's real blocks and counts how many the check catches. On 24 mainnet blocks from zec.rocks (3,533,7xx, Oct 28 2026) it tried 1,034 changes across Sapling, Orchard and Ironwood and caught all 1,034.

## What it checks

For each server, over a window of recent blocks (24 by default):

- **Complete.** Every Sapling spend and output and every Orchard and Ironwood action the block contains is in the server's compact block, at the same transaction and position, with the same nullifier, note commitment, ephemeral key and first 52 bytes of ciphertext. Nothing extra appears.
- **Current.** The server's tip matches the chain the peers follow. A server behind by more than three blocks, or on a fork, fails.
- **NU7.** The server's node follows the NU7 upgrade at block 3,543,405. Zebra 6.4 nodes stop at block 3,540,768, and nodes that aren't upgraded fork off at NU7.

Anything it can't confirm shows as "couldn't verify", never as a failure: a server it can't reach, a block two peers won't serve, a server that doesn't say which node it runs.

## Where the reference blocks come from

The reference doesn't depend on any company or API. Honest Server speaks the Zcash peer-to-peer protocol itself and, for every block it compares:

1. asks peers for the block with the hash the server reported;
2. checks the header's Equihash proof of work and difficulty target;
3. parses every transaction with librustzcash (`zcash_primitives` 0.31, which reads v4, v5 and v6 transactions, Ironwood included) and recomputes the merkle root from the transaction IDs;
4. checks the height in the coinbase;
5. counts the block only if two peers serve it and it passes all of the above.

For "Current" it walks the peers' headers forward from the server's last block, verifying each header, until the peers' tip.

## Privacy

The local check (`honest-server check`) talks only to the server you name and to Zcash peers. It sends nothing to us and needs no keys or wallet data.

The public table probes each server over Tor, each on its own circuit, using the calls a wallet makes when it syncs (server info, latest block, a block range). Servers see a Tor exit, not where the check runs.

Pass `--tor 127.0.0.1:9050` to run your own check over Tor too.

## Limits

- It checks a window of recent blocks, not the whole chain.
- The public table probes from one machine. A server that lies only to particular wallets would pass the table; the local check, run from your own connection, is how you catch that.
- It can't see what a server logs about the wallets that connect to it.
- It doesn't test transaction submission, mempool calls or tree states.
- NU7 readiness comes from the node release the server reports (Zebra 7.0.0 and Zakura 1.7.0 are the first that follow NU7). A server can misreport its version.

## Commands

```bash
honest-server check <host:port> [--blocks 24] [--tor 127.0.0.1:9050] [--json] [--test-drop-note]
honest-server table --servers servers.txt --out web/results.json [--tor 127.0.0.1:9050]
honest-server selftest <host:port> [--blocks 24]
honest-server peers
```

`servers.txt` lists the servers Zodl and Zingo ship as defaults plus community servers. `web/` is the static page that shows `results.json`.

## Deploy note

The table needs a machine that can open outbound connections on port 8233 (Zcash peers) and 443 (servers), with Tor running. A scheduled job runs `honest-server table` and publishes `web/`.

## License

MIT
