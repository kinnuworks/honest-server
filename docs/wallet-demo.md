# A real wallet behind the proxy

Two wallets, both on Zcash mainnet, both syncing only (nothing was sent): ECC's `zcash-devtool`, unmodified, and Zingo's `zingo-cli`.

## zcash-devtool, stock build

Recorded on Oct 28 2026 around 21:10 UTC with `zcash-devtool` built from github.com/zcash/zcash-devtool at commit `0b3436bb8d23` (Oct 17 2026), with no changes or extra features. It uses a plain connection for `127.0.0.1` on its own.

```bash
honest-server proxy zec.rocks:443 --listen 127.0.0.1:9067
zcash-devtool wallet -w ./w1 init --name demo -i ./id.txt -n main -s 127.0.0.1:9067 --birthday 3533914
zcash-devtool wallet -w ./w1 sync -s 127.0.0.1:9067
```

The proxy ran its start-up check (24 recent blocks against peers, the 2,000 before them through the note trees, both PASS), then served the wallet over Tor:

```
Light-wallet server on http://127.0.0.1:9067, forwarding to zec.rocks:443 (over Tor). Every block in the last 100 is checked against Zcash peers.
verified blocks 3533914-3533929 against Zcash peers
verified blocks 3533930-3533945 against Zcash peers
verified blocks 3533946-3533961 against Zcash peers
verified blocks 3533962-3533974 against Zcash peers
```

Wallet: `Scan complete for range ChainTip(3533914..3533975)`.

The same with `--test-drop-note` on the proxy and a second fresh wallet:

```
Error: code: 'Unrecoverable data loss or corruption', message: "Honest Server refused block 3533929 from the server: transaction a12a184366b6b6a165b54323067ad4c24a3e6dbd6f65e75f8abd89ce2208cce0: Ironwood actions: block has 2, server sent 1"
```

The block on a public explorer: [3,533,929](https://3xpl.com/zcash/block/3533929).

At 22:00 UTC the same normal sync ran again after the proxy started reaching Zcash peers through Tor as well: `Connecting to Zcash peers over Tor...`, start-up check PASS, `verified blocks 3533967-3533982 against Zcash peers`, and the wallet's `Scan complete for range ChainTip(3533967..3534008)`.

## zingo-cli

Recorded on Oct 28 2026 around 19:45 UTC against Zcash mainnet, with Zingo's command-line wallet (`zingo-cli` from zingolib `zingolib_v8.0.0-rc.1`). That release sends every online session through its Nym mixnet; to point it at a local server, it was built with the project's own `nakednet-test-mode` feature (`--no-default-features --features nakednet-test-mode`), and it only synced, never sent.

### 1. Normal sync through the proxy

```bash
honest-server proxy zec.rocks:443 --listen 127.0.0.1:9071
zingo-cli --data-dir ./wallet1 --server http://127.0.0.1:9071 --waitsync height
```

Proxy log (server reached over Tor, found running locally):

```
Light-wallet server on http://127.0.0.1:9071, forwarding to zec.rocks:443 (over Tor). Every block in the last 100 is checked against Zcash peers.
verified blocks 3533869-3533884 against Zcash peers
verified blocks 3533885-3533894 against Zcash peers
verified blocks 3533897-3533897 against Zcash peers
verified blocks 3533898-3533898 against Zcash peers
verified blocks 3533899-3533899 against Zcash peers
```

Wallet: a fresh wallet synced to height 3,533,899.

### 2. The same, with one note removed

```bash
honest-server proxy zec.rocks:443 --listen 127.0.0.1:9072 --test-drop-note
zingo-cli --data-dir ./wallet2 --server http://127.0.0.1:9072 --waitsync height
```

Proxy log:

```
test mode: dropped one Ironwood note from transaction 270445b41542b33b24c2d0c790e3e8d5e824e88f281d3e28a01c6216a985b11e in block 3533810
REFUSED Honest Server refused block 3533810 from the server: transaction 270445b41542b33b24c2d0c790e3e8d5e824e88f281d3e28a01c6216a985b11e: Ironwood actions: block has 2, server sent 1
```

Wallet:

```
error: Sync error.
caused by: server error
caused by: server request failed
caused by: code: 'Unrecoverable data loss or corruption', message: "Honest Server refused block 3533810 from the server: transaction 270445b41542b33b24c2d0c790e3e8d5e824e88f281d3e28a01c6216a985b11e: Ironwood actions: block has 2, server sent 1"
```

The wallet stops and says why, instead of syncing past a block that is missing one of its notes.

The block on a public explorer: [3,533,810](https://3xpl.com/zcash/block/3533810).
