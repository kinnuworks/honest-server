# A real wallet behind the proxy

Recorded on Oct 28 2026 around 19:45 UTC against Zcash mainnet, with Zingo's command-line wallet (`zingo-cli` from zingolib `zingolib_v8.0.0-rc.1`). That release sends every online session through its Nym mixnet; to point it at a local server, it was built with the project's own `nakednet-test-mode` feature (`--no-default-features --features nakednet-test-mode`), and it only synced, never sent.

## 1. Normal sync through the proxy

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

## 2. The same, with one note removed

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
