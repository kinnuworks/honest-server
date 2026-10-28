mod check;
mod compare;
mod lwd;
mod mutate;
mod p2p;
mod proxy;
mod verify;

use anyhow::Result;
use clap::{Parser, Subcommand};

use check::{CheckResult, Reference, Status};
use lwd::Route;

#[derive(Parser)]
#[command(name = "honest-server", about = "Catch Zcash light servers that lie.")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Check one server from this machine. Talks only to that server and to Zcash peers.
    Check {
        /// Server as host:port, e.g. zec.rocks:443
        server: String,
        /// How many recent blocks to compare
        #[arg(long, default_value_t = 24)]
        blocks: u64,
        /// Reach the server through a Tor SOCKS proxy, e.g. 127.0.0.1:9050
        #[arg(long)]
        tor: Option<String>,
        /// Print JSON instead of the readable report
        #[arg(long)]
        json: bool,
        /// Test mode: remove one real shielded note from the server's answer
        /// (and patch the tree sizes) to show what a lying server looks like
        #[arg(long)]
        test_drop_note: bool,
    },
    /// Run a light-wallet server on this machine for your wallet. It forwards
    /// everything to `server` and refuses recent blocks that don't match the
    /// verified blocks from Zcash peers.
    Proxy {
        /// The real server, e.g. zec.rocks:443
        server: String,
        #[arg(long, default_value = "127.0.0.1:9067")]
        listen: String,
        /// Tor SOCKS proxy to reach the server through (default: 127.0.0.1:9050 if it's running)
        #[arg(long)]
        tor: Option<String>,
        /// Connect to the server directly, without Tor
        #[arg(long)]
        direct: bool,
        /// Check every block within this many blocks of the tip
        #[arg(long, default_value_t = 100)]
        window: u64,
        /// Also check older blocks at random, about one in this many (off by
        /// default: peers would see which older heights the wallet syncs)
        #[arg(long, default_value_t = 0)]
        sample: u64,
        /// Also refuse blocks that two peers couldn't confirm
        #[arg(long)]
        strict: bool,
        /// Test mode: drop one real note before checking, to see a refusal
        #[arg(long)]
        test_drop_note: bool,
    },
    /// List the Zcash peers the reference blocks would come from.
    Peers,
    /// Self-test on live data: change every field of every shielded note in
    /// the server's real blocks, one at a time, and count how many are caught.
    Selftest {
        server: String,
        #[arg(long, default_value_t = 24)]
        blocks: u64,
    },
    /// Check a list of servers and write the public table as JSON.
    Table {
        /// File with one host:port per line ("# label" comments allowed)
        #[arg(long, default_value = "servers.txt")]
        servers: String,
        #[arg(long, default_value = "web/results.json")]
        out: String,
        #[arg(long, default_value_t = 24)]
        blocks: u64,
        #[arg(long)]
        tor: Option<String>,
    },
}

#[derive(serde::Serialize)]
struct Table {
    generated_at: u64,
    blocks_per_check: u64,
    peers: Vec<String>,
    servers: Vec<CheckResult>,
    test: Option<CheckResult>,
    selftest: Option<SelftestSummary>,
}

#[derive(serde::Serialize)]
struct SelftestSummary {
    server: String,
    report: mutate::MutationReport,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Check { server, blocks, tor, json, test_drop_note } => {
            let blocks = clamp_window(blocks);
            let route = tor.map(Route::Tor).unwrap_or(Route::Direct);
            // Reach the server first, so a wrong address fails in seconds.
            eprintln!("Reaching {server}...");
            if let Err(e) = lwd::reach(&server, &route).await {
                eprintln!("{e}");
                std::process::exit(3);
            }
            eprintln!("Connecting to Zcash peers...");
            let mut reference = Reference::new(4).await?;
            eprintln!("Checking {server}...");
            let r = if test_drop_note {
                match check::test_row(&server, &route, blocks, &mut reference).await {
                    Some(r) => r,
                    None => anyhow::bail!("couldn't build the test: no shielded notes in the window"),
                }
            } else {
                check::check(&server, &route, blocks, &mut reference).await
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&r)?);
            } else {
                print_report(&r);
            }
            std::process::exit(exit_code(&r));
        }
        Cmd::Selftest { server, blocks } => {
            let blocks = clamp_window(blocks);
            eprintln!("Connecting to Zcash peers...");
            let mut reference = Reference::new(4).await?;
            eprintln!("Changing real blocks from {server}...");
            match check::selftest(&server, &Route::Direct, blocks, &mut reference).await {
                Some(r) => {
                    println!("{} blocks, {} single changes tried, {} caught", r.blocks, r.tried, r.caught);
                    for (kind, (t, c)) in &r.by_kind {
                        println!("  {kind:<36} {c} of {t} caught");
                    }
                    for m in &r.missed {
                        println!("  MISSED {m}");
                    }
                    if r.caught != r.tried {
                        std::process::exit(1);
                    }
                }
                None => anyhow::bail!("couldn't get verified blocks from {server}"),
            }
        }
        Cmd::Proxy { server, listen, tor, direct, window, sample, strict, test_drop_note } => {
            // Tor by default: use the given proxy, or a local Tor if one is running.
            let route = if direct {
                Route::Direct
            } else if let Some(t) = tor {
                Route::Tor(t)
            } else if tokio::net::TcpStream::connect("127.0.0.1:9050").await.is_ok() {
                Route::Tor("127.0.0.1:9050".into())
            } else {
                eprintln!("No Tor found at 127.0.0.1:9050, so the server will see this machine's IP. Start Tor, or pass --direct to silence this.");
                Route::Direct
            };
            if sample > 0 {
                // Peers are reached directly (Tor exits don't carry port 8233), so
                // fetching the wallet's older blocks shows peers roughly which heights it syncs.
                eprintln!("Spot-checking about one in {sample} older blocks. Zcash peers will see which older heights this machine fetches.");
            }
            let upstream = match lwd::connect(&server, &route).await {
                Ok(u) => u,
                Err(e) => {
                    eprintln!("{}", lwd::plain_error(&server, &e));
                    std::process::exit(3);
                }
            };
            eprintln!("Connecting to Zcash peers...");
            let reference = Reference::new(4).await?;
            let addr: std::net::SocketAddr = listen.parse()?;
            eprintln!(
                "Light-wallet server on http://{addr}, forwarding to {server} ({}). Every block in the last {window} is checked against Zcash peers.",
                match route { Route::Direct => "direct", Route::Tor(_) => "over Tor" }
            );
            let svc = proxy::Proxy {
                upstream,
                reference: std::sync::Arc::new(tokio::sync::Mutex::new(reference)),
                window,
                strict,
                test_drop_note,
                sample,
                secret: p2p::dsha256(&std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
                    .to_le_bytes()),
            };
            tonic::transport::Server::builder()
                .add_service(lwd::rpc::compact_tx_streamer_server::CompactTxStreamerServer::new(svc).max_decoding_message_size(64 * 1024 * 1024))
                .serve(addr)
                .await?;
        }
        Cmd::Peers => {
            let all = p2p::connect_peers(30, 0).await;
            for p in &all {
                let ready = if p.version >= 170_190 { "NU7-ready" } else { "not NU7-ready" };
                println!("{} {} protocol {} height {} ({ready})", p.addr, p.user_agent, p.version, p.start_height);
            }
            println!("{} peers answered", all.len());
        }
        Cmd::Table { servers, out, blocks, tor } => {
            let route = tor.map(Route::Tor).unwrap_or(Route::Direct);
            let list: Vec<String> = std::fs::read_to_string(&servers)?
                .lines()
                .map(|l| l.split('#').next().unwrap_or("").trim().to_string())
                .filter(|l| !l.is_empty())
                .collect();
            let mut reference = Reference::new(10).await?;
            let mut results = Vec::new();
            for s in &list {
                eprintln!("Checking {s}...");
                let r = check::check(s, &route, blocks, &mut reference).await;
                print_report(&r);
                results.push(r);
            }
            let base = results
                .iter()
                .find(|r| r.complete == Status::Pass)
                .map(|r| r.server.clone());
            let test = match &base {
                Some(b) => check::test_row(b, &route, blocks, &mut reference).await,
                None => None,
            };
            let selftest = match &base {
                Some(b) => check::selftest(b, &route, blocks, &mut reference)
                    .await
                    .map(|report| SelftestSummary { server: b.clone(), report }),
                None => None,
            };
            let table = Table {
                generated_at: results.first().map(|r| r.checked_at).unwrap_or(0),
                blocks_per_check: blocks,
                peers: reference.peer_summary(),
                servers: results,
                test,
                selftest,
            };
            if let Some(dir) = std::path::Path::new(&out).parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(&out, serde_json::to_string_pretty(&table)?)?;
            eprintln!("Wrote {out}");
        }
    }
    Ok(())
}

/// Zcash nodes cap how many blocks one address may download, so a check
/// covers at most this many recent blocks.
const MAX_WINDOW: u64 = 60;

fn clamp_window(blocks: u64) -> u64 {
    if blocks > MAX_WINDOW {
        eprintln!("Zcash peers limit how many blocks one address can download, so this checks the latest {MAX_WINDOW} blocks.");
        MAX_WINDOW
    } else {
        blocks.max(2)
    }
}

/// 0 when every check passes, 1 when any fails, 3 when something couldn't
/// be verified and nothing failed.
fn exit_code(r: &CheckResult) -> i32 {
    let all = [r.complete, r.current, r.nu7];
    if all.contains(&Status::Fail) {
        1
    } else if all.contains(&Status::Unverified) {
        3
    } else {
        0
    }
}

fn mark(s: Status) -> &'static str {
    match s {
        Status::Pass => "PASS",
        Status::Fail => "FAIL",
        Status::Unverified => "couldn't verify",
    }
}

fn print_report(r: &CheckResult) {
    println!();
    println!("{}{}", r.server, if r.route == "test" { String::new() } else { format!(" ({})", r.route) });
    if !r.info.software.is_empty() {
        println!("  server: {}, node {}, tip {}", r.info.software, r.info.node, r.server_tip);
    }
    if let Some(c) = &r.consistency_only {
        println!("  A consistency-only check says: {} ({})", mark(c.status), c.detail);
    }
    match r.range {
        Some((a, b)) => {
            println!("  Complete  {}  blocks {a}-{b}, compared with full blocks from Zcash peers", mark(r.complete));
            println!(
                "                  {} shielded transactions, {} note commitments, {} nullifiers matched{}",
                r.tally.shielded_txs,
                r.tally.commitments,
                r.tally.nullifiers,
                match r.mismatches.len() {
                    0 => String::new(),
                    1 => "; 1 mismatch".to_string(),
                    n => format!("; {n} mismatches"),
                }
            );
        }
        None => println!("  Complete  {}", mark(r.complete)),
    }
    if let Some(x) = &r.exits {
        println!("  Exits     {} of {} Tor exits got blocks that match the verified ones", x.matched, x.exits);
    }
    match r.network_tip {
        Some(t) => println!("  Current   {}  server tip {}, network tip {t}", mark(r.current), r.server_tip),
        None => println!("  Current   {}", mark(r.current)),
    }
    if r.info.software.is_empty() {
        println!("  NU7       {}", mark(r.nu7));
    } else if r.info.reported_upgrade.is_empty() {
        println!("  NU7       {}  server reports no upcoming upgrade", mark(r.nu7));
    } else {
        println!("  NU7       {}  server reports {} at {}", mark(r.nu7), r.info.reported_upgrade, r.info.reported_upgrade_height);
    }
    for m in r.mismatches.iter().take(20) {
        println!("  MISMATCH  block {}, tx {}...: {}", m.height, &m.txid[..16], m.what);
    }
    if r.mismatches.len() > 20 {
        println!("  ...and {} more mismatches", r.mismatches.len() - 20);
    }
    for n in &r.notes {
        println!("  note: {n}");
    }
}
