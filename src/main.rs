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
        /// Reach the server through a Tor SOCKS proxy, e.g. 127.0.0.1:9050
        #[arg(long)]
        tor: Option<String>,
        /// Check blocks within this many blocks of the tip
        #[arg(long, default_value_t = 100)]
        window: u64,
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
            let route = tor.map(Route::Tor).unwrap_or(Route::Direct);
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
            if r.complete == Status::Fail || r.current == Status::Fail {
                std::process::exit(2);
            }
        }
        Cmd::Selftest { server, blocks } => {
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
                        std::process::exit(2);
                    }
                }
                None => anyhow::bail!("couldn't get verified blocks from {server}"),
            }
        }
        Cmd::Proxy { server, listen, tor, window, strict, test_drop_note } => {
            let route = tor.map(Route::Tor).unwrap_or(Route::Direct);
            eprintln!("Connecting to Zcash peers...");
            let reference = Reference::new(4).await?;
            let upstream = lwd::connect(&server, &route).await?;
            let addr: std::net::SocketAddr = listen.parse()?;
            eprintln!(
                "Light-wallet server on http://{addr}, forwarding to {server} ({}). Recent blocks are checked against Zcash peers.",
                match route { Route::Direct => "direct", Route::Tor(_) => "over Tor" }
            );
            let svc = proxy::Proxy {
                upstream,
                reference: std::sync::Arc::new(tokio::sync::Mutex::new(reference)),
                window,
                strict,
                test_drop_note,
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

fn mark(s: Status) -> &'static str {
    match s {
        Status::Pass => "PASS",
        Status::Fail => "FAIL",
        Status::Unverified => "couldn't verify",
    }
}

fn print_report(r: &CheckResult) {
    println!();
    println!("{} ({})", r.server, r.route);
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
    println!(
        "  NU7       {}  server reports {} at {}",
        mark(r.nu7),
        if r.info.reported_upgrade.is_empty() { "no pending upgrade" } else { &r.info.reported_upgrade },
        r.info.reported_upgrade_height
    );
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
