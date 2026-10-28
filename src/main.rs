mod check;
mod compare;
mod lwd;
mod p2p;
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Check { server, blocks, tor, json } => {
            let route = tor.map(Route::Tor).unwrap_or(Route::Direct);
            eprintln!("Connecting to Zcash peers...");
            let mut reference = Reference::new(8).await?;
            eprintln!("Checking {server}...");
            let r = check::check(&server, &route, blocks, &mut reference).await;
            if json {
                println!("{}", serde_json::to_string_pretty(&r)?);
            } else {
                print_report(&r);
            }
            if r.complete == Status::Fail || r.current == Status::Fail {
                std::process::exit(2);
            }
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
            let test = match base {
                Some(b) => check::test_row(&b, &route, blocks, &mut reference).await,
                None => None,
            };
            let table = Table {
                generated_at: results.first().map(|r| r.checked_at).unwrap_or(0),
                blocks_per_check: blocks,
                peers: reference.peer_summary(),
                servers: results,
                test,
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
    match r.range {
        Some((a, b)) => println!(
            "  Complete  {}  blocks {a}-{b}: {} blocks, {} shielded transactions, {} note commitments and {} nullifiers matched full blocks from Zcash peers",
            mark(r.complete), r.tally.blocks, r.tally.shielded_txs, r.tally.commitments, r.tally.nullifiers
        ),
        None => println!("  Complete  {}", mark(r.complete)),
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
    if let Some(c) = &r.consistency_only {
        println!("  A consistency-only check says: {} ({})", mark(c.status), c.detail);
    }
    for m in r.mismatches.iter().take(20) {
        println!("  MISMATCH block {} tx {} ({}): {}", m.height, m.txid, m.tx_index, m.what);
    }
    if r.mismatches.len() > 20 {
        println!("  ...and {} more mismatches", r.mismatches.len() - 20);
    }
    for n in &r.notes {
        println!("  note: {n}");
    }
}
