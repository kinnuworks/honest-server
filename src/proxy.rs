//! A light-wallet server for your own machine. It forwards everything to a
//! real server (over Tor if asked) and checks the recent blocks it hands to
//! the wallet against verified blocks from Zcash peers. A block that doesn't
//! match is refused, so the wallet never sees it.

use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status, Streaming};

use crate::check::Reference;
use crate::compare;
use crate::lwd::rpc::{self, compact_tx_streamer_server::CompactTxStreamer, CompactBlock};
use crate::lwd::Client;

type Out<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

/// Blocks verified together in one round of peer requests.
const BATCH: usize = 16;

pub struct Proxy {
    pub upstream: Client,
    pub reference: Arc<Mutex<Reference>>,
    /// Verify blocks within this many blocks of the server's tip.
    pub window: u64,
    /// Refuse blocks the peers couldn't confirm, not only ones that differ.
    pub strict: bool,
    /// Test mode: drop one shielded note from each batch before checking it.
    pub test_drop_note: bool,
}

impl Proxy {
    fn up(&self) -> Client {
        self.upstream.clone()
    }

    async fn verify_from(&self) -> Result<u64, Status> {
        let tip = self.up().get_latest_block(rpc::ChainSpec {}).await?.into_inner().height;
        Ok(tip.saturating_sub(self.window))
    }
}

/// Verifies a batch of blocks and returns them, or the reason to refuse.
async fn check_batch(
    reference: &Mutex<Reference>,
    mut blocks: Vec<CompactBlock>,
    strict: bool,
    test_drop_note: bool,
) -> Result<Vec<CompactBlock>, Status> {
    if test_drop_note {
        if let Some((altered, desc)) = compare::drop_one_note(&blocks) {
            eprintln!("test mode: {desc}");
            blocks = altered;
        }
    }
    let wanted: Vec<(u64, [u8; 32])> = blocks
        .iter()
        .filter_map(|b| b.hash.as_slice().try_into().ok().map(|h| (b.height, h)))
        .collect();
    let mut reference = reference.lock().await;
    reference.fetch(&wanted).await;
    let mut unverified = 0;
    for b in &blocks {
        match reference.compare(b) {
            Some(m) if !m.is_empty() => {
                let first = &m[0];
                let msg = format!(
                    "Honest Server refused block {} from the server: transaction {}: {}",
                    first.height, first.txid, first.what
                );
                eprintln!("REFUSED {msg}");
                return Err(Status::data_loss(msg));
            }
            Some(_) => {}
            None if strict => {
                let msg = format!("Honest Server couldn't verify block {} with two Zcash peers", b.height);
                eprintln!("REFUSED {msg}");
                return Err(Status::unavailable(msg));
            }
            None => unverified += 1,
        }
    }
    let (a, z) = (blocks.first().map(|b| b.height).unwrap_or(0), blocks.last().map(|b| b.height).unwrap_or(0));
    if unverified == 0 {
        eprintln!("verified blocks {a}-{z} against Zcash peers");
    } else {
        eprintln!("blocks {a}-{z}: {unverified} couldn't be verified, passed on");
    }
    Ok(blocks)
}

#[tonic::async_trait]
impl CompactTxStreamer for Proxy {
    async fn get_latest_block(&self, r: Request<rpc::ChainSpec>) -> Result<Response<rpc::BlockId>, Status> {
        self.up().get_latest_block(r.into_inner()).await
    }
    async fn get_block_nullifiers(&self, r: Request<rpc::BlockId>) -> Result<Response<CompactBlock>, Status> {
        self.up().get_block_nullifiers(r.into_inner()).await
    }
    async fn get_transaction(&self, r: Request<rpc::TxFilter>) -> Result<Response<rpc::RawTransaction>, Status> {
        self.up().get_transaction(r.into_inner()).await
    }
    async fn send_transaction(&self, r: Request<rpc::RawTransaction>) -> Result<Response<rpc::SendResponse>, Status> {
        self.up().send_transaction(r.into_inner()).await
    }
    async fn get_taddress_balance(&self, r: Request<rpc::AddressList>) -> Result<Response<rpc::Balance>, Status> {
        self.up().get_taddress_balance(r.into_inner()).await
    }
    async fn get_tree_state(&self, r: Request<rpc::BlockId>) -> Result<Response<rpc::TreeState>, Status> {
        self.up().get_tree_state(r.into_inner()).await
    }
    async fn get_latest_tree_state(&self, r: Request<rpc::Empty>) -> Result<Response<rpc::TreeState>, Status> {
        self.up().get_latest_tree_state(r.into_inner()).await
    }
    async fn get_address_utxos(&self, r: Request<rpc::GetAddressUtxosArg>) -> Result<Response<rpc::GetAddressUtxosReplyList>, Status> {
        self.up().get_address_utxos(r.into_inner()).await
    }
    async fn get_lightd_info(&self, r: Request<rpc::Empty>) -> Result<Response<rpc::LightdInfo>, Status> {
        self.up().get_lightd_info(r.into_inner()).await
    }
    async fn get_standard_fee(&self, r: Request<rpc::Empty>) -> Result<Response<rpc::StandardFee>, Status> {
        self.up().get_standard_fee(r.into_inner()).await
    }
    async fn ping(&self, r: Request<rpc::Duration>) -> Result<Response<rpc::PingResponse>, Status> {
        self.up().ping(r.into_inner()).await
    }
    type GetBlockRangeNullifiersStream = Out<CompactBlock>;
    async fn get_block_range_nullifiers(&self, r: Request<rpc::BlockRange>) -> Result<Response<Self::GetBlockRangeNullifiersStream>, Status> {
        let s = self.up().get_block_range_nullifiers(r.into_inner()).await?.into_inner();
        Ok(Response::new(Box::pin(s)))
    }
    type GetTaddressTxidsStream = Out<rpc::RawTransaction>;
    async fn get_taddress_txids(&self, r: Request<rpc::TransparentAddressBlockFilter>) -> Result<Response<Self::GetTaddressTxidsStream>, Status> {
        let s = self.up().get_taddress_txids(r.into_inner()).await?.into_inner();
        Ok(Response::new(Box::pin(s)))
    }
    type GetTaddressTransactionsStream = Out<rpc::RawTransaction>;
    async fn get_taddress_transactions(&self, r: Request<rpc::TransparentAddressBlockFilter>) -> Result<Response<Self::GetTaddressTransactionsStream>, Status> {
        let s = self.up().get_taddress_transactions(r.into_inner()).await?.into_inner();
        Ok(Response::new(Box::pin(s)))
    }
    type GetMempoolTxStream = Out<rpc::CompactTx>;
    async fn get_mempool_tx(&self, r: Request<rpc::GetMempoolTxRequest>) -> Result<Response<Self::GetMempoolTxStream>, Status> {
        let s = self.up().get_mempool_tx(r.into_inner()).await?.into_inner();
        Ok(Response::new(Box::pin(s)))
    }
    type GetMempoolStreamStream = Out<rpc::RawTransaction>;
    async fn get_mempool_stream(&self, r: Request<rpc::Empty>) -> Result<Response<Self::GetMempoolStreamStream>, Status> {
        let s = self.up().get_mempool_stream(r.into_inner()).await?.into_inner();
        Ok(Response::new(Box::pin(s)))
    }
    type GetSubtreeRootsStream = Out<rpc::SubtreeRoot>;
    async fn get_subtree_roots(&self, r: Request<rpc::GetSubtreeRootsArg>) -> Result<Response<Self::GetSubtreeRootsStream>, Status> {
        let s = self.up().get_subtree_roots(r.into_inner()).await?.into_inner();
        Ok(Response::new(Box::pin(s)))
    }
    type GetAddressUtxosStreamStream = Out<rpc::GetAddressUtxosReply>;
    async fn get_address_utxos_stream(&self, r: Request<rpc::GetAddressUtxosArg>) -> Result<Response<Self::GetAddressUtxosStreamStream>, Status> {
        let s = self.up().get_address_utxos_stream(r.into_inner()).await?.into_inner();
        Ok(Response::new(Box::pin(s)))
    }

    async fn get_taddress_balance_stream(&self, r: Request<Streaming<rpc::Address>>) -> Result<Response<rpc::Balance>, Status> {
        let inbound = r.into_inner().filter_map(|a| a.ok());
        self.up().get_taddress_balance_stream(inbound).await
    }

    async fn get_block(&self, r: Request<rpc::BlockId>) -> Result<Response<CompactBlock>, Status> {
        let b = self.up().get_block(r.into_inner()).await?.into_inner();
        if b.height >= self.verify_from().await? {
            let mut checked = check_batch(&self.reference, vec![b], self.strict, false).await?;
            return Ok(Response::new(checked.remove(0)));
        }
        Ok(Response::new(b))
    }

    type GetBlockRangeStream = Out<CompactBlock>;
    async fn get_block_range(&self, r: Request<rpc::BlockRange>) -> Result<Response<Self::GetBlockRangeStream>, Status> {
        let from = self.verify_from().await?;
        let mut upstream = self.up().get_block_range(r.into_inner()).await?.into_inner();
        let (tx, rx) = mpsc::channel(64);
        let reference = self.reference.clone();
        let (strict, test, window) = (self.strict, self.test_drop_note, self.window);
        tokio::spawn(async move {
            let mut batch: Vec<CompactBlock> = Vec::new();
            let mut passed = 0u64;
            loop {
                let next = upstream.next().await;
                let done = !matches!(next, Some(Ok(_)));
                match next {
                    Some(Ok(b)) if b.height >= from => batch.push(b),
                    Some(Ok(b)) => {
                        passed += 1;
                        if tx.send(Ok(b)).await.is_err() {
                            return;
                        }
                    }
                    Some(Err(e)) => {
                        let _ = tx.send(Err(e)).await;
                        return;
                    }
                    None => {}
                }
                if batch.len() >= BATCH || (done && !batch.is_empty()) {
                    match check_batch(&reference, std::mem::take(&mut batch), strict, test).await {
                        Ok(ok) => {
                            for b in ok {
                                if tx.send(Ok(b)).await.is_err() {
                                    return;
                                }
                            }
                        }
                        Err(e) => {
                            let _ = tx.send(Err(e)).await;
                            return;
                        }
                    }
                }
                if done {
                    break;
                }
            }
            if passed > 0 {
                eprintln!("passed on {passed} older blocks without checking (outside the last {window})");
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}
