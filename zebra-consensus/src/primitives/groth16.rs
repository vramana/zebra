//! Async Groth16 batch verifier service

use std::{
    future::Future,
    mem,
    pin::Pin,
    task::{Context, Poll},
};

use futures::future::{ready, Ready};
use once_cell::sync::Lazy;
use rand::thread_rng;
use tokio::sync::broadcast::{channel, RecvError, Sender};
use tower::Service;
use tower_batch::{Batch, BatchControl};
use tower_fallback::Fallback;
use tower_util::ServiceFn;

use bellman::{
    groth16::{batch, PreparedVerifyingKey},
    VerificationError,
};
use pairing::bls12_381::Bls12;

/// A Groth16 verification item, used as the request type of the service.
pub type Item = batch::Item<Bls12>;
pub type Error = VerificationError;

// XXX we'd like to have a similar Fallback as for Redjubjub,
// but it's unclear how to do that without capturing a &PreparedVerifyingKey,
// which prevents us from casting to a function.

pub struct Verifier {
    batch: batch::Verifier<Bls12>,
    // Making this 'static makes managing lifetimes much easier.
    pvk: &'static PreparedVerifyingKey<Bls12>,
    tx: Sender<Result<(), Error>>,
}

impl Verifier {
    fn new(pvk: &'static PreparedVerifyingKey<Bls12>) -> Self {
        let batch = batch::Verifier::default();
        let (tx, _) = channel(super::BROADCAST_BUFFER_SIZE);
        Self { batch, tx, pvk }
    }
}

impl Service<BatchControl<Item>> for Verifier {
    type Response = ();
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: BatchControl<Item>) -> Self::Future {
        match req {
            BatchControl::Item(item) => {
                tracing::trace!("got item");
                self.batch.queue(item);
                let mut rx = self.tx.subscribe();
                Box::pin(async move {
                    match rx.recv().await {
                        Ok(result) => result,
                        Err(RecvError::Lagged(_)) => {
                            tracing::error!(
                                "missed channel updates, BROADCAST_BUFFER_SIZE is too low!!"
                            );
                            Err(Error::InvalidProof)
                        }
                        Err(RecvError::Closed) => panic!("verifier was dropped without flushing"),
                    }
                })
            }

            BatchControl::Flush => {
                tracing::trace!("got flush command");
                let batch = mem::take(&mut self.batch);
                let _ = self.tx.send(batch.verify(thread_rng(), self.pvk));
                Box::pin(async { Ok(()) })
            }
        }
    }
}

impl Drop for Verifier {
    fn drop(&mut self) {
        // We need to flush the current batch in case there are still any pending futures.
        let batch = mem::take(&mut self.batch);
        let _ = self.tx.send(batch.verify(thread_rng(), self.pvk));
    }
}
