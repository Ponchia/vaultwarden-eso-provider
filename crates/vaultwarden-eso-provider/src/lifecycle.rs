use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use tokio::sync::Notify;

/// Process lifecycle state. The shutdown channel is a single-consumer latch
/// (the policy reload task), not a broadcast: `notify_one` stores one permit
/// so a late waiter still observes shutdown. Adding more consumers would
/// require `notify_waiters` plus per-waiter ordering handling.
#[derive(Clone)]
pub(crate) struct Lifecycle {
    shutting_down: Arc<AtomicBool>,
    shutdown: Arc<Notify>,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self {
            shutting_down: Arc::new(AtomicBool::new(false)),
            shutdown: Arc::new(Notify::new()),
        }
    }
}

impl Lifecycle {
    pub(crate) fn mark_shutting_down(&self) {
        self.shutting_down.store(true, Ordering::Release);
        // `notify_one` stores a permit if no task is waiting yet, so a waiter
        // that calls `shutdown_requested` later still observes the shutdown.
        self.shutdown.notify_one();
    }

    pub(crate) fn is_ready(&self) -> bool {
        !self.shutting_down.load(Ordering::Acquire)
    }

    /// Resolves once shutdown has been requested. Lets background tasks react
    /// promptly instead of only noticing on their next poll interval.
    pub(crate) async fn shutdown_requested(&self) {
        // Fast path: already shutting down (covers a `mark_shutting_down` that
        // ran before this future was first awaited).
        if !self.is_ready() {
            return;
        }
        self.shutdown.notified().await;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn shutdown_requested_waits_until_marked() {
        let lifecycle = Lifecycle::default();

        let before_shutdown =
            tokio::time::timeout(Duration::from_millis(20), lifecycle.shutdown_requested()).await;
        assert!(
            before_shutdown.is_err(),
            "shutdown_requested must not resolve before shutdown"
        );

        lifecycle.mark_shutting_down();
        assert!(!lifecycle.is_ready());

        let after_shutdown =
            tokio::time::timeout(Duration::from_secs(1), lifecycle.shutdown_requested()).await;
        assert!(
            after_shutdown.is_ok(),
            "shutdown_requested should resolve after shutdown"
        );
    }
}
