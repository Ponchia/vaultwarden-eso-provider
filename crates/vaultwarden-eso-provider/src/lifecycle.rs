use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use tokio::sync::Notify;

/// Process lifecycle state. Shutdown is a broadcast to every background task.
/// The atomic state makes the notification durable for late waiters.
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
        self.shutdown.notify_waiters();
    }

    pub(crate) fn is_ready(&self) -> bool {
        !self.shutting_down.load(Ordering::Acquire)
    }

    /// Resolves once shutdown has been requested. Lets background tasks react
    /// promptly instead of only noticing on their next poll interval.
    pub(crate) async fn shutdown_requested(&self) {
        // Register before checking the atomic state. This closes the race where
        // shutdown begins after the check but before the future starts waiting.
        let notified = self.shutdown.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if !self.is_ready() {
            return;
        }
        notified.await;
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

    #[tokio::test]
    async fn shutdown_wakes_every_registered_consumer() {
        let lifecycle = Lifecycle::default();
        let first_lifecycle = lifecycle.clone();
        let second_lifecycle = lifecycle.clone();
        let first = tokio::spawn(async move {
            first_lifecycle.shutdown_requested().await;
        });
        let second = tokio::spawn(async move {
            second_lifecycle.shutdown_requested().await;
        });
        tokio::task::yield_now().await;

        lifecycle.mark_shutting_down();

        let joined = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(first, second)
        })
        .await;
        let Ok((first_result, second_result)) = joined else {
            unreachable!("all shutdown consumers should wake promptly");
        };
        assert!(first_result.is_ok());
        assert!(second_result.is_ok());
    }
}
