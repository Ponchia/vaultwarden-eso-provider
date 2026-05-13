use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[derive(Clone, Default)]
pub(crate) struct Lifecycle {
    shutting_down: Arc<AtomicBool>,
}

impl Lifecycle {
    pub(crate) fn mark_shutting_down(&self) {
        self.shutting_down.store(true, Ordering::Release);
    }

    pub(crate) fn is_ready(&self) -> bool {
        !self.shutting_down.load(Ordering::Acquire)
    }
}
