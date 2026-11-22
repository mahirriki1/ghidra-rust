//! One serial preparation thread with a replaceable waiting job. Only the
//! desktop owns result adoption, and dropping a receiver discards its result.

use std::sync::{Arc, Condvar, Mutex, mpsc};

type Work = Box<dyn FnOnce() + Send>;
type Slot = Arc<(Mutex<State>, Condvar)>;

#[derive(Default)]
struct State {
    pending: Option<Work>,
    shutdown: bool,
}

#[derive(Default)]
pub(in crate::app) struct Preparation(Option<Slot>);

impl Preparation {
    pub(super) fn submit<T: Send + 'static>(
        &mut self,
        context: &eframe::egui::Context,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> std::io::Result<mpsc::Receiver<T>> {
        if self.0.is_none() {
            let slot = Slot::default();
            let thread = Arc::clone(&slot);
            std::thread::Builder::new()
                .name("decompiler-presentation".into())
                .spawn(move || run(thread))?;
            self.0 = Some(slot);
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        let context = context.clone();
        let (state, wake) = self.0.as_deref().expect("preparation thread");
        let previous = state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .pending
            .replace(Box::new(move || {
                if let Ok(output) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)) {
                    let _ = sender.send(output);
                }
                context.request_repaint();
            }));
        wake.notify_one();
        drop(previous);
        Ok(receiver)
    }

    pub(super) fn cancel(&mut self) {
        if let Some((state, _)) = self.0.as_deref() {
            let previous = state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .pending
                .take();
            drop(previous);
        }
    }
}

impl Drop for Preparation {
    fn drop(&mut self) {
        self.cancel();
        if let Some((state, wake)) = self.0.as_deref() {
            state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .shutdown = true;
            wake.notify_one();
        }
    }
}

fn run(slot: Slot) {
    let (state, wake) = &*slot;
    loop {
        let job = {
            let mut state = wake
                .wait_while(
                    state.lock().unwrap_or_else(|error| error.into_inner()),
                    |state| state.pending.is_none() && !state.shutdown,
                )
                .unwrap_or_else(|error| error.into_inner());
            if state.shutdown {
                return;
            }
            state.pending.take().expect("pending preparation")
        };
        job();
    }
}
