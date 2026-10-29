// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use envoy_proxy_dynamic_modules_rust_sdk::EnvoyHttpFilterScheduler;
use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::Instant,
};

#[derive(Default)]
struct Queue {
    deadlines: BTreeMap<(Instant, u64), Arc<dyn EnvoyHttpFilterScheduler>>,
    streams: HashMap<u64, Instant>,
    stop: bool,
}

pub struct Timer {
    inner: Arc<(Mutex<Queue>, Condvar)>,
    thread: Option<JoinHandle<()>>,
}

impl Timer {
    pub fn new() -> std::io::Result<Self> {
        let inner = Arc::new((Mutex::new(Queue::default()), Condvar::new()));
        let shared = inner.clone();
        let thread = thread::Builder::new()
            .name("bandwidth-timer".into())
            .spawn(move || {
                let (mutex, changed) = &*shared;
                let mut queue = mutex.lock().unwrap();
                loop {
                    if queue.stop {
                        break;
                    }
                    let Some((&(due, id), _)) = queue.deadlines.first_key_value() else {
                        queue = changed.wait(queue).unwrap();
                        continue;
                    };
                    let now = Instant::now();
                    if due > now {
                        queue = changed.wait_timeout(queue, due - now).unwrap().0;
                        continue;
                    }
                    let (_, scheduler) = queue.deadlines.pop_first().unwrap();
                    queue.streams.remove(&id);
                    // Hold the lock through commit so cancel() quiesces callbacks before stream teardown.
                    scheduler.commit(0);
                }
            })?;
        Ok(Self {
            inner,
            thread: Some(thread),
        })
    }

    pub fn id(&self) -> u64 {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    }

    pub fn schedule(&self, id: u64, due: Instant, scheduler: Arc<dyn EnvoyHttpFilterScheduler>) {
        let mut queue = self.inner.0.lock().unwrap();
        if let Some(old) = queue.streams.insert(id, due) {
            queue.deadlines.remove(&(old, id));
        }
        queue.deadlines.insert((due, id), scheduler);
        self.inner.1.notify_one();
    }

    pub fn cancel(&self, id: u64) {
        let mut queue = self.inner.0.lock().unwrap();
        if let Some(due) = queue.streams.remove(&id) {
            queue.deadlines.remove(&(due, id));
        }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        self.inner.0.lock().unwrap().stop = true;
        self.inner.1.notify_one();
        self.thread.take().unwrap().join().unwrap();
    }
}
