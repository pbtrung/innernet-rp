//! Test-only fault adapters. Never exported by a production crate.
use std::collections::VecDeque;

#[derive(Default)]
pub struct Clock {
    pub monotonic: u64,
    pub expiry: u64,
}
impl Clock {
    pub fn advance(&mut self, seconds: u64) {
        self.monotonic = self.monotonic.checked_add(seconds).unwrap();
        self.expiry = self.expiry.checked_add(seconds).unwrap();
    }
}

#[derive(Clone, Copy, Default)]
pub enum Fault {
    #[default]
    None,
    Before,
    After,
}
pub struct Storage<T> {
    pub durable: T,
    pub fault: Fault,
}
impl<T: Clone> Storage<T> {
    pub fn write(&mut self, next: &T) -> Result<(), ()> {
        if matches!(self.fault, Fault::Before) {
            return Err(());
        }
        self.durable = next.clone();
        if matches!(self.fault, Fault::After) {
            return Err(());
        }
        Ok(())
    }
    pub fn restart(&self) -> T {
        self.durable.clone()
    }
}

#[derive(Default)]
pub struct Transport<T> {
    pub queue: VecDeque<T>,
}
impl<T: Clone> Transport<T> {
    pub fn send(&mut self, message: T, fault: Fault) -> Result<(), ()> {
        if matches!(fault, Fault::Before) {
            return Err(());
        }
        self.queue.push_back(message);
        if matches!(fault, Fault::After) {
            return Err(());
        }
        Ok(())
    }
    pub fn fetch(&self) -> Vec<T> {
        self.queue.iter().cloned().collect()
    }
}

#[derive(Default)]
pub struct Kernel {
    pub generation: u64,
    pub handshake_generation: Option<u64>,
    pub gated: bool,
}
impl Kernel {
    pub fn replace(&mut self) {
        assert!(self.gated, "installation requires an application gate");
        self.generation = self.generation.checked_add(1).unwrap();
        self.handshake_generation = None;
    }
    pub fn confirm(&mut self, generation: u64) -> Result<(), ()> {
        if generation != self.generation || self.handshake_generation != Some(generation) {
            return Err(());
        }
        self.gated = false;
        Ok(())
    }
}
