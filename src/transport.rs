//! Minimal transport interfaces for interactive DKG message passing.

use std::collections::VecDeque;

use crate::types::{Error, PartyId};

/// Abstraction for message delivery.
pub trait Transport<M> {
    /// Broadcast a message to all parties.
    fn broadcast(&mut self, from: PartyId, msg: M) -> Result<(), Error>;

    /// Unicast a message to a specific party.
    fn unicast(&mut self, from: PartyId, to: PartyId, msg: M) -> Result<(), Error>;

    /// Drain all messages destined for `to`.
    fn drain_inbox(&mut self, to: PartyId) -> Vec<(PartyId, M)>;
}

/// In-memory transport for tests/examples.
pub struct InMemoryTransport<M> {
    n: u32,
    inboxes: Vec<VecDeque<(PartyId, M)>>,
}

impl<M: Clone> InMemoryTransport<M> {
    /// Create a transport for `n` parties (IDs 1..=n).
    pub fn new(n: u32) -> Self {
        let mut inboxes = Vec::with_capacity(n as usize);
        for _ in 0..n {
            inboxes.push(VecDeque::new());
        }
        Self { n, inboxes }
    }

    fn idx(&self, id: PartyId) -> Result<usize, Error> {
        if id == 0 || id > self.n {
            return Err(Error::InvalidParams);
        }
        Ok((id - 1) as usize)
    }
}

impl<M: Clone> Transport<M> for InMemoryTransport<M> {
    fn broadcast(&mut self, from: PartyId, msg: M) -> Result<(), Error> {
        for to in 1..=self.n {
            let idx = self.idx(to)?;
            self.inboxes[idx].push_back((from, msg.clone()));
        }
        Ok(())
    }

    fn unicast(&mut self, from: PartyId, to: PartyId, msg: M) -> Result<(), Error> {
        let idx = self.idx(to)?;
        self.inboxes[idx].push_back((from, msg));
        Ok(())
    }

    fn drain_inbox(&mut self, to: PartyId) -> Vec<(PartyId, M)> {
        let idx = match self.idx(to) {
            Ok(i) => i,
            Err(_) => return Vec::new(),
        };
        self.inboxes[idx].drain(..).collect()
    }
}
