//! Live ONECOIN consensus transport/runtime.
//!
//! Consensus messages travel over the authenticated AWE data plane. This module
//! deliberately keeps validator membership explicit: a node only participates
//! when its configured validator set contains its AWEID and public key.

use crate::identity::{AweId, Identity};
use crate::onecoin_consensus::{
    OnecoinBlock, OnecoinFinalizedState, QuorumCertificate, SignedBlockVote,
};
use crate::onecoin_store::PersistentOnecoinState;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

pub use crate::policy::ONECOIN_CONSENSUS_STREAM;
pub const MAX_CONSENSUS_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
const MAX_PENDING_BLOCKS: usize = 256;
const MAX_VOTES_PER_BLOCK: usize = 4096;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum OnecoinConsensusMessage {
    Proposal(OnecoinBlock),
    Vote(SignedBlockVote),
    Certificate(QuorumCertificate),
}

impl OnecoinConsensusMessage {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        if bytes.len() > MAX_CONSENSUS_MESSAGE_BYTES {
            return Err("ONECOIN consensus message too large".into());
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_CONSENSUS_MESSAGE_BYTES {
            return Err("ONECOIN consensus message too large".into());
        }
        serde_json::from_slice(bytes).map_err(|e| format!("invalid ONECOIN consensus message: {e}"))
    }
}

#[derive(Clone, Debug)]
pub struct OnecoinConsensusRuntime {
    pub state: PersistentOnecoinState,
    pub validators: BTreeMap<String, [u8; 32]>,
    pending: HashMap<[u8; 32], OnecoinBlock>,
    votes: HashMap<[u8; 32], BTreeMap<String, SignedBlockVote>>,
}

impl OnecoinConsensusRuntime {
    pub fn open(
        path: impl AsRef<Path>,
        validators: BTreeMap<String, [u8; 32]>,
    ) -> Result<Self, String> {
        let state = PersistentOnecoinState::open(path)
            .map_err(|e| format!("failed to open ONECOIN consensus state: {e}"))?;
        if validators.is_empty() {
            return Err("ONECOIN validator set is empty".into());
        }
        for (id, key) in &validators {
            if AweId::from_public_key(key).to_hex() != *id {
                return Err("ONECOIN validator AWEID/public-key mismatch".into());
            }
        }
        Ok(Self {
            state,
            validators,
            pending: HashMap::new(),
            votes: HashMap::new(),
        })
    }

    pub fn local_is_validator(&self, identity: &Identity) -> bool {
        self.validators
            .get(&identity.public.awe_id.to_hex())
            .is_some_and(|key| key == &identity.public.public_key)
    }

    pub fn handle(
        &mut self,
        sender: [u8; 32],
        identity: &Identity,
        message: OnecoinConsensusMessage,
    ) -> Result<Vec<([u8; 32], OnecoinConsensusMessage)>, String> {
        let sender_id = AweId::from_public_key(&sender).to_hex();
        if self.validators.get(&sender_id) != Some(&sender) {
            return Err("consensus sender is not a validator".into());
        }
        match message {
            OnecoinConsensusMessage::Proposal(block) => {
                self.handle_proposal(sender, identity, block)
            }
            OnecoinConsensusMessage::Vote(vote) => self.handle_vote(sender, vote),
            OnecoinConsensusMessage::Certificate(cert) => self.handle_certificate(cert),
        }
    }

    fn handle_proposal(
        &mut self,
        sender: [u8; 32],
        identity: &Identity,
        block: OnecoinBlock,
    ) -> Result<Vec<([u8; 32], OnecoinConsensusMessage)>, String> {
        block.validate_shape()?;
        if block.header.proposer != AweId::from_public_key(&sender) {
            return Err("proposal sender does not match block proposer".into());
        }
        let proposer_key = self
            .validators
            .get(&block.header.proposer.to_hex())
            .ok_or("proposal proposer is not a validator")?;
        if !block.verify_proposer(proposer_key) {
            return Err("invalid proposal signature".into());
        }
        if block.header.height != self.state.state.height + 1
            || block.header.previous_hash != self.state.state.tip_hash
        {
            return Err("proposal does not extend finalized state".into());
        }
        if self.pending.len() >= MAX_PENDING_BLOCKS && !self.pending.contains_key(&block.hash()) {
            return Err("too many pending consensus blocks".into());
        }
        let hash = block.hash();
        self.pending.insert(hash, block.clone());

        if self.local_is_validator(identity) {
            let vote = SignedBlockVote::new(identity, &block, true);
            Ok(vec![(sender, OnecoinConsensusMessage::Vote(vote))])
        } else {
            Ok(Vec::new())
        }
    }

    fn handle_vote(
        &mut self,
        sender: [u8; 32],
        vote: SignedBlockVote,
    ) -> Result<Vec<([u8; 32], OnecoinConsensusMessage)>, String> {
        if vote.voter != AweId::from_public_key(&sender) {
            return Err("vote sender does not match voter".into());
        }
        let key = self
            .validators
            .get(&vote.voter.to_hex())
            .ok_or("vote voter is not a validator")?;
        if !vote.verify(key) {
            return Err("invalid vote signature".into());
        }
        let block = self
            .pending
            .get(&vote.block_hash)
            .ok_or("vote references unknown block")?;
        if block.header.height != vote.height {
            return Err("vote height mismatch".into());
        }
        let entry = self.votes.entry(vote.block_hash).or_default();
        if entry.len() >= MAX_VOTES_PER_BLOCK && !entry.contains_key(&vote.voter.to_hex()) {
            return Err("too many votes for pending block".into());
        }
        let vote_hash = vote.block_hash;
        let vote_id = vote.voter.to_hex();
        entry.insert(vote_id, vote.clone());

        let cert = QuorumCertificate {
            block_hash: vote_hash,
            height: block.header.height,
            votes: entry.values().cloned().collect(),
        };
        if cert
            .verify(&self.validators, block.hash(), block.header.height)
            .is_ok()
        {
            self.state.finalize(block, &cert, &self.validators)?;
            self.pending.remove(&vote.block_hash);
            self.votes.remove(&vote.block_hash);
            return Ok(self
                .validators
                .values()
                .copied()
                .map(|peer| (peer, OnecoinConsensusMessage::Certificate(cert.clone())))
                .collect());
        }
        Ok(Vec::new())
    }

    fn handle_certificate(
        &mut self,
        cert: QuorumCertificate,
    ) -> Result<Vec<([u8; 32], OnecoinConsensusMessage)>, String> {
        let block = self
            .pending
            .get(&cert.block_hash)
            .ok_or("certificate references unknown block")?
            .clone();
        self.state.finalize(&block, &cert, &self.validators)?;
        self.pending.remove(&cert.block_hash);
        self.votes.remove(&cert.block_hash);
        Ok(Vec::new())
    }

    pub fn persisted_state(&self) -> &OnecoinFinalizedState {
        &self.state.state
    }
}
