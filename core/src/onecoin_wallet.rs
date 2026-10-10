//! Local ONECOIN wallet operations. Private identity material stays in the
//! existing AWENET identity/vault; this module never serializes a private key.

use crate::{
    identity::{AweId, Identity},
    onebank::{ExchangeOrder, P2POffer, UserTier, WalletBalance},
    onecoin::{OnecoinLedger, OnecoinTransaction, ATOMS_PER_COIN},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletState {
    pub owner: Option<AweId>,
    pub last_seen_nonce: u64,
    pub transaction_ids: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletSnapshot {
    pub owner: AweId,
    pub balance_atoms: u128,
    pub balance_coins: u128,
    pub nonce: u64,
    pub tier: UserTier,
    pub transactions: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Default)]
pub struct OnecoinWallet {
    pub state: WalletState,
}

impl OnecoinWallet {
    pub fn open(owner: AweId) -> Self {
        Self {
            state: WalletState {
                owner: Some(owner),
                ..Default::default()
            },
        }
    }

    pub fn snapshot(
        &self,
        ledger: &OnecoinLedger,
        tier: UserTier,
    ) -> Result<WalletSnapshot, String> {
        let owner = self
            .state
            .owner
            .clone()
            .ok_or("wallet is not initialized")?;
        let balance = WalletBalance::from_ledger(ledger, &owner);
        Ok(WalletSnapshot {
            owner,
            balance_atoms: balance.available_atoms,
            balance_coins: balance.available_atoms / ATOMS_PER_COIN,
            nonce: ledger
                .nonces
                .get(&balance.awe_id.to_hex())
                .copied()
                .unwrap_or(0),
            tier,
            transactions: self.state.transaction_ids.clone(),
        })
    }

    pub fn build_transfer(
        &mut self,
        identity: &Identity,
        ledger: &OnecoinLedger,
        recipient: &AweId,
        amount_atoms: u128,
        memo: Option<String>,
    ) -> Result<OnecoinTransaction, String> {
        let owner = self
            .state
            .owner
            .clone()
            .ok_or("wallet is not initialized")?;
        if owner != identity.public.awe_id {
            return Err("wallet owner does not match identity".into());
        }
        if amount_atoms == 0 {
            return Err("transfer amount must be positive".into());
        }
        if ledger.balance_atoms(&owner) < amount_atoms {
            return Err("insufficient ONECOIN balance".into());
        }
        let nonce = ledger.nonces.get(&owner.to_hex()).copied().unwrap_or(0);
        let tx = OnecoinTransaction::new(identity, nonce, recipient, amount_atoms, memo);
        self.state.last_seen_nonce = nonce;
        self.state.transaction_ids.push(tx.id());
        Ok(tx)
    }

    pub fn build_coin_transfer(
        &mut self,
        identity: &Identity,
        ledger: &OnecoinLedger,
        recipient: &AweId,
        coins: u128,
        memo: Option<String>,
    ) -> Result<OnecoinTransaction, String> {
        self.build_transfer(
            identity,
            ledger,
            recipient,
            coins.saturating_mul(ATOMS_PER_COIN),
            memo,
        )
    }

    pub fn apply(
        &mut self,
        ledger: &mut OnecoinLedger,
        tx: &OnecoinTransaction,
        identity: &Identity,
    ) -> Result<[u8; 32], String> {
        let id = ledger.apply_transfer(tx, &identity.public.public_key)?;
        if !self.state.transaction_ids.contains(&id) {
            self.state.transaction_ids.push(id);
        }
        self.state.last_seen_nonce = ledger
            .nonces
            .get(&identity.public.awe_id.to_hex())
            .copied()
            .unwrap_or(0);
        Ok(id)
    }

    pub fn verify_exchange_offer(
        &self,
        offer: &P2POffer,
        owner_public_key: &[u8; 32],
        now_unix: u64,
    ) -> bool {
        offer.verify(owner_public_key, now_unix)
    }

    pub fn create_exchange_order(
        &self,
        offer: &P2POffer,
        offer_owner_public_key: &[u8; 32],
        buyer: AweId,
        seller: AweId,
        amount_atoms: u128,
        fee_bps: u16,
        now_unix: u64,
    ) -> Result<ExchangeOrder, String> {
        ExchangeOrder::from_offer(
            offer,
            offer_owner_public_key,
            buyer,
            seller,
            amount_atoms,
            fee_bps,
            now_unix,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Username;

    #[test]
    fn wallet_builds_signed_transfer_without_storing_private_key() {
        let a = Identity::generate(Username::new("wallet-a").unwrap());
        let b = Identity::generate(Username::new("wallet-b").unwrap());
        let mut ledger = OnecoinLedger::default();
        ledger
            .initialize_genesis(&[a.public.awe_id.clone(), b.public.awe_id.clone()])
            .unwrap();
        let mut wallet = OnecoinWallet::open(a.public.awe_id.clone());
        let tx = wallet
            .build_coin_transfer(&a, &ledger, &b.public.awe_id, 1, None)
            .unwrap();
        wallet.apply(&mut ledger, &tx, &a).unwrap();
        assert_eq!(ledger.balance_atoms(&b.public.awe_id), 11 * ATOMS_PER_COIN);
    }
}
