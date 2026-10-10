//! ONEBANK governance, contribution tiers, wallet and P2P exchange primitives.
//!
//! ONEBANK is the policy/accounting layer for ONECOIN. It does not custody fiat:
//! fiat settlement is intentionally represented as an external payment rail.
//! The module therefore handles signed ONECOIN orders, fees, resource-based
//! rewards and governance without pretending to move real-world money itself.

use crate::{
    identity::{AweId, Identity},
    onecoin::{OnecoinAmount, OnecoinLedger, ATOMS_PER_COIN},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const ONEBANK_PROTOCOL: &str = "ONEBANK/1";
pub const MAX_FEE_BPS: u64 = 500;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum UserTier {
    Free,
    Basic,
    NetPlus,
    NetPro,
    NetUltra,
    Pro,
    DataGroup,
    CentreGroup,
    AwenetUser,
}

impl UserTier {
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::Free => "FREE",
            Self::Basic => "BASIC",
            Self::NetPlus => "NET+",
            Self::NetPro => "NET PRO",
            Self::NetUltra => "NET ULTRA",
            Self::Pro => "PRO",
            Self::DataGroup => "DATA GROUP",
            Self::CentreGroup => "CENTRE GROUP",
            Self::AwenetUser => "AWENET USER",
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceContribution {
    pub storage_bytes: u64,
    pub cpu_cores: u32,
    pub ram_bytes: u64,
    pub gpu_units: u32,
    pub bandwidth_bytes: u64,
    pub online_hours: u16,
    pub node_count: u32,
    pub server_count: u32,
    pub uptime_bps: u16,
    pub utilization_bps: u16,
}

impl ResourceContribution {
    pub fn validate(&self) -> Result<(), String> {
        if self.online_hours > 24 || self.uptime_bps > 10_000 || self.utilization_bps > 10_000 {
            return Err("invalid resource contribution bounds".into());
        }
        Ok(())
    }

    /// Stable integer score. The weights are deliberately explicit and can be
    /// changed by governance through a future policy version.
    pub fn score(&self) -> u128 {
        (self.storage_bytes as u128 / (1024 * 1024))
            .saturating_add((self.ram_bytes as u128 / (1024 * 1024)).saturating_mul(4))
            .saturating_add((self.cpu_cores as u128).saturating_mul(1024))
            .saturating_add((self.gpu_units as u128).saturating_mul(16_384))
            .saturating_add(self.bandwidth_bytes as u128 / (1024 * 1024))
            .saturating_add((self.node_count as u128).saturating_mul(10_000))
            .saturating_add((self.server_count as u128).saturating_mul(20_000))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TierBenefits {
    pub tier: UserTier,
    pub bonus_storage_bytes: u64,
    pub vps_cpu: u32,
    pub vps_ram_bytes: u64,
    pub vps_24_7: bool,
    pub node_server_management: bool,
    pub data_centre_management: bool,
    pub data_group_management: bool,
    pub centre_group_management: bool,
    pub minimum_monthly_atoms: u128,
}

impl TierBenefits {
    pub fn for_tier(tier: UserTier, contribution: &ResourceContribution) -> Self {
        let gb = 1024u64 * 1024 * 1024;
        match tier {
            UserTier::Free => Self {
                tier,
                bonus_storage_bytes: 20 * gb,
                vps_cpu: 1,
                vps_ram_bytes: gb,
                vps_24_7: false,
                node_server_management: false,
                data_centre_management: false,
                data_group_management: false,
                centre_group_management: false,
                minimum_monthly_atoms: 0,
            },
            UserTier::Basic => Self {
                tier,
                bonus_storage_bytes: 20 * gb,
                vps_cpu: 2,
                vps_ram_bytes: 4 * gb,
                vps_24_7: true,
                node_server_management: false,
                data_centre_management: false,
                data_group_management: false,
                centre_group_management: false,
                minimum_monthly_atoms: 10 * ATOMS_PER_COIN,
            },
            UserTier::NetPlus => Self {
                tier,
                bonus_storage_bytes: 30 * gb,
                vps_cpu: 2,
                vps_ram_bytes: 8 * gb,
                vps_24_7: true,
                node_server_management: true,
                data_centre_management: false,
                data_group_management: false,
                centre_group_management: false,
                minimum_monthly_atoms: 45 * ATOMS_PER_COIN,
            },
            UserTier::NetPro => Self {
                tier,
                bonus_storage_bytes: contribution.storage_bytes,
                vps_cpu: 0,
                vps_ram_bytes: contribution.ram_bytes,
                vps_24_7: true,
                node_server_management: true,
                data_centre_management: false,
                data_group_management: false,
                centre_group_management: false,
                minimum_monthly_atoms: 0,
            },
            UserTier::NetUltra => Self {
                tier,
                bonus_storage_bytes: contribution.storage_bytes,
                vps_cpu: 0,
                vps_ram_bytes: contribution.ram_bytes,
                vps_24_7: true,
                node_server_management: true,
                data_centre_management: true,
                data_group_management: false,
                centre_group_management: false,
                minimum_monthly_atoms: 0,
            },
            UserTier::Pro => Self {
                tier,
                bonus_storage_bytes: contribution.storage_bytes,
                vps_cpu: 0,
                vps_ram_bytes: contribution.ram_bytes,
                vps_24_7: true,
                node_server_management: true,
                data_centre_management: true,
                data_group_management: true,
                centre_group_management: false,
                minimum_monthly_atoms: 0,
            },
            UserTier::DataGroup => Self {
                tier,
                bonus_storage_bytes: contribution.storage_bytes,
                vps_cpu: 0,
                vps_ram_bytes: contribution.ram_bytes,
                vps_24_7: true,
                node_server_management: true,
                data_centre_management: true,
                data_group_management: true,
                centre_group_management: false,
                minimum_monthly_atoms: 0,
            },
            UserTier::CentreGroup => Self {
                tier,
                bonus_storage_bytes: contribution.storage_bytes,
                vps_cpu: 0,
                vps_ram_bytes: contribution.ram_bytes,
                vps_24_7: true,
                node_server_management: true,
                data_centre_management: true,
                data_group_management: true,
                centre_group_management: true,
                minimum_monthly_atoms: 0,
            },
            UserTier::AwenetUser => Self {
                tier,
                bonus_storage_bytes: 0,
                vps_cpu: 0,
                vps_ram_bytes: 0,
                vps_24_7: true,
                node_server_management: true,
                data_centre_management: true,
                data_group_management: true,
                centre_group_management: true,
                minimum_monthly_atoms: 0,
            },
        }
    }
}

pub fn classify_tier(r: &ResourceContribution) -> UserTier {
    if r.server_count >= 1_000_000 {
        return UserTier::CentreGroup;
    }
    if r.server_count >= 100_000 {
        return UserTier::DataGroup;
    }
    if r.server_count >= 100 {
        return UserTier::Pro;
    }
    if r.node_count >= 2 || r.server_count >= 2 {
        return UserTier::NetUltra;
    }
    if r.storage_bytes >= 1_000_000_000_000
        && r.cpu_cores >= 8
        && r.ram_bytes >= 16 * 1024 * 1024 * 1024
        && r.gpu_units >= 1
    {
        return UserTier::NetPro;
    }
    if r.storage_bytes >= 100 * 1024 * 1024 * 1024
        && r.cpu_cores >= 4
        && r.ram_bytes >= 8 * 1024 * 1024 * 1024
        && r.bandwidth_bytes >= 1_000_000_000_000
    {
        return UserTier::NetPlus;
    }
    if r.storage_bytes > 0
        || r.cpu_cores > 0
        || r.ram_bytes > 0
        || r.gpu_units > 0
        || r.bandwidth_bytes > 0
        || r.node_count > 0
        || r.server_count > 0
    {
        return UserTier::Basic;
    }
    UserTier::Free
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RewardPolicy {
    pub base_basic_atoms: u128,
    pub base_net_plus_atoms: u128,
    pub atoms_per_score: u128,
    pub usage_multiplier_bps: u64,
}

impl Default for RewardPolicy {
    fn default() -> Self {
        Self {
            base_basic_atoms: 10 * ATOMS_PER_COIN,
            base_net_plus_atoms: 45 * ATOMS_PER_COIN,
            atoms_per_score: 1_000_000,
            usage_multiplier_bps: 10_000,
        }
    }
}

impl RewardPolicy {
    pub fn monthly_minimum(&self, tier: UserTier) -> u128 {
        match tier {
            UserTier::Basic => self.base_basic_atoms,
            UserTier::NetPlus => self.base_net_plus_atoms,
            _ => 0,
        }
    }

    pub fn reward(
        &self,
        tier: UserTier,
        contribution: &ResourceContribution,
        usage_bps: u16,
    ) -> u128 {
        let minimum = self.monthly_minimum(tier);
        let score_reward = contribution.score().saturating_mul(self.atoms_per_score);
        let usage = score_reward
            .saturating_mul(usage_bps as u128)
            .saturating_div(10_000);
        minimum.saturating_add(
            usage
                .saturating_mul(self.usage_multiplier_bps as u128)
                .saturating_div(10_000),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnebankPolicy {
    pub fee_bps: u16,
    pub awenet_user_public_key: [u8; 32],
    pub reward_policy: RewardPolicy,
    pub fiat_reference: BTreeMap<String, u64>,
}

impl OnebankPolicy {
    pub fn new(awenet_user_public_key: [u8; 32]) -> Self {
        Self {
            fee_bps: 100,
            awenet_user_public_key,
            reward_policy: RewardPolicy::default(),
            fiat_reference: BTreeMap::from([("USD".into(), 100)]),
        }
    }

    pub fn set_fee(&mut self, bps: u16) -> Result<(), String> {
        if bps as u64 > MAX_FEE_BPS {
            return Err("ONEBANK fee cannot exceed 5%".into());
        }
        self.fee_bps = bps;
        Ok(())
    }

    pub fn fee_atoms(&self, amount_atoms: u128) -> u128 {
        amount_atoms
            .saturating_mul(self.fee_bps as u128)
            .saturating_div(10_000)
    }

    pub fn net_after_fee(&self, amount_atoms: u128) -> u128 {
        amount_atoms.saturating_sub(self.fee_atoms(amount_atoms))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletBalance {
    pub awe_id: AweId,
    pub available_atoms: u128,
    pub spendable_coins: u128,
}

impl WalletBalance {
    pub fn from_ledger(ledger: &OnecoinLedger, awe_id: &AweId) -> Self {
        let atoms = ledger.balance_atoms(awe_id);
        Self {
            awe_id: awe_id.clone(),
            available_atoms: atoms,
            spendable_coins: atoms / ATOMS_PER_COIN,
        }
    }

    pub fn amount(&self) -> OnecoinAmount {
        OnecoinAmount(self.available_atoms)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum FiatRail {
    ExternalPayment,
    BankTransfer,
    Cash,
    Other(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExchangeSide {
    Buy,
    Sell,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct P2POffer {
    pub id: [u8; 32],
    pub owner: AweId,
    pub side: ExchangeSide,
    pub amount_atoms: u128,
    pub price_minor_per_coin: u64,
    pub fiat_currency: String,
    pub rail: FiatRail,
    pub payment_reference: Option<String>,
    pub expires_at_unix: u64,
    #[serde(with = "crate::serde_bytes_64")]
    pub signature: [u8; 64],
}

impl P2POffer {
    pub fn new(
        owner: &Identity,
        side: ExchangeSide,
        amount_atoms: u128,
        price_minor_per_coin: u64,
        fiat_currency: String,
        rail: FiatRail,
        payment_reference: Option<String>,
        expires_at_unix: u64,
    ) -> Result<Self, String> {
        if amount_atoms == 0 || price_minor_per_coin == 0 {
            return Err("amount and price must be positive".into());
        }
        let mut offer = Self {
            id: [0; 32],
            owner: owner.public.awe_id.clone(),
            side,
            amount_atoms,
            price_minor_per_coin,
            fiat_currency,
            rail,
            payment_reference,
            expires_at_unix,
            signature: [0; 64],
        };
        offer.id =
            *blake3::hash(&serde_json::to_vec(&offer).map_err(|_| "offer serialization failed")?)
                .as_bytes();
        offer.signature = owner.sign(&offer.signing_bytes());
        Ok(offer)
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut copy = self.clone();
        copy.signature = [0; 64];
        serde_json::to_vec(&copy).expect("offer serialization")
    }

    pub fn verify(&self, owner_public_key: &[u8; 32], now_unix: u64) -> bool {
        self.expires_at_unix >= now_unix
            && self.owner.as_bytes() == AweId::from_public_key(owner_public_key).as_bytes()
            && Identity::verify(owner_public_key, &self.signing_bytes(), &self.signature)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExchangeOrder {
    pub id: [u8; 32],
    pub offer_id: [u8; 32],
    pub buyer: AweId,
    pub seller: AweId,
    pub amount_atoms: u128,
    pub fiat_minor: u128,
    pub onebank_fee_atoms: u128,
    pub fiat_currency: String,
    pub rail: FiatRail,
    pub created_at_unix: u64,
}

impl ExchangeOrder {
    pub fn from_offer(
        offer: &P2POffer,
        offer_owner_public_key: &[u8; 32],
        buyer: AweId,
        seller: AweId,
        amount_atoms: u128,
        fee_bps: u16,
        now_unix: u64,
    ) -> Result<Self, String> {
        if !offer.verify(offer_owner_public_key, now_unix) {
            return Err("exchange offer signature is invalid or the offer has expired".into());
        }
        if fee_bps > 500 {
            return Err("ONEBANK fee cannot exceed 5%".into());
        }
        if amount_atoms == 0 || amount_atoms > offer.amount_atoms {
            return Err("invalid order amount".into());
        }
        match offer.side {
            ExchangeSide::Sell if offer.owner != seller => {
                return Err("seller does not own the sell offer".into());
            }
            ExchangeSide::Buy if offer.owner != buyer => {
                return Err("buyer does not own the buy offer".into());
            }
            _ => {}
        }
        let price = offer.price_minor_per_coin as u128;
        let whole_coins = amount_atoms / ATOMS_PER_COIN;
        let fractional_atoms = amount_atoms % ATOMS_PER_COIN;
        let whole_fiat = whole_coins
            .checked_mul(price)
            .ok_or_else(|| "exchange fiat amount is too large".to_string())?;
        let fractional_fiat = fractional_atoms
            .checked_mul(price)
            .ok_or_else(|| "exchange fractional fiat amount is too large".to_string())?
            / ATOMS_PER_COIN;
        let fiat_minor = whole_fiat
            .checked_add(fractional_fiat)
            .ok_or_else(|| "exchange fiat amount is too large".to_string())?;
        let fee = amount_atoms
            .checked_mul(fee_bps as u128)
            .ok_or_else(|| "exchange fee calculation overflow".to_string())?
            / 10_000;
        let canonical_order =
            serde_json::to_vec(&(offer.id, &buyer, &seller, amount_atoms, now_unix))
                .map_err(|_| "exchange order serialization failed".to_string())?;
        Ok(Self {
            id: *blake3::hash(&canonical_order).as_bytes(),
            offer_id: offer.id,
            buyer,
            seller,
            amount_atoms,
            fiat_minor,
            onebank_fee_atoms: fee,
            fiat_currency: offer.fiat_currency.clone(),
            rail: offer.rail.clone(),
            created_at_unix: now_unix,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Username;
    #[test]
    fn tiers_follow_contribution() {
        assert_eq!(
            classify_tier(&ResourceContribution::default()),
            UserTier::Free
        );
        let mut r = ResourceContribution {
            storage_bytes: 1,
            ..Default::default()
        };
        assert_eq!(classify_tier(&r), UserTier::Basic);
        r.storage_bytes = 100 * 1024 * 1024 * 1024;
        r.cpu_cores = 4;
        r.ram_bytes = 8 * 1024 * 1024 * 1024;
        r.bandwidth_bytes = 1_000_000_000_000;
        assert_eq!(classify_tier(&r), UserTier::NetPlus);
    }

    #[test]
    fn net_plus_benefit_matches_default_reward_policy() {
        let benefits = TierBenefits::for_tier(UserTier::NetPlus, &ResourceContribution::default());
        let policy = RewardPolicy::default();
        assert_eq!(
            benefits.minimum_monthly_atoms,
            policy.monthly_minimum(UserTier::NetPlus)
        );
        assert_eq!(benefits.minimum_monthly_atoms, 45 * ATOMS_PER_COIN);
    }

    #[test]
    fn uptime_claim_alone_does_not_unlock_paid_tier() {
        let contribution = ResourceContribution {
            online_hours: 24,
            uptime_bps: 10_000,
            utilization_bps: 10_000,
            ..Default::default()
        };
        assert_eq!(classify_tier(&contribution), UserTier::Free);
    }

    #[test]
    fn exchange_order_rejects_arithmetic_overflow() {
        let seller = Identity::generate(Username::new("overflow-seller").unwrap());
        let buyer = Identity::generate(Username::new("overflow-buyer").unwrap());
        let offer = P2POffer::new(
            &seller,
            ExchangeSide::Sell,
            u128::MAX,
            u64::MAX,
            "USD".to_string(),
            FiatRail::BankTransfer,
            None,
            u64::MAX,
        )
        .unwrap();
        assert!(ExchangeOrder::from_offer(
            &offer,
            &seller.public.public_key,
            buyer.public.awe_id,
            seller.public.awe_id,
            u128::MAX,
            100,
            1,
        )
        .is_err());
    }

    #[test]
    fn fractional_coin_exchange_orders_preserve_fiat_value() {
        let seller = Identity::generate(Username::new("seller".to_string()).unwrap());
        let buyer = Identity::generate(Username::new("buyer".to_string()).unwrap());
        let offer = P2POffer::new(
            &seller,
            ExchangeSide::Sell,
            ATOMS_PER_COIN,
            100,
            "USD".to_string(),
            FiatRail::BankTransfer,
            None,
            u64::MAX,
        )
        .unwrap();
        let order = ExchangeOrder::from_offer(
            &offer,
            &seller.public.public_key,
            buyer.public.awe_id,
            seller.public.awe_id,
            ATOMS_PER_COIN / 2,
            100,
            1,
        )
        .unwrap();
        assert_eq!(order.fiat_minor, 50);
    }

    #[test]
    fn exchange_orders_reject_tampered_offers_and_excessive_fees() {
        let seller = Identity::generate(Username::new("offer-seller".to_string()).unwrap());
        let buyer = Identity::generate(Username::new("offer-buyer".to_string()).unwrap());
        let offer = P2POffer::new(
            &seller,
            ExchangeSide::Sell,
            ATOMS_PER_COIN,
            100,
            "USD".to_string(),
            FiatRail::BankTransfer,
            None,
            u64::MAX,
        )
        .unwrap();

        let mut tampered = offer.clone();
        tampered.price_minor_per_coin = 1;
        assert!(ExchangeOrder::from_offer(
            &tampered,
            &seller.public.public_key,
            buyer.public.awe_id.clone(),
            seller.public.awe_id.clone(),
            ATOMS_PER_COIN / 2,
            100,
            1,
        )
        .is_err());

        assert!(ExchangeOrder::from_offer(
            &offer,
            &seller.public.public_key,
            buyer.public.awe_id,
            seller.public.awe_id,
            ATOMS_PER_COIN / 2,
            501,
            1,
        )
        .is_err());
    }

    #[test]
    fn onebank_fee_is_bounded() {
        let id = [7; 32];
        let mut p = OnebankPolicy::new(id);
        p.set_fee(500).unwrap();
        assert_eq!(p.fee_atoms(100 * ATOMS_PER_COIN), 5 * ATOMS_PER_COIN);
        assert!(p.set_fee(501).is_err());
    }

    #[test]
    fn reward_grows_with_usage() {
        let p = RewardPolicy::default();
        let r = ResourceContribution {
            storage_bytes: 1024 * 1024 * 1024,
            ..Default::default()
        };
        assert!(p.reward(UserTier::Basic, &r, 10_000) > p.reward(UserTier::Basic, &r, 0));
    }
}
