mod native_ui;
use anyhow::{Context, Result};
use awep2p_core::data_plane::{
    StorageShardAck, StorageShardRequest, StorageShardTransfer, STORAGE_STREAM,
};
use awep2p_core::diagnostics::{NodeDiagnostics, NodeMetrics};
use awep2p_core::federation::{
    self, AweNetConfig, AweNodeConfig, DataCentreConfig, DataGroupConfig,
};
use awep2p_core::host::{AweHost, HostPolicy, SiteManifest};
use awep2p_core::identity::{AweId, AweSecret, Identity, LocalVault, Username};
use awep2p_core::lan_mesh::LanPeerBeacon;
use awep2p_core::messenger::format_uid;
use awep2p_core::network::{format_node_descriptor, Node};
use awep2p_core::onebank::{classify_tier, ExchangeSide, FiatRail, P2POffer, ResourceContribution};
use awep2p_core::onecoin::{OnecoinLedger, OnecoinTransaction, ATOMS_PER_COIN};
use awep2p_core::onecoin_consensus_runtime::{
    OnecoinConsensusMessage, OnecoinConsensusRuntime, ONECOIN_CONSENSUS_STREAM,
};
use awep2p_core::policy::{self, NetworkPolicy};
use awep2p_core::reputation::NodeReputation;
use awep2p_core::storage::{encode_shards, recover_shards, LocalNodeStore, StoragePolicy};
use awep2p_core::store::{AWEPackage, AppCapability, AppKind, Store};
use awep2p_core::supervisor::{PeerSupervisor, SupervisorConfig};
use std::{
    collections::BTreeMap,
    env, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const UI_HTML: &str = include_str!("../../awe-desktop/ui/index.html");
const UI_CSS: &str = include_str!("../../awe-desktop/ui/style.css");
const UI_JS: &str = include_str!("../../awe-desktop/ui/app.js");
const ONECOIN_JS: &str = include_str!("../../awe-desktop/ui/onecoin.js");
const ONECOIN_CSS: &str = include_str!("../../awe-desktop/ui/onecoin.css");
const QR_JS: &str = include_str!("../../awe-desktop/ui/vendor/qrcode.js");
const DEFAULT_UI_ADDR: &str = "127.0.0.1:41800";

type MessengerLog = Arc<Mutex<Vec<serde_json::Value>>>;
type FederationState = Arc<Mutex<AweNetConfig>>;
type StorageState = Arc<LocalNodeStore>;
type PendingAcks = Arc<Mutex<BTreeMap<[u8; 16], StorageShardAck>>>;
type PendingShards = Arc<Mutex<BTreeMap<[u8; 16], StorageShardTransfer>>>;
type PolicyState = Arc<Mutex<NetworkPolicy>>;
type CommunityState = Arc<Mutex<serde_json::Value>>;
type ConsensusState = Arc<Mutex<Option<OnecoinConsensusRuntime>>>;
type OnecoinLedgerState = Arc<Mutex<OnecoinLedger>>;
type OnecoinPendingState = Arc<Mutex<BTreeMap<String, OnecoinTransaction>>>;
type ContributionState = Arc<Mutex<ResourceContribution>>;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct OnecoinTransferAck {
    transaction_id: String,
    recipient: [u8; 32],
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct PersistedOnecoinState {
    format_version: u8,
    ledger: OnecoinLedger,
    #[serde(default)]
    pending_transfers: BTreeMap<String, OnecoinTransaction>,
}

impl Default for PersistedOnecoinState {
    fn default() -> Self {
        Self {
            format_version: 1,
            ledger: OnecoinLedger::default(),
            pending_transfers: BTreeMap::new(),
        }
    }
}

fn load_persisted_onecoin_state(path: &Path) -> Result<PersistedOnecoinState, String> {
    if !path.exists() {
        return Ok(PersistedOnecoinState::default());
    }
    let bytes = fs::read(path).map_err(|error| format!("cannot read ONECOIN state: {error}"))?;
    if let Ok(state) = serde_json::from_slice::<PersistedOnecoinState>(&bytes) {
        if state.format_version != 1 {
            return Err("unsupported persisted ONECOIN state version".into());
        }
        for (id, transaction) in &state.pending_transfers {
            if id != &hex::encode(transaction.id()) || !transaction.verify(&transaction.sender) {
                return Err("persisted ONECOIN outbox contains an invalid transaction".into());
            }
        }
        return Ok(state);
    }
    // Migrate the previous format, which stored only the ledger at this path.
    serde_json::from_slice::<OnecoinLedger>(&bytes)
        .map(|ledger| PersistedOnecoinState {
            ledger,
            ..PersistedOnecoinState::default()
        })
        .map_err(|_| "persisted ONECOIN state is corrupt; refusing to reset wallet balances".into())
}

fn persist_onecoin_state(
    path: &Path,
    ledger: &OnecoinLedger,
    pending_transfers: &BTreeMap<String, OnecoinTransaction>,
) -> Result<(), String> {
    let state = PersistedOnecoinState {
        format_version: 1,
        ledger: ledger.clone(),
        pending_transfers: pending_transfers.clone(),
    };
    let bytes = serde_json::to_vec_pretty(&state)
        .map_err(|error| format!("cannot serialize ONECOIN state: {error}"))?;
    let temporary = path.with_extension(format!("json.tmp-{}", std::process::id()));
    if let Err(error) = fs::write(&temporary, bytes) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("cannot write temporary ONECOIN state: {error}"));
    }
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("cannot commit ONECOIN state atomically: {error}"));
    }
    Ok(())
}

fn remove_pending_onecoin_transfer(
    path: &Path,
    ledger_state: &OnecoinLedgerState,
    pending_state: &OnecoinPendingState,
    transaction_id: &str,
) -> Result<bool, String> {
    let ledger = ledger_state
        .lock()
        .map_err(|_| "ONECOIN ledger lock failed".to_string())?;
    let mut pending = pending_state
        .lock()
        .map_err(|_| "ONECOIN outbox lock failed".to_string())?;
    let mut next_pending = pending.clone();
    if next_pending.remove(transaction_id).is_none() {
        return Ok(false);
    }
    persist_onecoin_state(path, &ledger, &next_pending)?;
    *pending = next_pending;
    Ok(true)
}
type HostState = Arc<Mutex<AweHost>>;

#[derive(Clone)]
struct UiState {
    node: Node,
    messenger: MessengerLog,
    federation_state: FederationState,
    federation_path: PathBuf,
    storage: StorageState,
    pending_acks: PendingAcks,
    pending_shards: PendingShards,
    policy_state: PolicyState,
    community: CommunityState,
    onecoin_ledger: OnecoinLedgerState,
    onecoin_outbox: OnecoinPendingState,
    onecoin_path: PathBuf,
    onecoin_offers_path: PathBuf,
    contribution: ContributionState,
    contribution_path: PathBuf,
    host: HostState,
    host_root: PathBuf,
}

async fn build_onecoin_validators(
    node: &Node,
    configured: &[String],
) -> BTreeMap<String, [u8; 32]> {
    let wanted = configured
        .iter()
        .map(|v| v.to_lowercase())
        .collect::<std::collections::BTreeSet<_>>();
    let mut validators = BTreeMap::new();
    let local_id = node.identity.public.awe_id.to_hex().to_lowercase();
    if wanted.contains(&local_id) {
        validators.insert(local_id, node.identity.public.public_key);
    }
    for peer in node.peers().await {
        let id = hex::encode(peer.awe_id).to_lowercase();
        if wanted.contains(&id) {
            validators.insert(id, peer.public_key);
        }
    }
    validators
}

fn default_vault() -> PathBuf {
    if let Some(home) = env::var_os("HOME") {
        return PathBuf::from(home).join(".awep2p").join("identity.vault");
    }
    if let Some(profile) = env::var_os("USERPROFILE") {
        return PathBuf::from(profile)
            .join(".awep2p")
            .join("identity.vault");
    }
    PathBuf::from("identity.vault")
}

fn usage() -> ! {
    eprintln!("AWEp2P\n\nUsage:\n  awe-node                 Start the complete local product\n  awe-node app             Start UI + local node\n  awe-node secret <username> [out-file]\n  awe-node init <username> [vault-file]\n  awe-node run <vault-file> <password> <listen-addr> [bootstrap-addr ...]\n  awe-node id <vault-file> <password> <username>\n  awe-node status [vault-file]\n  awe-node diagnostics\n  awe-node mesh <listen-port>\n  awe-node health\n  awe-node probe <address>");
    std::process::exit(2)
}

fn generate_secret_file(username_str: &str, out_path: Option<PathBuf>) -> Result<()> {
    let username = Username::new(username_str).map_err(anyhow::Error::msg)?;
    let identity = Identity::generate(username);
    let secret = AweSecret::generate(&identity);
    let bytes = secret
        .to_bytes()
        .context("failed to serialize .awesecret")?;
    let path = out_path.unwrap_or_else(|| {
        if let Some(home) = env::var_os("HOME") {
            PathBuf::from(home)
                .join(".awep2p")
                .join(format!("{username_str}.awesecret"))
        } else {
            PathBuf::from(format!("{username_str}.awesecret"))
        }
    });
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, bytes)?;
    println!("AWE-ID: {}", secret.awe_id);
    println!(
        "Node Descriptor: {}",
        format_node_descriptor(identity.public.awe_id.as_bytes())
    );
    println!("Saved: {}", path.display());
    Ok(())
}

fn init(username: &str, path: PathBuf) -> Result<()> {
    let identity =
        Identity::generate(Username::new(username.to_owned()).map_err(anyhow::Error::msg)?);
    let password = rpassword::prompt_password("Vault password: ")?;
    if password.is_empty() {
        anyhow::bail!("vault password must not be empty");
    }
    let vault = LocalVault::seal(&identity, &password).map_err(anyhow::Error::msg)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, vault)?;
    println!("AWE-ID: {}", identity.public.awe_id.to_hex());
    println!("Identity vault: {}", path.display());
    Ok(())
}

fn load_identity(path: &PathBuf, password: &str, username: &str) -> Result<Identity> {
    let data = fs::read(path)?;
    LocalVault::open(
        &data,
        Username::new(username.to_owned()).map_err(anyhow::Error::msg)?,
        password,
    )
    .map_err(anyhow::Error::msg)
}

fn allowed_ui_origin(origin: &str) -> bool {
    if matches!(
        origin,
        "http://tauri.localhost" | "https://tauri.localhost" | "tauri://localhost"
    ) {
        return true;
    }

    let ui_addr = std::env::var("AWE_UI_ADDR").unwrap_or_else(|_| "127.0.0.1:41800".to_string());
    let port = ui_addr
        .rsplit_once(':')
        .map(|(_, port)| port)
        .unwrap_or("41800");
    origin == format!("http://127.0.0.1:{port}") || origin == format!("http://localhost:{port}")
}

async fn http_response(status: &str, content_type: &str, body: &str, request: &str) -> Vec<u8> {
    let origin = request.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("origin").then_some(value.trim())
    });
    let cors_headers = match origin.filter(|value| allowed_ui_origin(value)) {
        Some(origin) => format!(
            "Access-Control-Allow-Origin: {origin}\r\nVary: Origin\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: content-type\r\n"
        ),
        None => String::new(),
    };
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{cors_headers}Cache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn http_response_bytes(status: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn restrict_secret_file_permissions(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(path, permissions)?;
    }
    #[cfg(not(unix))]
    {
        // Windows files inherit access-control rules from the user's profile
        // directory. Do not replace its ACL with a guessed policy here.
        let _ = path;
    }
    Ok(())
}

fn valid_site_domain(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 || value.starts_with('.') || value.ends_with('.') {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}

fn valid_site_content_type(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b" /;=.+-_".contains(&b))
}

fn find_site_manifest(host_root: &PathBuf, site_id: &str) -> std::io::Result<SiteManifest> {
    if site_id.len() != 64 || !site_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid AWE site ID",
        ));
    }
    for entry in fs::read_dir(host_root)? {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        let name = path.file_name().and_then(|v| v.to_str()).unwrap_or("");
        if !name.ends_with(".manifest.json") {
            continue;
        }
        let Ok(bytes) = fs::read(path) else { continue };
        let Ok(manifest) = serde_json::from_slice::<SiteManifest>(&bytes) else {
            continue;
        };
        if hex::encode(manifest.root_hash).eq_ignore_ascii_case(site_id) {
            return Ok(manifest);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "AWE site ID was not found on this node",
    ))
}

fn decode_site_path(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let high = (bytes[i + 1] as char).to_digit(16)?;
            let low = (bytes[i + 2] as char).to_digit(16)?;
            decoded.push(((high << 4) | low) as u8);
            i += 3;
        } else {
            decoded.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

async fn read_http_request(stream: &mut tokio::net::TcpStream) -> Result<String> {
    const HEADER_LIMIT: usize = 64 * 1024;
    const BODY_LIMIT: usize = 64 * 1024 * 1024;
    let mut data = Vec::with_capacity(8192);
    let header_end;
    loop {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            anyhow::bail!("client closed connection before HTTP headers");
        }
        data.extend_from_slice(&chunk[..n]);
        if data.len() > HEADER_LIMIT {
            anyhow::bail!("HTTP headers too large");
        }
        if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
    }

    let headers = String::from_utf8_lossy(&data[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);

    if content_length > BODY_LIMIT {
        anyhow::bail!("HTTP request body too large");
    }

    let target = header_end + content_length;
    if data.len() < target {
        let mut filled = data.len();
        data.resize(target, 0);
        while filled < target {
            let n = stream.read(&mut data[filled..target]).await?;
            if n == 0 {
                anyhow::bail!("client closed connection before request body was complete");
            }
            filled += n;
        }
    } else if data.len() > target {
        data.truncate(target);
    }

    String::from_utf8(data).context("HTTP request must be UTF-8")
}

#[allow(clippy::too_many_arguments)]
fn format_onecoin_atoms(atoms: u128) -> String {
    let whole = atoms / ATOMS_PER_COIN;
    let fraction = atoms % ATOMS_PER_COIN;
    let value = format!("{whole}.{fraction:018}");
    value
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_string()
}

fn parse_fiat_minor(value: &serde_json::Value) -> Result<u64, String> {
    let raw = if let Some(text) = value.as_str() {
        text.trim().to_owned()
    } else if value.is_number() {
        value.to_string()
    } else {
        return Err("price must be a decimal value".into());
    };
    if raw.is_empty() || raw.contains('e') || raw.contains('E') {
        return Err("price must be a plain decimal value".into());
    }
    let mut parts = raw.split('.');
    let whole = parts.next().unwrap_or("");
    let fraction = parts.next().unwrap_or("");
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 2
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("price must use at most 2 decimal places".into());
    }
    let whole_minor = whole
        .parse::<u64>()
        .map_err(|_| "price is too large".to_string())?
        .checked_mul(100)
        .ok_or_else(|| "price is too large".to_string())?;
    let padded_fraction = format!("{fraction:0<2}");
    let fraction_minor = if padded_fraction.is_empty() {
        0
    } else {
        padded_fraction
            .parse::<u64>()
            .map_err(|_| "price is invalid".to_string())?
    };
    let minor = whole_minor
        .checked_add(fraction_minor)
        .ok_or_else(|| "price is too large".to_string())?;
    if minor == 0 {
        return Err("price must be positive".into());
    }
    Ok(minor)
}

fn parse_resource_u64(value: &serde_json::Value, key: &str) -> Result<u64, String> {
    match value.get(key) {
        None => Ok(0),
        Some(field) => field
            .as_u64()
            .ok_or_else(|| format!("{} must be a non-negative integer", key)),
    }
}

fn parse_resource_u32(value: &serde_json::Value, key: &str) -> Result<u32, String> {
    u32::try_from(parse_resource_u64(value, key)?)
        .map_err(|_| format!("{} exceeds the supported maximum", key))
}

fn parse_resource_u16(value: &serde_json::Value, key: &str) -> Result<u16, String> {
    u16::try_from(parse_resource_u64(value, key)?)
        .map_err(|_| format!("{} exceeds the supported maximum", key))
}

fn parse_resource_contribution(value: &serde_json::Value) -> Result<ResourceContribution, String> {
    let contribution = ResourceContribution {
        storage_bytes: parse_resource_u64(value, "storage_bytes")?,
        cpu_cores: parse_resource_u32(value, "cpu_cores")?,
        ram_bytes: parse_resource_u64(value, "ram_bytes")?,
        gpu_units: parse_resource_u32(value, "gpu_units")?,
        bandwidth_bytes: parse_resource_u64(value, "bandwidth_bytes")?,
        online_hours: parse_resource_u16(value, "online_hours")?,
        node_count: parse_resource_u32(value, "node_count")?,
        server_count: parse_resource_u32(value, "server_count")?,
        uptime_bps: parse_resource_u16(value, "uptime_bps")?,
        utilization_bps: parse_resource_u16(value, "utilization_bps")?,
    };
    contribution.validate()?;
    Ok(contribution)
}

fn parse_onecoin_atoms(value: &serde_json::Value) -> Result<u128, String> {
    let raw = if let Some(text) = value.as_str() {
        text.trim().to_owned()
    } else if value.is_number() {
        value.to_string()
    } else {
        return Err("amount_coins must be a number or decimal string".into());
    };
    if raw.is_empty() || raw.contains('e') || raw.contains('E') {
        return Err("amount_coins must be a plain decimal value".into());
    }
    let mut parts = raw.split('.');
    let whole = parts.next().unwrap_or("");
    let fraction = parts.next().unwrap_or("");
    if parts.next().is_some() || whole.is_empty() || !whole.chars().all(|c| c.is_ascii_digit()) {
        return Err("amount_coins has invalid decimal syntax".into());
    }
    if fraction.len() > 18 || !fraction.chars().all(|c| c.is_ascii_digit()) {
        return Err("amount_coins supports at most 18 decimal places".into());
    }
    let whole_atoms = whole
        .parse::<u128>()
        .map_err(|_| "amount_coins is too large".to_string())?
        .checked_mul(ATOMS_PER_COIN)
        .ok_or_else(|| "amount_coins is too large".to_string())?;
    let padded = format!("{fraction:0<18}");
    let fraction_atoms = if padded.is_empty() {
        0
    } else {
        padded
            .parse::<u128>()
            .map_err(|_| "amount_coins has invalid precision".to_string())?
    };
    whole_atoms
        .checked_add(fraction_atoms)
        .ok_or_else(|| "amount_coins is too large".to_string())
}

async fn serve_ui(mut stream: tokio::net::TcpStream, state: UiState) -> Result<()> {
    let UiState {
        node,
        messenger,
        federation_state,
        federation_path,
        storage,
        pending_acks,
        pending_shards,
        policy_state,
        community,
        onecoin_ledger,
        onecoin_outbox,
        onecoin_path,
        onecoin_offers_path,
        contribution,
        contribution_path,
        host,
        host_root,
    } = state;
    let request = read_http_request(&mut stream).await?;
    let request_line = request.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let target = parts.next().unwrap_or("/");
    let path = target.split('?').next().unwrap_or("/");
    let request_host = request.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("host")
            .then_some(value.trim().to_ascii_lowercase())
    });
    let configured_port = env::var("AWE_UI_ADDR")
        .ok()
        .and_then(|addr| addr.rsplit_once(':').map(|(_, port)| port.to_string()))
        .unwrap_or_else(|| "41800".to_string());
    if let Some(host) = request_host.as_deref() {
        let site_suffix = format!(".localhost:{configured_port}");
        if let Some(site_host_id) = host.strip_suffix(&site_suffix) {
            if site_host_id.len() == 64 && site_host_id.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                let site_prefix = format!("/site/{site_host_id}");
                let allowed_site_path = path == site_prefix
                    || path
                        .strip_prefix(&site_prefix)
                        .is_some_and(|rest| rest.starts_with('/'));
                if !allowed_site_path {
                    // A hosted page has its own origin, but that does not make
                    // the local node API safe to expose to its JavaScript.
                    // Restrict this virtual host to its own site's files.
                    let response = http_response(
                        "404 Not Found",
                        "text/plain; charset=utf-8",
                        "Not Found",
                        &request,
                    )
                    .await;
                    stream.write_all(&response).await?;
                    return Ok(());
                }
            }
        }
    }

    // CORS headers alone do not prevent cross-origin requests from being sent.
    // Reject browser-originated state changes unless the caller is the local
    // AWENET UI. Requests without an Origin header remain available to local
    // native clients and command-line diagnostics.
    if path.starts_with("/api/")
        && matches!(
            method.to_ascii_uppercase().as_str(),
            "POST" | "PUT" | "PATCH" | "DELETE"
        )
    {
        let origin = request.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("origin").then_some(value.trim())
        });
        if origin.is_some_and(|value| !allowed_ui_origin(value)) {
            let response = http_response(
                "403 Forbidden",
                "application/json; charset=utf-8",
                r#"{"status":"error","error":"cross-origin API mutations are not allowed"}"#,
                &request,
            )
            .await;
            stream.write_all(&response).await?;
            return Ok(());
        }
    }

    // Complete browser CORS preflight before routing API requests.
    if method.eq_ignore_ascii_case("OPTIONS") {
        let response =
            http_response("204 No Content", "text/plain; charset=utf-8", "", &request).await;
        stream.write_all(&response).await?;
        return Ok(());
    }

    if let Some(site_route) = path.strip_prefix("/site/") {
        let mut parts = site_route.splitn(2, '/');
        let site_id = parts.next().unwrap_or("");
        let site_port = env::var("AWE_UI_ADDR")
            .ok()
            .and_then(|addr| addr.rsplit_once(':').map(|(_, port)| port.to_string()))
            .unwrap_or_else(|| "41800".to_string());
        let expected_host = format!("{}.localhost:{}", site_id.to_ascii_lowercase(), site_port);
        let request_host = request.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("host")
                .then_some(value.trim().to_ascii_lowercase())
        });
        if site_id.len() == 64
            && site_id.bytes().all(|byte| byte.is_ascii_hexdigit())
            && request_host.as_deref() != Some(expected_host.as_str())
        {
            // Never execute untrusted hosted content on the trusted UI/API origin.
            // The per-site localhost subdomain gives each site a separate browser origin.
            let location = format!("http://{expected_host}/site/{site_route}");
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nCache-Control: no-store\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).await?;
            return Ok(());
        }
        let requested_path = decode_site_path(parts.next().unwrap_or("index.html"))
            .unwrap_or_else(|| "index.html".to_string());
        let requested_path = if requested_path.starts_with('/') {
            requested_path
        } else {
            format!("/{requested_path}")
        };
        let response = match find_site_manifest(&host_root, site_id) {
            Ok(manifest) => {
                let content_type = manifest
                    .files
                    .iter()
                    .find(|file| {
                        file.path
                            == awep2p_core::host::normalize_path(&requested_path)
                                .unwrap_or_default()
                    })
                    .map(|file| file.content_type.clone())
                    .unwrap_or_else(|| "application/octet-stream".to_string());
                match host.lock() {
                    Ok(mut host) => match host.get_authorized(&manifest, &requested_path, None) {
                        Ok(bytes) => http_response_bytes("200 OK", &content_type, &bytes),
                        Err(error) => http_response_bytes(
                            "404 Not Found",
                            "text/plain; charset=utf-8",
                            error.to_string().as_bytes(),
                        ),
                    },
                    Err(_) => http_response_bytes(
                        "500 Internal Server Error",
                        "text/plain; charset=utf-8",
                        b"AWE host is unavailable",
                    ),
                }
            }
            Err(error) => http_response_bytes(
                if error.kind() == std::io::ErrorKind::InvalidInput {
                    "400 Bad Request"
                } else {
                    "404 Not Found"
                },
                "text/plain; charset=utf-8",
                error.to_string().as_bytes(),
            ),
        };
        stream.write_all(&response).await?;
        return Ok(());
    }

    let (status, mime, body) = match path {
        "/" | "/index.html" => ("200 OK", "text/html; charset=utf-8", UI_HTML.to_string()),
        "/style.css" => ("200 OK", "text/css; charset=utf-8", UI_CSS.to_string()),
        "/app.js" => ("200 OK", "application/javascript; charset=utf-8", UI_JS.to_string()),
        "/onecoin.js" => ("200 OK", "application/javascript; charset=utf-8", ONECOIN_JS.to_string()),
        "/onecoin.css" => ("200 OK", "text/css; charset=utf-8", ONECOIN_CSS.to_string()),
        "/vendor/qrcode.js" => ("200 OK", "application/javascript; charset=utf-8", QR_JS.to_string()),
        "/api/sites" if method == "GET" => {
            let sites = fs::read_dir(&host_root)
                .ok()
                .into_iter()
                .flatten()
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".manifest.json"))
                .filter_map(|entry| fs::read(entry.path()).ok())
                .filter_map(|bytes| serde_json::from_slice::<SiteManifest>(&bytes).ok())
                .filter(SiteManifest::open)
                .map(|manifest| serde_json::json!({
                    "site_id": hex::encode(manifest.root_hash),
                    "name": manifest.domain,
                    "version": manifest.version,
                    "files": manifest.files.len(),
                    "open": true
                }))
                .collect::<Vec<_>>();
            ("200 OK", "application/json; charset=utf-8", serde_json::json!({"status":"ok","sites":sites}).to_string())
        },
        "/api/sites/publish" if method == "POST" => {
            let request_body = request.split_once("\r\n\r\n").map(|(_, body)| body).unwrap_or("");
            let parsed = serde_json::from_str::<serde_json::Value>(request_body);
            match parsed {
                Err(_) => ("400 Bad Request", "application/json; charset=utf-8", serde_json::json!({"status":"error","error":"invalid JSON body"}).to_string()),
                Ok(payload) => {
                    let domain = payload.get("domain").and_then(|v| v.as_str()).unwrap_or("").trim().to_ascii_lowercase();
                    let version = payload.get("version").and_then(|v| v.as_u64()).unwrap_or(1);
                    let files = payload.get("files").and_then(|v| v.as_array()).cloned().unwrap_or_default();
                    if !valid_site_domain(&domain) || version == 0 || files.is_empty() || files.len() > 256 {
                        ("400 Bad Request", "application/json; charset=utf-8", serde_json::json!({"status":"error","error":"domain must be a valid site name and files must contain 1-256 entries"}).to_string())
                    } else {
                        match host.lock() {
                            Err(_) => ("500 Internal Server Error", "application/json; charset=utf-8", serde_json::json!({"status":"error","error":"AWE host is unavailable"}).to_string()),
                            Ok(mut host) => {
                                if host.load_manifest(&domain).is_ok_and(|existing| version <= existing.version) {
                                    ("409 Conflict", "application/json; charset=utf-8", serde_json::json!({"status":"error","error":"site version must increase when updating a site"}).to_string())
                                } else {
                                    let mut hosted_files = Vec::with_capacity(files.len());
                                    let mut error = None;
                                    for file in files {
                                        let path = file.get("path").and_then(|v| v.as_str()).unwrap_or("");
                                        let content_type = file.get("content_type").and_then(|v| v.as_str()).unwrap_or("text/plain; charset=utf-8");
                                        if !valid_site_content_type(content_type) {
                                            error = Some("invalid content type");
                                            break;
                                        }
                                        let data = if let Some(text) = file.get("content").and_then(|v| v.as_str()) {
                                            Some(text.as_bytes().to_vec())
                                        } else {
                                            file.get("data_hex").and_then(|v| v.as_str()).and_then(|hex_data| hex::decode(hex_data).ok())
                                        };
                                        let Some(data) = data else {
                                            error = Some("each file requires content or valid data_hex");
                                            break;
                                        };
                                        if hosted_files.iter().any(|existing: &awep2p_core::host::HostedFile| existing.path == awep2p_core::host::normalize_path(path).unwrap_or_default()) {
                                            error = Some("duplicate file path");
                                            break;
                                        }
                                        match host.publish_file(path, &data, content_type) {
                                            Ok(file) => hosted_files.push(file),
                                            Err(_) => { error = Some("invalid file path or host storage policy rejected the file"); break; }
                                        }
                                    }
                                    if let Some(error) = error {
                                        ("400 Bad Request", "application/json; charset=utf-8", serde_json::json!({"status":"error","error":error}).to_string())
                                    } else {
                                        match host.publish_manifest(&domain, version, node.identity.public.public_key.to_vec(), hosted_files) {
                                            Err(error) => ("400 Bad Request", "application/json; charset=utf-8", serde_json::json!({"status":"error","error":error.to_string()}).to_string()),
                                            Ok(manifest) => match host.save_manifest(&manifest) {
                                                Err(error) => ("500 Internal Server Error", "application/json; charset=utf-8", serde_json::json!({"status":"error","error":error.to_string()}).to_string()),
                                                Ok(()) => ("200 OK", "application/json; charset=utf-8", serde_json::json!({
                                                    "status":"published",
                                                    "name":manifest.domain,
                                                    "version":manifest.version,
                                                    "site_id":hex::encode(manifest.root_hash),
                                                    "files":manifest.files.len(),
                                                    "url":format!("awe://site-{}",hex::encode(manifest.root_hash))
                                                }).to_string())
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "/api/onebank/wallet" if method == "GET" => {
            let ledger = onecoin_ledger.lock().map(|l| l.clone()).unwrap_or_default();
            let pending_transfers = onecoin_outbox.lock().map(|pending| pending.len()).unwrap_or_default();
            let id = node.identity.public.awe_id.clone();
            let balance_atoms = ledger.balance_atoms(&id);
            let contribution_snapshot = contribution.lock().map(|r| r.clone()).unwrap_or_default();
            let tier = classify_tier(&contribution_snapshot).wire_name();
            ("200 OK", "application/json; charset=utf-8", serde_json::json!({
                "awe_id": id.to_hex(),
                "balance_atoms": balance_atoms,
                "balance_coins": balance_atoms / ATOMS_PER_COIN,
                "balance_coins_exact": format_onecoin_atoms(balance_atoms),
                "pending_transfers": pending_transfers,
                "tier": tier,
                "fee_bps": 100,
                "resource_score": contribution_snapshot.score(),
                "resource": contribution_snapshot,
                "resource_verified": false,
                "exchange": "P2P_ONECOIN_ONLY",
                "fiat_settlement": "EXTERNAL_PERSON_TO_PERSON"
            }).to_string())
        },
        "/api/onebank/contribution" if method == "GET" => {
            let r = contribution.lock().map(|v| v.clone()).unwrap_or_default();
            ("200 OK", "application/json; charset=utf-8", serde_json::json!({
                "resource": r,
                "tier": classify_tier(&r).wire_name(),
                "verified": false,
                "reward_status": "requires_signed_usage_receipt"
            }).to_string())
        },
        "/api/onebank/contribution" if method == "POST" => {
            let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
            let parsed = serde_json::from_str::<serde_json::Value>(body)
                .map_err(|_| "invalid contribution JSON".to_string())
                .and_then(|value| parse_resource_contribution(&value));
            match parsed {
                Err(error) => (
                    "400 Bad Request",
                    "application/json; charset=utf-8",
                    serde_json::json!({"status":"error","error":error}).to_string(),
                ),
                Ok(resource) => {
                    match contribution.lock() {
                        Err(_) => (
                            "500 Internal Server Error",
                            "application/json; charset=utf-8",
                            serde_json::json!({"status":"error","error":"resource contribution lock failed"}).to_string(),
                        ),
                        Ok(mut guard) => {
                            let persisted = serde_json::to_vec_pretty(&resource)
                                .map_err(|error| error.to_string())
                                .and_then(|bytes| fs::write(&contribution_path, bytes).map_err(|error| error.to_string()));
                            match persisted {
                                Ok(()) => {
                                    *guard = resource.clone();
                                    (
                                        "200 OK",
                                        "application/json; charset=utf-8",
                                        serde_json::json!({
                                            "status":"accepted_for_verification",
                                            "tier": classify_tier(&resource).wire_name(),
                                            "verified":false,
                                            "reward_status":"requires_signed_usage_receipt"
                                        }).to_string(),
                                    )
                                }
                                Err(error) => (
                                    "500 Internal Server Error",
                                    "application/json; charset=utf-8",
                                    serde_json::json!({"status":"error","error":error}).to_string(),
                                ),
                            }
                        }
                    }
                }
            }
        },
        "/api/onebank/wallet/send" if method == "POST" => {
            let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
            let parsed = serde_json::from_str::<serde_json::Value>(body);
            match parsed {
                Err(_) => (
                    "400 Bad Request",
                    "application/json; charset=utf-8",
                    serde_json::json!({"status":"rejected","error":"invalid JSON body"}).to_string(),
                ),
                Ok(parsed) => {
                let recipient_hex = parsed.get("recipient").and_then(|v| v.as_str()).unwrap_or("");
                let amount_value = parsed.get("amount_coins").cloned().unwrap_or(serde_json::Value::Null);
                let memo = parsed.get("memo").and_then(|v| v.as_str()).map(str::to_owned);
                let result: Result<(String, u128, OnecoinTransaction), String> = (|| {
                    if recipient_hex.len() != 64 || !recipient_hex.chars().all(|c| c.is_ascii_hexdigit()) {
                        return Err("recipient must be a 64-character AWE-ID".into());
                    }
                    let amount_atoms = parse_onecoin_atoms(&amount_value)?;
                    if amount_atoms == 0 {
                        return Err("amount_coins must be positive".into());
                    }
                    let recipient = AweId::from_hex(recipient_hex)?;
                    if recipient == node.identity.public.awe_id {
                        return Err("cannot transfer ONECOIN to the same wallet".into());
                    }

                    // Mutate clones first and persist the ledger and retry queue as
                    // one atomic snapshot. A failed write must never spend in memory.
                    let mut ledger = onecoin_ledger
                        .lock()
                        .map_err(|_| "ONECOIN ledger lock failed".to_string())?;
                    let mut outbox = onecoin_outbox
                        .lock()
                        .map_err(|_| "ONECOIN outbox lock failed".to_string())?;
                    let mut next_ledger = ledger.clone();
                    let mut next_outbox = outbox.clone();
                    let sender = node.identity.public.awe_id.clone();
                    if next_ledger.members.is_empty() {
                        next_ledger.initialize_genesis(std::slice::from_ref(&sender))?;
                    }
                    next_ledger.ensure_member(&recipient);
                    if next_ledger.balance_atoms(&sender) < amount_atoms {
                        return Err("insufficient ONECOIN balance".into());
                    }
                    let nonce = next_ledger.nonces.get(&sender.to_hex()).copied().unwrap_or(0);
                    let tx = OnecoinTransaction::new(&node.identity, nonce, &recipient, amount_atoms, memo);
                    let (tx_id, _fee_atoms) = next_ledger.apply_transfer_with_fee(
                        &tx,
                        &node.identity.public.public_key,
                        100,
                    )?;
                    let tx_id = hex::encode(tx_id);
                    next_outbox.insert(tx_id.clone(), tx.clone());
                    persist_onecoin_state(&onecoin_path, &next_ledger, &next_outbox)?;
                    *ledger = next_ledger;
                    *outbox = next_outbox;
                    Ok((tx_id, _fee_atoms, tx))
                })();

                match result {
                    Ok((tx_id, fee_atoms, tx)) => {
                        let transport_send_accepted = match serde_json::to_vec(&tx) {
                            Ok(bytes) => node
                                .send_to_peer(
                                    &tx.recipient,
                                    policy::ONECOIN_TRANSFER_STREAM,
                                    bytes,
                                )
                                .await
                                .is_ok(),
                            Err(_) => false,
                        };
                        let still_pending = onecoin_outbox
                            .lock()
                            .map(|queue| queue.contains_key(&tx_id))
                            .unwrap_or(true);
                        (
                            "200 OK",
                            "application/json; charset=utf-8",
                            serde_json::json!({
                                "status":"accepted",
                                "tx_id":tx_id,
                                "fee_atoms":fee_atoms,
                                "fee_bps":100,
                                "transport_send_accepted":transport_send_accepted,
                                "recipient_delivered":!still_pending,
                                "recipient_pending":still_pending
                            }).to_string(),
                        )
                    }
                    Err(error) => (
                        "400 Bad Request",
                        "application/json; charset=utf-8",
                        serde_json::json!({"status":"rejected","error":error}).to_string(),
                    ),
                }
                }
            }
        },
        "/api/onebank/exchange/offers" if method == "GET" => {
            let offers: Vec<serde_json::Value> = fs::read(&onecoin_offers_path)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .unwrap_or_default();
            let verified = offers
                .into_iter()
                .filter(|offer| {
                    let public_key = offer
                        .get("owner_public_key")
                        .and_then(|value| value.as_str())
                        .and_then(|value| hex::decode(value).ok())
                        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok());
                    let signed = offer
                        .get("signed_offer")
                        .cloned()
                        .and_then(|value| serde_json::from_value::<P2POffer>(value).ok());
                    match (public_key, signed) {
                        (Some(public_key), Some(signed)) => {
                            offer.get("owner").and_then(|value| value.as_str())
                                == Some(signed.owner.to_hex().as_str())
                                && signed.verify(&public_key, now_unix())
                        }
                        _ => false,
                    }
                })
                .collect::<Vec<_>>();
            (
                "200 OK",
                "application/json; charset=utf-8",
                serde_json::to_string(&verified).unwrap_or_else(|_| "[]".into()),
            )
        },
        "/api/onebank/exchange/offers" if method == "POST" => {
            let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
            let result: Result<serde_json::Value, String> = (|| {
                let payload: serde_json::Value =
                    serde_json::from_str(body).map_err(|_| "invalid offer JSON".to_string())?;
                let data = payload.get("offer").unwrap_or(&payload);
                let side_text = data
                    .get("side")
                    .and_then(|value| value.as_str())
                    .ok_or("offer side is required")?
                    .to_ascii_lowercase();
                let side = match side_text.as_str() {
                    "buy" => ExchangeSide::Buy,
                    "sell" => ExchangeSide::Sell,
                    _ => return Err("offer side must be buy or sell".into()),
                };
                let amount_atoms = parse_onecoin_atoms(
                    data.get("amount").ok_or("offer amount is required")?,
                )?;
                let price_minor = parse_fiat_minor(
                    data.get("price").ok_or("offer price is required")?,
                )?;
                let currency = data
                    .get("currency")
                    .and_then(|value| value.as_str())
                    .unwrap_or("USD")
                    .trim()
                    .to_ascii_uppercase();
                if !["USD", "EUR", "AMD", "GBP"].contains(&currency.as_str()) {
                    return Err("unsupported fiat currency".into());
                }
                let rail_text = data
                    .get("rail")
                    .and_then(|value| value.as_str())
                    .ok_or("offer payment rail is required")?;
                let (rail, rail_label) = match rail_text.to_ascii_lowercase().as_str() {
                    "externalpayment" | "external_payment" => {
                        (FiatRail::ExternalPayment, "ExternalPayment")
                    }
                    "banktransfer" | "bank_transfer" => {
                        (FiatRail::BankTransfer, "BankTransfer")
                    }
                    "cash" => (FiatRail::Cash, "Cash"),
                    _ => return Err("unsupported payment rail".into()),
                };
                let now = now_unix();
                let expires = now.saturating_add(30 * 24 * 60 * 60);
                let signed = P2POffer::new(
                    &node.identity,
                    side.clone(),
                    amount_atoms,
                    price_minor,
                    currency.clone(),
                    rail,
                    None,
                    expires,
                )?;
                let signed_value = serde_json::to_value(&signed)
                    .map_err(|_| "signed offer serialization failed".to_string())?;
                let value = serde_json::json!({
                    "id": hex::encode(signed.id),
                    "side": side_text,
                    "amount": format_onecoin_atoms(amount_atoms),
                    "price": format!("{}.{:02}", price_minor / 100, price_minor % 100),
                    "currency": currency,
                    "rail": rail_label,
                    "owner": node.identity.public.awe_id.to_hex(),
                    "owner_public_key": hex::encode(node.identity.public.public_key),
                    "created_at": now,
                    "expires_at_unix": expires,
                    "signature_verified": signed.verify(&node.identity.public.public_key, now),
                    "signed_offer": signed_value,
                    "settlement": "DIRECT_PERSON_TO_PERSON",
                    "coin_transfer": "AWENET_WALLET",
                    "fiat_transfer": "OUTSIDE_AWENET"
                });
                Ok(value)
            })();
            match result {
                Ok(offer) => {
                    let mut offers: Vec<serde_json::Value> = fs::read(&onecoin_offers_path)
                        .ok()
                        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                        .unwrap_or_default();
                    offers.retain(|stored| {
                        stored
                            .get("signed_offer")
                            .cloned()
                            .and_then(|value| serde_json::from_value::<P2POffer>(value).ok())
                            .is_some_and(|signed| signed.verify(
                                &node.identity.public.public_key,
                                now_unix(),
                            ))
                    });
                    offers.push(offer.clone());
                    match fs::write(&onecoin_offers_path, serde_json::to_vec_pretty(&offers).unwrap_or_default()) {
                        Ok(()) => (
                            "200 OK",
                            "application/json; charset=utf-8",
                            serde_json::json!({
                                "status": "published",
                                "offer": offer,
                                "notice": "The offer is signed by this node. Fiat settlement is external and no payment is executed by this listing."
                            }).to_string(),
                        ),
                        Err(error) => (
                            "500 Internal Server Error",
                            "application/json; charset=utf-8",
                            serde_json::json!({"status":"error","error":error.to_string()}).to_string(),
                        ),
                    }
                }
                Err(error) => (
                    "400 Bad Request",
                    "application/json; charset=utf-8",
                    serde_json::json!({"status":"rejected","error":error}).to_string(),
                ),
            }
        },
        "/api/node" => ("200 OK", "application/json; charset=utf-8", serde_json::json!({
            "id": format_uid(node.identity.public.awe_id.as_bytes()),
            "descriptor": node.node_descriptor(),
            "username": node.identity.public.username.as_str(),
            "address": node.listen_addr.to_string(),
            "protocol": 1
        }).to_string()),
        "/api/policy" => {
            let policy = policy_state.lock().map(|p| p.clone()).unwrap_or_default();
            ("200 OK", "application/json; charset=utf-8", serde_json::to_string(&policy).unwrap_or_else(|_| "{}".into()))
        },
        "/api/status" => {
            let peers = node.closest_peers(node.identity.public.awe_id.as_bytes(), 64).await;
            let peer_json = peers.iter().map(|p| serde_json::json!({
                "id": format_uid(&p.awe_id),
                "address": p.addresses.first().map(ToString::to_string).unwrap_or_else(|| "unknown".into()),
                "last_seen": p.last_seen_unix
            })).collect::<Vec<_>>();
            ("200 OK", "application/json; charset=utf-8", serde_json::json!({
                "product": "AWEp2P", "status": "online",
                "node_id": format_uid(node.identity.public.awe_id.as_bytes()),
                "node_address": node.listen_addr.to_string(),
                "transport": "AWE encrypted TCP", "ui": "connected", "peers": peer_json, "discovered_peers": peer_json.len(), "active_connections": node.active_peer_count().await
            }).to_string())
        },
        "/api/connect" if method == "POST" => {
            let address = request.split("address=").nth(1).and_then(|x| x.split_whitespace().next()).unwrap_or("");
            let address = address.replace("%3A", ":").replace("%3a", ":");
            match address.parse::<SocketAddr>() {
                Ok(addr) => {
                    let connect_node = node.clone();
                    tokio::spawn(async move {
                        let _ = connect_node.bootstrap(&[addr]).await;
                    });
                    ("202 Accepted", "application/json; charset=utf-8",
                        serde_json::json!({"status":"connecting","address":addr.to_string()}).to_string())
                },
                Err(_) => ("400 Bad Request", "application/json; charset=utf-8", serde_json::json!({"status":"error","error":"invalid socket address"}).to_string())
            }
        },
        "/api/federation" => {
            let state = federation_state.lock().map(|s| s.clone()).unwrap_or_default();
            ("200 OK", "application/json; charset=utf-8", serde_json::json!({
                "format": state.format, "version": state.version, "local_node_id": state.local_node_id,
                "data_centre_id": state.local_data_centre_id, "data_group_id": state.local_data_group_id,
                "joined_data_centres": state.joined_data_centres, "joined_data_groups": state.joined_data_groups,
                "bootstrap_endpoints": state.bootstrap_endpoints
            }).to_string())
        },
        "/api/federation/generate" if method == "POST" => {
            let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
            let parsed: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
            let kind = parsed.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            let name = parsed.get("name").and_then(|v| v.as_str()).unwrap_or("AWE");
            let now = now_unix();
            let result: Result<(String, String), String> = match kind {
                "awenode" => {
                    let endpoint = parsed.get("endpoint").and_then(|v| v.as_str()).map(str::to_owned).unwrap_or_else(|| node.listen_addr.to_string());
                    let bootstrap = parsed.get("bootstrap").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect()).unwrap_or_default();
                    let dc_id = parsed.get("data_centre_id").and_then(|v| v.as_str()).map(str::to_owned).or_else(|| federation_state.lock().ok().and_then(|s| s.local_data_centre_id.clone())).unwrap_or_else(|| format!("dc-{}", &hex::encode(blake3::hash(format!("AWE/DC/{}", format_uid(node.identity.public.awe_id.as_bytes())).as_bytes()).as_bytes())[..24]));
                    let cfg = federation::generate_awenode_for_dc(&format_uid(node.identity.public.awe_id.as_bytes()), &dc_id, name, &endpoint, bootstrap, now);
                    serde_json::to_string_pretty(&cfg).map(|s| ("awenode.awenode".into(), s)).map_err(|e| e.to_string())
                },
                "awedc" => {
                    let dc_id = parsed.get("data_centre_id").and_then(|v| v.as_str()).unwrap_or("");
                    let endpoints = parsed.get("endpoints").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect()).unwrap_or_else(|| vec![node.listen_addr.to_string()]);
                    let members = parsed.get("member_node_ids").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect()).unwrap_or_else(|| vec![format_uid(node.identity.public.awe_id.as_bytes())]);
                    if dc_id.is_empty() { Err("data_centre_id is required".into()) } else {
                        let cfg = federation::generate_awedc(&format_uid(node.identity.public.awe_id.as_bytes()), dc_id, name, endpoints, members, now);
                        serde_json::to_string_pretty(&cfg).map(|s| ("data-centre.awedc".into(), s)).map_err(|e| e.to_string())
                    }
                },
                "dgc" => {
                    let dc_id = parsed.get("owner_data_centre_id").and_then(|v| v.as_str()).unwrap_or("");
                    let centres = parsed.get("data_centre_ids").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect()).unwrap_or_default();
                    if dc_id.is_empty() { Err("owner_data_centre_id is required".into()) } else {
                        let cfg = federation::generate_dgc(dc_id, name, centres, now);
                        serde_json::to_string_pretty(&cfg).map(|s| ("data-group.dgc".into(), s)).map_err(|e| e.to_string())
                    }
                },
                _ => Err("kind must be awenode, awedc or dgc".to_string())
            };
            match result {
                Ok((filename, content)) => ("200 OK", "application/json; charset=utf-8", serde_json::json!({"status":"generated","filename":filename,"content":content}).to_string()),
                Err(error) => ("400 Bad Request", "application/json; charset=utf-8", serde_json::json!({"status":"error","error":error.to_string()}).to_string())
            }
        },
        "/api/federation/import" if method == "POST" => {
            let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
            let parsed: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
            let kind = parsed.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            let content = parsed.get("content").and_then(|v| v.as_str()).unwrap_or("");
            let result: Result<(), anyhow::Error> = match kind {
                "awenode" => {
                    let cfg: AweNodeConfig = serde_json::from_str(content)?;
                    federation::validate_awenode(&cfg).map_err(anyhow::Error::msg)?;
                    let mut s = federation_state.lock().map_err(|_| anyhow::anyhow!("state lock poisoned"))?;
                    s.local_node_id = format_uid(node.identity.public.awe_id.as_bytes());
                    s.local_data_centre_id = Some(cfg.data_centre_id.clone());
                    s.bootstrap_endpoints = cfg.bootstrap_endpoints.clone();
                    if !s.bootstrap_endpoints.contains(&cfg.endpoint) {
                        s.bootstrap_endpoints.push(cfg.endpoint.clone());
                    }
                    if !s.joined_data_centres.contains(&cfg.data_centre_id) { s.joined_data_centres.push(cfg.data_centre_id); }
                    s.format = "awenet".into(); s.version = federation::FORMAT_VERSION;
                    Ok(())
                },
                "awedc" => {
                    let cfg: DataCentreConfig = serde_json::from_str(content).map_err(anyhow::Error::msg)?;
                    federation::validate_awedc(&cfg).map_err(anyhow::Error::msg)?;
                    let mut s = federation_state.lock().map_err(|_| anyhow::anyhow!("state lock poisoned"))?;
                    s.local_node_id = format_uid(node.identity.public.awe_id.as_bytes());
                    // .awedc is a data-centre federation invitation: it adds the
                    // remote DC as a peer, rather than silently changing this node's
                    // own DC identity.
                    if s.local_data_centre_id.is_none() {
                        s.local_data_centre_id = Some(format!("dc-{}", &hex::encode(blake3::hash(format!("AWE/DC/{}", s.local_node_id).as_bytes()).as_bytes())[..24]));
                    }
                    s.bootstrap_endpoints.extend(cfg.endpoints.clone());
                    s.bootstrap_endpoints.sort(); s.bootstrap_endpoints.dedup();
                    if !s.joined_data_centres.contains(&cfg.data_centre_id) { s.joined_data_centres.push(cfg.data_centre_id.clone()); }
                    s.format = "awenet".into(); s.version = federation::FORMAT_VERSION;
                    Ok(())
                },
                "dgc" => {
                    let cfg: DataGroupConfig = serde_json::from_str(content).map_err(anyhow::Error::msg)?;
                    federation::validate_dgc(&cfg).map_err(anyhow::Error::msg)?;
                    let mut s = federation_state.lock().map_err(|_| anyhow::anyhow!("state lock poisoned"))?;
                    s.local_node_id = format_uid(node.identity.public.awe_id.as_bytes());
                    s.local_data_group_id = Some(cfg.data_group_id.clone());
                    for dc in cfg.data_centre_ids.clone() { if !s.joined_data_centres.contains(&dc) { s.joined_data_centres.push(dc); } }
                    if !s.joined_data_groups.contains(&cfg.data_group_id) { s.joined_data_groups.push(cfg.data_group_id); }
                    s.format = "awenet".into(); s.version = federation::FORMAT_VERSION;
                    Ok(())
                },
                _ => Err(anyhow::anyhow!("kind must be awenode, awedc or dgc"))
            };
            match result {
                Ok(()) => {
                    let endpoints = federation_state.lock().map(|s| s.bootstrap_endpoints.clone()).unwrap_or_default();
                    let addresses = endpoints.iter().filter_map(|x| x.parse::<SocketAddr>().ok()).collect::<Vec<_>>();
                    let discovered = if addresses.is_empty() { 0 } else { node.bootstrap(&addresses).await.unwrap_or(0) };
                    if let Ok(state) = federation_state.lock() { let _ = federation::save_json(&*state, &federation_path); }
                    ("200 OK", "application/json; charset=utf-8", serde_json::json!({"status":"imported","connected_bootstrap_peers":discovered}).to_string())
                },
                Err(error) => ("400 Bad Request", "application/json; charset=utf-8", serde_json::json!({"status":"error","error":error.to_string()}).to_string())
            }
        },
        "/api/health" => ("200 OK", "application/json; charset=utf-8", serde_json::json!({
            "status":"healthy","core":"ready","network":"listening","ui":"ready","api":"ready"
        }).to_string()),
        "/api/call/signals" => {
            let since = request.lines().next().unwrap_or("").split_whitespace().nth(1)
                .and_then(|p| p.split('?').nth(1))
                .and_then(|q| q.split('&').find_map(|v| v.strip_prefix("since=")))
                .and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
            let local_uid = format_uid(node.identity.public.awe_id.as_bytes());
            let signals = messenger.lock().map(|log| log.iter().filter(|m| {
                m.get("kind").and_then(|v| v.as_str()) == Some("awe.call.v1")
                    && m.get("recipient").and_then(|v| v.as_str()) == Some(local_uid.as_str())
                    && m.get("timestamp").and_then(|v| v.as_u64()).unwrap_or(0) > since
            }).cloned().collect::<Vec<_>>()).unwrap_or_default();
            ("200 OK", "application/json; charset=utf-8", serde_json::json!({"status":"ok","signals":signals}).to_string())
        },
        "/api/call/signal" if method == "POST" => {
            let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
            let parsed: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
            let recipient = parsed.get("recipient").and_then(|v| v.as_str()).unwrap_or("").trim();
            let call_id = parsed.get("call_id").and_then(|v| v.as_str()).unwrap_or("").trim();
            let signal_type = parsed.get("signal_type").and_then(|v| v.as_str()).unwrap_or("").trim();
            let data = parsed.get("data").and_then(|v| v.as_str()).unwrap_or("");
            if recipient.is_empty() || call_id.is_empty() || signal_type.is_empty() || data.is_empty() {
                ("400 Bad Request", "application/json; charset=utf-8", serde_json::json!({"status":"error","error":"recipient, call_id, signal_type and data are required"}).to_string())
            } else {
                let peers = node.closest_peers(node.identity.public.awe_id.as_bytes(), 64).await;
                let recipient_id = hex::decode(recipient).ok().and_then(|b| <[u8;32]>::try_from(b).ok())
                    .or_else(|| peers.iter().find(|p| format_uid(&p.awe_id) == recipient).map(|p| p.awe_id));
                match recipient_id {
                    None => ("400 Bad Request", "application/json; charset=utf-8", serde_json::json!({"status":"error","error":"recipient must be a 64-hex AWE ID or discovered UID"}).to_string()),
                    Some(recipient_id) => {
                        let timestamp = now_unix();
                        let digest = blake3::hash(format!("call:{}:{}:{}:{}", call_id, signal_type, timestamp, format_uid(node.identity.public.awe_id.as_bytes())).as_bytes());
                        let id = hex::encode(&digest.as_bytes()[..16]);
                        let envelope = serde_json::json!({
                            "kind":"awe.call.v1","id":id,"call_id":call_id,
                            "sender":format_uid(node.identity.public.awe_id.as_bytes()),
                            "recipient":format_uid(&recipient_id),"signal_type":signal_type,"data":data,"timestamp":timestamp
                        });
                        match serde_json::to_vec(&envelope) {
                            Ok(payload) => match node.send_to_peer(&recipient_id, 100, payload).await {
                                Ok(_) => {
                                    if let Ok(mut log)=messenger.lock(){ log.push(envelope.clone()); }
                                    ("200 OK","application/json; charset=utf-8",serde_json::json!({"status":"sent","signal":envelope}).to_string())
                                },
                                Err(error)=>("502 Bad Gateway","application/json; charset=utf-8",serde_json::json!({"status":"error","error":error.to_string()}).to_string())
                            },
                            Err(error)=>("500 Internal Server Error","application/json; charset=utf-8",serde_json::json!({"status":"error","error":error.to_string()}).to_string())
                        }
                    }
                }
            }
        },
        "/api/groups" => {
            let groups = community.lock().map(|s| s.get("groups").cloned().unwrap_or_else(|| serde_json::json!([]))).unwrap_or_else(|_| serde_json::json!([]));
            ("200 OK", "application/json; charset=utf-8", serde_json::json!({"status":"ok","groups":groups}).to_string())
        },
        "/api/groups/create" if method == "POST" => {
            let body=request.split("\r\n\r\n").nth(1).unwrap_or("");
            let p:serde_json::Value=serde_json::from_str(body).unwrap_or_default();
            let title=p.get("title").and_then(|v|v.as_str()).unwrap_or("").trim().to_string();
            let mut members=p.get("members").and_then(|v|v.as_array()).cloned().unwrap_or_default().into_iter().filter_map(|v|v.as_str().map(str::to_string)).filter(|v|!v.is_empty()).collect::<Vec<_>>();
            let local=node.identity.public.awe_id.to_hex();
            if title.is_empty(){("400 Bad Request","application/json; charset=utf-8",serde_json::json!({"status":"error","error":"title is required"}).to_string())}else{
                if !members.contains(&local){members.push(local.clone());} members.sort();members.dedup();
                let id=format!("gid-{}",hex::encode(&blake3::hash(format!("{}:{}:{}",local,title,now_unix()).as_bytes()).as_bytes()[..12]));
                let group=serde_json::json!({"id":id,"title":title,"owner":local,"members":members,"created_at":now_unix(),"messages":[]});
                if let Ok(mut s)=community.lock(){if let Some(a)=s.get_mut("groups").and_then(|v|v.as_array_mut()){a.push(group.clone());}}
                let env=serde_json::json!({"kind":"awe.group.v1","event":"upsert","group":group,"sender":local});
                let members=group.get("members").and_then(|v|v.as_array()).cloned().unwrap_or_default(); let mut delivered=0usize;
                if let Ok(payload)=serde_json::to_vec(&env){for peer in node.peers().await{let pid=hex::encode(peer.awe_id);if pid!=local&&members.iter().any(|v|v.as_str()==Some(pid.as_str()))&&node.send_to_peer(&peer.awe_id,100,payload.clone()).await.is_ok(){delivered+=1;}}}
                ("200 OK","application/json; charset=utf-8",serde_json::json!({"status":"created","group":group,"delivered_members":delivered}).to_string())
            }
        },
        "/api/groups/send" if method == "POST" => {
            let body=request.split("\r\n\r\n").nth(1).unwrap_or(""); let p:serde_json::Value=serde_json::from_str(body).unwrap_or_default();
            let gid=p.get("group_id").and_then(|v|v.as_str()).unwrap_or("").trim(); let text=p.get("text").and_then(|v|v.as_str()).unwrap_or("").trim(); let local=node.identity.public.awe_id.to_hex();
            if gid.is_empty()||text.is_empty(){("400 Bad Request","application/json; charset=utf-8",serde_json::json!({"status":"error","error":"group_id and text are required"}).to_string())}else{
                let group=community.lock().ok().and_then(|s|s.get("groups").and_then(|v|v.as_array()).and_then(|a|a.iter().find(|g|g.get("id").and_then(|v|v.as_str())==Some(gid)).cloned()));
                match group{
                    None=>("404 Not Found","application/json; charset=utf-8",serde_json::json!({"status":"error","error":"group not found"}).to_string()),
                    Some(group) if !group.get("members").and_then(|v|v.as_array()).map(|a|a.iter().any(|v|v.as_str()==Some(local.as_str()))).unwrap_or(false)=>("403 Forbidden","application/json; charset=utf-8",serde_json::json!({"status":"error","error":"not a group member"}).to_string()),
                    Some(group)=>{
                        let timestamp=now_unix(); let message=serde_json::json!({"id":hex::encode(&blake3::hash(format!("group:{}:{}:{}",gid,local,timestamp).as_bytes()).as_bytes()[..16]),"sender":local,"text":text,"timestamp":timestamp});
                        if let Ok(mut st)=community.lock(){if let Some(g)=st.get_mut("groups").and_then(|v|v.as_array_mut()).and_then(|a|a.iter_mut().find(|g|g.get("id").and_then(|v|v.as_str())==Some(gid))){if let Some(a)=g.get_mut("messages").and_then(|v|v.as_array_mut()){a.push(message.clone());}}}
                        let env=serde_json::json!({"kind":"awe.group.v1","event":"message","group_id":gid,"message":message,"sender":local}); let members=group.get("members").and_then(|v|v.as_array()).cloned().unwrap_or_default(); let mut delivered=0usize;
                        if let Ok(payload)=serde_json::to_vec(&env){for peer in node.peers().await{let pid=hex::encode(peer.awe_id);if pid!=local&&members.iter().any(|v|v.as_str()==Some(pid.as_str())){let sent=node.send_to_peer_confirmed(&peer.awe_id,100,payload.clone()).await.is_ok()||node.send_to_peer(&peer.awe_id,100,payload.clone()).await.is_ok();if sent{delivered+=1;}}}}
                        ("200 OK","application/json; charset=utf-8",serde_json::json!({"status":"sent","message":message,"delivered_members":delivered}).to_string())
                    }
                }
            }
        },
        "/api/channels" => {
            let channels=community.lock().map(|s|s.get("channels").cloned().unwrap_or_else(||serde_json::json!([]))).unwrap_or_else(|_|serde_json::json!([]));
            ("200 OK","application/json; charset=utf-8",serde_json::json!({"status":"ok","channels":channels}).to_string())
        },
        "/api/channels/create" if method == "POST" => {
            let body=request.split("\r\n\r\n").nth(1).unwrap_or(""); let p:serde_json::Value=serde_json::from_str(body).unwrap_or_default(); let title=p.get("title").and_then(|v|v.as_str()).unwrap_or("").trim().to_string(); let local=node.identity.public.awe_id.to_hex();
            if title.is_empty(){("400 Bad Request","application/json; charset=utf-8",serde_json::json!({"status":"error","error":"title is required"}).to_string())}else{
                let id=format!("cid-{}",hex::encode(&blake3::hash(format!("{}:{}:{}",local,title,now_unix()).as_bytes()).as_bytes()[..12])); let channel=serde_json::json!({"id":id,"title":title,"owner":local,"subscribers":[local],"created_at":now_unix(),"messages":[]});
                if let Ok(mut st)=community.lock(){if let Some(a)=st.get_mut("channels").and_then(|v|v.as_array_mut()){a.push(channel.clone());}}
                let env=serde_json::json!({"kind":"awe.channel.v1","event":"upsert","channel":channel,"sender":local}); let mut delivered=0usize;
                if let Ok(payload)=serde_json::to_vec(&env) {
                    for peer in node.peers().await {
                        let sent = match node.send_to_peer_confirmed(&peer.awe_id,100,payload.clone()).await {
                            Ok(_) => true,
                            Err(_) => node.send_to_peer(&peer.awe_id,100,payload.clone()).await.is_ok(),
                        };
                        if sent { delivered+=1; }
                    }
                }
                ("200 OK","application/json; charset=utf-8",serde_json::json!({"status":"created","channel":channel,"delivered_peers":delivered}).to_string())
            }
        },
        "/api/channels/subscribe" if method == "POST" => {
            let body=request.split("\r\n\r\n").nth(1).unwrap_or("");
            let p:serde_json::Value=serde_json::from_str(body).unwrap_or_default();
            let cid=p.get("channel_id").and_then(|v|v.as_str()).unwrap_or("").trim();
            let local=node.identity.public.awe_id.to_hex();
            let channel=community.lock().ok().and_then(|s|s.get("channels").and_then(|v|v.as_array()).and_then(|a|a.iter().find(|c|c.get("id").and_then(|v|v.as_str())==Some(cid)).cloned()));
            match channel {
                None if cid.is_empty()=>("400 Bad Request","application/json; charset=utf-8",serde_json::json!({"status":"error","error":"channel_id is required"}).to_string()),
                None=>("404 Not Found","application/json; charset=utf-8",serde_json::json!({"status":"error","error":"channel not found"}).to_string()),
                Some(channel)=>{
                    let owner=channel.get("owner").and_then(|v|v.as_str()).unwrap_or("").to_string();
                    if let Ok(mut st)=community.lock(){if let Some(ch)=st.get_mut("channels").and_then(|v|v.as_array_mut()).and_then(|a|a.iter_mut().find(|c|c.get("id").and_then(|v|v.as_str())==Some(cid))){if let Some(a)=ch.get_mut("subscribers").and_then(|v|v.as_array_mut()){if !a.iter().any(|v|v.as_str()==Some(local.as_str())){a.push(serde_json::Value::String(local.clone()));}}}}
                    if owner==local {
                        ("200 OK","application/json; charset=utf-8",serde_json::json!({"status":"subscribed","channel_id":cid,"subscriber":local,"owner_notified":true}).to_string())
                    } else {
                        let owner_id=hex::decode(&owner).ok().and_then(|b|<[u8;32]>::try_from(b).ok());
                        let event=serde_json::json!({"kind":"awe.channel.v1","event":"subscribe","channel_id":cid,"subscriber":local});
                        let (sent, delivery_error) = match owner_id {
                            Some(id) => match serde_json::to_vec(&event) {
                                Ok(bytes) => match node.send_to_peer_confirmed(&id, 100, bytes.clone()).await {
                                    Ok(_) => (true, None),
                                    Err(confirmed_error) => match node.send_to_peer(&id, 100, bytes).await {
                                        Ok(_) => (true, None),
                                        Err(fallback_error) => (false, Some(format!(
                                            "confirmed send failed: {confirmed_error}; fallback send failed: {fallback_error}"
                                        ))),
                                    },
                                },
                                Err(error) => (false, Some(error.to_string())),
                            },
                            None => (false, Some("invalid channel owner AWEID".to_string())),
                        };
                        (if sent{"200 OK"}else{"202 Accepted"},"application/json; charset=utf-8",serde_json::json!({"status":"subscribed","channel_id":cid,"subscriber":local,"owner_notified":sent,"pending":!sent,"delivery_error":delivery_error}).to_string())
                    }
                }
            }
        },
        "/api/channels/publish" if method == "POST" => {
            let body=request.split("\r\n\r\n").nth(1).unwrap_or(""); let p:serde_json::Value=serde_json::from_str(body).unwrap_or_default(); let cid=p.get("channel_id").and_then(|v|v.as_str()).unwrap_or("").trim(); let text=p.get("text").and_then(|v|v.as_str()).unwrap_or("").trim(); let local=node.identity.public.awe_id.to_hex();
            let channel=community.lock().ok().and_then(|s|s.get("channels").and_then(|v|v.as_array()).and_then(|a|a.iter().find(|c|c.get("id").and_then(|v|v.as_str())==Some(cid)).cloned()));
            match channel{
                None=>("404 Not Found","application/json; charset=utf-8",serde_json::json!({"status":"error","error":"channel not found"}).to_string()),
                Some(channel) if channel.get("owner").and_then(|v|v.as_str())!=Some(local.as_str())=>("403 Forbidden","application/json; charset=utf-8",serde_json::json!({"status":"error","error":"only channel owner may publish"}).to_string()),
                Some(_channel) if text.is_empty()=>("400 Bad Request","application/json; charset=utf-8",serde_json::json!({"status":"error","error":"text is required"}).to_string()),
                Some(_channel)=>{
                    let message=serde_json::json!({"id":hex::encode(&blake3::hash(format!("channel:{}:{}:{}",cid,local,now_unix()).as_bytes()).as_bytes()[..16]),"sender":local,"text":text,"timestamp":now_unix()});
                    if let Ok(mut st)=community.lock(){if let Some(ch)=st.get_mut("channels").and_then(|v|v.as_array_mut()).and_then(|a|a.iter_mut().find(|c|c.get("id").and_then(|v|v.as_str())==Some(cid))){if let Some(a)=ch.get_mut("messages").and_then(|v|v.as_array_mut()){a.push(message.clone());}}}
                    let env=serde_json::json!({"kind":"awe.channel.v1","event":"message","channel_id":cid,"message":message,"sender":local}); let mut delivered=0usize;
                    let active=node.active_peers().await;
                    for peer_id in active{let pid=format_uid(&peer_id);if pid!=local{let send_node=node.clone();let bytes=serde_json::to_vec(&env).unwrap_or_default();let fallback=serde_json::json!({"kind":"awe.messenger.v1","id":message.get("id").cloned().unwrap_or_else(||serde_json::json!("")),"sender":local,"recipient":pid,"text":text,"timestamp":message.get("timestamp").cloned().unwrap_or_else(||serde_json::json!(now_unix())),"channel_id":cid,"channel_message":message.clone(),"silent":true});let fallback_bytes=serde_json::to_vec(&fallback).unwrap_or_default();tokio::spawn(async move{if send_node.send_to_peer(&peer_id,100,bytes).await.is_err(){let _=send_node.send_to_peer_confirmed(&peer_id,100,fallback_bytes.clone()).await;}else{let _=send_node.send_to_peer(&peer_id,100,fallback_bytes).await;}});delivered+=1;}}
                    ("200 OK","application/json; charset=utf-8",serde_json::json!({"status":"published","message":message,"delivered_subscribers":delivered}).to_string())
                }
            }
        },
        "/api/messenger" => {
            ("200 OK", "application/json; charset=utf-8", serde_json::json!({
                "transport":"AWE encrypted TCP",
                "application_transport":"authenticated peer data stream",
                "messages": messenger.lock().map(|x| x.clone()).unwrap_or_default()
            }).to_string())
        },
        "/api/store/publish" if method == "POST" => {
            let body = request.split_once("\r\n\r\n").map(|(_, body)| body).unwrap_or("");
            let parsed = serde_json::from_str::<serde_json::Value>(body);
            match parsed {
                Err(_) => ("400 Bad Request", "application/json; charset=utf-8", serde_json::json!({"status":"error","error":"invalid JSON body"}).to_string()),
                Ok(payload) => {
                    let id = payload.get("id").and_then(|v| v.as_str()).unwrap_or("").trim();
                    let name = payload.get("name").and_then(|v| v.as_str()).unwrap_or("").trim();
                    let version = payload.get("version").and_then(|v| v.as_str()).unwrap_or("").trim();
                    let entry = payload.get("entry").and_then(|v| v.as_str()).unwrap_or("").trim();
                    let kind = payload.get("kind").and_then(|v| serde_json::from_value::<AppKind>(v.clone()).ok());
                    let permissions = payload.get("permissions").cloned()
                        .map(serde_json::from_value::<Vec<AppCapability>>);
                    let price_value = payload.get("price_onecoin_atoms");
                    let price = match price_value {
                        None | Some(serde_json::Value::Null) => Some(None),
                        Some(v) => v.as_str().and_then(|s| s.parse::<u128>().ok())
                            .or_else(|| v.as_u64().map(u128::from)).map(Some),
                    };
                    let file_values = payload.get("files").and_then(|v| v.as_array()).cloned().unwrap_or_default();
                    if id.is_empty() || name.is_empty() || version.is_empty() || entry.is_empty() || kind.is_none() || permissions.as_ref().is_none_or(|p| p.is_err()) || price.is_none() || file_values.is_empty() || file_values.len() > 256 {
                        ("400 Bad Request", "application/json; charset=utf-8", serde_json::json!({"status":"error","error":"id, name, version, entry, kind, valid permissions/price and 1-256 files are required"}).to_string())
                    } else {
                        let permissions = permissions.and_then(Result::ok).unwrap_or_default();
                        let price = price.flatten();
                        let mut files = BTreeMap::new();
                        let mut invalid = None;
                        for file in file_values {
                            let path = file.get("path").and_then(|v| v.as_str()).unwrap_or("");
                            let data = file.get("data_hex").and_then(|v| v.as_str()).and_then(|v| hex::decode(v).ok());
                            match data {
                                Some(bytes) if !path.is_empty() && path.starts_with('/') && !path.contains('\\') && !path.split('/').any(|part| part == "..") && !files.contains_key(path) => { files.insert(path.to_string(), bytes); }
                                _ => { invalid = Some("each file needs a unique safe absolute path and valid data_hex"); break; }
                            }
                        }
                        if let Some(error) = invalid {
                            ("400 Bad Request", "application/json; charset=utf-8", serde_json::json!({"status":"error","error":error}).to_string())
                        } else if files.values().map(Vec::len).sum::<usize>() > 24 * 1024 * 1024 {
                            ("413 Payload Too Large", "application/json; charset=utf-8", serde_json::json!({"status":"error","error":"package upload exceeds the 24 MiB API limit"}).to_string())
                        } else if !files.contains_key(entry) {
                            ("400 Bad Request", "application/json; charset=utf-8", serde_json::json!({"status":"error","error":"entry must reference one of the uploaded files"}).to_string())
                        } else {
                            let root = PathBuf::from(data_dir_for_api()).join("store");
                            let package = AWEPackage::new(&node.identity, id, name, version, kind.unwrap_or(AppKind::Wasm), entry, files, permissions, Vec::new())
                                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e));
                            match package.and_then(|mut package| {
                                if let Some(atoms) = price { package.set_price_onecoin(&node.identity, Some(atoms)).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?; }
                                Store::open(&root)?.publish(&package)
                            }) {
                                Ok(hash) => {
                                    let hash = hex::encode(hash);
                                    let size = fs::metadata(root.join("packages").join(&hash)).map(|m| m.len()).unwrap_or(0);
                                    ("200 OK", "application/json; charset=utf-8", serde_json::json!({"status":"published","package_hash":hash,"id":id,"name":name,"size":size,"scope":"local-store","signed_by":format_uid(node.identity.public.awe_id.as_bytes())}).to_string())
                                }
                                Err(error) => ("400 Bad Request", "application/json; charset=utf-8", serde_json::json!({"status":"error","error":error.to_string()}).to_string())
                            }
                        }
                    }
                }
            }
        },
        "/api/store/catalog" => {
            let root = PathBuf::from(data_dir_for_api()).join("store");
            match Store::open(&root) {
                Ok(_store) => {
                    let mut apps = Vec::new();
                    if let Ok(entries) = fs::read_dir(root.join("packages")) {
                        for entry in entries.flatten() {
                            if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) { continue; }
                            let Ok(bytes) = fs::read(entry.path()) else { continue; };
                            let Ok(package) = awep2p_core::store::AWEPackage::from_bytes(&bytes) else { continue; };
                            let package_hash = hex::encode(blake3::hash(&bytes).as_bytes());
                            apps.push(serde_json::json!({
                                "package_hash": package_hash,
                                "manifest": package.manifest.manifest
                            }));
                        }
                    }
                    apps.sort_by(|a,b| a.get("package_hash").and_then(|v| v.as_str()).cmp(&b.get("package_hash").and_then(|v| v.as_str())));
                    let installed = fs::read_dir(root.join("installed")).ok().into_iter().flatten()
                        .filter_map(|e| e.ok()).filter_map(|e| fs::read(e.path()).ok())
                        .filter_map(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                        .collect::<Vec<_>>();
                    ("200 OK", "application/json; charset=utf-8", serde_json::json!({"status":"ok","apps":apps,"installed":installed}).to_string())
                }
                Err(error) => ("500 Internal Server Error", "application/json; charset=utf-8", serde_json::json!({"status":"error","error":error.to_string()}).to_string())
            }
        },
        "/api/store/install" if method == "POST" => {
            let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
            let parsed: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
            let hash = parsed.get("package_hash").and_then(|v| v.as_str()).unwrap_or("");
            let granted = parsed.get("granted_permissions").cloned().unwrap_or_else(|| serde_json::json!([]));
            let hash_bytes = hex::decode(hash).ok().and_then(|b| <[u8;32]>::try_from(b).ok());
            let permissions: Result<Vec<AppCapability>, _> = serde_json::from_value(granted);
            match (hash_bytes, permissions) {
                (Some(hash), Ok(permissions)) => {
                    let root = PathBuf::from(data_dir_for_api()).join("store");
                    match Store::open(&root).and_then(|store| store.install(&hash, &permissions)) {
                        Ok(app) => ("200 OK", "application/json; charset=utf-8", serde_json::json!({"status":"installed","app":app}).to_string()),
                        Err(error) => ("400 Bad Request", "application/json; charset=utf-8", serde_json::json!({"status":"error","error":error.to_string()}).to_string())
                    }
                }
                _ => ("400 Bad Request", "application/json; charset=utf-8", serde_json::json!({"status":"error","error":"invalid package hash or permissions"}).to_string())
            }
        },
        "/api/security" => ("200 OK", "application/json; charset=utf-8", serde_json::json!({
            "identity":"ed25519","transport":"x25519 + chacha20-poly1305","replay_protection":"enabled","a2p2_fixed_packet":1280
        }).to_string()),
        "/api/messenger/send" if method == "POST" => {
            let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
            let parsed: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
            let recipient = parsed.get("recipient").and_then(|v| v.as_str()).unwrap_or("").trim();
            let text = parsed.get("text").and_then(|v| v.as_str()).unwrap_or("").trim();
            if recipient.is_empty() || text.is_empty() {
                ("400 Bad Request", "application/json; charset=utf-8", serde_json::json!({"status":"error","error":"recipient and text are required"}).to_string())
            } else {
                let runtime_policy = policy_state.lock().map(|p| p.clone()).unwrap_or_default();
                if !runtime_policy.allows_message(text.len()) || !runtime_policy.allows_stream(policy::MESSENGER_STREAM) {
                    ("413 Payload Too Large", "application/json; charset=utf-8", serde_json::json!({"status":"rejected","error":"message rejected by local AWENET policy"}).to_string())
                } else {
                let peers = node.closest_peers(node.identity.public.awe_id.as_bytes(), 64).await;
                let recipient_id = if let Some(hex_id) = recipient.strip_prefix("0x").or_else(|| recipient.strip_prefix("0X")) {
                    hex::decode(hex_id).ok().and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                } else {
                    hex::decode(recipient).ok().and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                }.or_else(|| {
                    peers.iter().find(|peer| format_uid(&peer.awe_id) == recipient).map(|peer| peer.awe_id)
                });
                match recipient_id {
                    None => ("400 Bad Request", "application/json; charset=utf-8", serde_json::json!({"status":"error","error":"recipient must be a 64-hex AWE ID or a discovered UID"}).to_string()),
                    Some(recipient_id) => {
                        let timestamp = now_unix();
                let digest = blake3::hash(format!("{}:{}:{}:{}", format_uid(node.identity.public.awe_id.as_bytes()), recipient, text, timestamp).as_bytes());
                let message_id = hex::encode(&digest.as_bytes()[..16]);
                let envelope = serde_json::json!({
                    "kind": "awe.messenger.v1",
                    "id": message_id,
                    "sender": format_uid(node.identity.public.awe_id.as_bytes()),
                    "recipient": format_uid(&recipient_id),
                    "text": text,
                    "timestamp": timestamp
                });
                match serde_json::to_vec(&envelope) {
                    Ok(payload) => match node.send_to_peer(&recipient_id, 100, payload).await {
                        Ok(rtt) => {
                            let item = serde_json::json!({
                                "id": message_id,
                                "sender": format_uid(node.identity.public.awe_id.as_bytes()),
                                "recipient": format_uid(&recipient_id),
                                "text": text,
                                "state": "sent",
                                "timestamp": timestamp,
                                "rtt_ms": rtt.as_millis()
                            });
                            if let Ok(mut log) = messenger.lock() {
                                log.push(item.clone());
                            }
                            ("200 OK", "application/json; charset=utf-8", serde_json::json!({"status":"sent","message":item}).to_string())
                        }
                        Err(error) => {
                            let item = serde_json::json!({
                                "id": message_id,
                                "sender": format_uid(node.identity.public.awe_id.as_bytes()),
                                "recipient": format_uid(&recipient_id),
                                "text": text,
                                "state": "failed",
                                "timestamp": timestamp,
                                "error": error.to_string()
                            });
                            if let Ok(mut log) = messenger.lock() {
                                log.push(item.clone());
                            }
                            ("502 Bad Gateway", "application/json; charset=utf-8", serde_json::json!({"status":"failed","message":item}).to_string())
                        }
                    },
                    Err(error) => ("500 Internal Server Error", "application/json; charset=utf-8", serde_json::json!({"status":"error","error":error.to_string()}).to_string())
                }
                    }
                }
            }
        }
        },
        "/api/storage/put" if method == "POST" => {
            let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
            let parsed: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
            let filename = parsed.get("filename").and_then(|v| v.as_str()).unwrap_or("object.bin").trim();
            let data_hex = parsed.get("data_hex").and_then(|v| v.as_str()).unwrap_or("").trim();

            if filename.is_empty() || data_hex.is_empty() {
                ("400 Bad Request", "application/json; charset=utf-8",
                    serde_json::json!({"status":"error","error":"filename and data_hex are required"}).to_string())
            } else {
                match hex::decode(data_hex) {
                    Err(_) => ("400 Bad Request", "application/json; charset=utf-8",
                        serde_json::json!({"status":"error","error":"data_hex is not valid hexadecimal"}).to_string()),
                    Ok(data) => {
                        let runtime_policy = policy_state.lock().map(|p| p.clone()).unwrap_or_default();
                        if !runtime_policy.allows_upload(data.len()) || !runtime_policy.allows_stream(STORAGE_STREAM) {
                            ("403 Forbidden", "application/json; charset=utf-8", serde_json::json!({"status":"rejected","error":"upload rejected by local AWENET policy"}).to_string())
                        } else {
                        let policy = StoragePolicy::for_file_size(data.len());
                        let file_id = *blake3::hash(&data).as_bytes();
                        let peers = node.closest_peers(node.identity.public.awe_id.as_bytes(), 64).await;
                        let local_id = format_uid(node.identity.public.awe_id.as_bytes());
                        let mut node_ids = vec![local_id.clone()];
                        for peer in &peers {
                            let id = format_uid(&peer.awe_id);
                            if id != local_id && !node_ids.contains(&id) {
                                node_ids.push(id);
                            }
                        }

                        match awep2p_core::replication::build_plan_for_shards(file_id, &node_ids, policy.total_shards()) {
                            Err(error) => ("409 Conflict", "application/json; charset=utf-8",
                                serde_json::json!({"status":"error","error":error,"discovered_nodes":node_ids.len()}).to_string()),
                            Ok(plan) => match encode_shards(&data, &policy) {
                                Err(error) => ("500 Internal Server Error", "application/json; charset=utf-8",
                                    serde_json::json!({"status":"error","error":error.to_string()}).to_string()),
                                Ok(shards) => {
                                    let shard_hashes: Vec<String> = shards.iter()
                                        .map(|shard| hex::encode(blake3::hash(shard).as_bytes()))
                                        .collect();
                                    let mut peer_ids = std::collections::BTreeMap::<String, [u8; 32]>::new();
                                    for peer in peers {
                                        peer_ids.insert(format_uid(&peer.awe_id), peer.awe_id);
                                    }
                                    let mut stored_local = 0usize;
                                    let mut sent_remote = 0usize;
                                    let mut failed = Vec::new();
                                    let transfer_limit = Arc::new(tokio::sync::Semaphore::new(32));
                                    let mut remote_jobs: tokio::task::JoinSet<Result<(usize, Option<serde_json::Value>), String>> = tokio::task::JoinSet::new();

                                    for (index, shard) in shards.into_iter().enumerate() {
                                        let placement = &plan.placements[index];
                                        let shard_hash = *blake3::hash(&shard).as_bytes();
                                        for target in &placement.nodes {
                                            if target == &local_id {
                                                match storage.put(&shard) {
                                                    Ok(_) => stored_local += 1,
                                                    Err(error) => failed.push(serde_json::json!({
                                                        "shard": index, "node": target, "error": error.to_string()
                                                    }))
                                                }
                                            } else if let Some(peer_id) = peer_ids.get(target).copied() {
                                                let request_id = blake3::hash(
                                                    format!("upload:{}:{}:{}:{}", hex::encode(file_id), index, target, now_unix()).as_bytes()
                                                ).as_bytes()[..16].try_into().unwrap_or([0u8; 16]);
                                                let transfer = StorageShardTransfer::new(
                                                    request_id,
                                                    *node.identity.public.awe_id.as_bytes(),
                                                    file_id,
                                                    index as u16,
                                                    policy.total_shards() as u16,
                                                    data.len() as u64,
                                                    shard.clone(),
                                                );
                                                let Ok(bytes) = serde_json::to_vec(&transfer) else {
                                                    failed.push(serde_json::json!({
                                                        "shard": index, "node": target, "error": "failed to serialize storage transfer"
                                                    }));
                                                    continue;
                                                };
                                                let task_node = node.clone();
                                                let task_pending_acks = pending_acks.clone();
                                                let task_limit = transfer_limit.clone();
                                                let target_name = target.clone();
                                                remote_jobs.spawn(async move {
                                                    let _permit = task_limit.acquire_owned().await
                                                        .map_err(|_| "storage transfer scheduler closed".to_string())?;
                                                    match task_node.send_to_peer(&peer_id, STORAGE_STREAM, bytes).await {
                                                        Ok(_) => {
                                                            let deadline = tokio::time::Instant::now()
                                                                + std::time::Duration::from_secs(5);
                                                            let mut confirmed = false;
                                                            while tokio::time::Instant::now() < deadline {
                                                                if let Ok(mut acks) = task_pending_acks.lock() {
                                                                    if let Some(ack) = acks.remove(&request_id) {
                                                                        confirmed = ack.file_id == file_id
                                                                            && ack.shard_index == index as u16
                                                                            && ack.stored_object_id == shard_hash;
                                                                        break;
                                                                    }
                                                                }
                                                                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                                                            }
                                                            if confirmed {
                                                                Ok((1usize, None))
                                                            } else {
                                                                // The transport accepted the shard and the receiver's data-plane
                                                                // handler persists it before attempting the application ACK.
                                                                // Keep the transfer successful when only the ACK callback is
                                                                // unavailable, while exposing that the application ACK was missed.
                                                                Ok((
                                                                    1usize,
                                                                    Some(serde_json::json!({
                                                                        "shard": index,
                                                                        "node": target_name,
                                                                        "warning": "remote storage ACK not confirmed"
                                                                    })),
                                                                ))
                                                            }
                                                        }
                                                        Err(error) => Ok((0usize, Some(serde_json::json!({
                                                            "shard": index, "node": target_name, "error": error.to_string()
                                                        }))))
                                                    }
                                                });
                                            } else {
                                                failed.push(serde_json::json!({
                                                    "shard": index, "node": target, "error": "peer is no longer known"
                                                }));
                                            }
                                        }
                                    }

                                    while let Some(result) = remote_jobs.join_next().await {
                                        match result {
                                            Ok(Ok((count, error))) => {
                                                sent_remote += count;
                                                if let Some(error) = error {
                                                    failed.push(error);
                                                }
                                            }
                                            Ok(Err(error)) => failed.push(serde_json::json!({
                                                "error": format!("storage transfer task failed: {error}")
                                            })),
                                            Err(error) => failed.push(serde_json::json!({
                                                "error": format!("storage transfer task panicked: {error}")
                                            })),
                                        }
                                    }

                                    let manifest_path = PathBuf::from(data_dir_for_api())
                                        .join("storage")
                                        .join("manifests");
                                    let _ = fs::create_dir_all(&manifest_path);
                                    let manifest = serde_json::json!({
                                        "version": 1,
                                        "file_id": hex::encode(file_id),
                                        "filename": filename,
                                        "original_size": data.len(),
                                        "shards": policy.total_shards(),
                                        "data_shards": policy.data_shards,
                                        "parity_shards": policy.parity_shards,
                                        "replicas": 3,
                                        "shard_hashes": shard_hashes,
                                        "placements": plan.placements,
                                        "stored_local": stored_local,
                                        "sent_remote": sent_remote
                                    });
                                    let _ = fs::write(
                                        manifest_path.join(format!("{}.json", hex::encode(file_id))),
                                        serde_json::to_vec_pretty(&manifest).unwrap_or_default(),
                                    );

                                    let status = if failed
                                        .iter()
                                        .all(|entry| entry.get("error").is_none())
                                    {
                                        "stored"
                                    } else {
                                        "partial"
                                    };
                                    ("200 OK", "application/json; charset=utf-8",
                                        serde_json::json!({
                                            "status": status,
                                            "file_id": hex::encode(file_id),
                                            "filename": filename,
                                            "original_size": data.len(),
                                            "shards": 1000,
                                            "replicas": 3,
                                            "stored_local": stored_local,
                                            "sent_remote": sent_remote,
                                            "failures": failed
                                        }).to_string())
                                }
                            }
                        }
                    }
                }
            }
        }
        },
        "/api/storage/push" if method == "POST" => {
            let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
            let parsed: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
            let recipient = parsed.get("recipient").and_then(|v| v.as_str()).unwrap_or("").trim();
            let file_id_hex = parsed.get("file_id").and_then(|v| v.as_str()).unwrap_or("").trim();
            let shard_index = parsed.get("shard_index").and_then(|v| v.as_u64()).unwrap_or(u64::MAX);
            let original_size = parsed.get("original_size").and_then(|v| v.as_u64()).unwrap_or(0);
            let payload_hex = parsed.get("payload_hex").and_then(|v| v.as_str()).unwrap_or("").trim();

            let recipient_id = hex::decode(recipient)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .or(None);
            let file_id = hex::decode(file_id_hex)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok());
            let payload = hex::decode(payload_hex).ok();

            match (recipient_id, file_id, payload, usize::try_from(shard_index)) {
                (Some(peer_id), Some(file_id), Some(payload), Ok(index)) if index < 1000 => {
                    let transfer = StorageShardTransfer::new(
                        blake3::hash(format!("{}:{}:{}", file_id_hex, shard_index, now_unix()).as_bytes())
                            .as_bytes()[..16]
                            .try_into()
                            .unwrap_or([0u8; 16]),
                        *node.identity.public.awe_id.as_bytes(),
                        file_id,
                        shard_index as u16,
                        1000,
                        original_size,
                        payload,
                    );
                    match serde_json::to_vec(&transfer) {
                        Ok(bytes) => match node.send_to_peer(&peer_id, STORAGE_STREAM, bytes).await {
                            Ok(rtt) => ("200 OK", "application/json; charset=utf-8",
                                serde_json::json!({"status":"sent","stream":STORAGE_STREAM,"shard_index":index,"rtt_ms":rtt.as_millis()}).to_string()),
                            Err(error) => ("502 Bad Gateway", "application/json; charset=utf-8",
                                serde_json::json!({"status":"error","error":error.to_string()}).to_string())
                        },
                        Err(error) => ("500 Internal Server Error", "application/json; charset=utf-8",
                            serde_json::json!({"status":"error","error":error.to_string()}).to_string())
                    }
                }
                _ => ("400 Bad Request", "application/json; charset=utf-8",
                    serde_json::json!({"status":"error","error":"recipient, 32-byte file_id, shard_index 0..999 and payload_hex are required"}).to_string())
            }
        },
        "/api/storage/get" => {
            let query = request.lines().next().unwrap_or("");
            let file_id_hex = query.split_whitespace().nth(1)
                .and_then(|path| path.split('?').nth(1))
                .and_then(|q| q.split('&').find_map(|p| p.strip_prefix("file_id=")))
                .unwrap_or("");
            let manifest_path = PathBuf::from(data_dir_for_api())
                .join("storage").join("manifests")
                .join(format!("{file_id_hex}.json"));
            match fs::read(&manifest_path) {
                Ok(bytes) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
                    Ok(manifest) => {
                        let total_shards = manifest
                            .get("shards")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(1000)
                            .clamp(12, 1000) as usize;
                        let policy = StoragePolicy::custom_scaled(total_shards);
                        let mut shards = vec![None; total_shards];
                        let mut present = 0usize;
                        let mut missing = Vec::new();
                        if let Some(placements) = manifest.get("placements").and_then(|v| v.as_array()) {
                            for (index, placement) in placements.iter().enumerate().take(total_shards) {
                                let local = format_uid(node.identity.public.awe_id.as_bytes());
                                let owns = placement.get("nodes").and_then(|v| v.as_array())
                                    .map(|nodes| nodes.iter().any(|n| n.as_str() == Some(&local))).unwrap_or(false);
                                if owns {
                                    if let Ok(hash_bytes) = hex::decode(
                                        manifest.get("shard_hashes").and_then(|v| v.get(index))
                                            .and_then(|v| v.as_str()).unwrap_or("")
                                    ) {
                                        if let Ok(hash) = <[u8;32]>::try_from(hash_bytes) {
                                            if let Ok(data) = storage.get(&hash) {
                                                shards[index] = Some(data);
                                                present += 1;
                                                continue;
                                            }
                                        }
                                    }
                                }
                                missing.push(index);
                            }
                        }
                        if present < policy.data_shards && !missing.is_empty() {
                            let peers = node.peers().await;
                            let peer_ids = peers.into_iter()
                                .map(|p| (format_uid(&p.awe_id), p.awe_id))
                                .collect::<std::collections::BTreeMap<_, _>>();
                            let local_id = format_uid(node.identity.public.awe_id.as_bytes());

                            for index in missing.clone() {
                                if present >= policy.data_shards {
                                    break;
                                }
                                let Some(placement) = manifest.get("placements").and_then(|v| v.get(index)).and_then(|v| v.get("nodes")).and_then(|v| v.as_array()) else {
                                    continue;
                                };
                                let Some(expected_hex) = manifest.get("shard_hashes").and_then(|v| v.get(index)).and_then(|v| v.as_str()) else {
                                    continue;
                                };
                                let Ok(expected_bytes) = hex::decode(expected_hex) else {
                                    continue;
                                };
                                let Ok(expected_hash) = <[u8; 32]>::try_from(expected_bytes) else {
                                    continue;
                                };
                                let original_size = manifest
            .get("original_size")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

                                for target in placement.iter().filter_map(|v| v.as_str()) {
                                    if target == local_id {
                                        continue;
                                    }
                                    let Some(peer_id) = peer_ids.get(target) else {
                                        continue;
                                    };
                                    let request_id = blake3::hash(
                                        format!("download:{}:{}:{}:{}", file_id_hex, index, target, now_unix()).as_bytes()
                                    ).as_bytes()[..16].try_into().unwrap_or([0u8; 16]);
                                    let request = StorageShardRequest::new(
                                        request_id,
                                        *node.identity.public.awe_id.as_bytes(),
                                        <[u8;32]>::try_from(hex::decode(file_id_hex).unwrap_or_default()).unwrap_or([0;32]),
                                        index as u16,
                                        policy.total_shards() as u16,
                                        expected_hash,
                                        original_size,
                                        4 * 1024 * 1024,
                                    );
                                    let Ok(bytes) = serde_json::to_vec(&request) else {
                                        continue;
                                    };
                                    if node.send_to_peer(peer_id, STORAGE_STREAM, bytes).await.is_err() {
                                        continue;
                                    }
                                    let deadline =
                            tokio::time::Instant::now() + std::time::Duration::from_secs(5);
                                    while tokio::time::Instant::now() < deadline {
                                        if let Ok(mut responses) = pending_shards.lock() {
                                            if let Some(response) = responses.remove(&request_id) {
                                                if response.file_id == request.file_id
                                                    && response.shard_index == index as u16
                                                    && response.verify().is_ok()
                                                    && response.payload_hash == expected_hash
                                                {
                                                    if let Ok(object_id) = storage.put(&response.payload) {
                                                        if object_id == expected_hash {
                                                            shards[index] = Some(response.payload);
                                                            present += 1;
                                                        }
                                                    }
                                                }
                                                break;
                                            }
                                        }
                                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                                    }
                                    if shards[index].is_some() {
                                        break;
                                    }
                                }
                            }
                        }

                        if present < policy.data_shards {
                            ("409 Conflict","application/json; charset=utf-8",
                                serde_json::json!({"status":"insufficient_shards","present":present,"required":policy.data_shards,"missing":missing}).to_string())
                        } else {
                        match recover_shards(&mut shards, &policy) {
                            Ok(mut data) => {
                                let original_size = manifest.get("original_size").and_then(|v| v.as_u64()).unwrap_or(data.len() as u64) as usize;
                                data.truncate(original_size);
                                ("200 OK","application/json; charset=utf-8",
                                    serde_json::json!({
                                        "status":"reconstructed",
                                        "file_id":file_id_hex,
                                        "filename":manifest.get("filename").and_then(|v| v.as_str()).unwrap_or("object.bin"),
                                        "size":data.len(),
                                        "data_hex":hex::encode(data)
                                    }).to_string())
                            },
                            Err(error) => ("500 Internal Server Error","application/json; charset=utf-8",
                                serde_json::json!({"status":"error","error":error.to_string()}).to_string())
                        }
                        }
                    },
                    Err(error) => ("500 Internal Server Error","application/json; charset=utf-8",
                        serde_json::json!({"status":"error","error":error.to_string()}).to_string())
                },
                Err(_) => ("404 Not Found","application/json; charset=utf-8",
                    serde_json::json!({"status":"not_found","file_id":file_id_hex}).to_string())
            }
        },
        "/api/storage/health" => {
            let mut online: std::collections::BTreeSet<String> = node
                .closest_peers(node.identity.public.awe_id.as_bytes(), 4096)
                .await
                .into_iter()
                .map(|p| format_uid(&p.awe_id))
                .collect();
            online.insert(format_uid(node.identity.public.awe_id.as_bytes()));
            let manifest_dir = PathBuf::from(data_dir_for_api()).join("storage").join("manifests");
            let mut files = 0usize;
            let mut healthy = 0usize;
            let mut degraded = 0usize;
            if let Ok(entries) = fs::read_dir(&manifest_dir) {
                for entry in entries.flatten() {
                    if let Ok(bytes) = fs::read(entry.path()) {
                        if let Ok(m) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                            files += 1;
                            let mut ok = true;
                            if let Some(placements) = m.get("placements").and_then(|v| v.as_array()) {
                                for p in placements {
                                    let count = p.get("nodes").and_then(|v| v.as_array()).map(|ns|
                                        ns.iter().filter(|n| n.as_str().map(|s| online.contains(s)).unwrap_or(false)).count()
                                    ).unwrap_or(0);
                                    if count < 3 { ok = false; break; }
                                }
                            } else { ok = false; }
                            if ok { healthy += 1; } else { degraded += 1; }
                        }
                    }
                }
            }
            ("200 OK","application/json; charset=utf-8",
                serde_json::json!({"files":files,"healthy_files":healthy,"degraded_files":degraded,"online_nodes":online.len()}).to_string())
        },
        "/api/storage" => {
            let stats = storage.stats().unwrap_or_default();
            let free = awep2p_core::node::get_available_disk_space(PathBuf::from(data_dir_for_api()).as_path()).unwrap_or(0);
            ("200 OK", "application/json; charset=utf-8", serde_json::json!({
                "root": data_dir_for_api(),
                "free_bytes": free,
                "capacity_bytes": stats.capacity,
                "used_bytes": stats.used,
                "objects": stats.objects,
                "healthy_replicas": stats.healthy_replicas,
                "repaired_chunks": stats.repaired_chunks,
                "replication_policy": {"shards": 1000, "replicas": 3}
            }).to_string())
        },
        _ => ("404 Not Found", "text/plain; charset=utf-8", "Not Found".to_string()),
    };
    stream
        .write_all(&http_response(status, mime, &body, &request).await)
        .await?;
    stream.shutdown().await?;
    Ok(())
}

fn data_dir_for_api() -> String {
    if let Some(value) = env::var_os("AWE_DATA_DIR") {
        return PathBuf::from(value).display().to_string();
    }
    if let Some(home) = env::var_os("USERPROFILE").or_else(|| env::var_os("HOME")) {
        PathBuf::from(home).join(".awep2p").display().to_string()
    } else {
        PathBuf::from(".awep2p").display().to_string()
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn autonomous_repair_cycle(
    node: &Node,
    storage: &LocalNodeStore,
    pending_shards: &PendingShards,
    pending_acks: &PendingAcks,
    data_dir: &std::path::Path,
    policy: &NetworkPolicy,
) {
    if !policy.enabled || !policy.allows_stream(STORAGE_STREAM) {
        return;
    }

    let manifest_dir = data_dir.join("storage").join("manifests");
    let Ok(entries) = fs::read_dir(&manifest_dir) else {
        return;
    };

    let peers = node.peers().await;
    let local_id = format_uid(node.identity.public.awe_id.as_bytes());
    let mut peer_ids = std::collections::BTreeMap::<String, [u8; 32]>::new();
    for peer in peers {
        peer_ids.insert(format_uid(&peer.awe_id), peer.awe_id);
    }

    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        let Ok(mut manifest) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        let Some(shard_hashes) = manifest
            .get("shard_hashes")
            .and_then(|v| v.as_array())
            .cloned()
        else {
            continue;
        };
        let file_id_hex = manifest
            .get("file_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let Ok(file_id_bytes) = hex::decode(&file_id_hex) else {
            continue;
        };
        let Ok(file_id) = <[u8; 32]>::try_from(file_id_bytes) else {
            continue;
        };
        let original_size = manifest
            .get("original_size")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let total_shards = manifest.get("shards").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let mut manifest_changed = false;
        {
            let Some(placements) = manifest
                .get_mut("placements")
                .and_then(|v| v.as_array_mut())
            else {
                continue;
            };

            for index in 0..total_shards.min(1000) {
                let Some(nodes_value) = placements
                    .get_mut(index)
                    .and_then(|v| v.get_mut("nodes"))
                    .and_then(|v| v.as_array_mut())
                else {
                    continue;
                };
                let current_nodes = nodes_value
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect::<Vec<_>>();
                let available = current_nodes
                    .iter()
                    .filter(|id| *id == &local_id || peer_ids.contains_key(*id))
                    .count();
                if available >= 3 {
                    continue;
                }

                let Some(expected_hex) = shard_hashes.get(index).and_then(|v| v.as_str()) else {
                    continue;
                };
                let Ok(expected_bytes) = hex::decode(expected_hex) else {
                    continue;
                };
                let Ok(expected_hash) = <[u8; 32]>::try_from(expected_bytes) else {
                    continue;
                };

                let mut source_data: Option<Vec<u8>> = None;
                for source in &current_nodes {
                    if source == &local_id {
                        if let Ok(data) = storage.get(&expected_hash) {
                            source_data = Some(data);
                            break;
                        }
                    } else if let Some(source_id) = peer_ids.get(source) {
                        let request_id = blake3::hash(
                            format!(
                                "repair-source:{}:{}:{}:{}",
                                file_id_hex,
                                index,
                                source,
                                now_unix()
                            )
                            .as_bytes(),
                        )
                        .as_bytes()[..16]
                            .try_into()
                            .unwrap_or([0u8; 16]);
                        let request = StorageShardRequest::new(
                            request_id,
                            *node.identity.public.awe_id.as_bytes(),
                            file_id,
                            index as u16,
                            total_shards as u16,
                            expected_hash,
                            original_size,
                            4 * 1024 * 1024,
                        );
                        let Ok(request_bytes) = serde_json::to_vec(&request) else {
                            continue;
                        };
                        if node
                            .send_to_peer(source_id, STORAGE_STREAM, request_bytes)
                            .await
                            .is_err()
                        {
                            continue;
                        }
                        let deadline =
                            tokio::time::Instant::now() + std::time::Duration::from_secs(5);
                        while tokio::time::Instant::now() < deadline {
                            if let Ok(mut pending) = pending_shards.lock() {
                                if let Some(response) = pending.remove(&request_id) {
                                    if response.file_id == file_id
                                        && response.shard_index == index as u16
                                        && response.payload_hash == expected_hash
                                        && response.verify().is_ok()
                                    {
                                        source_data = Some(response.payload);
                                    }
                                    break;
                                }
                            }
                            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                        }
                        if source_data.is_some() {
                            break;
                        }
                    }
                }

                let Some(data) = source_data else {
                    continue;
                };
                if !policy.allows_shard(data.len())
                    || *blake3::hash(&data).as_bytes() != expected_hash
                {
                    continue;
                }

                let mut repaired = false;
                let mut candidates = peer_ids
                    .keys()
                    .filter(|id| !current_nodes.contains(id))
                    .cloned()
                    .collect::<Vec<_>>();
                if !current_nodes.contains(&local_id) {
                    candidates.insert(0, local_id.clone());
                }
                candidates.sort();
                candidates.dedup();

                for target in candidates {
                    if current_nodes.contains(&target) {
                        continue;
                    }

                    if target == local_id {
                        if storage.put(&data).is_ok() {
                            nodes_value.push(serde_json::Value::String(target.clone()));
                            repaired = true;
                        }
                    } else if let Some(target_id) = peer_ids.get(&target) {
                        let request_id = blake3::hash(
                            format!(
                                "repair-target:{}:{}:{}:{}",
                                file_id_hex,
                                index,
                                target,
                                now_unix()
                            )
                            .as_bytes(),
                        )
                        .as_bytes()[..16]
                            .try_into()
                            .unwrap_or([0u8; 16]);
                        let transfer = StorageShardTransfer::new(
                            request_id,
                            *node.identity.public.awe_id.as_bytes(),
                            file_id,
                            index as u16,
                            total_shards as u16,
                            original_size,
                            data.clone(),
                        );
                        let Ok(transfer_bytes) = serde_json::to_vec(&transfer) else {
                            continue;
                        };
                        if node
                            .send_to_peer(target_id, STORAGE_STREAM, transfer_bytes)
                            .await
                            .is_err()
                        {
                            continue;
                        }
                        let deadline =
                            tokio::time::Instant::now() + std::time::Duration::from_secs(5);
                        while tokio::time::Instant::now() < deadline {
                            if let Ok(mut acks) = pending_acks.lock() {
                                if let Some(ack) = acks.remove(&request_id) {
                                    if ack.file_id == file_id
                                        && ack.shard_index == index as u16
                                        && ack.stored_object_id == expected_hash
                                    {
                                        nodes_value.push(serde_json::Value::String(target.clone()));
                                        repaired = true;
                                    }
                                    break;
                                }
                            }
                            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                        }
                    }

                    if repaired {
                        break;
                    }
                }

                if repaired {
                    manifest_changed = true;
                }
            }
        }

        if manifest_changed {
            let _ = fs::write(
                &path,
                serde_json::to_vec_pretty(&manifest).unwrap_or_default(),
            );
        }
    }
}

async fn run_product() -> Result<()> {
    let data_dir = if let Some(value) = env::var_os("AWE_DATA_DIR") {
        PathBuf::from(value)
    } else if let Some(home) = env::var_os("USERPROFILE").or_else(|| env::var_os("HOME")) {
        PathBuf::from(home).join(".awep2p")
    } else {
        PathBuf::from(".awep2p")
    };
    fs::create_dir_all(&data_dir)?;
    let secret_path = data_dir.join("node.awesecret");
    let identity = if secret_path.exists() {
        restrict_secret_file_permissions(&secret_path)?;
        AweSecret::from_bytes(&fs::read(&secret_path)?)
            .map_err(anyhow::Error::msg)?
            .authenticate()
            .map_err(anyhow::Error::msg)?
    } else {
        let identity =
            Identity::generate(Username::new("awe-node".to_string()).map_err(anyhow::Error::msg)?);
        let secret = AweSecret::generate(&identity);
        fs::write(&secret_path, secret.to_bytes()?)?;
        restrict_secret_file_permissions(&secret_path)?;
        identity
    };
    let node_id = format_uid(identity.public.awe_id.as_bytes());
    let listen: SocketAddr = env::var("AWE_LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:41000".into())
        .parse()
        .context("invalid AWE_LISTEN_ADDR")?;
    let node = Node::new(identity, listen);
    let storage_root = data_dir.join("storage");
    fs::create_dir_all(&storage_root)?;
    let storage_quota = awep2p_core::node::get_available_disk_space(&storage_root)
        .context("failed to determine available node storage capacity")?;
    if storage_quota == 0 {
        anyhow::bail!("node storage has no available capacity");
    }
    let storage: StorageState = Arc::new(LocalNodeStore::open(&storage_root, storage_quota)?);
    let host_root = data_dir.join("host");
    fs::create_dir_all(&host_root)?;
    let host_quota = (storage_quota / 4).max(1);
    let host: HostState = Arc::new(Mutex::new(AweHost::open(
        &host_root,
        host_quota,
        HostPolicy::default(),
    )?));
    let messenger: MessengerLog = Arc::new(Mutex::new(Vec::new()));
    let community_path = data_dir.join("community.json");
    let community: CommunityState = Arc::new(Mutex::new(
        fs::read(&community_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_else(|| serde_json::json!({"groups":[],"channels":[]})),
    ));
    let community_save = community.clone();
    let community_save_path = community_path.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            if let Ok(state) = community_save.lock() {
                if let Ok(bytes) = serde_json::to_vec_pretty(&*state) {
                    let _ = fs::write(&community_save_path, bytes);
                }
            }
        }
    });
    let pending_acks: PendingAcks = Arc::new(Mutex::new(BTreeMap::new()));
    let pending_shards: PendingShards = Arc::new(Mutex::new(BTreeMap::new()));
    let federation_path = data_dir.join("awenet.json");
    let policy_path = data_dir.join("policy.json");
    let initial_policy = policy::load_or_create(&policy_path).map_err(anyhow::Error::msg)?;
    let policy_state: PolicyState = Arc::new(Mutex::new(initial_policy));
    let federation_state: FederationState = if federation_path.exists() {
        fs::read(&federation_path)
            .ok()
            .and_then(|b| serde_json::from_slice::<AweNetConfig>(&b).ok())
            .map(|mut s| {
                s.local_node_id = node_id.clone();
                Arc::new(Mutex::new(s))
            })
            .unwrap_or_else(|| {
                Arc::new(Mutex::new(AweNetConfig {
                    format: "awenet".into(),
                    version: federation::FORMAT_VERSION,
                    local_node_id: node_id.clone(),
                    ..Default::default()
                }))
            })
    } else {
        Arc::new(Mutex::new(AweNetConfig {
            format: "awenet".into(),
            version: federation::FORMAT_VERSION,
            local_node_id: node_id.clone(),
            ..Default::default()
        }))
    };
    if let Ok(state) = federation_state.lock() {
        let _ = federation::save_json(&*state, &federation_path);
    }
    let policy_refresh = policy_state.clone();
    let policy_refresh_path = policy_path.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
            let current = policy_refresh.lock().map(|p| p.clone()).unwrap_or_default();
            if let Ok(next) = policy::load_if_changed(&policy_refresh_path, &current) {
                if let Ok(mut p) = policy_refresh.lock() {
                    *p = next;
                }
            }
        }
    });
    let startup_bootstrap = federation_state
        .lock()
        .map(|s| s.bootstrap_endpoints.clone())
        .unwrap_or_default()
        .iter()
        .filter_map(|x| x.parse::<SocketAddr>().ok())
        .collect::<Vec<_>>();
    if !startup_bootstrap.is_empty() {
        let _ = node.bootstrap(&startup_bootstrap).await;
        let supervisor = PeerSupervisor::new(
            node.clone(),
            startup_bootstrap.clone(),
            SupervisorConfig::default(),
        )
        .map_err(anyhow::Error::msg)?;
        let _supervisor_task = supervisor.spawn();
    }
    let repair_node = node.clone();
    let repair_storage = storage.clone();
    let repair_pending_shards = pending_shards.clone();
    let repair_pending_acks = pending_acks.clone();
    let repair_policy = policy_state.clone();
    let repair_data_dir = data_dir.clone();
    tokio::spawn(async move {
        loop {
            let policy = repair_policy.lock().map(|p| p.clone()).unwrap_or_default();
            autonomous_repair_cycle(
                &repair_node,
                &repair_storage,
                &repair_pending_shards,
                &repair_pending_acks,
                &repair_data_dir,
                &policy,
            )
            .await;
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    });

    let node_for_listener = node.clone();
    tokio::spawn(async move {
        if let Err(e) = node_for_listener.listen().await {
            eprintln!("AWE node stopped: {e}");
        }
    });

    let onecoin_path = data_dir.join("onecoin-ledger.json");
    let persisted_onecoin =
        load_persisted_onecoin_state(&onecoin_path).map_err(anyhow::Error::msg)?;
    let onecoin_ledger: OnecoinLedgerState = Arc::new(Mutex::new(persisted_onecoin.ledger));
    let onecoin_outbox: OnecoinPendingState =
        Arc::new(Mutex::new(persisted_onecoin.pending_transfers));
    {
        let mut ledger = onecoin_ledger
            .lock()
            .map_err(|_| anyhow::anyhow!("ONECOIN ledger lock failed"))?;
        let pending = onecoin_outbox
            .lock()
            .map_err(|_| anyhow::anyhow!("ONECOIN outbox lock failed"))?;
        if ledger.members.is_empty() {
            ledger
                .initialize_genesis(std::slice::from_ref(&node.identity.public.awe_id))
                .map_err(anyhow::Error::msg)?;
        }
        persist_onecoin_state(&onecoin_path, &ledger, &pending).map_err(anyhow::Error::msg)?;
    }
    let onecoin_offers_path = data_dir.join("onecoin-exchange-offers.json");
    let contribution_path = data_dir.join("resource-contribution.json");
    let contribution: ContributionState = Arc::new(Mutex::new(
        fs::read(&contribution_path)
            .ok()
            .and_then(|b| serde_json::from_slice::<ResourceContribution>(&b).ok())
            .unwrap_or_default(),
    ));

    let consensus_state: ConsensusState = {
        let configured = env::var("AWE_ONECOIN_VALIDATORS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if configured.is_empty() {
            Arc::new(Mutex::new(None))
        } else {
            let validators = build_onecoin_validators(&node, &configured).await;
            if validators.len()
                != configured
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
            {
                eprintln!(
                    "ONECOIN consensus waiting: not all configured validators are discovered"
                );
                Arc::new(Mutex::new(None))
            } else {
                let state_path = data_dir.join("onecoin-consensus.json");
                match OnecoinConsensusRuntime::open(&state_path, validators) {
                    Ok(mut runtime) => {
                        if runtime.state.state.ledger.members.is_empty() {
                            let members = runtime
                                .validators
                                .values()
                                .map(|key| AweId::from_public_key(key))
                                .collect::<Vec<_>>();
                            if !members.is_empty() {
                                if let Err(error) =
                                    runtime.state.state.ledger.initialize_genesis(&members)
                                {
                                    eprintln!("ONECOIN genesis initialization failed: {error}");
                                } else if let Err(error) = runtime.state.save() {
                                    eprintln!("ONECOIN genesis persistence failed: {error}");
                                }
                            }
                        }
                        Arc::new(Mutex::new(Some(runtime)))
                    }
                    Err(error) => {
                        eprintln!("ONECOIN consensus disabled: {error}");
                        Arc::new(Mutex::new(None))
                    }
                }
            }
        }
    };

    let dispatcher_node = node.clone();
    let dispatcher_storage = storage.clone();
    let dispatcher_messenger = messenger.clone();
    let dispatcher_acks = pending_acks.clone();
    let dispatcher_policy = policy_state.clone();
    let dispatcher_community = community.clone();
    let dispatcher_consensus = consensus_state.clone();
    let dispatcher_onecoin_ledger = onecoin_ledger.clone();
    let dispatcher_onecoin_outbox = onecoin_outbox.clone();
    let dispatcher_onecoin_path = onecoin_path.clone();
    tokio::spawn(async move {
        loop {
            for (sender, stream, payload) in dispatcher_node.take_inbox() {
                let runtime_policy = dispatcher_policy
                    .lock()
                    .map(|p| p.clone())
                    .unwrap_or_default();
                if !runtime_policy.allows_stream(stream) {
                    continue;
                }
                if stream == ONECOIN_CONSENSUS_STREAM {
                    let result = {
                        let mut guard = dispatcher_consensus.lock().ok();
                        match guard.as_mut().and_then(|g| g.as_mut()) {
                            Some(runtime) => match OnecoinConsensusMessage::decode(&payload) {
                                Ok(message) => {
                                    runtime.handle(sender, &dispatcher_node.identity, message)
                                }
                                Err(error) => Err(error),
                            },
                            None => Ok(Vec::new()),
                        }
                    };
                    if let Ok(outbound) = result {
                        for (peer, message) in outbound {
                            if let Ok(bytes) = message.encode() {
                                let _ = dispatcher_node
                                    .send_to_peer(&peer, ONECOIN_CONSENSUS_STREAM, bytes)
                                    .await;
                            }
                        }
                    }
                    continue;
                }
                if stream == policy::ONECOIN_TRANSFER_STREAM {
                    // A network DataAck means only that the frame reached the
                    // remote inbox. Clear the durable outbox only after an app ACK
                    // emitted by the recipient after its ledger is persisted.
                    if let Ok(ack) = serde_json::from_slice::<OnecoinTransferAck>(&payload) {
                        eprintln!(
                            "ONECOIN app ACK received from peer {} for transaction {} (ACK recipient {})",
                            hex::encode(sender),
                            ack.transaction_id,
                            hex::encode(ack.recipient)
                        );
                        if ack.recipient == sender {
                            let matches_pending = dispatcher_onecoin_outbox
                                .lock()
                                .ok()
                                .and_then(|queue| {
                                    queue
                                        .get(&ack.transaction_id)
                                        .map(|tx| tx.recipient == ack.recipient)
                                })
                                .unwrap_or(false);
                            eprintln!(
                                "ONECOIN app ACK pending match={} for transaction {}",
                                matches_pending, ack.transaction_id
                            );
                            if matches_pending {
                                if let Err(error) = remove_pending_onecoin_transfer(
                                    &dispatcher_onecoin_path,
                                    &dispatcher_onecoin_ledger,
                                    &dispatcher_onecoin_outbox,
                                    &ack.transaction_id,
                                ) {
                                    eprintln!(
                                        "ONECOIN recipient ACK could not be persisted: {error}"
                                    );
                                }
                            }
                        }
                        continue;
                    }

                    if let Ok(tx) = serde_json::from_slice::<OnecoinTransaction>(&payload) {
                        let tx_sender_aweid = *AweId::from_public_key(&tx.sender).as_bytes();
                        if tx.recipient == *dispatcher_node.identity.public.awe_id.as_bytes()
                            && tx_sender_aweid == sender
                        {
                            let received = (|| -> Result<(), String> {
                                let mut ledger = dispatcher_onecoin_ledger
                                    .lock()
                                    .map_err(|_| "ONECOIN ledger lock failed".to_string())?;
                                let pending = dispatcher_onecoin_outbox
                                    .lock()
                                    .map_err(|_| "ONECOIN outbox lock failed".to_string())?;
                                let mut next_ledger = ledger.clone();
                                let sender_id = AweId::from_public_key(&tx.sender);
                                next_ledger.ensure_member(&sender_id);
                                next_ledger.ensure_member(&dispatcher_node.identity.public.awe_id);
                                let changed = next_ledger.receive_transfer(
                                    &tx,
                                    &tx.sender,
                                    &dispatcher_node.identity.public.awe_id,
                                )?;
                                if changed {
                                    persist_onecoin_state(
                                        &dispatcher_onecoin_path,
                                        &next_ledger,
                                        &pending,
                                    )?;
                                    *ledger = next_ledger;
                                }
                                Ok(())
                            })();
                            match received {
                                Ok(()) => {
                                    eprintln!(
                                        "ONECOIN transfer persisted receiver={} transaction={}",
                                        dispatcher_node.identity.public.awe_id.to_hex(),
                                        hex::encode(tx.id())
                                    );
                                    let ack = OnecoinTransferAck {
                                        transaction_id: hex::encode(tx.id()),
                                        recipient: *dispatcher_node
                                            .identity
                                            .public
                                            .awe_id
                                            .as_bytes(),
                                    };
                                    if let Ok(bytes) = serde_json::to_vec(&ack) {
                                        match tokio::time::timeout(
                                            std::time::Duration::from_secs(8),
                                            dispatcher_node.send_to_peer_confirmed(
                                                &sender,
                                                policy::ONECOIN_TRANSFER_STREAM,
                                                bytes,
                                            ),
                                        )
                                        .await
                                        {
                                            Ok(Ok(_)) => eprintln!(
                                                "ONECOIN transfer application ACK delivered to peer {} for {}",
                                                hex::encode(sender),
                                                hex::encode(tx.id())
                                            ),
                                            Ok(Err(error)) => eprintln!(
                                                "ONECOIN transfer ACK send failed for peer {} transaction {}: {error}",
                                                hex::encode(sender),
                                                hex::encode(tx.id())
                                            ),
                                            Err(_) => eprintln!(
                                                "ONECOIN transfer ACK send timed out for peer {} transaction {}",
                                                hex::encode(sender),
                                                hex::encode(tx.id())
                                            ),
                                        }
                                    }
                                }
                                Err(error) => {
                                    eprintln!("ONECOIN incoming transfer was not applied: {error}")
                                }
                            }
                        }
                    }
                    continue;
                }
                if stream == 100 {
                    if let Ok(message) = serde_json::from_slice::<serde_json::Value>(&payload) {
                        if message.get("kind").and_then(|v| v.as_str()) == Some("awe.call.v1") {
                            let id = message.get("id").and_then(|v| v.as_str()).unwrap_or("");
                            let recipient = message
                                .get("recipient")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let call_id = message
                                .get("call_id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let signal_type = message
                                .get("signal_type")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let data = message.get("data").and_then(|v| v.as_str()).unwrap_or("");
                            if !id.is_empty()
                                && !recipient.is_empty()
                                && !call_id.is_empty()
                                && !signal_type.is_empty()
                                && !data.is_empty()
                            {
                                if let Ok(mut log) = dispatcher_messenger.lock() {
                                    if !log.iter().any(|existing| {
                                        existing.get("id").and_then(|v| v.as_str()) == Some(id)
                                    }) {
                                        let mut item = message.clone();
                                        if let Some(obj) = item.as_object_mut() {
                                            obj.insert(
                                                "sender".into(),
                                                serde_json::json!(format_uid(&sender)),
                                            );
                                        }
                                        log.push(item);
                                    }
                                }
                            }
                            continue;
                        }
                        if message.get("kind").and_then(|v| v.as_str()) == Some("awe.group.v1") {
                            if let Ok(mut state) = dispatcher_community.lock() {
                                let event =
                                    message.get("event").and_then(|v| v.as_str()).unwrap_or("");
                                let sender_uid = hex::encode(sender);
                                if event == "upsert" {
                                    if let Some(group) = message.get("group").cloned() {
                                        let owner = group
                                            .get("owner")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("");
                                        if owner == sender_uid {
                                            let gid = group
                                                .get("id")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("");
                                            if let Some(groups) = state
                                                .get_mut("groups")
                                                .and_then(|v| v.as_array_mut())
                                            {
                                                if let Some(existing) =
                                                    groups.iter_mut().find(|g| {
                                                        g.get("id").and_then(|v| v.as_str())
                                                            == Some(gid)
                                                    })
                                                {
                                                    *existing = group;
                                                } else {
                                                    groups.push(group);
                                                }
                                            }
                                        }
                                    }
                                } else if event == "message" {
                                    let gid = message
                                        .get("group_id")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("");
                                    if let Some(g) = state
                                        .get_mut("groups")
                                        .and_then(|v| v.as_array_mut())
                                        .and_then(|a| {
                                            a.iter_mut().find(|g| {
                                                g.get("id").and_then(|v| v.as_str()) == Some(gid)
                                            })
                                        })
                                    {
                                        let member = g
                                            .get("members")
                                            .and_then(|v| v.as_array())
                                            .map(|a| {
                                                a.iter().any(|v| {
                                                    v.as_str() == Some(sender_uid.as_str())
                                                })
                                            })
                                            .unwrap_or(false);
                                        if member {
                                            if let Some(m) = message.get("message").cloned() {
                                                if let Some(a) = g
                                                    .get_mut("messages")
                                                    .and_then(|v| v.as_array_mut())
                                                {
                                                    a.push(m);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            continue;
                        }
                        if message.get("kind").and_then(|v| v.as_str()) == Some("awe.channel.v1") {
                            let event = message.get("event").and_then(|v| v.as_str()).unwrap_or("");
                            let sender_uid = hex::encode(sender);
                            let mut sync: Option<(String, Vec<u8>)> = None;
                            if let Ok(mut state) = dispatcher_community.lock() {
                                if event == "upsert" {
                                    if let Some(channel) = message.get("channel").cloned() {
                                        let owner = channel
                                            .get("owner")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("");
                                        if owner == sender_uid {
                                            let cid = channel
                                                .get("id")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("");
                                            if let Some(chs) = state
                                                .get_mut("channels")
                                                .and_then(|v| v.as_array_mut())
                                            {
                                                if let Some(existing) = chs.iter_mut().find(|c| {
                                                    c.get("id").and_then(|v| v.as_str())
                                                        == Some(cid)
                                                }) {
                                                    *existing = channel;
                                                } else {
                                                    chs.push(channel);
                                                }
                                            }
                                        }
                                    }
                                } else if event == "subscribe" {
                                    let cid = message
                                        .get("channel_id")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("");
                                    // The authenticated transport identity is authoritative; never trust a
                                    // payload-supplied subscriber ID for channel membership.
                                    let subscriber = sender_uid.as_str();
                                    if message
                                        .get("subscriber")
                                        .and_then(|v| v.as_str())
                                        .is_some_and(|claimed| claimed != subscriber)
                                    {
                                        continue;
                                    }
                                    let local_uid = hex::encode(
                                        dispatcher_node.identity.public.awe_id.as_bytes(),
                                    );
                                    if let Some(ch) = state
                                        .get_mut("channels")
                                        .and_then(|v| v.as_array_mut())
                                        .and_then(|a| {
                                            a.iter_mut().find(|c| {
                                                c.get("id").and_then(|v| v.as_str()) == Some(cid)
                                            })
                                        })
                                    {
                                        if ch.get("owner").and_then(|v| v.as_str())
                                            == Some(local_uid.as_str())
                                        {
                                            if !ch
                                                .get("subscribers")
                                                .and_then(|v| v.as_array())
                                                .map(|a| {
                                                    a.iter().any(|v| v.as_str() == Some(subscriber))
                                                })
                                                .unwrap_or(false)
                                            {
                                                if let Some(a) = ch
                                                    .get_mut("subscribers")
                                                    .and_then(|v| v.as_array_mut())
                                                {
                                                    a.push(serde_json::Value::String(
                                                        subscriber.to_string(),
                                                    ));
                                                }
                                            }
                                            let env = serde_json::json!({"kind":"awe.channel.v1","event":"upsert","channel":ch.clone(),"sender":local_uid});
                                            if let Ok(bytes) = serde_json::to_vec(&env) {
                                                sync = Some((subscriber.to_string(), bytes));
                                            }
                                        }
                                    }
                                } else if event == "message" {
                                    let cid = message
                                        .get("channel_id")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("");
                                    if let Some(ch) = state
                                        .get_mut("channels")
                                        .and_then(|v| v.as_array_mut())
                                        .and_then(|a| {
                                            a.iter_mut().find(|c| {
                                                c.get("id").and_then(|v| v.as_str()) == Some(cid)
                                            })
                                        })
                                    {
                                        let subscriber = ch
                                            .get("subscribers")
                                            .and_then(|v| v.as_array())
                                            .map(|a| {
                                                a.iter().any(|v| {
                                                    v.as_str() == Some(sender_uid.as_str())
                                                })
                                            })
                                            .unwrap_or(false)
                                            || ch.get("owner").and_then(|v| v.as_str())
                                                == Some(sender_uid.as_str());
                                        if subscriber {
                                            if let Some(m) = message.get("message").cloned() {
                                                if let Some(a) = ch
                                                    .get_mut("messages")
                                                    .and_then(|v| v.as_array_mut())
                                                {
                                                    a.push(m);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            if let Some((target_uid, bytes)) = sync {
                                let sync_node = dispatcher_node.clone();
                                tokio::spawn(async move {
                                    let peers = sync_node.active_peers().await;
                                    if let Some(target) =
                                        peers.into_iter().find(|p| hex::encode(*p) == target_uid)
                                    {
                                        let _ = sync_node.send_to_peer(&target, 100, bytes).await;
                                    }
                                });
                            }
                            continue;
                        }
                        if message.get("kind").and_then(|v| v.as_str()) == Some("awe.messenger.v1")
                        {
                            let id = message.get("id").and_then(|v| v.as_str()).unwrap_or("");
                            let text_value =
                                message.get("text").and_then(|v| v.as_str()).unwrap_or("");
                            let recipient = message
                                .get("recipient")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            if !id.is_empty() && !text_value.is_empty() && !recipient.is_empty() {
                                if let (Some(cid), Some(channel_message)) = (
                                    message.get("channel_id").and_then(|v| v.as_str()),
                                    message.get("channel_message").cloned(),
                                ) {
                                    if let Ok(mut state) = dispatcher_community.lock() {
                                        if let Some(ch) = state
                                            .get_mut("channels")
                                            .and_then(|v| v.as_array_mut())
                                            .and_then(|a| {
                                                a.iter_mut().find(|c| {
                                                    c.get("id").and_then(|v| v.as_str())
                                                        == Some(cid)
                                                })
                                            })
                                        {
                                            let sender_uid = format_uid(&sender);
                                            let authorized = ch
                                                .get("owner")
                                                .and_then(|v| v.as_str())
                                                == Some(sender_uid.as_str())
                                                || ch
                                                    .get("subscribers")
                                                    .and_then(|v| v.as_array())
                                                    .map(|a| {
                                                        a.iter().any(|v| {
                                                            v.as_str() == Some(sender_uid.as_str())
                                                        })
                                                    })
                                                    .unwrap_or(false);
                                            if authorized {
                                                if let Some(a) = ch
                                                    .get_mut("messages")
                                                    .and_then(|v| v.as_array_mut())
                                                {
                                                    a.push(channel_message);
                                                }
                                            }
                                        }
                                    }
                                }
                                if message.get("silent").and_then(|v| v.as_bool()) != Some(true) {
                                    let item = serde_json::json!({
                                        "id": id,
                                        "sender": format_uid(&sender),
                                        "recipient": recipient,
                                        "text": text_value,
                                        "state": "delivered",
                                        "timestamp": message.get("timestamp").and_then(|v| v.as_u64()).unwrap_or_else(now_unix)
                                    });
                                    if let Ok(mut log) = dispatcher_messenger.lock() {
                                        if !log.iter().any(|existing| {
                                            existing.get("id").and_then(|v| v.as_str()) == Some(id)
                                        }) {
                                            log.push(item);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    continue;
                }
                if stream != STORAGE_STREAM {
                    continue;
                }
                if let Ok(ack) = serde_json::from_slice::<StorageShardAck>(&payload) {
                    if ack.version == awep2p_core::data_plane::STORAGE_PROTOCOL_VERSION {
                        if let Ok(mut pending) = dispatcher_acks.lock() {
                            pending.insert(ack.request_id, ack);
                        }
                    }
                    continue;
                }

                if let Ok(request) = serde_json::from_slice::<StorageShardRequest>(&payload) {
                    if request.requester != sender || request.verify().is_err() {
                        continue;
                    }
                    let Ok(data) = dispatcher_storage.get(&request.expected_hash) else {
                        continue;
                    };
                    if data.len() > request.max_bytes as usize
                        || !runtime_policy.allows_shard(data.len())
                    {
                        continue;
                    }
                    let transfer = StorageShardTransfer::new(
                        request.request_id,
                        *dispatcher_node.identity.public.awe_id.as_bytes(),
                        request.file_id,
                        request.shard_index,
                        request.total_shards,
                        request.original_size,
                        data,
                    );
                    if transfer.payload_hash != request.expected_hash {
                        continue;
                    }
                    if let Ok(bytes) = serde_json::to_vec(&transfer) {
                        let _ = dispatcher_node
                            .send_to_peer(&sender, STORAGE_STREAM, bytes)
                            .await;
                    }
                    continue;
                }

                let Ok(transfer) = serde_json::from_slice::<StorageShardTransfer>(&payload) else {
                    continue;
                };
                if transfer.sender != sender || transfer.verify().is_err() {
                    continue;
                }
                let Ok(object_id) = dispatcher_storage.put(&transfer.payload) else {
                    continue;
                };
                let ack = StorageShardAck::new(
                    transfer.request_id,
                    transfer.file_id,
                    transfer.shard_index,
                    object_id,
                );
                if let Ok(bytes) = serde_json::to_vec(&ack) {
                    let _ = dispatcher_node
                        .send_to_peer(&sender, STORAGE_STREAM, bytes)
                        .await;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    });

    let ui_addr: SocketAddr = env::var("AWE_UI_ADDR")
        .unwrap_or_else(|_| DEFAULT_UI_ADDR.into())
        .parse()
        .context("invalid AWE_UI_ADDR")?;
    let listener = tokio::net::TcpListener::bind(ui_addr)
        .await
        .with_context(|| format!("cannot bind AWEp2P UI to {ui_addr}"))?;
    println!("AWEp2P is running.");
    println!("Node: {node_id}");
    println!("Node transport: {listen}");
    println!("Native UI: AWENET desktop window");

    let native_ui_addr = ui_addr;
    // The HTTP listener owns a node clone; the outbox retry worker keeps the
    // original handle so it can reconnect to peers independently.
    let ui_node = node.clone();
    let ui_onecoin_ledger = onecoin_ledger.clone();
    let ui_onecoin_outbox = onecoin_outbox.clone();
    let ui_onecoin_path = onecoin_path.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("UI listener error: {error}");
                    continue;
                }
            };
            let api_node = ui_node.clone();
            let api_messenger = messenger.clone();
            let api_federation = federation_state.clone();
            let api_storage = storage.clone();
            let api_pending_acks = pending_acks.clone();
            let api_pending_shards = pending_shards.clone();
            let api_federation_path = federation_path.clone();
            let api_policy = policy_state.clone();
            let api_community = community.clone();
            let api_onecoin_ledger = ui_onecoin_ledger.clone();
            let api_onecoin_outbox = ui_onecoin_outbox.clone();
            let api_onecoin_path = ui_onecoin_path.clone();
            let api_onecoin_offers_path = onecoin_offers_path.clone();
            let api_contribution = contribution.clone();
            let api_contribution_path = contribution_path.clone();
            let api_host = host.clone();
            let api_host_root = host_root.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_ui(
                    stream,
                    UiState {
                        node: api_node,
                        messenger: api_messenger,
                        federation_state: api_federation,
                        federation_path: api_federation_path,
                        storage: api_storage,
                        pending_acks: api_pending_acks,
                        pending_shards: api_pending_shards,
                        policy_state: api_policy,
                        community: api_community,
                        onecoin_ledger: api_onecoin_ledger,
                        onecoin_outbox: api_onecoin_outbox,
                        onecoin_path: api_onecoin_path,
                        onecoin_offers_path: api_onecoin_offers_path,
                        contribution: api_contribution,
                        contribution_path: api_contribution_path,
                        host: api_host,
                        host_root: api_host_root,
                    },
                )
                .await
                {
                    eprintln!("UI request error: {e}");
                }
            });
        }
    });

    // Retry durable outgoing transfers. Duplicate delivery is safe because the
    // receiver tracks transaction IDs and sender nonces before crediting a wallet.
    let retry_node = node.clone();
    let retry_outbox = onecoin_outbox.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            let pending = match retry_outbox.lock() {
                Ok(queue) => queue
                    .iter()
                    .map(|(id, tx)| (id.clone(), tx.clone()))
                    .collect::<Vec<_>>(),
                Err(_) => continue,
            };
            for (id, tx) in pending {
                let Ok(bytes) = serde_json::to_vec(&tx) else {
                    continue;
                };
                // Keep the item queued until the recipient's application ACK
                // arrives on the same stream and passes identity/transaction checks.
                if let Err(error) = retry_node
                    .send_to_peer(&tx.recipient, policy::ONECOIN_TRANSFER_STREAM, bytes)
                    .await
                {
                    eprintln!("ONECOIN pending transfer {id} will be retried: {error}");
                }
            }
        }
    });

    if env::var_os("AWE_NO_NATIVE_UI").is_some() {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    }

    native_ui::run(native_ui_addr).map_err(anyhow::Error::msg)?;
    Ok(())
}

async fn run_node(
    path: PathBuf,
    password: String,
    username: String,
    listen: SocketAddr,
    bootstrap: Vec<SocketAddr>,
) -> Result<()> {
    let identity = load_identity(&path, &password, &username)?;
    let node = Node::new(identity, listen);
    if !bootstrap.is_empty() {
        node.bootstrap(&bootstrap)
            .await
            .context("bootstrap failed")?;
        // Discovery is a continuous control-plane function, not a startup step.
        // Keep multiple seeds and learned peers alive so partitions can heal.
        node.spawn_discovery_loop(bootstrap.clone());
    }
    node.listen().await.map_err(anyhow::Error::msg)
}

fn print_id(path: PathBuf, password: String, username: String) -> Result<()> {
    println!(
        "{}",
        load_identity(&path, &password, &username)?
            .public
            .awe_id
            .to_hex()
    );
    Ok(())
}
fn print_status(path: PathBuf) -> Result<()> {
    println!(
        "{}",
        if path.exists() {
            format!("Vault exists at {}", path.display())
        } else {
            format!("Vault not found at {}", path.display())
        }
    );
    Ok(())
}
fn print_diagnostics() -> Result<()> {
    let mut d = NodeDiagnostics::new();
    d.update_metrics(NodeMetrics::default());
    println!("Status: {:?}", d.status());
    println!("Metrics: {:?}", d.metrics());
    Ok(())
}
fn run_mesh(port: u16) -> Result<()> {
    let addr: SocketAddr = format!("0.0.0.0:{port}").parse()?;
    let beacon = LanPeerBeacon::new([1u8; 32], addr, false);
    let bytes = beacon.encode().map_err(anyhow::Error::msg)?;
    println!("Broadcast beacon bytes: {}", bytes.len());
    println!(
        "Decoded: {:?}",
        LanPeerBeacon::decode(&bytes)
            .map_err(anyhow::Error::msg)?
            .node_id
    );
    Ok(())
}
fn print_health() -> Result<()> {
    println!(
        "Initial reputation score: {}",
        NodeReputation::new([1u8; 32]).score()
    );
    println!("Health: ONLINE");
    Ok(())
}
async fn probe(address: SocketAddr) -> Result<()> {
    let node = Node::new(
        Identity::generate(Username::new("probe-node").map_err(anyhow::Error::msg)?),
        "127.0.0.1:0".parse()?,
    );
    let mut c = node.connect(address).await.map_err(anyhow::Error::msg)?;
    println!("Authenticated peer: {:?}", c.remote_id);
    println!(
        "Heartbeat: {:?}",
        c.ping_roundtrip(1).await.map_err(anyhow::Error::msg)?
    );
    println!(
        "Encrypted data-plane: {:?}",
        c.send_data_roundtrip(7, b"AWEP2P-REAL-DATA-PROBE-v1".to_vec())
            .await
            .map_err(anyhow::Error::msg)?
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        None | Some("app") | Some("gui") => run_product().await,
        Some("secret") => {
            let username = args.next().unwrap_or_else(|| usage());
            generate_secret_file(&username, args.next().map(PathBuf::from))
        }
        Some("init") => {
            let username = args.next().unwrap_or_else(|| usage());
            init(
                &username,
                args.next().map(PathBuf::from).unwrap_or_else(default_vault),
            )
        }
        Some("run") => {
            let path = args.next().map(PathBuf::from).unwrap_or_else(|| usage());
            let password = args.next().unwrap_or_else(|| usage());
            let listen = args
                .next()
                .unwrap_or_else(|| usage())
                .parse()
                .context("invalid listen address")?;
            let username = env::var("AWE_USERNAME").unwrap_or_else(|_| "node".to_string());
            let bootstrap = args
                .map(|x| x.parse().context("invalid bootstrap address"))
                .collect::<Result<Vec<SocketAddr>>>()?;
            run_node(path, password, username, listen, bootstrap).await
        }
        Some("id") => print_id(
            args.next().map(PathBuf::from).unwrap_or_else(|| usage()),
            args.next().unwrap_or_else(|| usage()),
            args.next().unwrap_or_else(|| usage()),
        ),
        Some("status") => {
            print_status(args.next().map(PathBuf::from).unwrap_or_else(default_vault))
        }
        Some("diagnostics") => print_diagnostics(),
        Some("mesh") => run_mesh(args.next().unwrap_or_else(|| "41000".into()).parse()?),
        Some("health") => print_health(),
        Some("probe") => {
            probe(
                args.next()
                    .unwrap_or_else(|| usage())
                    .parse()
                    .context("invalid peer address")?,
            )
            .await
        }
        _ => usage(),
    }
}

#[cfg(test)]
mod amount_parser_tests {
    use super::*;

    fn temporary_state_path(name: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("awenet-{name}-{}-{nonce}.json", std::process::id()))
    }

    #[test]
    fn persisted_onecoin_state_roundtrips_and_overwrites_atomically() {
        let path = temporary_state_path("outbox-roundtrip");
        let sender = Identity::generate(Username::new("persist-sender").unwrap());
        let recipient = Identity::generate(Username::new("persist-recipient").unwrap());
        let extra = Identity::generate(Username::new("persist-extra").unwrap());
        let mut ledger = OnecoinLedger::default();
        ledger
            .initialize_genesis(&[
                sender.public.awe_id.clone(),
                recipient.public.awe_id.clone(),
            ])
            .unwrap();
        let tx = OnecoinTransaction::new(
            &sender,
            0,
            &recipient.public.awe_id,
            7,
            Some("durable pending transfer".into()),
        );
        let tx_id = hex::encode(tx.id());
        let pending = BTreeMap::from([(tx_id.clone(), tx.clone())]);

        persist_onecoin_state(&path, &ledger, &pending).unwrap();
        let loaded = load_persisted_onecoin_state(&path).unwrap();
        assert_eq!(loaded.format_version, 1);
        assert_eq!(loaded.ledger.members.len(), 2);
        assert_eq!(loaded.pending_transfers.get(&tx_id), Some(&tx));

        let mut changed_ledger = loaded.ledger;
        changed_ledger.ensure_member(&extra.public.awe_id);
        persist_onecoin_state(&path, &changed_ledger, &BTreeMap::new()).unwrap();
        let changed = load_persisted_onecoin_state(&path).unwrap();
        assert_eq!(changed.ledger.members.len(), 3);
        assert!(changed.pending_transfers.is_empty());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn persisted_onecoin_state_migrates_legacy_ledger_and_rejects_corruption() {
        let path = temporary_state_path("legacy-migration");
        let identity = Identity::generate(Username::new("persist-migration").unwrap());
        let mut legacy = OnecoinLedger::default();
        legacy
            .initialize_genesis(std::slice::from_ref(&identity.public.awe_id))
            .unwrap();
        fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();

        let migrated = load_persisted_onecoin_state(&path).unwrap();
        assert_eq!(migrated.format_version, 1);
        assert_eq!(
            migrated.ledger.balance_atoms(&identity.public.awe_id),
            legacy.balance_atoms(&identity.public.awe_id)
        );
        assert!(migrated.pending_transfers.is_empty());

        fs::write(&path, b"{ definitely not valid JSON").unwrap();
        assert!(load_persisted_onecoin_state(&path).is_err());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn contribution_parser_rejects_narrow_integer_overflow_and_invalid_types() {
        assert!(
            parse_resource_contribution(&serde_json::json!({"cpu_cores":4294967296u64})).is_err()
        );
        assert!(
            parse_resource_contribution(&serde_json::json!({"online_hours":65536u64})).is_err()
        );
        assert!(parse_resource_contribution(&serde_json::json!({"uptime_bps":10001u64})).is_err());
        assert!(parse_resource_contribution(&serde_json::json!({"storage_bytes":1.5})).is_err());
        assert!(parse_resource_contribution(&serde_json::json!({"cpu_cores":"4"})).is_err());
        assert!(parse_resource_contribution(&serde_json::json!({"online_hours":25})).is_err());
        assert_eq!(
            parse_resource_contribution(&serde_json::json!({"cpu_cores":4,"storage_bytes":1024}))
                .unwrap()
                .cpu_cores,
            4
        );
    }

    #[test]
    fn atom_formatter_preserves_all_eighteen_decimal_places() {
        assert_eq!(format_onecoin_atoms(1), "0.000000000000000001");
        assert_eq!(format_onecoin_atoms(ATOMS_PER_COIN / 2), "0.5");
        assert_eq!(format_onecoin_atoms(ATOMS_PER_COIN), "1");
    }

    #[test]
    fn coin_decimal_parser_uses_eighteen_atom_places() {
        assert_eq!(
            parse_onecoin_atoms(&serde_json::json!("0.5")).unwrap(),
            ATOMS_PER_COIN / 2
        );
        assert_eq!(
            parse_onecoin_atoms(&serde_json::json!("0.000000000000000001")).unwrap(),
            1
        );
        assert_eq!(
            parse_onecoin_atoms(&serde_json::json!("1.00000001")).unwrap(),
            ATOMS_PER_COIN + 10_000_000_000
        );
        assert!(parse_onecoin_atoms(&serde_json::json!("1.0000000000000000001")).is_err());
        assert!(parse_onecoin_atoms(&serde_json::json!("1e-3")).is_err());
        assert!(parse_onecoin_atoms(&serde_json::json!("-1")).is_err());
        assert!(parse_onecoin_atoms(&serde_json::json!("")).is_err());
        assert!(parse_onecoin_atoms(&serde_json::json!(null)).is_err());
        assert!(parse_onecoin_atoms(&serde_json::json!(
            "340282366920938463463.374607431768211456"
        ))
        .is_err());
    }
}
