use anyhow::{Context, Result};
use awep2p_core::data_plane::{
    StorageShardAck, StorageShardRequest, StorageShardTransfer, STORAGE_STREAM,
};
use awep2p_core::diagnostics::{NodeDiagnostics, NodeMetrics};
use awep2p_core::federation::{
    self, AweNetConfig, AweNodeConfig, DataCentreConfig, DataGroupConfig,
};
use awep2p_core::identity::{AweSecret, Identity, LocalVault, Username};
use awep2p_core::lan_mesh::LanPeerBeacon;
use awep2p_core::messenger::format_uid;
use awep2p_core::messenger_runtime::{ContactId, Envelope as RuntimeEnvelope, MediaKind, MessengerState};
use awep2p_core::network::{format_node_descriptor, Node};
use awep2p_core::policy::{self, NetworkPolicy};
use awep2p_core::reputation::NodeReputation;
use awep2p_core::storage::{encode_shards, recover_shards, LocalNodeStore, StoragePolicy};
use awep2p_core::supervisor::{PeerSupervisor, SupervisorConfig};
use std::{
    collections::BTreeMap,
    env, fs,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const UI_HTML: &str = include_str!("../../awe-desktop/ui/index.html");
const UI_CSS: &str = include_str!("../../awe-desktop/ui/style.css");
const UI_JS: &str = include_str!("../../awe-desktop/ui/app.js");
const DEFAULT_UI_ADDR: &str = "127.0.0.1:41800";

type MessengerLog = Arc<Mutex<Vec<serde_json::Value>>>;
type FederationState = Arc<Mutex<AweNetConfig>>;
type StorageState = Arc<LocalNodeStore>;
type PendingAcks = Arc<Mutex<BTreeMap<[u8; 16], StorageShardAck>>>;
type PendingMessengerAcks = Arc<Mutex<BTreeMap<String, u64>>>;
type MessengerRuntimeState = Arc<Mutex<MessengerState>>;
type PendingShards = Arc<Mutex<BTreeMap<[u8; 16], StorageShardTransfer>>>;
type PolicyState = Arc<Mutex<NetworkPolicy>>;

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

async fn http_response(status: &str, content_type: &str, body: &str) -> Vec<u8> {
    format!("HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: content-type\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}", body.len()).into_bytes()
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
async fn serve_ui(
    mut stream: tokio::net::TcpStream,
    node: Node,
    messenger: MessengerLog,
    federation_state: FederationState,
    federation_path: PathBuf,
    storage: StorageState,
    pending_acks: PendingAcks,
    pending_messenger_acks: PendingMessengerAcks,
    messenger_runtime: MessengerRuntimeState,
    pending_shards: PendingShards,
    policy_state: PolicyState,
) -> Result<()> {
    let request = read_http_request(&mut stream).await?;
    let request_line = request.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let path = parts.next().unwrap_or("/").split('?').next().unwrap_or("/");
    let (status, mime, body) = match path {
        "/" | "/index.html" => ("200 OK", "text/html; charset=utf-8", UI_HTML.to_string()),
        "/style.css" => ("200 OK", "text/css; charset=utf-8", UI_CSS.to_string()),
        "/app.js" => ("200 OK", "application/javascript; charset=utf-8", UI_JS.to_string()),
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
        "/api/messenger" => {
            ("200 OK", "application/json; charset=utf-8", serde_json::json!({
                "transport":"AWE encrypted TCP",
                "application_transport":"authenticated peer data stream",
                "messages": messenger.lock().map(|x| x.clone()).unwrap_or_default()
            }).to_string())
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
                let message_id_bytes = <[u8; 16]>::try_from(&digest.as_bytes()[..16]).expect("blake3 digest slice has 16 bytes");
                let message_id = hex::encode(message_id_bytes);
                let sequence = messenger_runtime
                    .lock()
                    .map(|mut runtime| runtime.allocate_sequence())
                    .unwrap_or(timestamp);
                let envelope = RuntimeEnvelope {
                    message_id: message_id_bytes,
                    sender: ContactId(*node.identity.public.awe_id.as_bytes()),
                    recipient: ContactId(recipient_id),
                    session_epoch: timestamp,
                    sequence,
                    kind: MediaKind::Text,
                    ciphertext: text.as_bytes().to_vec(),
                };
                if let Ok(mut runtime) = messenger_runtime.lock() {
                    let _ = runtime.queue(envelope.clone(), timestamp);
                }
                match serde_json::to_vec(&envelope) {
                    Ok(payload) => {
                        if let Ok(mut pending) = pending_messenger_acks.lock() {
                            pending.remove(&message_id);
                        }
                        match node.send_to_peer(&recipient_id, policy::MESSENGER_STREAM, payload).await {
                            Ok(rtt) => {
                                if let Ok(mut runtime) = messenger_runtime.lock() {
                                    let _ = runtime.mark_sent(message_id_bytes, timestamp);
                                }
                                let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
                                let mut delivered = false;
                                while tokio::time::Instant::now() < deadline {
                                    if let Ok(mut pending) = pending_messenger_acks.lock() {
                                        if pending.remove(&message_id).is_some() {
                                            if let Ok(mut runtime) = messenger_runtime.lock() {
                                                let _ = runtime.mark_delivered(message_id_bytes);
                                            }
                                            delivered = true;
                                            break;
                                        }
                                    }
                                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                                }
                                if !delivered {
                                    if let Ok(mut runtime) = messenger_runtime.lock() {
                                        let _ = runtime.mark_failed(message_id_bytes, "remote ACK timeout", now_unix());
                                    }
                                }
                                let state = if delivered { "delivered" } else { "pending" };
                                let item = serde_json::json!({
                                    "id": message_id,
                                    "sender": format_uid(node.identity.public.awe_id.as_bytes()),
                                    "recipient": format_uid(&recipient_id),
                                    "text": text,
                                    "state": state,
                                    "timestamp": timestamp,
                                    "rtt_ms": rtt.as_millis()
                                });
                                if let Ok(mut log) = messenger.lock() {
                                    log.push(item.clone());
                                }
                                if delivered {
                                    ("200 OK", "application/json; charset=utf-8", serde_json::json!({"status":"delivered","message":item}).to_string())
                                } else {
                                    ("504 Gateway Timeout", "application/json; charset=utf-8", serde_json::json!({"status":"pending_ack","message":item}).to_string())
                                }
                            }
                            Err(error) => {
                                if let Ok(mut runtime) = messenger_runtime.lock() {
                                    let _ = runtime.mark_failed(message_id_bytes, error.to_string(), now_unix());
                                }
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
                        }
                    }
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
                                                                Ok((0usize, Some(serde_json::json!({
                                                                    "shard": index, "node": target_name, "error": "remote storage ACK not confirmed"
                                                                }))))
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

                                    let status = if failed.is_empty() { "stored" } else { "partial" };
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
        .write_all(&http_response(status, mime, &body).await)
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
        AweSecret::from_bytes(&fs::read(&secret_path)?)
            .map_err(anyhow::Error::msg)?
            .authenticate()
            .map_err(anyhow::Error::msg)?
    } else {
        let identity =
            Identity::generate(Username::new("awe-node".to_string()).map_err(anyhow::Error::msg)?);
        let secret = AweSecret::generate(&identity);
        fs::write(&secret_path, secret.to_bytes()?)?;
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
    let messenger: MessengerLog = Arc::new(Mutex::new(Vec::new()));
    let pending_acks: PendingAcks = Arc::new(Mutex::new(BTreeMap::new()));
    let pending_messenger_acks: PendingMessengerAcks = Arc::new(Mutex::new(BTreeMap::new()));
    let messenger_runtime: MessengerRuntimeState = Arc::new(Mutex::new(MessengerState::default()));
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

    let dispatcher_node = node.clone();
    let dispatcher_storage = storage.clone();
    let dispatcher_messenger = messenger.clone();
    let dispatcher_acks = pending_acks.clone();
    let dispatcher_policy = policy_state.clone();
    let dispatcher_messenger_runtime = messenger_runtime.clone();
    let retry_node = node.clone();
    let retry_runtime = messenger_runtime.clone();
    let retry_policy = policy_state.clone();
    tokio::spawn(async move {
        loop {
            let now = now_unix();
            let retries = retry_runtime.lock().map(|state| state.due_retries(now)).unwrap_or_default();
            for retry in retries {
                if let Ok(policy) = retry_policy.lock() {
                    if !policy.allows_stream(policy::MESSENGER_STREAM) { continue; }
                }
                let recipient = retry.envelope.recipient.0;
                let payload = match serde_json::to_vec(&retry.envelope) { Ok(p) => p, Err(_) => continue };
                match retry_node.send_to_peer(&recipient, policy::MESSENGER_STREAM, payload).await {
                    Ok(_) => {
                        if let Ok(mut state) = retry_runtime.lock() {
                            let _ = state.mark_sent(retry.envelope.message_id, now);
                        }
                    }
                    Err(error) => {
                        if let Ok(mut state) = retry_runtime.lock() {
                            let _ = state.mark_failed(retry.envelope.message_id, error.to_string(), now);
                        }
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    });
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
                if stream == policy::MESSENGER_STREAM {
                    if let Ok(message) = serde_json::from_slice::<serde_json::Value>(&payload) {
                        if message.get("kind").and_then(|v| v.as_str()) == Some("awe.messenger.ack.v1") {
                            if let Some(id) = message.get("id").and_then(|v| v.as_str()) {
                                if let Ok(mut pending) = pending_messenger_acks.lock() {
                                    pending.insert(id.to_owned(), now_unix());
                                }
                                if let Ok(bytes) = hex::decode(id) {
                                    if let Ok(message_id) = <[u8; 16]>::try_from(bytes.as_slice()) {
                                        if let Ok(mut runtime) = dispatcher_messenger_runtime.lock() {
                                            let _ = runtime.mark_delivered(message_id);
                                        }
                                    }
                                }
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
                                let ack = serde_json::json!({"kind":"awe.messenger.ack.v1","id":id});
                                if let Ok(bytes) = serde_json::to_vec(&ack) {
                                    let _ = dispatcher_node.send_to_peer(&sender, policy::MESSENGER_STREAM, bytes).await;
                                }
                            }
                        }
                    }
                    continue;
                }
                if stream == policy::MESSENGER_STREAM {
                    if let Ok(runtime_envelope) = serde_json::from_slice::<RuntimeEnvelope>(&payload) {
                        if runtime_envelope.validate().is_ok()
                            && runtime_envelope.recipient.0 == *dispatcher_node.identity.public.awe_id.as_bytes()
                        {
                            let sender_id = runtime_envelope.sender.0;
                            if let Ok(mut runtime) = dispatcher_messenger_runtime.lock() {
                                if !runtime.replay.accept(sender_id, runtime_envelope.sequence) {
                                    continue;
                                }
                            }
                            let id = hex::encode(runtime_envelope.message_id);
                            let text_value = String::from_utf8_lossy(&runtime_envelope.ciphertext).to_string();
                            let item = serde_json::json!({
                                "id": id,
                                "sender": format_uid(&sender_id),
                                "recipient": format_uid(&runtime_envelope.recipient.0),
                                "text": text_value,
                                "state": "delivered",
                                "timestamp": runtime_envelope.session_epoch
                            });
                            if let Ok(mut log) = dispatcher_messenger.lock() {
                                if !log.iter().any(|existing| existing.get("id").and_then(|v| v.as_str()) == Some(&id)) {
                                    log.push(item);
                                }
                            }
                            let ack = serde_json::json!({"kind":"awe.messenger.ack.v1","id":id});
                            if let Ok(bytes) = serde_json::to_vec(&ack) {
                                let _ = dispatcher_node.send_to_peer(&sender_id, policy::MESSENGER_STREAM, bytes).await;
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
                        .send_to_peer_confirmed(&sender, STORAGE_STREAM, bytes)
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
    println!("UI: http://{ui_addr}");

    let url = format!("http://{ui_addr}/");
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "", &url])
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(&url).spawn();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
    }

    loop {
        let (stream, _) = listener.accept().await?;
        let api_node = node.clone();
        let api_messenger = messenger.clone();
        let api_federation = federation_state.clone();
        let api_storage = storage.clone();
        let api_pending_acks = pending_acks.clone();
        let api_pending_messenger_acks = pending_messenger_acks.clone();
        let api_messenger_runtime = messenger_runtime.clone();
        let api_pending_shards = pending_shards.clone();
        let api_federation_path = federation_path.clone();
        let api_policy = policy_state.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_ui(
                stream,
                api_node,
                api_messenger,
                api_federation,
                api_federation_path,
                api_storage,
                api_pending_acks,
                api_pending_messenger_acks,
                api_messenger_runtime,
                api_pending_shards,
                api_policy,
            )
            .await
            {
                eprintln!("UI request error: {e}");
            }
        });
    }
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
