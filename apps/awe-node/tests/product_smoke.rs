use std::{
    env, fs,
    io::{Read, Write},
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command},
    thread,
    time::{Duration, Instant},
};

fn raw_response(addr: &str, request: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    stream.write_all(request.as_bytes()).expect("write request");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("read response");
    String::from_utf8_lossy(&response).into_owned()
}

fn request(addr: &str, request: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    stream.write_all(request.as_bytes()).expect("write");
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut out = Vec::with_capacity(65536);
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if out.len() >= 65536 {
                    break;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut =>
            {
                if Instant::now() >= deadline {
                    panic!(
                        "read timed out for {}: {err}",
                        request.lines().next().unwrap_or("<request>")
                    );
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(err) => panic!("read: {err}"),
        }
    }
    String::from_utf8_lossy(&out)
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or("")
        .to_string()
}

fn get(addr: &str, path: &str) -> String {
    request(
        addr,
        &format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
    )
}

fn post(addr: &str, path: &str, body: &str) -> String {
    request(
        addr,
        &format!(
            "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
}

fn wait_for_health(addr: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if Instant::now() >= deadline {
            panic!("node at {addr} did not become healthy");
        }
        if let Ok(mut stream) = TcpStream::connect(addr) {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
            let _ = stream.write_all(
                format!("GET /api/health HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            );
            let mut body = String::new();
            if stream.read_to_string(&mut body).is_ok() && body.contains(r#""status":"healthy""#) {
                return;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn spawn_node(bin: &PathBuf, data: &PathBuf, listen: u16, ui: u16) -> Child {
    Command::new(bin)
        .env("AWE_DATA_DIR", data)
        .env("AWE_LISTEN_ADDR", format!("127.0.0.1:{listen}"))
        .env("AWE_UI_ADDR", format!("127.0.0.1:{ui}"))
        .env("AWE_NO_BROWSER", "1")
        .env("AWE_NO_NATIVE_UI", "1")
        .spawn()
        .expect("spawn node")
}

#[test]
fn three_node_product_smoke() {
    let bin = PathBuf::from(env::var_os("CARGO_BIN_EXE_awe-node").expect("binary path"));
    let root = env::temp_dir().join(format!("awep2p-smoke-{}", std::process::id()));
    let dirs = [root.join("n1"), root.join("n2"), root.join("n3")];
    for dir in &dirs {
        fs::create_dir_all(dir).expect("create data dir");
    }

    let mut children = vec![
        spawn_node(&bin, &dirs[0], 46101, 46201),
        spawn_node(&bin, &dirs[1], 46102, 46202),
        spawn_node(&bin, &dirs[2], 46103, 46203),
    ];

    let result = std::panic::catch_unwind(|| {
        wait_for_health("127.0.0.1:46201");
        wait_for_health("127.0.0.1:46202");
        wait_for_health("127.0.0.1:46203");

        let site_id = "a".repeat(64);
        let site_response = raw_response(
            "127.0.0.1:46201",
            &format!(
                "GET /site/{site_id}/index.html HTTP/1.1\r\nHost: 127.0.0.1:46201\r\nConnection: close\r\n\r\n"
            ),
        );
        assert!(
            site_response.starts_with("HTTP/1.1 302 Found"),
            "hosted site should redirect to its isolated origin: {site_response}"
        );
        assert!(
            site_response.contains(&format!(
                "Location: http://{site_id}.localhost:46201/site/{site_id}/index.html"
            )),
            "site redirect must use a per-site localhost origin: {site_response}"
        );

        let isolated_api = raw_response(
            "127.0.0.1:46201",
            &format!(
                "GET /api/status HTTP/1.1\r\nHost: {site_id}.localhost:46201\r\nConnection: close\r\n\r\n"
            ),
        );
        assert!(
            isolated_api.starts_with("HTTP/1.1 404 Not Found"),
            "isolated hosted-site origin must not access the node API: {isolated_api}"
        );
        assert!(
            !isolated_api.contains("\"node_id\""),
            "isolated hosted-site origin must not receive node status data"
        );

        let isolated_preflight = raw_response(
            "127.0.0.1:46201",
            &format!(
                "OPTIONS /api/status HTTP/1.1\r\nHost: {site_id}.localhost:46201\r\nOrigin: http://{site_id}.localhost:46201\r\nAccess-Control-Request-Method: GET\r\nConnection: close\r\n\r\n"
            ),
        );
        assert!(
            isolated_preflight.starts_with("HTTP/1.1 404 Not Found"),
            "isolated hosted-site origin must not obtain API preflight access: {isolated_preflight}"
        );

        let cross_site = raw_response(
            "127.0.0.1:46201",
            &format!(
                "GET /site/{}/index.html HTTP/1.1\r\nHost: {site_id}.localhost:46201\r\nConnection: close\r\n\r\n",
                "b".repeat(64)
            ),
        );
        assert!(
            cross_site.starts_with("HTTP/1.1 404 Not Found"),
            "a site origin must not serve another site's content: {cross_site}"
        );

        let forbidden = raw_response(
            "127.0.0.1:46201",
            "POST /api/onebank/contribution HTTP/1.1\r\nHost: 127.0.0.1:46201\r\nOrigin: https://untrusted.example\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        );
        assert!(
            forbidden.starts_with("HTTP/1.1 403 Forbidden"),
            "cross-origin API mutation must be rejected: {forbidden}"
        );

        for (port, ui) in [
            (46101u16, 46201u16),
            (46102u16, 46202u16),
            (46103u16, 46203u16),
        ] {
            let status = get(&format!("127.0.0.1:{ui}"), "/api/status");
            assert!(
                status.contains(r#""status":"online""#),
                "status {port}: {status}"
            );
            assert!(
                status.contains(&format!("127.0.0.1:{port}")),
                "address {port}: {status}"
            );
        }

        let storage = get("127.0.0.1:46201", "/api/storage");
        assert!(
            storage.contains(r#""capacity_bytes""#),
            "storage API: {storage}"
        );
        assert!(
            storage.contains(r#""replication_policy""#),
            "replication policy: {storage}"
        );

        let published_offer = post(
            "127.0.0.1:46201",
            "/api/onebank/exchange/offers",
            r#"{"offer":{"side":"sell","amount":"0.5","price":"1.25","currency":"USD","rail":"BankTransfer"}}"#,
        );
        let published_offer: serde_json::Value =
            serde_json::from_str(&published_offer).expect("published offer JSON");
        assert_eq!(
            published_offer.get("status").and_then(|v| v.as_str()),
            Some("published"),
            "offer should be published"
        );
        let offer = published_offer.get("offer").expect("signed offer wrapper");
        assert_eq!(
            offer.get("signature_verified").and_then(|v| v.as_bool()),
            Some(true),
            "offer must be signed by the publishing node"
        );
        assert_eq!(
            offer
                .get("owner_public_key")
                .and_then(|v| v.as_str())
                .map(str::len),
            Some(64),
            "offer must retain the signer's public key"
        );
        let published_id = offer.get("id").and_then(|v| v.as_str()).expect("offer id");
        let offers: serde_json::Value =
            serde_json::from_str(&get("127.0.0.1:46201", "/api/onebank/exchange/offers"))
                .expect("verified offer list JSON");
        assert!(
            offers.as_array().is_some_and(|list| {
                list.iter()
                    .any(|item| item.get("id").and_then(|v| v.as_str()) == Some(published_id))
            }),
            "verified listing should be returned"
        );

        let offers_path = dirs[0].join("onecoin-exchange-offers.json");
        let mut stored: serde_json::Value =
            serde_json::from_slice(&fs::read(&offers_path).expect("read persisted offers"))
                .expect("persisted offer JSON");
        stored.as_array_mut().expect("offer array")[0]["owner_public_key"] =
            serde_json::Value::String("00".repeat(32));
        fs::write(
            &offers_path,
            serde_json::to_vec_pretty(&stored).expect("serialize tampered offer"),
        )
        .expect("write tampered offer");
        let after_tamper: serde_json::Value =
            serde_json::from_str(&get("127.0.0.1:46201", "/api/onebank/exchange/offers"))
                .expect("offer list after tamper");
        assert_eq!(
            after_tamper.as_array().map(Vec::len),
            Some(0),
            "the API must not return an offer with a tampered signer key"
        );

        // Queue a transfer while the recipient is offline; it must survive
        // that failure and be retried after the peer connects.
        let node2_pre: serde_json::Value =
            serde_json::from_str(&get("127.0.0.1:46202", "/api/onebank/wallet"))
                .expect("node2 wallet before connection");
        let node2_id_pre = node2_pre
            .get("awe_id")
            .and_then(|v| v.as_str())
            .expect("node2 AWEID before connection")
            .to_string();
        let node2_balance_pre = node2_pre
            .get("balance_atoms")
            .and_then(|v| v.as_u64())
            .expect("node2 balance before connection");
        let queued_transfer = post(
            "127.0.0.1:46201",
            "/api/onebank/wallet/send",
            &format!(
                r#"{{"recipient":"{node2_id_pre}","amount_coins":"0.25","memo":"outbox retry smoke"}}"#
            ),
        );
        assert!(
            queued_transfer.contains(r#""status":"accepted""#)
                && queued_transfer.contains(r#""recipient_pending":true"#),
            "offline transfer should be accepted into the durable outbox: {queued_transfer}"
        );
        let queued_wallet: serde_json::Value =
            serde_json::from_str(&get("127.0.0.1:46201", "/api/onebank/wallet"))
                .expect("sender wallet with pending transfer");
        assert!(
            queued_wallet
                .get("pending_transfers")
                .and_then(|v| v.as_u64())
                .is_some_and(|count| count >= 1),
            "pending ONECOIN transfer must be visible in wallet status: {queued_wallet}"
        );

        let connect2 = post(
            "127.0.0.1:46201",
            "/api/connect?address=127.0.0.1%3A46102",
            "{}",
        );
        assert!(
            connect2.contains(r#""status":"connecting""#),
            "node2: {connect2}"
        );

        let connect3 = post(
            "127.0.0.1:46201",
            "/api/connect?address=127.0.0.1%3A46103",
            "{}",
        );
        assert!(
            connect3.contains(r#""status":"connecting""#),
            "node3: {connect3}"
        );

        thread::sleep(Duration::from_secs(2));

        let retry_deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let recipient: serde_json::Value =
                serde_json::from_str(&get("127.0.0.1:46202", "/api/onebank/wallet"))
                    .expect("recipient wallet while retrying outbox");
            let current = recipient
                .get("balance_atoms")
                .and_then(|v| v.as_u64())
                .expect("recipient balance while retrying outbox");
            if current >= node2_balance_pre + 250_000_000_000_000_000u64 {
                break;
            }
            if Instant::now() >= retry_deadline {
                panic!("durable ONECOIN outbox did not deliver after connection: {recipient}");
            }
            thread::sleep(Duration::from_millis(100));
        }
        let ack_deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let sender_wallet_after_retry: serde_json::Value =
                serde_json::from_str(&get("127.0.0.1:46201", "/api/onebank/wallet"))
                    .expect("sender wallet after outbox delivery");
            if sender_wallet_after_retry
                .get("pending_transfers")
                .and_then(|v| v.as_u64())
                == Some(0)
            {
                break;
            }
            if Instant::now() >= ack_deadline {
                panic!(
                    "recipient applied transfer but sender outbox was not cleared by application ACK: {sender_wallet_after_retry}"
                );
            }
            thread::sleep(Duration::from_millis(100));
        }

        let status = get("127.0.0.1:46201", "/api/status");
        assert!(
            status.contains(r#""active_connections":2"#),
            "connections: {status}"
        );

        let node2_wallet_before: serde_json::Value =
            serde_json::from_str(&get("127.0.0.1:46202", "/api/onebank/wallet"))
                .expect("node2 wallet before json");
        let node2_id = node2_wallet_before
            .get("awe_id")
            .and_then(|v| v.as_str())
            .expect("node2 AWEID")
            .to_string();
        let wallet_before: serde_json::Value =
            serde_json::from_str(&get("127.0.0.1:46201", "/api/onebank/wallet"))
                .expect("wallet before json");
        let onecoin_send = post(
            "127.0.0.1:46201",
            "/api/onebank/wallet/send",
            &format!(r#"{{"recipient":"{node2_id}","amount_coins":1,"memo":"E2E fee test"}}"#),
        );
        assert!(
            onecoin_send.contains(r#""status":"accepted""#),
            "ONECOIN send: {onecoin_send}"
        );
        assert!(
            onecoin_send.contains(r#""fee_bps":100"#),
            "ONEBANK fee: {onecoin_send}"
        );
        let wallet_after: serde_json::Value =
            serde_json::from_str(&get("127.0.0.1:46201", "/api/onebank/wallet"))
                .expect("wallet after json");
        let receiver_deadline = Instant::now() + Duration::from_secs(5);
        let node2_wallet_after: serde_json::Value = loop {
            let current: serde_json::Value =
                serde_json::from_str(&get("127.0.0.1:46202", "/api/onebank/wallet"))
                    .expect("node2 wallet after json");
            let before_balance = node2_wallet_before
                .get("balance_atoms")
                .and_then(|v| v.as_u64())
                .expect("receiver balance");
            let current_balance = current
                .get("balance_atoms")
                .and_then(|v| v.as_u64())
                .expect("receiver current balance");
            if current_balance == before_balance + 1_000_000_000_000_000_000u64 {
                break current;
            }
            if Instant::now() >= receiver_deadline {
                panic!("recipient wallet did not receive transfer: {current}");
            }
            thread::sleep(Duration::from_millis(100));
        };
        let before = wallet_before
            .get("balance_atoms")
            .and_then(|v| v.as_u64())
            .expect("sender balance");
        let after = wallet_after
            .get("balance_atoms")
            .and_then(|v| v.as_u64())
            .expect("sender after");
        let receiver_before = node2_wallet_before
            .get("balance_atoms")
            .and_then(|v| v.as_u64())
            .expect("receiver balance");
        let receiver_after = node2_wallet_after
            .get("balance_atoms")
            .and_then(|v| v.as_u64())
            .expect("receiver after");
        assert_eq!(
            before - after,
            1_010_000_000_000_000_000u64,
            "sender pays amount plus 1% fee"
        );
        assert_eq!(
            receiver_after - receiver_before,
            1_000_000_000_000_000_000u64,
            "receiver gets exact amount"
        );
        let message = post(
            "127.0.0.1:46201",
            "/api/messenger/send",
            &format!(r#"{{"recipient":"{node2_id}","text":"AWEP2P-E2E-MESSENGER"}}"#),
        );
        assert!(
            message.contains(r#""status":"sent""#),
            "messenger send: {message}"
        );
        let message_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let received = get("127.0.0.1:46202", "/api/messenger");
            if received.contains("AWEP2P-E2E-MESSENGER")
                && received.contains(r#""state":"delivered""#)
            {
                break;
            }
            if Instant::now() >= message_deadline {
                panic!("messenger delivery not observed: {received}");
            }
            thread::sleep(Duration::from_millis(100));
        }

        let group_create = post(
            "127.0.0.1:46201",
            "/api/groups/create",
            &format!(r#"{{"title":"E2E Group","members":["{node2_id}"]}}"#),
        );
        assert!(
            group_create.contains(r#""status":"created""#),
            "group create: {group_create}"
        );
        let group: serde_json::Value =
            serde_json::from_str(&group_create).expect("group create json");
        let group_id = group
            .get("group")
            .and_then(|g| g.get("id"))
            .and_then(|v| v.as_str())
            .expect("group id");
        let group_sync_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let groups = get("127.0.0.1:46202", "/api/groups");
            if groups.contains(group_id) && groups.contains("E2E Group") {
                break;
            }
            if Instant::now() >= group_sync_deadline {
                panic!("group sync not observed: {groups}");
            }
            thread::sleep(Duration::from_millis(100));
        }
        let group_send = post(
            "127.0.0.1:46201",
            "/api/groups/send",
            &format!(r#"{{"group_id":"{group_id}","text":"AWEP2P-E2E-GROUP"}}"#),
        );
        assert!(
            group_send.contains(r#""status":"sent""#)
                && group_send.contains(r#""delivered_members":1"#),
            "group send did not reach a member: {group_send}"
        );
        let group_message_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let groups = get("127.0.0.1:46202", "/api/groups");
            if groups.contains("AWEP2P-E2E-GROUP") {
                break;
            }
            if Instant::now() >= group_message_deadline {
                panic!("group message not observed: {groups}");
            }
            thread::sleep(Duration::from_millis(100));
        }

        let channel_create = post(
            "127.0.0.1:46201",
            "/api/channels/create",
            r#"{"title":"E2E Channel"}"#,
        );
        assert!(
            channel_create.contains(r#""status":"created""#),
            "channel create: {channel_create}"
        );
        let channel: serde_json::Value =
            serde_json::from_str(&channel_create).expect("channel create json");
        let channel_id = channel
            .get("channel")
            .and_then(|g| g.get("id"))
            .and_then(|v| v.as_str())
            .expect("channel id");
        assert!(
            channel
                .get("delivered_peers")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                > 0,
            "channel update was not acknowledged by any peer: {channel_create}"
        );
        let channel_sync_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let channels = get("127.0.0.1:46202", "/api/channels");
            if channels.contains(channel_id) && channels.contains("E2E Channel") {
                break;
            }
            if Instant::now() >= channel_sync_deadline {
                panic!("channel sync not observed: {channels}");
            }
            thread::sleep(Duration::from_millis(100));
        }
        let subscribe = post(
            "127.0.0.1:46202",
            "/api/channels/subscribe",
            &format!(r#"{{"channel_id":"{channel_id}"}}"#),
        );
        assert!(
            subscribe.contains(r#""status":"subscribed""#),
            "subscribe: {subscribe}"
        );
        assert!(
            subscribe.contains(r#""owner_notified":true"#),
            "owner notification was not acknowledged: {subscribe}"
        );
        let subscriber_channels = get("127.0.0.1:46202", "/api/channels");
        assert!(
            subscriber_channels.contains(&format!(r#""{node2_id}""#)),
            "subscriber state: {subscriber_channels}"
        );
        let owner_channels_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let owner_channels = get("127.0.0.1:46201", "/api/channels");
            if owner_channels.contains(&format!(r#""{node2_id}""#)) {
                break;
            }
            if Instant::now() >= owner_channels_deadline {
                panic!("owner did not receive subscription: {owner_channels}");
            }
            thread::sleep(Duration::from_millis(100));
        }
        let publish = post(
            "127.0.0.1:46201",
            "/api/channels/publish",
            &format!(r#"{{"channel_id":"{channel_id}","text":"AWEP2P-E2E-CHANNEL"}}"#),
        );
        assert!(
            publish.contains(r#""status":"published""#),
            "publish: {publish}"
        );
        let channel_message_deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let channels = get("127.0.0.1:46202", "/api/channels");
            if channels.contains("AWEP2P-E2E-CHANNEL") {
                break;
            }
            if Instant::now() >= channel_message_deadline {
                panic!("channel message not observed: {channels}");
            }
            thread::sleep(Duration::from_millis(100));
        }

        let ui = get("127.0.0.1:46201", "/");
        assert!(ui.contains("<title>AWENET</title>"), "desktop UI: {ui}");
        let store = get("127.0.0.1:46201", "/api/store/catalog");
        assert!(store.contains(r#""status":"ok""#), "store API: {store}");

        // Exercise Creator Studio's real local publication endpoint and its validation.
        let wasm_hex = "0061736d01000000";
        let publish_app = post(
            "127.0.0.1:46201",
            "/api/store/publish",
            &format!(
                r#"{{"id":"smoke.creator.app","name":"Creator Smoke Test","version":"1.0.0","kind":"Wasm","entry":"/app.wasm","permissions":[],"price_onecoin_atoms":null,"files":[{{"path":"/app.wasm","data_hex":"{wasm_hex}"}}]}}"#
            ),
        );
        assert!(
            publish_app.contains(r#""status":"published""#)
                && publish_app.contains(r#""scope":"local-store""#),
            "Creator Studio package publication: {publish_app}"
        );
        let catalog_after_publish = get("127.0.0.1:46201", "/api/store/catalog");
        assert!(
            catalog_after_publish.contains("smoke.creator.app"),
            "published package missing from verified catalog: {catalog_after_publish}"
        );
        let bad_entry = post(
            "127.0.0.1:46201",
            "/api/store/publish",
            &format!(
                r#"{{"id":"smoke.bad.entry","name":"Invalid Entry","version":"1.0.0","kind":"Wasm","entry":"/missing.wasm","permissions":[],"price_onecoin_atoms":null,"files":[{{"path":"/app.wasm","data_hex":"{wasm_hex}"}}]}}"#
            ),
        );
        assert!(
            bad_entry.contains(r#""status":"error""#) && bad_entry.contains("entry must reference"),
            "invalid package entry should be rejected: {bad_entry}"
        );

        let payload = "AWEP2P-REAL-PRODUCT-SMOKE";
        let hex = payload
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let stored = post(
            "127.0.0.1:46201",
            "/api/storage/put",
            &format!(r#"{{"filename":"smoke.txt","data_hex":"{hex}"}}"#),
        );
        assert!(
            stored.contains(r#""status":"stored""#),
            "storage put: {stored}"
        );
        let file_id = stored
            .split(r#""file_id":""#)
            .nth(1)
            .and_then(|x| x.split('"').next())
            .expect("file id");
        let downloaded = get(
            "127.0.0.1:46201",
            &format!("/api/storage/get?file_id={file_id}"),
        );
        assert!(
            downloaded.contains(r#""status":"reconstructed""#)
                && downloaded.contains(&format!(r#""data_hex":"{hex}""#)),
            "storage get: {downloaded}"
        );

        let site_publish = post(
            "127.0.0.1:46201",
            "/api/sites/publish",
            r#"{"domain":"smoke-site","version":1,"files":[{"path":"/index.html","content_type":"text/html; charset=utf-8","content":"<!doctype html><title>AWENET site smoke</title>"}]}"#,
        );
        assert!(
            site_publish.contains(r#""status":"published""#),
            "site publish: {site_publish}"
        );
        let site: serde_json::Value =
            serde_json::from_str(&site_publish).expect("site publish json");
        let site_id = site
            .get("site_id")
            .and_then(|v| v.as_str())
            .expect("published site ID");
        let served_site = raw_response(
            "127.0.0.1:46201",
            &format!(
                "GET /site/{site_id}/index.html HTTP/1.1\r\nHost: {site_id}.localhost:46201\r\nConnection: close\r\n\r\n"
            ),
        );
        assert!(
            served_site.contains("AWENET site smoke"),
            "published site content was not served: {served_site}"
        );
    });

    for child in &mut children {
        let _ = child.kill();
        let _ = child.wait();
    }
    let _ = fs::remove_dir_all(&root);
    result.expect("product smoke test failed");
}
