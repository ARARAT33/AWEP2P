use std::{
    env, fs,
    io::{Read, Write},
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command},
    thread,
    time::{Duration, Instant},
};

fn request(addr: &str, request: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");
    stream.write_all(request.as_bytes()).expect("write");
    let mut out = String::new();
    stream.read_to_string(&mut out).expect("read");
    out.split("\r\n\r\n").nth(1).unwrap_or("").to_string()
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

        let connect2 = post(
            "127.0.0.1:46201",
            "/api/connect?address=127.0.0.1%3A46102",
            "{}",
        );
        assert!(
            connect2.contains(r#""status":"connected""#),
            "node2: {connect2}"
        );

        let connect3 = post(
            "127.0.0.1:46201",
            "/api/connect?address=127.0.0.1%3A46103",
            "{}",
        );
        assert!(
            connect3.contains(r#""status":"connected""#),
            "node3: {connect3}"
        );

        let status = get("127.0.0.1:46201", "/api/status");
        assert!(
            status.contains(r#""active_connections":2"#),
            "status: {status}"
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
        assert!(stored.contains(r#""status":"stored""#), "storage: {stored}");
        assert!(
            stored.contains(r#""sent_remote":24"#),
            "replication: {stored}"
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
        assert!(downloaded.contains(payload), "download: {downloaded}");
    });

    for child in &mut children {
        let _ = child.kill();
        let _ = child.wait();
    }
    let _ = fs::remove_dir_all(&root);
    result.expect("product smoke test failed");
}
