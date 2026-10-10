use eframe::egui;
use serde_json::Value;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Home,
    Network,
    Wallet,
    Messenger,
    Browser,
    Node,
    Settings,
}

impl Page {
    fn title(self) -> &'static str {
        match self {
            Self::Home => "Home",
            Self::Network => "AWENET Network",
            Self::Wallet => "ONECOIN Wallet",
            Self::Messenger => "Messenger",
            Self::Browser => "AWENET Browser",
            Self::Node => "Node",
            Self::Settings => "Settings",
        }
    }
}

pub fn run(addr: SocketAddr) -> Result<(), String> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1240.0, 780.0])
            .with_min_inner_size([980.0, 620.0])
            .with_title("AWENET"),
        ..Default::default()
    };
    eframe::run_native(
        "AWENET",
        options,
        Box::new(move |_cc| Ok(Box::new(AweNetDesktop::new(addr)))),
    )
    .map_err(|error| error.to_string())
}

struct AweNetDesktop {
    addr: SocketAddr,
    page: Page,
    status: Value,
    wallet: Value,
    recipient: String,
    amount: String,
    memo: String,
    object_id: String,
    search: String,
    message: String,
    last_refresh: Instant,
}

impl AweNetDesktop {
    fn new(addr: SocketAddr) -> Self {
        let mut app = Self {
            addr,
            page: Page::Home,
            status: Value::Null,
            wallet: Value::Null,
            recipient: String::new(),
            amount: "1".into(),
            memo: String::new(),
            object_id: String::new(),
            search: String::new(),
            message: String::new(),
            last_refresh: Instant::now() - Duration::from_secs(10),
        };
        app.refresh();
        app
    }

    fn request(&self, method: &str, path: &str, body: Option<&str>) -> Result<Value, String> {
        let mut stream = TcpStream::connect_timeout(&self.addr, Duration::from_secs(2))
            .map_err(|e| format!("AWENET backend unavailable: {e}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .map_err(|e| e.to_string())?;
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .map_err(|e| e.to_string())?;
        let body_bytes = body.unwrap_or("").as_bytes();
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: awenet\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body_bytes.len(),
            body.unwrap_or("")
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| e.to_string())?;
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&response);
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
        serde_json::from_str(body).map_err(|e| format!("invalid backend response: {e}"))
    }

    fn refresh(&mut self) {
        if self.last_refresh.elapsed() < Duration::from_millis(700) {
            return;
        }
        self.last_refresh = Instant::now();
        match self.request("GET", "/api/status", None) {
            Ok(value) => self.status = value,
            Err(error) => self.message = error,
        }
        if let Ok(value) = self.request("GET", "/api/onebank/wallet", None) {
            self.wallet = value;
        }
    }

    fn send_onecoin(&mut self) {
        let amount = self.amount.trim();
        if amount.is_empty() || amount.starts_with('-') {
            self.message = "Enter a valid positive ONECOIN amount.".into();
            return;
        }
        let recipient = self.recipient.trim();
        if recipient.len() != 64 {
            self.message = "Recipient must be a 64-character AWEID.".into();
            return;
        }
        let body = serde_json::json!({
            "recipient": recipient,
            "amount_coins": amount,
            "memo": if self.memo.trim().is_empty() { Value::Null } else { Value::String(self.memo.trim().into()) }
        });
        match self.request("POST", "/api/onebank/wallet/send", Some(&body.to_string())) {
            Ok(value) => {
                self.message = value
                    .get("status")
                    .and_then(Value::as_str)
                    .map(|s| format!("Transfer: {s}"))
                    .unwrap_or_else(|| value.to_string());
                self.refresh();
            }
            Err(error) => self.message = error,
        }
    }

    fn home(&mut self, ui: &mut egui::Ui) {
        ui.heading("AWENET");
        ui.label("One network. One native application. Shared resources.");
        ui.add_space(14.0);
        let peers = self
            .status
            .get("active_connections")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let node = self
            .status
            .get("node")
            .and_then(Value::as_str)
            .unwrap_or("starting");
        ui.horizontal(|ui| {
            ui.group(|ui| {
                ui.strong("Network");
                ui.label(format!("{peers} active connections"));
            });
            ui.group(|ui| {
                ui.strong("Node");
                ui.label(node);
            });
            ui.group(|ui| {
                ui.strong("ONECOIN");
                ui.label(format!(
                    "{}",
                    self.wallet
                        .get("balance_coins")
                        .and_then(Value::as_f64)
                        .unwrap_or(0.0)
                ));
            });
        });
        ui.add_space(18.0);
        ui.heading("Quick actions");
        ui.horizontal_wrapped(|ui| {
            if ui.button("Open Wallet").clicked() {
                self.page = Page::Wallet;
            }
            if ui.button("Network").clicked() {
                self.page = Page::Network;
            }
            if ui.button("Messenger").clicked() {
                self.page = Page::Messenger;
            }
            if ui.button("AWENET Browser").clicked() {
                self.page = Page::Browser;
            }
            if ui.button("Node").clicked() {
                self.page = Page::Node;
            }
        });
    }

    fn network(&mut self, ui: &mut egui::Ui) {
        ui.heading("AWENET Network");
        let connections = self
            .status
            .get("active_connections")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let peers = self
            .status
            .get("peers")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        ui.label(format!("Active connections: {connections}"));
        ui.label(format!("Known peers: {}", peers.len()));
        ui.separator();
        for peer in peers {
            let id = peer.get("id").and_then(Value::as_str).unwrap_or("unknown");
            let address = peer
                .get("address")
                .and_then(Value::as_str)
                .unwrap_or("private");
            ui.horizontal(|ui| {
                ui.label(id);
                ui.label(address);
            });
        }
    }

    fn wallet(&mut self, ui: &mut egui::Ui) {
        ui.heading("ONECOIN Wallet");
        ui.label(format!(
            "Balance: {} ONECOIN",
            self.wallet
                .get("balance_coins_exact")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| self.wallet.get("balance_coins").map(ToString::to_string))
                .unwrap_or_else(|| "0".into())
        ));
        ui.label(format!(
            "Tier: {}",
            self.wallet
                .get("tier")
                .and_then(Value::as_str)
                .unwrap_or("FREE")
        ));
        ui.separator();
        ui.label("Recipient AWEID");
        ui.text_edit_singleline(&mut self.recipient);
        ui.label("Amount");
        ui.text_edit_singleline(&mut self.amount);
        ui.label("Memo");
        ui.text_edit_singleline(&mut self.memo);
        if ui.button("Send ONECOIN").clicked() {
            self.send_onecoin();
        }
        if !self.message.is_empty() {
            ui.separator();
            ui.label(&self.message);
        }
    }

    fn messenger(&mut self, ui: &mut egui::Ui) {
        ui.heading("Messenger");
        ui.label("Native messenger workspace");
        ui.separator();
        ui.label("Channels are available through the AWENET node. Select a channel from the native workspace when channel controls are expanded.");
        if ui.button("Open channels").clicked() {
            self.message = match self.request("GET", "/api/channels", None) {
                Ok(value) => value.to_string(),
                Err(error) => error,
            };
        }
        if !self.message.is_empty() {
            ui.label(&self.message);
        }
    }

    fn browser(&mut self, ui: &mut egui::Ui) {
        ui.heading("AWENET Browser");
        ui.label("Open an AWENET object directly by ID. No external browser is used.");
        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut self.object_id);
            if ui.button("Open").clicked() {
                let id = self.object_id.trim();
                self.message = if id.is_empty() {
                    "Enter an object ID.".into()
                } else {
                    format!("Requested AWENET object: {id}")
                };
            }
        });
        ui.add_space(10.0);
        ui.label("Search");
        ui.text_edit_singleline(&mut self.search);
        ui.label("Search index integration will use the native object resolver as it is enabled.");
        if !self.message.is_empty() {
            ui.label(&self.message);
        }
    }

    fn node(&mut self, ui: &mut egui::Ui) {
        ui.heading("Node");
        ui.label("Local node status and resource contribution");
        ui.separator();
        ui.label(format!(
            "AWEID: {}",
            self.wallet
                .get("awe_id")
                .and_then(Value::as_str)
                .unwrap_or("loading")
        ));
        ui.label(format!(
            "Tier: {}",
            self.wallet
                .get("tier")
                .and_then(Value::as_str)
                .unwrap_or("FREE")
        ));
        ui.label(format!(
            "Resource score: {}",
            self.wallet
                .get("resource_score")
                .and_then(Value::as_u64)
                .unwrap_or(0)
        ));
        ui.label("Resource controls are persisted by the AWENET node; this native page is the control surface.");
    }

    fn settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Settings");
        ui.label("AWENET uses the local node as its secure runtime.");
        ui.label(format!("Backend: {}", self.addr));
        ui.label("External browser launch is disabled for the native application.");
    }
}

impl eframe::App for AweNetDesktop {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.refresh();

        ui.horizontal(|ui| {
            ui.heading("AWENET");
            ui.separator();
            ui.label(self.page.title());
            if ui.button("Refresh").clicked() {
                self.last_refresh = Instant::now() - Duration::from_secs(2);
                self.refresh();
            }
            if !self.message.is_empty() {
                ui.separator();
                ui.label(&self.message);
            }
        });
        ui.separator();

        ui.horizontal(|ui| {
            for (page, label) in [
                (Page::Home, "Home"),
                (Page::Network, "Network"),
                (Page::Wallet, "ONECOIN"),
                (Page::Messenger, "Messenger"),
                (Page::Browser, "AWENET Browser"),
                (Page::Node, "Node"),
                (Page::Settings, "Settings"),
            ] {
                if ui.selectable_label(self.page == page, label).clicked() {
                    self.page = page;
                    self.message.clear();
                }
            }
        });
        ui.separator();

        egui::ScrollArea::vertical().show(ui, |ui| match self.page {
            Page::Home => self.home(ui),
            Page::Network => self.network(ui),
            Page::Wallet => self.wallet(ui),
            Page::Messenger => self.messenger(ui),
            Page::Browser => self.browser(ui),
            Page::Node => self.node(ui),
            Page::Settings => self.settings(ui),
        });

        ui.separator();
        ui.small(format!("Native desktop mode • backend {}", self.addr));
        ui.ctx().request_repaint_after(Duration::from_millis(500));
    }
}
