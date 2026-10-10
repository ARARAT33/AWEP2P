use std::{fs, process::{Child, Command}, sync::Mutex};
#[cfg(not(target_os = "android"))]
use tauri::Manager;

#[cfg(not(target_os = "android"))]
struct NodeProcess(Mutex<Option<Child>>);

#[cfg(not(target_os = "android"))]
fn start_node(app: &tauri::AppHandle) -> Result<Child, String> {
    let dir = app.path().resource_dir().map_err(|e| format!("cannot locate app resources: {e}"))?;
    let bin_dir = dir.join("binaries");
    let entries = fs::read_dir(&bin_dir).map_err(|e| format!("cannot read node bundle directory {}: {e}", bin_dir.display()))?;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|x| x.to_str()).unwrap_or("");
        if name.starts_with("awe-node") {
            return Command::new(&path)
                .env("AWE_NO_NATIVE_UI", "1")
                .spawn()
                .map_err(|e| format!("cannot start bundled AWENET node {}: {e}", path.display()));
        }
    }
    Err(format!("bundled AWENET node binary was not found in {}", bin_dir.display()))
}

#[cfg(not(target_os = "android"))]
fn stop_node(app: &tauri::AppHandle) {
    if let Some(state) = app.try_state::<NodeProcess>() {
        if let Ok(mut slot) = state.0.lock() {
            if let Some(mut child) = slot.take() {
                match child.try_wait() {
                    Ok(Some(_)) => {}
                    _ => {
                        if let Err(error) = child.kill() {
                            eprintln!("Could not stop AWENET node process: {error}");
                        }
                        let _ = child.wait();
                    }
                }
            }
        }
    }
}


#[cfg(not(target_os = "android"))]
#[tauri::command]
fn open_browser_window(app: tauri::AppHandle, url: String) -> Result<(), String> {
    if url.len() > 2048 {
        return Err("URL is too long".into());
    }
    let parsed = url::Url::parse(url.trim())
        .map_err(|error| format!("Invalid browser URL: {error}"))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(
            "Only HTTP/HTTPS URLs with a host and without embedded credentials are allowed"
                .into(),
        );
    }
    let host = parsed.host_str().unwrap_or("AWENET Browser").to_string();
    let target = tauri::WebviewUrl::External(parsed);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let label = format!("awenet-browser-{nonce}");
    tauri::WebviewWindowBuilder::new(&app, &label, target)
        .title(format!("{host} — AWENET Browser"))
        .inner_size(1200.0, 800.0)
        .build()
        .map(|_| ())
        .map_err(|error| format!("Could not open browser window: {error}"))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default();
    #[cfg(not(target_os = "android"))]
    let builder = builder.invoke_handler(tauri::generate_handler![open_browser_window]);
    #[cfg(not(target_os = "android"))]
    let builder = builder.setup(|app| {
        let child = match start_node(app.handle()) {
            Ok(child) => Some(child),
            Err(error) => {
                eprintln!("AWENET node startup failed: {error}");
                None
            }
        };
        app.manage(NodeProcess(Mutex::new(child)));
        Ok(())
    });
    let mut app = builder
        .build(tauri::generate_context!())
        .expect("error while building AWEp2P");
    app.run(|app_handle, event| {
        #[cfg(not(target_os = "android"))]
        if let tauri::RunEvent::Exit = event {
            stop_node(&app_handle);
        }
        #[cfg(target_os = "android")]
        let _ = (app_handle, event);
    });
}
