use anyhow::{Context, Result};
use awep2p_core::identity::{Identity, LocalVault, Username};
use awep2p_core::network::Node;
use std::{env, fs, net::SocketAddr, path::PathBuf};

const USAGE: &str = r#"AWE Node

Usage:
  awe-node init <username> [vault-file]
  awe-node run <vault-file> <password> <listen-addr> [bootstrap-addr ...]
  awe-node id <vault-file> <password> <username>

Examples:
  awe-node init ararat ~/.awep2p/identity.vault
  awe-node run ~/.awep2p/identity.vault 'local-password' 0.0.0.0:41000 203.0.113.10:41000
"#;

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
    eprintln!("{USAGE}");
    std::process::exit(2)
}

fn init(username: &str, path: PathBuf) -> Result<()> {
    let username = Username::new(username.to_owned()).map_err(anyhow::Error::msg)?;
    let identity = Identity::generate(username);
    let password =
        rpassword::prompt_password("Vault password: ").context("failed to read vault password")?;
    if password.is_empty() {
        anyhow::bail!("vault password must not be empty");
    }
    let vault = LocalVault::seal(&identity, &password).map_err(anyhow::Error::msg)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("failed to create AWE data directory")?;
    }
    fs::write(&path, vault).context("failed to write identity vault")?;
    println!("AWE-ID: {}", identity.public.awe_id.to_hex());
    println!("Identity vault: {}", path.display());
    Ok(())
}

fn load_identity(path: &PathBuf, password: &str, username: &str) -> Result<Identity> {
    let data = fs::read(path).context("failed to read identity vault")?;
    let username = Username::new(username.to_owned()).map_err(anyhow::Error::msg)?;
    LocalVault::open(&data, username, password).map_err(anyhow::Error::msg)
}

async fn run(
    path: PathBuf,
    password: String,
    username: String,
    listen: SocketAddr,
    bootstrap: Vec<SocketAddr>,
) -> Result<()> {
    let identity = load_identity(&path, &password, &username)?;
    println!("AWE-ID: {}", identity.public.awe_id.to_hex());
    println!("Listening: {listen}");
    let node = Node::new(identity, listen);
    if !bootstrap.is_empty() {
        let found = node
            .bootstrap(&bootstrap)
            .await
            .context("bootstrap failed")?;
        println!("Discovered peers: {found}");
    }
    node.listen().await.map_err(anyhow::Error::msg)
}

fn print_id(path: PathBuf, password: String, username: String) -> Result<()> {
    let identity = load_identity(&path, &password, &username)?;
    println!("{}", identity.public.awe_id.to_hex());
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("init") => {
            let username = args.next().unwrap_or_else(|| usage());
            let path = args.next().map(PathBuf::from).unwrap_or_else(default_vault);
            init(&username, path)
        }
        Some("run") => {
            let path = args.next().map(PathBuf::from).unwrap_or_else(|| usage());
            let password = args.next().unwrap_or_else(|| usage());
            let listen: SocketAddr = args
                .next()
                .unwrap_or_else(|| usage())
                .parse()
                .context("invalid listen address")?;
            let username = env::var("AWE_USERNAME").unwrap_or_else(|_| usage());
            let bootstrap = args
                .map(|x| x.parse().context("invalid bootstrap address"))
                .collect::<Result<Vec<SocketAddr>>>()?;
            run(path, password, username, listen, bootstrap).await
        }
        Some("id") => {
            let path = args.next().map(PathBuf::from).unwrap_or_else(|| usage());
            let password = args.next().unwrap_or_else(|| usage());
            let username = args.next().unwrap_or_else(|| usage());
            print_id(path, password, username)
        }
        _ => usage(),
    }
}
