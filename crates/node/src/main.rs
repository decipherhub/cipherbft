//! CipherBFT Node CLI
//!
//! A Cosmos SDK-style CLI for the CipherBFT blockchain node.

use anyhow::Result;
use cipherd::{generate_local_configs, Node, NodeConfig};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{info, Level};
use tracing_subscriber::EnvFilter;

/// Default home directory name
const DEFAULT_HOME_DIR: &str = ".cipherd";

/// CipherBFT Daemon
#[derive(Parser)]
#[command(name = "cipherd")]
#[command(author = "CipherBFT Contributors")]
#[command(version)]
#[command(about = "CipherBFT Daemon", long_about = None)]
#[command(propagate_version = true)]
#[command(arg_required_else_help = true)]
struct Cli {
    /// Directory for config and data
    #[arg(long, global = true, default_value_os_t = default_home_dir())]
    home: PathBuf,

    /// The logging level (trace|debug|info|warn|error)
    #[arg(long, global = true, default_value = "info")]
    log_level: String,

    /// The logging format (json|plain)
    #[arg(long, global = true, default_value = "plain")]
    log_format: String,

    /// Disable colored logs
    #[arg(long, global = true, default_value = "false")]
    log_no_color: bool,

    /// Print out full stack trace on errors
    #[arg(long, global = true, default_value = "false")]
    trace: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize private validator, p2p, genesis, and application configuration files
    Init {
        /// Moniker for this node
        #[arg(long)]
        moniker: Option<String>,

        /// Chain ID for the network
        #[arg(long, default_value = "cipherbft-1")]
        chain_id: String,

        /// Overwrite existing configuration
        #[arg(long, default_value = "false")]
        overwrite: bool,
    },

    /// Run the full node
    Start {
        /// Path to configuration file (overrides --home)
        #[arg(long)]
        config: Option<PathBuf>,
    },

    /// Generate testnet configuration files for local multi-validator testing
    Testnet {
        /// Number of validators to generate
        #[arg(short = 'n', long, default_value = "4")]
        validators: usize,

        /// Output directory for config files
        #[arg(short, long, default_value = "./testnet")]
        output: PathBuf,
    },

    /// Run a local testnet with multiple validators (for development)
    #[command(name = "testnet-start")]
    TestnetStart {
        /// Number of validators
        #[arg(short = 'n', long, default_value = "4")]
        validators: usize,

        /// Duration to run in seconds (0 = run until Ctrl+C)
        #[arg(short, long, default_value = "0")]
        duration: u64,
    },

    /// Manage your application's keys
    Keys {
        #[command(subcommand)]
        command: KeysCommands,
    },

    /// Utilities for managing application configuration
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },

    /// Query remote node for status
    Status {
        /// Node address to query (host:port)
        #[arg(long, default_value = "127.0.0.1:26657")]
        node: String,
    },

    /// Print the application binary version information
    Version {
        /// Output format (text|json)
        #[arg(long, default_value = "text")]
        output: String,
    },

    /// Validates the genesis file at the default location or at the location passed as an arg
    Validate {
        /// Path to genesis file (optional, uses default if not provided)
        #[arg(long)]
        genesis: Option<PathBuf>,
    },

    /// Tool for helping with debugging your application
    Debug {
        #[command(subcommand)]
        command: DebugCommands,
    },
}

#[derive(Subcommand)]
enum KeysCommands {
    /// Add a new key
    Add {
        /// Name of the key
        name: String,
    },

    /// List all keys
    List,

    /// Show key details
    Show {
        /// Name of the key
        name: String,
    },

    /// Delete a key
    Delete {
        /// Name of the key
        name: String,

        /// Skip confirmation prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },

    /// Export a key to a file
    Export {
        /// Name of the key
        name: String,
    },

    /// Import a key from a file
    Import {
        /// Name of the key
        name: String,

        /// Path to the key file
        #[arg(long)]
        file: PathBuf,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Show current configuration
    Show,

    /// Set a configuration value
    Set {
        /// Configuration key
        key: String,

        /// Configuration value
        value: String,
    },

    /// Get a configuration value
    Get {
        /// Configuration key
        key: String,
    },
}

#[derive(Subcommand)]
enum DebugCommands {
    /// Print raw bytes for a block at a given height
    RawBytes {
        /// Block height
        height: u64,
    },

    /// Decode and print a transaction
    DecodeTx {
        /// Hex-encoded transaction bytes
        tx_bytes: String,
    },
}

fn default_home_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(DEFAULT_HOME_DIR)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing based on global flags
    init_tracing(&cli.log_level, &cli.log_format, cli.log_no_color);

    let result = match cli.command {
        Commands::Init {
            moniker,
            chain_id,
            overwrite,
        } => cmd_init(&cli.home, moniker, &chain_id, overwrite),

        Commands::Start { config } => {
            let config_path = config.unwrap_or_else(|| cli.home.join("config/node.json"));
            cmd_start(config_path).await
        }

        Commands::Testnet { validators, output } => cmd_testnet(validators, output),

        Commands::TestnetStart {
            validators,
            duration,
        } => cmd_testnet_start(validators, duration).await,

        Commands::Keys { command } => cmd_keys(&cli.home, command),

        Commands::Config { command } => cmd_config(&cli.home, command),

        Commands::Status { node } => cmd_status(&node),

        Commands::Version { output } => cmd_version(&output),

        Commands::Validate { genesis } => cmd_validate(&cli.home, genesis),

        Commands::Debug { command } => cmd_debug(command),
    };

    if let Err(e) = &result {
        if cli.trace {
            eprintln!("Error: {:?}", e);
        } else {
            eprintln!("Error: {}", e);
        }
        std::process::exit(1);
    }

    Ok(())
}

fn init_tracing(log_level: &str, log_format: &str, no_color: bool) {
    let level = match log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level.to_string()));

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .with_ansi(!no_color);

    match log_format {
        "json" => subscriber.json().init(),
        _ => subscriber.init(),
    }
}

// =============================================================================
// Command Implementations
// =============================================================================

fn cmd_init(
    home: &PathBuf,
    moniker: Option<String>,
    chain_id: &str,
    overwrite: bool,
) -> Result<()> {
    let config_dir = home.join("config");
    let data_dir = home.join("data");

    if config_dir.exists() && !overwrite {
        anyhow::bail!(
            "Configuration already exists at {}. Use --overwrite to replace.",
            home.display()
        );
    }

    std::fs::create_dir_all(&config_dir)?;
    std::fs::create_dir_all(&data_dir)?;

    // Generate a single node configuration
    let configs = generate_local_configs(1);
    let config = &configs[0];

    let config_path = config_dir.join("node.json");
    config.save(&config_path)?;

    let node_moniker =
        moniker.unwrap_or_else(|| format!("node-{}", hex::encode(&config.validator_id.0[..8])));

    println!("Successfully initialized node configuration");
    println!();
    println!("  Home:     {}", home.display());
    println!("  Moniker:  {}", node_moniker);
    println!("  Chain ID: {}", chain_id);
    println!("  Config:   {}", config_path.display());
    println!();
    println!("To start the node:");
    println!("  cipherd start --home {}", home.display());

    Ok(())
}

async fn cmd_start(config_path: PathBuf) -> Result<()> {
    if !config_path.exists() {
        anyhow::bail!(
            "Configuration file not found: {}\nRun 'cipherd init' first to create configuration.",
            config_path.display()
        );
    }

    info!("Loading configuration from {}", config_path.display());

    let config = NodeConfig::load(&config_path)?;
    info!("Starting node with validator ID: {:?}", config.validator_id);

    let node = Node::new(config)?;
    node.run().await?;

    Ok(())
}

fn cmd_testnet(num_validators: usize, output: PathBuf) -> Result<()> {
    println!(
        "Generating testnet configuration for {} validators...",
        num_validators
    );
    println!();

    std::fs::create_dir_all(&output)?;

    let configs = generate_local_configs(num_validators);

    for (i, config) in configs.iter().enumerate() {
        let node_dir = output.join(format!("node{}", i));
        std::fs::create_dir_all(&node_dir)?;

        let config_path = node_dir.join("config.json");
        config.save(&config_path)?;

        println!("  Created node{} (validator {:?})", i, config.validator_id);
    }

    println!();
    println!("Testnet configuration created in: {}", output.display());
    println!();
    println!("To start individual nodes:");
    for i in 0..num_validators {
        println!(
            "  cipherd start --config {}/node{}/config.json",
            output.display(),
            i
        );
    }
    println!();
    println!("Or run all nodes locally with:");
    println!("  cipherd testnet-start --validators {}", num_validators);

    Ok(())
}

async fn cmd_testnet_start(num_validators: usize, duration: u64) -> Result<()> {
    info!("Starting local testnet with {} validators", num_validators);

    // Generate configurations
    let configs = generate_local_configs(num_validators);

    // Collect validator info for cross-registration
    let validator_info: Vec<_> = configs
        .iter()
        .map(|c| {
            let keypair = c.keypair().unwrap();
            (c.validator_id, keypair.public_key.clone())
        })
        .collect();

    // Create and start nodes
    let mut handles = Vec::new();

    for config in configs {
        let validator_id = config.validator_id;
        let mut node = Node::new(config)?;

        // Register ALL validators (including ourselves - needed for threshold calculation)
        for (vid, pubkey) in &validator_info {
            node.add_validator(*vid, pubkey.clone());
        }

        let handle = tokio::spawn(async move {
            if let Err(e) = node.run().await {
                tracing::error!("Node {:?} error: {}", validator_id, e);
            }
        });

        handles.push(handle);

        // Stagger node startup slightly
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    info!("All {} nodes started", num_validators);

    // Run for specified duration or until Ctrl+C
    if duration > 0 {
        info!("Running for {} seconds...", duration);
        tokio::time::sleep(tokio::time::Duration::from_secs(duration)).await;
        info!("Duration elapsed, shutting down...");
    } else {
        info!("Press Ctrl+C to stop...");
        tokio::signal::ctrl_c().await?;
        info!("Received shutdown signal...");
    }

    // All handles will be dropped, tasks will be cancelled
    info!("Testnet stopped");

    Ok(())
}

fn cmd_keys(home: &PathBuf, command: KeysCommands) -> Result<()> {
    let keys_dir = home.join("keys");

    match command {
        KeysCommands::Add { name } => {
            std::fs::create_dir_all(&keys_dir)?;
            // Generate a new BLS keypair
            let keypair = cipherd::generate_keypair();
            let key_path = keys_dir.join(format!("{}.json", name));

            let pubkey_bytes = keypair.public_key.to_bytes();
            let secret_bytes = keypair.secret_key.to_bytes();

            let key_data = serde_json::json!({
                "name": name,
                "type": "bls12-381",
                "public_key": hex::encode(&pubkey_bytes),
                "secret_key": hex::encode(&secret_bytes),
            });

            std::fs::write(&key_path, serde_json::to_string_pretty(&key_data)?)?;

            println!("Key '{}' created successfully", name);
            println!();
            println!("  Name:       {}", name);
            println!("  Type:       bls12-381");
            println!("  Public Key: {}", hex::encode(&pubkey_bytes));
            println!();
            println!("**Important**: Keep your secret key safe and never share it.");
        }

        KeysCommands::List => {
            if !keys_dir.exists() {
                println!("No keys found. Use 'cipherd keys add <name>' to create a key.");
                return Ok(());
            }

            println!("Available keys:");
            println!();
            for entry in std::fs::read_dir(&keys_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().map_or(false, |ext| ext == "json") {
                    if let Some(name) = path.file_stem() {
                        println!("  - {}", name.to_string_lossy());
                    }
                }
            }
        }

        KeysCommands::Show { name } => {
            let key_path = keys_dir.join(format!("{}.json", name));
            if !key_path.exists() {
                anyhow::bail!("Key '{}' not found", name);
            }

            let data: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&key_path)?)?;
            println!("Name:       {}", data["name"]);
            println!("Public Key: {}", data["public_key"]);
        }

        KeysCommands::Delete { name, yes } => {
            let key_path = keys_dir.join(format!("{}.json", name));
            if !key_path.exists() {
                anyhow::bail!("Key '{}' not found", name);
            }

            if !yes {
                println!("Are you sure you want to delete key '{}'? [y/N]", name);
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if input.trim().to_lowercase() != "y" {
                    println!("Aborted.");
                    return Ok(());
                }
            }

            std::fs::remove_file(&key_path)?;
            println!("Key '{}' deleted", name);
        }

        KeysCommands::Export { name } => {
            let key_path = keys_dir.join(format!("{}.json", name));
            if !key_path.exists() {
                anyhow::bail!("Key '{}' not found", name);
            }

            let data = std::fs::read_to_string(&key_path)?;
            println!("{}", data);
        }

        KeysCommands::Import { name, file } => {
            std::fs::create_dir_all(&keys_dir)?;
            let key_path = keys_dir.join(format!("{}.json", name));
            if key_path.exists() {
                anyhow::bail!(
                    "Key '{}' already exists. Delete it first or choose a different name.",
                    name
                );
            }

            let data = std::fs::read_to_string(&file)?;
            // Validate JSON
            let _: serde_json::Value = serde_json::from_str(&data)?;
            std::fs::write(&key_path, data)?;

            println!("Key '{}' imported successfully", name);
        }
    }

    Ok(())
}

fn cmd_config(home: &PathBuf, command: ConfigCommands) -> Result<()> {
    let config_path = home.join("config/node.json");

    match command {
        ConfigCommands::Show => {
            if !config_path.exists() {
                anyhow::bail!(
                    "Configuration not found at {}. Run 'cipherd init' first.",
                    config_path.display()
                );
            }

            let data = std::fs::read_to_string(&config_path)?;
            println!("{}", data);
        }

        ConfigCommands::Get { key } => {
            if !config_path.exists() {
                anyhow::bail!(
                    "Configuration not found at {}. Run 'cipherd init' first.",
                    config_path.display()
                );
            }

            let data: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&config_path)?)?;

            // Simple dot-notation path lookup
            let parts: Vec<&str> = key.split('.').collect();
            let mut current = &data;
            for part in &parts {
                current = current
                    .get(part)
                    .ok_or_else(|| anyhow::anyhow!("Key '{}' not found in configuration", key))?;
            }

            println!("{}", serde_json::to_string_pretty(current)?);
        }

        ConfigCommands::Set { key, value } => {
            if !config_path.exists() {
                anyhow::bail!(
                    "Configuration not found at {}. Run 'cipherd init' first.",
                    config_path.display()
                );
            }

            let data = std::fs::read_to_string(&config_path)?;
            let mut config: serde_json::Value = serde_json::from_str(&data)?;

            // Simple dot-notation path setting
            let parts: Vec<&str> = key.split('.').collect();
            let mut current = &mut config;
            for (i, part) in parts.iter().enumerate() {
                if i == parts.len() - 1 {
                    // Try to parse value as JSON, fallback to string
                    let new_value: serde_json::Value = serde_json::from_str(&value)
                        .unwrap_or_else(|_| serde_json::Value::String(value.clone()));
                    current[*part] = new_value;
                } else {
                    current = current.get_mut(part).ok_or_else(|| {
                        anyhow::anyhow!("Key path '{}' not found in configuration", key)
                    })?;
                }
            }

            std::fs::write(&config_path, serde_json::to_string_pretty(&config)?)?;
            println!("Configuration updated: {} = {}", key, value);
        }
    }

    Ok(())
}

fn cmd_status(node: &str) -> Result<()> {
    // TODO: Implement proper RPC status query
    println!("Querying node status at {}...", node);
    println!();
    println!("Status querying not yet implemented.");
    println!("This will show node sync status, validator info, and network state.");

    Ok(())
}

fn cmd_version(output: &str) -> Result<()> {
    let version_info = VersionInfo::new();

    match output {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&version_info)?);
        }
        _ => {
            println!("{}: {}", version_info.name, version_info.version);
            println!("git commit: {}", version_info.git_commit);
            println!("build tags: {}", version_info.build_tags);
            println!("rust version: {}", version_info.rust_version);
        }
    }

    Ok(())
}

fn cmd_validate(home: &PathBuf, genesis_path: Option<PathBuf>) -> Result<()> {
    let path = genesis_path.unwrap_or_else(|| home.join("config/genesis.json"));

    if !path.exists() {
        anyhow::bail!("Genesis file not found at {}", path.display());
    }

    let data = std::fs::read_to_string(&path)?;
    let genesis: serde_json::Value = serde_json::from_str(&data)?;

    // Basic validation
    if genesis.get("chain_id").is_none() {
        anyhow::bail!("Genesis file missing 'chain_id' field");
    }

    println!("Genesis file at {} is valid", path.display());

    Ok(())
}

fn cmd_debug(command: DebugCommands) -> Result<()> {
    match command {
        DebugCommands::RawBytes { height } => {
            println!(
                "Debug: Fetching raw bytes for block at height {}...",
                height
            );
            println!("Not yet implemented.");
        }

        DebugCommands::DecodeTx { tx_bytes } => {
            println!("Debug: Decoding transaction bytes...");
            println!("Input: {}", tx_bytes);
            println!("Not yet implemented.");
        }
    }

    Ok(())
}

// =============================================================================
// Version Info
// =============================================================================

#[derive(serde::Serialize)]
struct VersionInfo {
    name: String,
    version: String,
    git_commit: String,
    build_tags: String,
    rust_version: String,
}

impl VersionInfo {
    fn new() -> Self {
        Self {
            name: "cipherd".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            git_commit: option_env!("GIT_COMMIT").unwrap_or("unknown").to_string(),
            build_tags: "rust,bls".to_string(),
            rust_version: option_env!("CARGO_PKG_RUST_VERSION")
                .unwrap_or("unknown")
                .to_string(),
        }
    }
}
