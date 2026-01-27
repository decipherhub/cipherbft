//! CipherBFT Node CLI
//!
//! A Cosmos SDK-style CLI for the CipherBFT blockchain node.

use alloy_primitives::U256;
use anyhow::{Context, Result};
use cipherbft_crypto::{
    BlsKeyPair, BlsSecretKey, Ed25519KeyPair, Ed25519SecretKey, ExposeSecret, KeyMetadata, Keyring,
    KeyringBackend,
};
use cipherd::key_cli::KeyringBackendArg;
use cipherd::{
    execute_keys_command, generate_local_configs, GenesisGenerator, GenesisGeneratorConfig,
    GenesisLoader, KeysCommand, Node, NodeConfig, NodeSupervisor, ValidatorKeyFile,
    CIPHERD_HOME_ENV, DEFAULT_HOME_DIR,
};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{info, Level};
use tracing_subscriber::EnvFilter;

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

        /// EVM Chain ID for the network (default: 85300)
        #[arg(long, default_value = "85300")]
        chain_id: u64,

        /// Network identifier (e.g., "cipherbft-testnet-1")
        #[arg(long, default_value = "cipherbft-testnet-1")]
        network_id: String,

        /// Initial stake per validator in ETH (default: 32)
        #[arg(long, default_value = "32")]
        initial_stake_eth: u64,

        /// Overwrite existing configuration
        #[arg(long, default_value = "false")]
        overwrite: bool,
    },

    /// Run the full node
    Start {
        /// Path to configuration file (overrides --home)
        #[arg(long)]
        config: Option<PathBuf>,

        /// Path to genesis file (overrides config and env var)
        #[arg(long)]
        genesis: Option<PathBuf>,

        /// Keyring backend for key storage (overrides client.toml setting)
        ///
        /// - file: EIP-2335 encrypted keystores (default, recommended)
        /// - os: OS native keyring (macOS Keychain, Windows Credential Manager)
        /// - test: Unencrypted storage (development only!)
        #[arg(long, value_enum)]
        keyring_backend: Option<KeyringBackendArg>,
    },

    /// Generate testnet/devnet configuration files for local multi-validator testing
    #[command(alias = "devnet")]
    Testnet {
        #[command(subcommand)]
        command: TestnetCommands,
    },

    /// Manage your application's keys (secure EIP-2335 keystores)
    ///
    /// Common options like --keyring-backend can be specified at this level
    /// or at the subcommand level. Subcommand-level options take precedence.
    Keys {
        /// Keyring backend for key storage (can also be specified per-subcommand)
        ///
        /// - file: EIP-2335 encrypted keystores (default, recommended)
        /// - os: OS native keyring (macOS Keychain, Windows Credential Manager)
        /// - test: Unencrypted storage (development only!)
        #[arg(long, value_enum)]
        keyring_backend: Option<KeyringBackendArg>,

        /// Directory containing keystore files (can also be specified per-subcommand)
        #[arg(long)]
        keys_dir: Option<PathBuf>,

        #[command(subcommand)]
        command: KeysCommand,
    },

    /// Utilities for managing application configuration
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },

    /// Query remote node for status via JSON-RPC
    Status {
        /// Node RPC URL to query (e.g., http://localhost:8545)
        #[arg(long, default_value = "http://localhost:8545")]
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

    /// Genesis file generation and management commands
    Genesis {
        #[command(subcommand)]
        command: GenesisCommands,
    },

    /// Tool for helping with debugging your application
    Debug {
        #[command(subcommand)]
        command: DebugCommands,
    },
}

// Old KeysCommands removed - now using key_cli::KeysCommand with EIP-2335 encrypted storage

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
enum GenesisCommands {
    /// Generate a new genesis file with auto-generated validator keys
    Generate {
        /// Number of validators to generate
        #[arg(short = 'n', long, default_value = "4")]
        validators: usize,

        /// Chain ID for the EVM network
        #[arg(long, default_value = "85300")]
        chain_id: u64,

        /// Network identifier (e.g., "cipherbft-testnet-1")
        #[arg(long, default_value = "cipherbft-testnet-1")]
        network_id: String,

        /// Initial stake per validator in ETH (default: 32 ETH)
        #[arg(long, default_value = "32")]
        initial_stake_eth: u64,

        /// Output path for the genesis file
        #[arg(short, long, default_value = "./genesis.json")]
        output: PathBuf,

        /// Output directory for validator key files (default: ./keys)
        #[arg(long, default_value = "./keys")]
        keys_dir: PathBuf,

        /// Skip writing validator key files
        #[arg(long, default_value = "false")]
        no_keys: bool,

        /// Extra account allocations in format address:balance_eth (can be repeated)
        /// Example: --extra-alloc 0x123...abc:1000 --extra-alloc 0x456...def:500
        #[arg(long = "extra-alloc", value_name = "ADDR:ETH")]
        extra_alloc: Vec<String>,
    },

    /// Add a genesis account to an existing genesis file
    #[command(name = "add-genesis-account")]
    AddGenesisAccount {
        /// Account address (0x... format)
        address: String,

        /// Initial balance in ETH
        #[arg(long, default_value = "100")]
        balance_eth: u64,

        /// Path to genesis file
        #[arg(long)]
        genesis: Option<PathBuf>,
    },

    /// Generate a genesis transaction (gentx) for a validator
    Gentx {
        /// Path to validator key file (validator-N.json)
        #[arg(long)]
        key_file: PathBuf,

        /// Stake amount in ETH
        #[arg(long, default_value = "32")]
        stake_eth: u64,

        /// Validator moniker/name
        #[arg(long)]
        moniker: Option<String>,

        /// Commission rate percentage (0-100)
        #[arg(long, default_value = "10")]
        commission_rate: u8,

        /// Output directory for gentx file
        #[arg(long, default_value = "./gentx")]
        output_dir: PathBuf,
    },

    /// Collect genesis transactions and add them to genesis file
    #[command(name = "collect-gentxs")]
    CollectGentxs {
        /// Directory containing gentx files
        #[arg(long, default_value = "./gentx")]
        gentx_dir: PathBuf,

        /// Path to genesis file
        #[arg(long)]
        genesis: Option<PathBuf>,
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

#[derive(Subcommand)]
enum TestnetCommands {
    /// Initialize testnet configuration files for multi-validator setup
    #[command(name = "init-files")]
    InitFiles {
        /// Number of validators to generate
        #[arg(short = 'n', long, default_value = "4")]
        validators: usize,

        /// Output directory for testnet files
        #[arg(short, long, default_value = "./testnet")]
        output: PathBuf,

        /// Chain ID for the network
        #[arg(long, default_value = "85300")]
        chain_id: u64,

        /// Network identifier
        #[arg(long, default_value = "cipherbft-testnet-1")]
        network_id: String,

        /// Initial stake per validator in ETH
        #[arg(long, default_value = "32")]
        initial_stake_eth: u64,

        /// Initial balance per validator in ETH (for gas fees and transactions)
        #[arg(long, default_value = "100")]
        initial_balance_eth: u64,

        /// Starting P2P port (increments by 10 for each validator)
        #[arg(long, default_value = "9000")]
        starting_port: u16,

        /// Extra account allocations in format address:balance_eth (can be repeated)
        /// Example: --extra-alloc 0x123...abc:1000 --extra-alloc 0x456...def:500
        #[arg(long = "extra-alloc", value_name = "ADDR:ETH")]
        extra_alloc: Vec<String>,
    },

    /// Start a local testnet with multiple validators (in-process)
    Start {
        /// Number of validators
        #[arg(short = 'n', long, default_value = "4")]
        validators: usize,

        /// Duration to run in seconds (0 = run until Ctrl+C)
        #[arg(short, long, default_value = "0")]
        duration: u64,
    },
}

/// Returns the default home directory for cipherd.
///
/// Resolution order:
/// 1. `CIPHERD_HOME` environment variable (if set)
/// 2. `~/.cipherd` (default)
fn default_home_dir() -> PathBuf {
    // Check for CIPHERD_HOME environment variable first
    if let Ok(home) = std::env::var(CIPHERD_HOME_ENV) {
        return PathBuf::from(home);
    }

    // Fall back to default: ~/.cipherd
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
            network_id,
            initial_stake_eth,
            overwrite,
        } => cmd_init(
            &cli.home,
            moniker,
            chain_id,
            &network_id,
            initial_stake_eth,
            overwrite,
        ),

        Commands::Start {
            config,
            genesis,
            keyring_backend,
        } => {
            let config_path = config.unwrap_or_else(|| cli.home.join("config/node.json"));
            cmd_start(config_path, genesis, keyring_backend).await
        }

        Commands::Testnet { command } => cmd_testnet(command).await,

        Commands::Keys {
            keyring_backend,
            keys_dir,
            command,
        } => execute_keys_command(&cli.home, keyring_backend, keys_dir, command),

        Commands::Config { command } => cmd_config(&cli.home, command),

        Commands::Status { node } => cmd_status(&node).await,

        Commands::Version { output } => cmd_version(&output),

        Commands::Validate { genesis } => cmd_validate(&cli.home, genesis),

        Commands::Genesis { command } => cmd_genesis(&cli.home, command),

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
    home: &std::path::Path,
    moniker: Option<String>,
    chain_id: u64,
    network_id: &str,
    initial_stake_eth: u64,
    overwrite: bool,
) -> Result<()> {
    let config_dir = home.join("config");
    let data_dir = home.join("data");
    // Keys are stored in {home}/keys (consistent with client.toml and keys commands)
    let keys_dir = home.join("keys");

    if config_dir.exists() && !overwrite {
        anyhow::bail!(
            "Configuration already exists at {}. Use --overwrite to replace.",
            home.display()
        );
    }

    // Create directory structure
    std::fs::create_dir_all(&config_dir)?;
    std::fs::create_dir_all(&data_dir)?;
    std::fs::create_dir_all(&keys_dir)?;

    // Generate a random node identifier for the moniker (not validator ID)
    let node_id: [u8; 4] = rand::random();
    let node_moniker = moniker.unwrap_or_else(|| format!("node-{}", hex::encode(node_id)));

    // ========================================
    // Generate genesis with single validator
    // ========================================
    println!("Generating genesis file with single validator...");

    // Convert ETH to wei (1 ETH = 10^18 wei)
    let initial_stake = U256::from(initial_stake_eth) * U256::from(1_000_000_000_000_000_000u128);

    let genesis_config = GenesisGeneratorConfig {
        num_validators: 1,
        chain_id,
        network_id: network_id.to_string(),
        initial_stake,
        ..Default::default()
    };

    let mut rng = rand::thread_rng();
    let genesis_result = GenesisGenerator::generate(&mut rng, genesis_config)
        .context("Failed to generate genesis")?;

    // Save genesis file
    let genesis_path = config_dir.join("genesis.json");
    genesis_result
        .genesis
        .save(&genesis_path)
        .context("Failed to save genesis file")?;

    // Save validator key file
    let validator = &genesis_result.validators[0];
    let key_file = ValidatorKeyFile::from_generated(0, validator);
    let validator_key_path = keys_dir.join("validator-0.json");
    let key_json = key_file
        .to_json()
        .context("Failed to serialize validator key")?;
    std::fs::write(&validator_key_path, key_json)?;

    // Create client.toml (Cosmos SDK style) for CLI settings
    let client_config = cipherd::ClientConfig {
        chain_id: chain_id.to_string(),
        keyring_backend: cipherd::DEFAULT_KEYRING_BACKEND.to_string(),
        keyring_dir: String::new(), // Use default: {home}/keys
        keyring_default_keyname: cipherd::DEFAULT_KEY_NAME.to_string(),
        output: "text".to_string(),
        node: "tcp://localhost:26657".to_string(),
        broadcast_mode: "sync".to_string(),
    };
    client_config.save(home)?;

    // Create NodeConfig without validator_id (will be derived at start time from keys)
    // Note: keystore settings are now in client.toml
    let base_port = 9000u16;
    let config = NodeConfig {
        validator_id: None, // Derived at runtime from BLS key
        keyring_backend: cipherd::DEFAULT_KEYRING_BACKEND.to_string(),
        key_name: cipherd::DEFAULT_KEY_NAME.to_string(),
        keystore_dir: None, // Use client.toml settings
        keystore_account: Some(0),
        primary_listen: format!("127.0.0.1:{}", base_port)
            .parse()
            .expect("default address format is always valid"),
        consensus_listen: format!("127.0.0.1:{}", base_port + 5)
            .parse()
            .expect("default address format is always valid"),
        worker_listens: vec![format!("127.0.0.1:{}", base_port + 1)
            .parse()
            .expect("default address format is always valid")],
        peers: Vec::new(),
        num_workers: 1,
        home_dir: Some(home.to_path_buf()),
        data_dir: data_dir.clone(),
        genesis_path: Some(genesis_path.clone()),
        car_interval_ms: 100,
        max_batch_txs: 100,
        max_batch_bytes: 1024 * 1024,
        rpc_enabled: true,
        rpc_http_port: cipherd::DEFAULT_RPC_HTTP_PORT,
        rpc_ws_port: cipherd::DEFAULT_RPC_WS_PORT,
        metrics_port: cipherd::DEFAULT_METRICS_PORT,
    };

    let config_path = config_dir.join("node.json");
    config.save(&config_path)?;

    // Write a node info file with basic metadata
    let node_info_path = config_dir.join("node_info.json");
    let node_info = serde_json::json!({
        "moniker": node_moniker,
        "chain_id": chain_id,
        "network_id": network_id,
        "created_at": chrono::Utc::now().to_rfc3339(),
    });
    std::fs::write(&node_info_path, serde_json::to_string_pretty(&node_info)?)?;

    let client_config_path = cipherd::ClientConfig::config_path(home);

    println!();
    println!("Successfully initialized node configuration");
    println!();
    println!("  Home:          {}", home.display());
    println!("  Moniker:       {}", node_moniker);
    println!("  Chain ID:      {}", chain_id);
    println!("  Network ID:    {}", network_id);
    println!("  Node config:   {}", config_path.display());
    println!("  Client config: {}", client_config_path.display());
    println!("  Genesis:       {}", genesis_path.display());
    println!("  Keys dir:      {}", keys_dir.display());
    println!();
    println!("Genesis Summary:");
    println!(
        "  Validators:    {}",
        genesis_result.genesis.validator_count()
    );
    println!("  Total Stake:   {} ETH", initial_stake_eth);
    println!(
        "  Validator:     {} (ed25519: {}...)",
        validator.address,
        &validator.ed25519_pubkey_hex[..16]
    );
    println!();
    println!("Validator key saved to: {}", validator_key_path.display());
    println!();
    println!("Next steps:");
    println!();
    println!("  1. Start the node:");
    println!("     cipherd start --home {}", home.display());
    println!();
    println!("  2. (Optional) For joining an existing network, replace the genesis file:");
    println!("     {}", genesis_path.display());

    Ok(())
}

async fn cmd_start(
    config_path: PathBuf,
    genesis_override: Option<PathBuf>,
    keyring_backend_override: Option<KeyringBackendArg>,
) -> Result<()> {
    use cipherbft_crypto::{Keyring, KeyringBackend};

    if !config_path.exists() {
        anyhow::bail!(
            "Configuration file not found: {}\nRun 'cipherd init' first to create configuration.",
            config_path.display()
        );
    }

    info!("Loading configuration from {}", config_path.display());

    let mut config = NodeConfig::load(&config_path)?;

    // Derive home directory from config path (config_path is typically {home}/config/node.json)
    let home = config_path
        .parent() // config/
        .and_then(|p| p.parent()) // home/
        .ok_or_else(|| anyhow::anyhow!("Cannot determine home directory from config path"))?;

    // Load client config (Cosmos SDK style) for keyring settings
    let client_config = cipherd::ClientConfig::load(home)?;

    // Determine keyring backend: CLI flag > node.json > client.toml > default
    let keyring_backend: KeyringBackend = if let Some(backend_arg) = keyring_backend_override {
        // CLI flag takes precedence
        backend_arg.into()
    } else {
        // Prefer node.json keyring_backend, fall back to client.toml
        let keyring_backend_str = config.effective_keyring_backend();
        keyring_backend_str
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid keyring backend: {}", keyring_backend_str))?
    };

    // Warn if using non-production backend
    if !keyring_backend.is_production_safe() {
        eprintln!(
            "WARNING: Using '{}' backend which is NOT safe for production!",
            keyring_backend
        );
    }

    // Get keys directory: node.json keystore_dir > client.toml > default
    // This allows devnet init-files to set keystore_dir in node.json
    let keys_dir = if config.keystore_dir.is_some() {
        config.effective_keystore_dir()
    } else {
        client_config.effective_keyring_dir(home)
    };
    // Use key_name from node.json
    let key_name = config.effective_key_name();
    let account = config.effective_keystore_account();

    info!(
        "Loading keys from {} (backend: {}, key: {})",
        keys_dir.display(),
        keyring_backend,
        key_name
    );

    // Create keyring
    let keyring = Keyring::new(keyring_backend, &keys_dir)
        .map_err(|e| anyhow::anyhow!("Failed to initialize keyring: {}", e))?;

    // Key names follow the pattern: {key_name}_{account}_{type}
    let ed25519_key_name = format!("{}_{}_ed25519", key_name, account);
    let bls_key_name = format!("{}_{}_bls", key_name, account);

    // Check if keys exist
    if !keyring.key_exists(&ed25519_key_name) {
        anyhow::bail!(
            "Ed25519 key '{}' not found.\n\
             Run 'cipherd keys add {} --validator' to create keys.",
            ed25519_key_name,
            key_name
        );
    }

    if !keyring.key_exists(&bls_key_name) {
        anyhow::bail!(
            "BLS key '{}' not found.\n\
             Validators require both Ed25519 and BLS keys.\n\
             Run 'cipherd keys add {} --validator' to create keys.",
            bls_key_name,
            key_name
        );
    }

    // Get passphrase if required by the backend
    let passphrase = if keyring_backend.requires_passphrase() {
        Some(
            rpassword::prompt_password("Enter keystore passphrase: ")
                .context("Failed to read passphrase")?,
        )
    } else {
        None
    };

    // Load Ed25519 key
    info!("Loading Ed25519 key: {}", ed25519_key_name);
    let ed25519_secret_bytes = keyring
        .get_key(&ed25519_key_name, passphrase.as_deref())
        .map_err(|e| anyhow::anyhow!("Failed to load Ed25519 key: {}", e))?;

    let ed25519_bytes: [u8; 32] = ed25519_secret_bytes
        .expose_secret()
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid Ed25519 key length, expected 32 bytes"))?;
    let ed25519_secret = Ed25519SecretKey::from_bytes(&ed25519_bytes);
    let ed25519_keypair = Ed25519KeyPair::from_secret_key(ed25519_secret);

    // Load BLS key
    info!("Loading BLS key: {}", bls_key_name);
    let bls_secret_bytes = keyring
        .get_key(&bls_key_name, passphrase.as_deref())
        .map_err(|e| anyhow::anyhow!("Failed to load BLS key: {}", e))?;

    let bls_bytes: [u8; 32] = bls_secret_bytes
        .expose_secret()
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid BLS key length, expected 32 bytes"))?;
    let bls_secret = BlsSecretKey::from_bytes(&bls_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid BLS key: {:?}", e))?;
    let bls_keypair = BlsKeyPair::from_secret_key(bls_secret);

    // Derive validator ID from Ed25519 public key (consistent with genesis)
    let validator_id = ed25519_keypair.public_key.validator_id();
    info!("Derived validator ID: {:?}", validator_id);

    // Override genesis path if provided via CLI
    if genesis_override.is_some() {
        config.genesis_path = genesis_override;
    }

    // Resolve and load genesis file
    let genesis_path = config.effective_genesis_path();
    info!("Loading genesis from {}", genesis_path.display());

    let genesis = GenesisLoader::load_and_validate(&genesis_path)?;

    info!("Starting node as validator {:?}", validator_id);

    // Create node with keypairs, enable execution layer, and bootstrap validators from genesis
    let mut node = Node::new(config, bls_keypair, ed25519_keypair)?
        .with_execution_layer_from_genesis(&genesis)?;
    node.bootstrap_validators_from_genesis(&genesis)?;

    // Create a supervisor for structured task management and graceful shutdown
    let supervisor = NodeSupervisor::new();

    // Set up signal handling for graceful shutdown
    let shutdown_supervisor = supervisor.clone();
    tokio::spawn(async move {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!("Failed to listen for Ctrl+C: {}", e);
            return;
        }
        info!("Received Ctrl+C, initiating graceful shutdown...");
        if let Err(e) = shutdown_supervisor.shutdown().await {
            tracing::warn!("Shutdown warning: {}", e);
        }
    });

    // Run node with the supervisor for coordinated task management
    node.run_with_supervisor(supervisor).await?;

    Ok(())
}

async fn cmd_testnet(command: TestnetCommands) -> Result<()> {
    match command {
        TestnetCommands::InitFiles {
            validators,
            output,
            chain_id,
            network_id,
            initial_stake_eth,
            initial_balance_eth,
            starting_port,
            extra_alloc,
        } => cmd_testnet_init_files(
            validators,
            &output,
            chain_id,
            &network_id,
            initial_stake_eth,
            initial_balance_eth,
            starting_port,
            extra_alloc,
        ),
        TestnetCommands::Start {
            validators,
            duration,
        } => cmd_testnet_start(validators, duration).await,
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_testnet_init_files(
    num_validators: usize,
    output: &std::path::Path,
    chain_id: u64,
    network_id: &str,
    initial_stake_eth: u64,
    initial_balance_eth: u64,
    starting_port: u16,
    extra_alloc: Vec<String>,
) -> Result<()> {
    use alloy_primitives::Address;
    use cipherd::PeerConfig;

    println!(
        "Generating testnet configuration for {} validators...",
        num_validators
    );
    println!();

    std::fs::create_dir_all(output)?;

    // Parse extra alloc entries
    let mut extra_alloc_parsed: Vec<(Address, U256)> = Vec::new();
    for entry in &extra_alloc {
        let parts: Vec<&str> = entry.split(':').collect();
        if parts.len() != 2 {
            anyhow::bail!(
                "Invalid extra-alloc format: '{}'. Expected address:balance_eth",
                entry
            );
        }
        let address: Address = parts[0]
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid address in extra-alloc: {}", parts[0]))?;
        let balance_eth: u64 = parts[1].parse().map_err(|_| {
            anyhow::anyhow!(
                "Invalid balance in extra-alloc: {}. Expected integer ETH value",
                parts[1]
            )
        })?;
        let balance_wei = U256::from(balance_eth) * U256::from(1_000_000_000_000_000_000u128);
        extra_alloc_parsed.push((address, balance_wei));
    }

    // Generate genesis with validators - this is our single source of truth for keys
    let eth_to_wei = U256::from(1_000_000_000_000_000_000u128);
    let initial_stake = U256::from(initial_stake_eth) * eth_to_wei;
    let initial_balance = U256::from(initial_balance_eth) * eth_to_wei;
    let genesis_config = GenesisGeneratorConfig {
        num_validators,
        chain_id,
        network_id: network_id.to_string(),
        initial_stake,
        initial_balance,
        extra_alloc: extra_alloc_parsed,
        ..Default::default()
    };

    let mut rng = rand::thread_rng();
    let genesis_result = GenesisGenerator::generate(&mut rng, genesis_config)?;

    // Write shared genesis file
    let genesis_path = output.join("genesis.json");
    let genesis_json = genesis_result.genesis.to_json()?;
    std::fs::write(&genesis_path, genesis_json)?;
    println!("  Created shared genesis: {}", genesis_path.display());

    // Build peer configs from genesis validators (same keys as genesis)
    let peer_configs: Vec<PeerConfig> = genesis_result
        .validators
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let port_offset = starting_port + (i as u16 * 10);
            PeerConfig {
                validator_id: hex::encode(v.validator_id.as_bytes()),
                bls_public_key_hex: v.bls_pubkey_hex.clone(),
                ed25519_public_key_hex: v.ed25519_pubkey_hex.clone(),
                primary_addr: format!("127.0.0.1:{}", port_offset).parse().unwrap(),
                consensus_addr: format!("127.0.0.1:{}", port_offset + 5).parse().unwrap(),
                worker_addrs: vec![format!("127.0.0.1:{}", port_offset + 1).parse().unwrap()],
            }
        })
        .collect();

    // Create directories and configs for each node using genesis validators
    for (i, validator) in genesis_result.validators.iter().enumerate() {
        let node_dir = output.join(format!("node{}", i));
        let config_dir = node_dir.join("config");
        let data_dir = node_dir.join("data");
        let keys_dir = node_dir.join("keys");
        std::fs::create_dir_all(&config_dir)?;
        std::fs::create_dir_all(&data_dir)?;
        std::fs::create_dir_all(&keys_dir)?;

        let port_offset = starting_port + (i as u16 * 10);
        let key_name = format!("validator-{}", i);
        let account = 0u32;

        // Store keys in the node's keyring using "test" backend (no passphrase for devnet)
        let keyring = Keyring::new(KeyringBackend::Test, &keys_dir)
            .map_err(|e| anyhow::anyhow!("Failed to create keyring: {}", e))?;

        // Key names follow the pattern: {key_name}_{account}_{type}
        let ed25519_key_name = format!("{}_{}_ed25519", key_name, account);
        let bls_key_name = format!("{}_{}_bls", key_name, account);

        // Store Ed25519 key
        let ed25519_secret = hex::decode(validator.ed25519_secret_hex.clone().unwrap_or_default())
            .map_err(|e| anyhow::anyhow!("Invalid ed25519 secret hex: {}", e))?;
        let ed25519_metadata =
            KeyMetadata::new(&ed25519_key_name, "ed25519", &validator.ed25519_pubkey_hex)
                .with_description(&format!("Devnet validator {} Ed25519 key", i));
        keyring
            .store_key(&ed25519_metadata, &ed25519_secret, None)
            .map_err(|e| anyhow::anyhow!("Failed to store Ed25519 key: {}", e))?;

        // Store BLS key
        let bls_secret = hex::decode(validator.bls_secret_hex.clone().unwrap_or_default())
            .map_err(|e| anyhow::anyhow!("Invalid BLS secret hex: {}", e))?;
        let bls_metadata = KeyMetadata::new(&bls_key_name, "bls12-381", &validator.bls_pubkey_hex)
            .with_description(&format!("Devnet validator {} BLS key", i));
        keyring
            .store_key(&bls_metadata, &bls_secret, None)
            .map_err(|e| anyhow::anyhow!("Failed to store BLS key: {}", e))?;

        // Build node config using the SAME validator ID as in genesis
        // Use "test" backend for devnet (no passphrase required)
        let node_config = NodeConfig {
            validator_id: Some(validator.validator_id),
            keyring_backend: "test".to_string(),
            key_name: key_name.clone(),
            keystore_dir: Some(keys_dir.clone()),
            keystore_account: Some(account),
            primary_listen: format!("0.0.0.0:{}", port_offset).parse()?,
            consensus_listen: format!("0.0.0.0:{}", port_offset + 5).parse()?,
            worker_listens: vec![format!("0.0.0.0:{}", port_offset + 1).parse()?],
            // Add all other validators as peers
            peers: peer_configs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, p)| p.clone())
                .collect(),
            num_workers: 1,
            home_dir: Some(node_dir.clone()),
            data_dir: data_dir.clone(),
            genesis_path: Some(genesis_path.clone()),
            car_interval_ms: 100,
            max_batch_txs: 100,
            max_batch_bytes: 1024 * 1024,
            rpc_enabled: true,
            // Each validator gets HTTP and WS ports spaced by 10 to avoid conflicts
            rpc_http_port: cipherd::DEFAULT_RPC_HTTP_PORT + (i as u16 * 10),
            rpc_ws_port: cipherd::DEFAULT_RPC_WS_PORT + (i as u16 * 10),
            metrics_port: cipherd::DEFAULT_METRICS_PORT + (i as u16 * 10),
        };

        let config_path = config_dir.join("node.json");
        node_config.save(&config_path)?;

        println!(
            "  Created node{} (validator {:?}, port {})",
            i, validator.validator_id, port_offset
        );
    }

    // Write validator key files
    let keys_dir = output.join("keys");
    std::fs::create_dir_all(&keys_dir)?;
    for (i, validator) in genesis_result.validators.iter().enumerate() {
        let key_file = ValidatorKeyFile::from_generated(i, validator);
        let key_path = keys_dir.join(format!("validator-{}.json", i));
        let key_json = key_file.to_json()?;
        std::fs::write(&key_path, key_json)?;
    }
    println!(
        "  Created validator keys: {}/validator-*.json",
        keys_dir.display()
    );

    println!();
    println!("Testnet configuration created in: {}", output.display());
    println!();
    println!("Genesis Summary:");
    println!("  Chain ID:    {}", chain_id);
    println!("  Network ID:  {}", network_id);
    println!("  Validators:  {}", num_validators);
    println!("  Stake/Node:  {} ETH", initial_stake_eth);
    println!();
    println!("To start individual nodes:");
    for i in 0..num_validators {
        println!(
            "  cipherd start --config {}/node{}/config/node.json",
            output.display(),
            i
        );
    }
    println!();
    println!("Or run all nodes locally with:");
    println!("  cipherd testnet start --validators {}", num_validators);

    Ok(())
}

async fn cmd_testnet_start(num_validators: usize, duration: u64) -> Result<()> {
    info!("Starting local testnet with {} validators", num_validators);

    // Generate configurations with keypairs
    let test_configs = generate_local_configs(num_validators);

    // Collect validator info for cross-registration (both BLS and Ed25519 keys)
    // Note: test configs always have validator_id set, so unwrap is safe here
    let validator_info: Vec<_> = test_configs
        .iter()
        .map(|tc| {
            (
                tc.config
                    .validator_id
                    .expect("test config should have validator_id"),
                tc.bls_keypair.public_key.clone(),
                tc.ed25519_keypair.public_key.clone(),
            )
        })
        .collect();

    // Create a shared supervisor for coordinated task management across all nodes
    // This ensures graceful shutdown propagates to all validators simultaneously
    let supervisor = NodeSupervisor::new();

    // Create and start nodes under the shared supervisor
    for tc in test_configs {
        let _validator_id = tc
            .config
            .validator_id
            .expect("test config should have validator_id");
        let mut node = Node::new(tc.config, tc.bls_keypair, tc.ed25519_keypair)?;

        // Register ALL validators (including ourselves - needed for threshold calculation)
        // BLS keys are used for DCL threshold signatures, Ed25519 keys for consensus signing
        for (vid, bls_pubkey, ed25519_pubkey) in &validator_info {
            node.add_validator(*vid, bls_pubkey.clone(), ed25519_pubkey.clone());
        }

        // Spawn each node under the shared supervisor for coordinated lifecycle management
        let node_supervisor = supervisor.clone();
        supervisor.spawn(
            // Note: Using a static string for task name as required by spawn()
            "validator-node",
            async move {
                node.run_with_supervisor(node_supervisor).await?;
                Ok(())
            },
        );

        // Stagger node startup slightly
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    info!(
        "All {} nodes started under shared supervisor",
        num_validators
    );

    // Wait for shutdown trigger (duration or Ctrl+C)
    let shutdown_reason = if duration > 0 {
        info!("Running for {} seconds...", duration);
        tokio::select! {
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(duration)) => {
                "duration elapsed"
            }
            _ = tokio::signal::ctrl_c() => {
                "Ctrl+C received"
            }
        }
    } else {
        info!("Press Ctrl+C to stop...");
        tokio::signal::ctrl_c().await?;
        "Ctrl+C received"
    };

    info!("Shutdown triggered: {}", shutdown_reason);

    // Initiate graceful shutdown through the supervisor
    // This propagates cancellation to all nodes in the correct order
    info!(
        "Initiating coordinated shutdown of all {} validators...",
        num_validators
    );
    if let Err(e) = supervisor.shutdown().await {
        tracing::warn!("Shutdown warning: {}", e);
    }

    info!("Testnet stopped gracefully");

    Ok(())
}

// Old cmd_keys function removed - now using key_cli::execute_keys_command
// with secure EIP-2335 encrypted keystores

fn cmd_config(home: &std::path::Path, command: ConfigCommands) -> Result<()> {
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

async fn cmd_status(node: &str) -> Result<()> {
    use jsonrpsee::core::client::ClientT;
    use jsonrpsee::http_client::HttpClientBuilder;
    use jsonrpsee::rpc_params;

    println!("Querying node status at {}...", node);
    println!();

    // Build HTTP client with reasonable timeout
    let client = HttpClientBuilder::default()
        .request_timeout(std::time::Duration::from_secs(10))
        .build(node)
        .context("Failed to create RPC client")?;

    // Query chain ID
    let chain_id: String = client
        .request("eth_chainId", rpc_params![])
        .await
        .context("Failed to query chain ID")?;
    let chain_id_num = u64::from_str_radix(chain_id.trim_start_matches("0x"), 16).unwrap_or(0);

    // Query block number
    let block_number: String = client
        .request("eth_blockNumber", rpc_params![])
        .await
        .context("Failed to query block number")?;
    let block_num = u64::from_str_radix(block_number.trim_start_matches("0x"), 16).unwrap_or(0);

    // Query sync status
    let syncing: serde_json::Value = client
        .request("eth_syncing", rpc_params![])
        .await
        .context("Failed to query sync status")?;

    // Query peer count
    let peer_count: String = client
        .request("net_peerCount", rpc_params![])
        .await
        .context("Failed to query peer count")?;
    let peer_count_num = u64::from_str_radix(peer_count.trim_start_matches("0x"), 16).unwrap_or(0);

    // Query client version
    let client_version: String = client
        .request("web3_clientVersion", rpc_params![])
        .await
        .context("Failed to query client version")?;

    // Format output
    println!("Node Status:");
    println!("  Client:     {}", client_version);
    println!("  Chain ID:   {}", chain_id_num);
    println!("  Height:     {}", block_num);

    // Parse sync status
    if syncing.is_boolean() && !syncing.as_bool().unwrap_or(true) {
        println!("  Syncing:    false (fully synced)");
    } else if let Some(sync_obj) = syncing.as_object() {
        let starting = sync_obj
            .get("startingBlock")
            .and_then(|v| v.as_str())
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);
        let current = sync_obj
            .get("currentBlock")
            .and_then(|v| v.as_str())
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);
        let highest = sync_obj
            .get("highestBlock")
            .and_then(|v| v.as_str())
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);
        println!(
            "  Syncing:    true ({}/{} blocks)",
            current - starting,
            highest - starting
        );
    } else {
        println!("  Syncing:    false");
    }

    println!("  Peers:      {}", peer_count_num);

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

fn cmd_validate(home: &std::path::Path, genesis_path: Option<PathBuf>) -> Result<()> {
    let path = genesis_path.unwrap_or_else(|| home.join("config/genesis.json"));

    if !path.exists() {
        anyhow::bail!("Genesis file not found at {}", path.display());
    }

    // Use GenesisLoader for comprehensive validation
    let genesis = GenesisLoader::load_and_validate(&path)?;

    println!("Genesis file at {} is valid", path.display());
    println!();
    println!("  Chain ID:    {}", genesis.chain_id());
    println!("  Network ID:  {}", genesis.cipherbft.network_id);
    println!("  Validators:  {}", genesis.validator_count());
    println!("  Total Stake: {} wei", genesis.total_staked());

    Ok(())
}

fn cmd_genesis(home: &std::path::Path, command: GenesisCommands) -> Result<()> {
    match command {
        GenesisCommands::Generate {
            validators,
            chain_id,
            network_id,
            initial_stake_eth,
            output,
            keys_dir,
            no_keys,
            extra_alloc,
        } => cmd_genesis_generate(
            validators,
            chain_id,
            &network_id,
            initial_stake_eth,
            &output,
            &keys_dir,
            no_keys,
            extra_alloc,
        ),
        GenesisCommands::AddGenesisAccount {
            address,
            balance_eth,
            genesis,
        } => {
            let genesis_path = genesis.unwrap_or_else(|| home.join("config/genesis.json"));
            cmd_genesis_add_account(&address, balance_eth, &genesis_path)
        }
        GenesisCommands::Gentx {
            key_file,
            stake_eth,
            moniker,
            commission_rate,
            output_dir,
        } => cmd_genesis_gentx(&key_file, stake_eth, moniker, commission_rate, &output_dir),
        GenesisCommands::CollectGentxs { gentx_dir, genesis } => {
            let genesis_path = genesis.unwrap_or_else(|| home.join("config/genesis.json"));
            cmd_genesis_collect_gentxs(&gentx_dir, &genesis_path)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_genesis_generate(
    num_validators: usize,
    chain_id: u64,
    network_id: &str,
    initial_stake_eth: u64,
    output: &std::path::Path,
    keys_dir: &std::path::Path,
    no_keys: bool,
    extra_alloc: Vec<String>,
) -> Result<()> {
    use alloy_primitives::Address;

    println!("Generating genesis file...");
    println!();

    // Parse extra alloc entries
    let mut extra_alloc_parsed: Vec<(Address, U256)> = Vec::new();
    for entry in &extra_alloc {
        let parts: Vec<&str> = entry.split(':').collect();
        if parts.len() != 2 {
            anyhow::bail!(
                "Invalid extra-alloc format: '{}'. Expected address:balance_eth",
                entry
            );
        }
        let address: Address = parts[0]
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid address in extra-alloc: {}", parts[0]))?;
        let balance_eth: u64 = parts[1].parse().map_err(|_| {
            anyhow::anyhow!(
                "Invalid balance in extra-alloc: {}. Expected integer ETH value",
                parts[1]
            )
        })?;
        let balance_wei = U256::from(balance_eth) * U256::from(1_000_000_000_000_000_000u128);
        extra_alloc_parsed.push((address, balance_wei));
    }

    // Convert ETH to wei (1 ETH = 10^18 wei)
    let initial_stake = U256::from(initial_stake_eth) * U256::from(1_000_000_000_000_000_000u128);

    let config = GenesisGeneratorConfig {
        num_validators,
        chain_id,
        network_id: network_id.to_string(),
        initial_stake,
        extra_alloc: extra_alloc_parsed,
        ..Default::default()
    };

    // Generate using thread_rng
    let mut rng = rand::thread_rng();
    let result = GenesisGenerator::generate(&mut rng, config)?;

    // Write genesis file
    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let genesis_json = result.genesis.to_json()?;
    std::fs::write(output, genesis_json)?;
    println!("  Genesis file: {}", output.display());

    // Write validator key files
    if !no_keys {
        std::fs::create_dir_all(keys_dir)?;
        for (i, validator) in result.validators.iter().enumerate() {
            let key_file = ValidatorKeyFile::from_generated(i, validator);
            let key_path = keys_dir.join(format!("validator-{}.json", i));
            let key_json = key_file.to_json()?;
            std::fs::write(&key_path, key_json)?;
        }
        println!("  Validator keys: {}/validator-*.json", keys_dir.display());
    }

    println!();
    println!("Genesis Summary:");
    println!("  Chain ID:    {}", result.genesis.chain_id());
    println!("  Network ID:  {}", result.genesis.cipherbft.network_id);
    println!("  Validators:  {}", result.genesis.validator_count());
    println!(
        "  Total Stake: {} ETH",
        initial_stake_eth * num_validators as u64
    );
    println!();

    // Print validator info
    println!("Validators:");
    for (i, validator) in result.validators.iter().enumerate() {
        println!(
            "  [{}] {} (ed25519: {}...)",
            i,
            validator.address,
            &validator.ed25519_pubkey_hex[..16]
        );
    }

    println!();
    println!("Genesis generation complete!");
    println!();
    println!("To validate the generated genesis:");
    println!("  cipherd validate --genesis {}", output.display());

    Ok(())
}

/// Add a genesis account to an existing genesis file (similar to Cosmos SDK add-genesis-account)
fn cmd_genesis_add_account(
    address: &str,
    balance_eth: u64,
    genesis_path: &std::path::Path,
) -> Result<()> {
    use alloy_primitives::Address;

    if !genesis_path.exists() {
        anyhow::bail!(
            "Genesis file not found at {}. Run 'cipherd init' or 'cipherd genesis generate' first.",
            genesis_path.display()
        );
    }

    // Parse and validate address
    let address: Address = address
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid address format: {}", address))?;

    // Load existing genesis
    let genesis_json = std::fs::read_to_string(genesis_path)?;
    let mut genesis: serde_json::Value = serde_json::from_str(&genesis_json)?;

    // Convert ETH to wei
    let balance_wei = U256::from(balance_eth) * U256::from(1_000_000_000_000_000_000u128);

    // Add to alloc section
    let alloc = genesis
        .get_mut("alloc")
        .and_then(|a| a.as_object_mut())
        .ok_or_else(|| anyhow::anyhow!("Invalid genesis: missing 'alloc' section"))?;

    let address_str = format!("{:?}", address);
    let address_key = address_str.strip_prefix("0x").unwrap_or(&address_str);

    // Check if account already exists
    if alloc.contains_key(address_key) {
        anyhow::bail!("Account {} already exists in genesis", address_str);
    }

    // Add account entry
    alloc.insert(
        address_key.to_string(),
        serde_json::json!({
            "balance": format!("{:#x}", balance_wei),
        }),
    );

    // Write updated genesis
    let updated_json = serde_json::to_string_pretty(&genesis)?;
    std::fs::write(genesis_path, updated_json)?;

    println!("Added genesis account:");
    println!("  Address: {}", address_str);
    println!("  Balance: {} ETH ({} wei)", balance_eth, balance_wei);
    println!();
    println!("Genesis updated: {}", genesis_path.display());

    Ok(())
}

/// Generate a genesis transaction (gentx) for a validator (similar to Cosmos SDK gentx)
fn cmd_genesis_gentx(
    key_file: &std::path::Path,
    stake_eth: u64,
    moniker: Option<String>,
    commission_rate: u8,
    output_dir: &std::path::Path,
) -> Result<()> {
    if !key_file.exists() {
        anyhow::bail!("Key file not found: {}", key_file.display());
    }

    // Load validator key file
    let key_json = std::fs::read_to_string(key_file)?;
    let key_data: serde_json::Value = serde_json::from_str(&key_json)?;

    // Support both naming conventions: bls_pubkey (ValidatorKeyFile) and bls_public_key
    let bls_pubkey = key_data
        .get("bls_pubkey")
        .or_else(|| key_data.get("bls_public_key"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing 'bls_pubkey' or 'bls_public_key' in key file"))?;

    // Support both naming conventions: ed25519_pubkey (ValidatorKeyFile) and ed25519_public_key
    let ed25519_pubkey = key_data
        .get("ed25519_pubkey")
        .or_else(|| key_data.get("ed25519_public_key"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!("Missing 'ed25519_pubkey' or 'ed25519_public_key' in key file")
        })?;

    let address = key_data
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing 'address' in key file"))?;

    let validator_index = key_data.get("index").and_then(|v| v.as_u64()).unwrap_or(0);

    // Derive moniker from key file name if not provided
    let validator_moniker = moniker.unwrap_or_else(|| {
        key_file
            .file_stem()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("validator-{}", validator_index))
    });

    // Convert stake to wei
    let stake_wei = U256::from(stake_eth) * U256::from(1_000_000_000_000_000_000u128);

    // Create gentx structure
    let gentx = serde_json::json!({
        "type": "cipherbft/MsgCreateValidator",
        "value": {
            "moniker": validator_moniker,
            "commission_rate": commission_rate,
            "validator_address": address,
            "bls_public_key": bls_pubkey,
            "ed25519_public_key": ed25519_pubkey,
            "stake": format!("{:#x}", stake_wei),
            "stake_eth": stake_eth,
        }
    });

    // Write gentx file
    std::fs::create_dir_all(output_dir)?;
    let gentx_filename = format!("gentx-{}.json", validator_moniker);
    let gentx_path = output_dir.join(&gentx_filename);
    let gentx_json = serde_json::to_string_pretty(&gentx)?;
    std::fs::write(&gentx_path, gentx_json)?;

    println!("Generated genesis transaction:");
    println!("  Moniker:    {}", validator_moniker);
    println!("  Address:    {}", address);
    println!("  Stake:      {} ETH", stake_eth);
    println!("  Commission: {}%", commission_rate);
    println!();
    println!("Gentx file: {}", gentx_path.display());
    println!();
    println!("Share this file with the genesis coordinator to be included in genesis.");
    println!("Or run 'cipherd genesis collect-gentxs' to add to genesis.");

    Ok(())
}

/// Collect genesis transactions and add validators to genesis (similar to Cosmos SDK collect-gentxs)
fn cmd_genesis_collect_gentxs(
    gentx_dir: &std::path::Path,
    genesis_path: &std::path::Path,
) -> Result<()> {
    use alloy_primitives::Address;

    if !gentx_dir.exists() {
        anyhow::bail!("Gentx directory not found: {}", gentx_dir.display());
    }

    if !genesis_path.exists() {
        anyhow::bail!(
            "Genesis file not found at {}. Run 'cipherd init' or 'cipherd genesis generate' first.",
            genesis_path.display()
        );
    }

    // Load existing genesis
    let genesis_json = std::fs::read_to_string(genesis_path)?;
    let mut genesis: serde_json::Value = serde_json::from_str(&genesis_json)?;

    // First pass: collect existing validator addresses and gather gentx data
    let existing_validators: Vec<String> = genesis
        .get("cipherbft")
        .and_then(|c| c.get("validators"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.get("address").and_then(|a| a.as_str()))
                .map(|s| s.to_lowercase())
                .collect()
        })
        .unwrap_or_default();

    // Collect all gentx data first
    struct GentxData {
        address: String,
        bls_pubkey: String,
        ed25519_pubkey: String,
        stake: String,
        moniker: String,
        addr_key: String,
    }

    let mut gentx_entries: Vec<GentxData> = Vec::new();

    for entry in std::fs::read_dir(gentx_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }

        if path
            .file_name()
            .is_none_or(|n| !n.to_string_lossy().starts_with("gentx-"))
        {
            continue;
        }

        // Parse gentx file
        let gentx_json = std::fs::read_to_string(&path)?;
        let gentx: serde_json::Value = serde_json::from_str(&gentx_json)?;

        let value = gentx
            .get("value")
            .ok_or_else(|| anyhow::anyhow!("Invalid gentx: missing 'value' in {:?}", path))?;

        let address = value
            .get("validator_address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid gentx: missing 'validator_address'"))?
            .to_string();

        let bls_pubkey = value
            .get("bls_public_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid gentx: missing 'bls_public_key'"))?
            .to_string();

        let ed25519_pubkey = value
            .get("ed25519_public_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid gentx: missing 'ed25519_public_key'"))?
            .to_string();

        let stake = value
            .get("stake")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid gentx: missing 'stake'"))?
            .to_string();

        let moniker = value
            .get("moniker")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        // Parse and validate address
        let addr_parsed: Address = address
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid validator address in gentx: {}", address))?;
        let addr_key = format!("{:?}", addr_parsed)
            .strip_prefix("0x")
            .unwrap_or(&format!("{:?}", addr_parsed))
            .to_lowercase();

        // Check for duplicate
        if existing_validators.iter().any(|a| a.contains(&addr_key)) {
            println!("  Skipping duplicate validator: {} ({})", moniker, address);
            continue;
        }

        gentx_entries.push(GentxData {
            address,
            bls_pubkey,
            ed25519_pubkey,
            stake,
            moniker,
            addr_key,
        });
    }

    if gentx_entries.is_empty() {
        anyhow::bail!("No valid gentx files found in {}", gentx_dir.display());
    }

    // Now apply all changes to genesis
    // Get or create validators array in cipherbft section
    let cipherbft = genesis
        .get_mut("cipherbft")
        .and_then(|c| c.as_object_mut())
        .ok_or_else(|| anyhow::anyhow!("Invalid genesis: missing 'cipherbft' section"))?;

    let validators = cipherbft
        .entry("validators")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("Invalid genesis: 'validators' is not an array"))?;

    // Add validators
    for gentx in &gentx_entries {
        let validator_entry = serde_json::json!({
            "address": gentx.address,
            "bls_public_key": gentx.bls_pubkey,
            "ed25519_public_key": gentx.ed25519_pubkey,
            "stake": gentx.stake,
        });
        validators.push(validator_entry);
        println!("  Added validator: {} ({})", gentx.moniker, gentx.address);
    }

    // Get alloc section and add entries
    let alloc = genesis
        .get_mut("alloc")
        .and_then(|a| a.as_object_mut())
        .ok_or_else(|| anyhow::anyhow!("Invalid genesis: missing 'alloc' section"))?;

    for gentx in &gentx_entries {
        if !alloc.contains_key(&gentx.addr_key) {
            alloc.insert(
                gentx.addr_key.clone(),
                serde_json::json!({
                    "balance": gentx.stake,
                }),
            );
        }
    }

    // Write updated genesis
    let updated_json = serde_json::to_string_pretty(&genesis)?;
    std::fs::write(genesis_path, updated_json)?;

    println!();
    println!("Collected {} genesis transactions", gentx_entries.len());
    println!("Genesis updated: {}", genesis_path.display());
    println!();
    println!("To validate the genesis:");
    println!("  cipherd validate --genesis {}", genesis_path.display());

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
