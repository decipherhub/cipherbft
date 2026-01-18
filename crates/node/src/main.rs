//! CipherBFT Node CLI
//!
//! A Cosmos SDK-style CLI for the CipherBFT blockchain node.

use alloy_primitives::U256;
use anyhow::Result;
use cipherd::{
    execute_keys_command, generate_local_configs, GenesisGenerator, GenesisGeneratorConfig,
    GenesisLoader, KeysCommand, Node, NodeConfig, ValidatorKeyFile, CIPHERD_HOME_ENV,
    DEFAULT_HOME_DIR, EXIT_CONFIG_ERROR,
};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{info, warn, Level};
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
    },

    /// Generate testnet configuration files for local multi-validator testing
    Testnet {
        #[command(subcommand)]
        command: TestnetCommands,
    },

    /// Manage your application's keys (secure EIP-2335 keystores)
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
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

        /// Starting P2P port (increments by 10 for each validator)
        #[arg(long, default_value = "9000")]
        starting_port: u16,
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

        Commands::Start { config, genesis } => {
            let config_path = config.unwrap_or_else(|| cli.home.join("config/node.json"));
            cmd_start(config_path, genesis).await
        }

        Commands::Testnet { command } => cmd_testnet(command).await,

        Commands::Keys { command } => execute_keys_command(&cli.home, command),

        Commands::Config { command } => cmd_config(&cli.home, command),

        Commands::Status { node } => cmd_status(&node),

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
    let mut config = configs[0].clone();

    // Update paths to use the actual home directory
    config.home_dir = Some(home.to_path_buf());
    config.data_dir = data_dir.clone();

    let config_path = config_dir.join("node.json");
    config.save(&config_path)?;

    let node_moniker =
        moniker.unwrap_or_else(|| format!("node-{}", hex::encode(&config.validator_id.0[..8])));

    // Generate genesis file
    let genesis_path = config_dir.join("genesis.json");
    // Convert ETH to wei (1 ETH = 10^18 wei)
    let initial_stake = U256::from(initial_stake_eth) * U256::from(1_000_000_000_000_000_000u128);
    let initial_balance = U256::from(100u64) * U256::from(1_000_000_000_000_000_000u128); // 100 ETH

    let genesis = GenesisGenerator::generate_from_node_config(
        &config,
        chain_id,
        network_id,
        initial_stake,
        initial_balance,
    )?;

    let genesis_json = genesis.to_json()?;
    std::fs::write(&genesis_path, genesis_json)?;

    println!("Successfully initialized node configuration");
    println!();
    println!("  Home:       {}", home.display());
    println!("  Moniker:    {}", node_moniker);
    println!("  Chain ID:   {}", chain_id);
    println!("  Network ID: {}", network_id);
    println!("  Config:     {}", config_path.display());
    println!("  Genesis:    {}", genesis_path.display());
    println!();
    println!("To start the node:");
    println!("  cipherd start --home {}", home.display());

    Ok(())
}

async fn cmd_start(config_path: PathBuf, genesis_override: Option<PathBuf>) -> Result<()> {
    if !config_path.exists() {
        anyhow::bail!(
            "Configuration file not found: {}\nRun 'cipherd init' first to create configuration.",
            config_path.display()
        );
    }

    info!("Loading configuration from {}", config_path.display());

    let mut config = NodeConfig::load(&config_path)?;

    // SECURITY: Detect plaintext keys and require migration
    if config.has_plaintext_keys() && !config.has_keystore_config() {
        eprintln!();
        eprintln!("=============================================================================");
        eprintln!("  SECURITY ERROR: Plaintext keys detected in configuration!");
        eprintln!("=============================================================================");
        eprintln!();
        eprintln!("  Your configuration file contains secret keys in plaintext format.");
        eprintln!("  This is a security risk and is no longer supported.");
        eprintln!();
        eprintln!("  Configuration file: {}", config_path.display());
        eprintln!();
        eprintln!("  To migrate to secure encrypted keystores, run:");
        eprintln!();
        eprintln!("    cipherd keys migrate --dry-run");
        eprintln!();
        eprintln!("  Review the output, then run without --dry-run to perform the migration:");
        eprintln!();
        eprintln!("    cipherd keys migrate");
        eprintln!();
        eprintln!("  After migration, update your config to use:");
        eprintln!();
        eprintln!("    keystore_dir = \"{}\"", config.effective_keystore_dir().display());
        eprintln!();
        eprintln!("  And remove the 'bls_secret_key_hex' and 'ed25519_secret_key_hex' fields.");
        eprintln!();
        eprintln!("  For more information, see: cipherd keys --help");
        eprintln!("=============================================================================");
        eprintln!();
        std::process::exit(EXIT_CONFIG_ERROR);
    }

    // Warn if both keystore and plaintext keys are present (use keystore)
    if config.has_plaintext_keys() && config.has_keystore_config() {
        warn!(
            "Configuration contains both keystore_dir and plaintext keys. \
             Using keystore_dir and ignoring plaintext keys. \
             Consider removing the plaintext key fields from your config."
        );
    }

    // Override genesis path if provided via CLI
    if genesis_override.is_some() {
        config.genesis_path = genesis_override;
    }

    // Resolve and load genesis file
    let genesis_path = config.effective_genesis_path();
    info!("Loading genesis from {}", genesis_path.display());

    let genesis = GenesisLoader::load_and_validate(&genesis_path)?;

    info!("Starting node with validator ID: {:?}", config.validator_id);

    // Create node and bootstrap validators from genesis
    let mut node = Node::new(config)?;
    node.bootstrap_validators_from_genesis(&genesis)?;

    node.run().await?;

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
            starting_port,
        } => cmd_testnet_init_files(
            validators,
            &output,
            chain_id,
            &network_id,
            initial_stake_eth,
            starting_port,
        ),
        TestnetCommands::Start {
            validators,
            duration,
        } => cmd_testnet_start(validators, duration).await,
    }
}

fn cmd_testnet_init_files(
    num_validators: usize,
    output: &std::path::Path,
    chain_id: u64,
    network_id: &str,
    initial_stake_eth: u64,
    starting_port: u16,
) -> Result<()> {
    println!(
        "Generating testnet configuration for {} validators...",
        num_validators
    );
    println!();

    std::fs::create_dir_all(output)?;

    // Generate node configs
    let configs = generate_local_configs(num_validators);

    // Generate a shared genesis file with all validators
    let initial_stake = U256::from(initial_stake_eth) * U256::from(1_000_000_000_000_000_000u128);
    let genesis_config = GenesisGeneratorConfig {
        num_validators,
        chain_id,
        network_id: network_id.to_string(),
        initial_stake,
        ..Default::default()
    };

    let mut rng = rand::thread_rng();
    let genesis_result = GenesisGenerator::generate(&mut rng, genesis_config)?;

    // Write shared genesis file
    let genesis_path = output.join("genesis.json");
    let genesis_json = genesis_result.genesis.to_json()?;
    std::fs::write(&genesis_path, genesis_json)?;
    println!("  Created shared genesis: {}", genesis_path.display());

    // Create directories and configs for each node
    for (i, config) in configs.iter().enumerate() {
        let node_dir = output.join(format!("node{}", i));
        let config_dir = node_dir.join("config");
        let data_dir = node_dir.join("data");
        std::fs::create_dir_all(&config_dir)?;
        std::fs::create_dir_all(&data_dir)?;

        // Modify config with unique ports and genesis path
        let mut node_config = config.clone();
        let port_offset = starting_port + (i as u16 * 10);
        node_config.primary_listen = format!("0.0.0.0:{}", port_offset).parse()?;
        node_config.consensus_listen = format!("0.0.0.0:{}", port_offset + 5).parse()?;
        node_config.genesis_path = Some(genesis_path.clone());

        let config_path = config_dir.join("node.json");
        node_config.save(&config_path)?;

        println!(
            "  Created node{} (validator {:?}, port {})",
            i,
            config.validator_id,
            starting_port + (i as u16 * 10)
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

    // Generate configurations
    let configs = generate_local_configs(num_validators);

    // Collect validator info for cross-registration (both BLS and Ed25519 keys)
    let validator_info: Vec<_> = configs
        .iter()
        .map(|c| {
            let bls_keypair = c.keypair().unwrap();
            let ed25519_keypair = c.ed25519_keypair().unwrap();
            (
                c.validator_id,
                bls_keypair.public_key.clone(),
                ed25519_keypair.public_key.clone(),
            )
        })
        .collect();

    // Create and start nodes
    let mut handles = Vec::new();

    for config in configs {
        let validator_id = config.validator_id;
        let mut node = Node::new(config)?;

        // Register ALL validators (including ourselves - needed for threshold calculation)
        // BLS keys are used for DCL threshold signatures, Ed25519 keys for consensus signing
        for (vid, bls_pubkey, ed25519_pubkey) in &validator_info {
            node.add_validator(*vid, bls_pubkey.clone(), ed25519_pubkey.clone());
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
        } => cmd_genesis_generate(
            validators,
            chain_id,
            &network_id,
            initial_stake_eth,
            &output,
            &keys_dir,
            no_keys,
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

fn cmd_genesis_generate(
    num_validators: usize,
    chain_id: u64,
    network_id: &str,
    initial_stake_eth: u64,
    output: &std::path::Path,
    keys_dir: &std::path::Path,
    no_keys: bool,
) -> Result<()> {
    println!("Generating genesis file...");
    println!();

    // Convert ETH to wei (1 ETH = 10^18 wei)
    let initial_stake = U256::from(initial_stake_eth) * U256::from(1_000_000_000_000_000_000u128);

    let config = GenesisGeneratorConfig {
        num_validators,
        chain_id,
        network_id: network_id.to_string(),
        initial_stake,
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
