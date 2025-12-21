//! CipherBFT Node CLI
//!
//! MVP binary for testing DCL with multiple validators.

use anyhow::Result;
use cipherbft_node::{generate_local_configs, Node, NodeConfig};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
#[command(name = "cipherbft-node")]
#[command(about = "CipherBFT Node - MVP for DCL testing")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate configuration files for local testing
    GenConfig {
        /// Number of validators
        #[arg(short, long, default_value = "4")]
        validators: usize,

        /// Output directory for config files
        #[arg(short, long, default_value = "./configs")]
        output: PathBuf,
    },

    /// Run a node with the given configuration
    Run {
        /// Path to the configuration file
        #[arg(short, long)]
        config: PathBuf,

        /// Log level (trace, debug, info, warn, error)
        #[arg(short, long, default_value = "info")]
        log_level: String,
    },

    /// Run all validators locally for testing (spawns multiple tasks)
    LocalTest {
        /// Number of validators
        #[arg(short, long, default_value = "4")]
        validators: usize,

        /// Log level
        #[arg(short, long, default_value = "info")]
        log_level: String,

        /// Duration to run in seconds (0 = run until Ctrl+C)
        #[arg(short, long, default_value = "30")]
        duration: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenConfig { validators, output } => {
            gen_config(validators, output)?;
        }
        Commands::Run { config, log_level } => {
            init_tracing(&log_level);
            run_node(config).await?;
        }
        Commands::LocalTest {
            validators,
            log_level,
            duration,
        } => {
            init_tracing(&log_level);
            local_test(validators, duration).await?;
        }
    }

    Ok(())
}

fn init_tracing(log_level: &str) {
    let level = match log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(true)
        .with_thread_ids(true)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");
}

fn gen_config(validators: usize, output: PathBuf) -> Result<()> {
    println!("Generating configuration for {} validators...", validators);

    std::fs::create_dir_all(&output)?;

    let configs = generate_local_configs(validators);

    for (i, config) in configs.iter().enumerate() {
        let path = output.join(format!("node-{}.json", i));
        config.save(&path)?;
        println!(
            "  Created {} (validator {:?})",
            path.display(),
            config.validator_id
        );
    }

    println!("\nTo run a node:");
    println!(
        "  cipherbft-node run --config {}/node-0.json",
        output.display()
    );

    println!("\nTo run all validators locally:");
    println!("  cipherbft-node local-test --validators {}", validators);

    Ok(())
}

async fn run_node(config_path: PathBuf) -> Result<()> {
    info!("Loading configuration from {}", config_path.display());

    let config = NodeConfig::load(&config_path)?;
    info!("Starting node with validator ID: {:?}", config.validator_id);

    let node = Node::new(config)?;
    node.run().await?;

    Ok(())
}

async fn local_test(num_validators: usize, duration: u64) -> Result<()> {
    info!("Starting local test with {} validators", num_validators);

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
    info!("Local test complete");

    Ok(())
}
