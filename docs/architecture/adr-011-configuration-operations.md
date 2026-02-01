# ADR 011: Configuration and Operations

## Changelog

* 2026-02-01: Added implementation status
* 2025-12-07: Initial draft

## Status

ACCEPTED Partially Implemented

## Implementation Status

| Component | Status | Location |
|-----------|--------|----------|
| Node Binary | Implemented | `crates/node/src/main.rs` |
| Config File Parser | Implemented | `crates/node/src/config.rs` |
| Genesis Loader | Implemented | `crates/node/src/genesis.rs` |
| Prometheus Metrics | Implemented | `crates/metrics/` |
| Structured Logging | Implemented | `crates/node/src/logging.rs` |
| CLI Commands | Partial | `init`, `run` implemented; `reset`, `export-state` pending |
| Key Generation | Partial | Manual key generation; automated ceremony pending |

### Implementation Notes

- **Config Path**: Default `~/.cipherbft/config.toml`
- **Data Directory**: Default `~/.cipherbft/data/`
- **Metrics Port**: Default 9090 (Prometheus)
- **Log Format**: JSON structured logging with configurable level

## Abstract

CipherBFT provides a command-line interface for node initialization, configuration, and operation. This ADR defines the configuration file format, CLI commands, structured logging, and Prometheus metrics for production operation.

## Context

CipherBFT requires operational tooling for:
1. **Node initialization**: Create config files and data directories
2. **Configuration management**: Consensus, P2P, EVM, and storage settings
3. **Node lifecycle**: Start, stop, and reset commands
4. **Observability**: Structured logging and Prometheus metrics
5. **Health monitoring**: Status endpoints for load balancers

### Design Goals

- **Simple setup**: Single init command for new nodes
- **Standard formats**: TOML config, JSON logs
- **Full observability**: 50+ Prometheus metrics
- **Production ready**: Health checks and graceful shutdown

## Alternatives

### Alternative 1: Environment Variables Only

Configure everything via environment variables.

**Pros:**
- Container-friendly
- No config files to manage

**Cons:**
- Verbose for complex configs
- Hard to version control
- Difficult nested structures

### Alternative 2: Geth-style Flags

Use extensive command-line flags like Geth.

**Pros:**
- Familiar to Ethereum operators
- Direct override

**Cons:**
- Very long command lines
- Hard to maintain

### Alternative 3: TOML Config + CLI Override (Chosen)

TOML configuration file with CLI flag overrides.

**Pros:**
- Readable config format
- Version controllable
- CLI overrides for deployment
- Consistent with Rust ecosystem

**Cons:**
- Must maintain config schema
- Two sources of truth

## Decision

Use TOML configuration files with CLI flag overrides and structured JSON logging.

### Configuration File Structure

```toml
# ~/.cipherbft/config.toml

[node]
# Node identity
name = "validator-1"
# Data directory
data_dir = "~/.cipherbft/data"

[consensus]
# Timeout settings (milliseconds)
propose_timeout = 3000
prevote_timeout = 1000
precommit_timeout = 1000
# Timeout backoff
timeout_delta = 500
max_timeout = 30000

[dcl]
# Attestation collection timeout (milliseconds)
attestation_timeout = 500
# Timeout backoff delta
attestation_delta = 250
max_attestation_timeout = 5000

[p2p]
# Listen address
listen_addr = "0.0.0.0:26656"
# External address (for NAT)
external_addr = ""
# Seed nodes
seeds = ["node1@192.168.1.10:26656", "node2@192.168.1.11:26656"]
# Maximum peers
max_peers = 50
# Enable PEX
pex = true

[rpc]
# HTTP RPC
http_addr = "127.0.0.1:8545"
# WebSocket RPC
ws_addr = "127.0.0.1:8546"
# Maximum connections
max_connections = 100
# Enabled namespaces
namespaces = ["eth", "web3", "net"]

[evm]
# Chain ID
chain_id = 1337
# Block gas limit
block_gas_limit = 30000000
# Base fee (initial)
base_fee = 1000000000

[storage]
# Database path
db_path = "~/.cipherbft/data/db"
# Block pruning retention
pruning_retention = 100000
# WAL directory
wal_path = "~/.cipherbft/data/wal"

[mempool]
# Maximum transactions
max_size = 10000
# Maximum per account
max_per_account = 100
# Maximum nonce gap
max_nonce_gap = 16

[metrics]
# Prometheus endpoint
enabled = true
addr = "127.0.0.1:9090"

[logging]
# Log level (debug, info, warn, error)
level = "info"
# Log format (json, pretty)
format = "json"
# Log file (optional)
file = ""
```

### Genesis Configuration

```json
{
  "chainId": 1337,
  "timestamp": "2024-01-01T00:00:00Z",
  "gasLimit": 30000000,
  "baseFeePerGas": "1000000000",
  "alloc": {
    "0x...": {
      "balance": "1000000000000000000000"
    }
  }
}
```

### Validator Keys Configuration

```toml
# ~/.cipherbft/keys.toml

[consensus]
# Ed25519 private key (hex)
private_key = "0x..."

[dcl]
# BLS12-381 private key (hex)
private_key = "0x..."
```

### CLI Commands

```
cipherbft - CipherBFT Consensus Engine

USAGE:
    cipherbft <COMMAND>

COMMANDS:
    init      Initialize node configuration and data directories
    start     Start the consensus node
    reset     Clear all state and restart fresh
    keys      Key management commands
    status    Query node status
    version   Print version information
    help      Print help information

OPTIONS:
    -c, --config <PATH>    Config file path [default: ~/.cipherbft/config.toml]
    -v, --verbose          Increase logging verbosity
    -q, --quiet            Decrease logging verbosity
    --log-format <FMT>     Log format (json, pretty) [default: json]
```

### Command Implementations

```rust
// crates/cli/src/commands/init.rs

/// Initialize a new CipherBFT node
#[derive(Parser)]
pub struct InitCommand {
    /// Chain ID
    #[arg(long, default_value = "1337")]
    chain_id: u64,

    /// Data directory
    #[arg(long, default_value = "~/.cipherbft")]
    home: PathBuf,

    /// Generate new validator keys
    #[arg(long)]
    validator: bool,
}

impl InitCommand {
    pub fn run(&self) -> Result<()> {
        let home = expand_tilde(&self.home);

        // Create directories
        fs::create_dir_all(&home)?;
        fs::create_dir_all(home.join("data"))?;
        fs::create_dir_all(home.join("data/db"))?;
        fs::create_dir_all(home.join("data/wal"))?;

        // Generate default config
        let config = Config::default_with_chain_id(self.chain_id);
        let config_path = home.join("config.toml");
        fs::write(&config_path, toml::to_string_pretty(&config)?)?;

        // Generate genesis if not exists
        let genesis_path = home.join("genesis.json");
        if !genesis_path.exists() {
            let genesis = Genesis::default_with_chain_id(self.chain_id);
            fs::write(&genesis_path, serde_json::to_string_pretty(&genesis)?)?;
        }

        // Generate validator keys if requested
        if self.validator {
            let keys = ValidatorKeys::generate();
            let keys_path = home.join("keys.toml");
            fs::write(&keys_path, toml::to_string_pretty(&keys)?)?;

            println!("Validator address: {}", keys.address());
            println!("Ed25519 public key: {}", keys.consensus_pubkey());
            println!("BLS public key: {}", keys.dcl_pubkey());
        }

        println!("Initialized CipherBFT node at {}", home.display());
        Ok(())
    }
}
```

```rust
// crates/cli/src/commands/start.rs

/// Start the CipherBFT node
#[derive(Parser)]
pub struct StartCommand {
    /// Config file path
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Override P2P listen address
    #[arg(long)]
    p2p_addr: Option<SocketAddr>,

    /// Override RPC address
    #[arg(long)]
    rpc_addr: Option<SocketAddr>,

    /// Log level
    #[arg(long)]
    log_level: Option<Level>,
}

impl StartCommand {
    pub async fn run(&self) -> Result<()> {
        // Load config
        let mut config = Config::load(self.config.as_ref())?;

        // Apply CLI overrides
        if let Some(addr) = self.p2p_addr {
            config.p2p.listen_addr = addr;
        }
        if let Some(addr) = self.rpc_addr {
            config.rpc.http_addr = addr;
        }

        // Initialize logging
        init_logging(&config.logging)?;

        // Load keys
        let keys = ValidatorKeys::load(&config.keys_path)?;

        // Initialize components
        let storage = Storage::new(&config.storage)?;
        let network = Network::new(&config.p2p).await?;
        let mempool = Mempool::new(&config.mempool);
        let evm = EvmExecutor::new(&config.evm);

        // Build consensus engine
        let engine = ConsensusEngine::builder()
            .with_storage(storage)
            .with_network(network)
            .with_mempool(mempool)
            .with_evm(evm)
            .with_keys(keys)
            .build()?;

        // Start RPC server
        let rpc = RpcServer::new(&config.rpc, engine.clone()).await?;

        // Start metrics server
        if config.metrics.enabled {
            MetricsServer::start(&config.metrics).await?;
        }

        // Handle shutdown signals
        let shutdown = shutdown_signal();

        // Run engine until shutdown
        tokio::select! {
            result = engine.run() => {
                result?;
            }
            _ = shutdown => {
                info!("Shutdown signal received");
                engine.stop().await?;
            }
        }

        Ok(())
    }
}
```

### Structured Logging

```rust
// crates/logging/src/lib.rs
use tracing_subscriber::{fmt, EnvFilter};

pub fn init_logging(config: &LoggingConfig) -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.level));

    let subscriber = fmt::Subscriber::builder()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(false)
        .with_file(true)
        .with_line_number(true);

    match config.format.as_str() {
        "json" => {
            let subscriber = subscriber.json().finish();
            tracing::subscriber::set_global_default(subscriber)?;
        }
        "pretty" => {
            let subscriber = subscriber.pretty().finish();
            tracing::subscriber::set_global_default(subscriber)?;
        }
        _ => return Err(Error::InvalidLogFormat),
    }

    Ok(())
}
```

### Prometheus Metrics

```rust
// crates/metrics/src/lib.rs
use prometheus::{
    Counter, CounterVec, Gauge, GaugeVec, Histogram, HistogramVec,
    register_counter, register_counter_vec, register_gauge,
    register_gauge_vec, register_histogram, register_histogram_vec,
};

lazy_static! {
    // Consensus metrics
    pub static ref CONSENSUS_HEIGHT: Gauge = register_gauge!(
        "cipherbft_consensus_height",
        "Current consensus height"
    ).unwrap();

    pub static ref CONSENSUS_ROUND: Gauge = register_gauge!(
        "cipherbft_consensus_round",
        "Current consensus round"
    ).unwrap();

    pub static ref CONSENSUS_PROPOSALS: Counter = register_counter!(
        "cipherbft_consensus_proposals_total",
        "Total proposals created"
    ).unwrap();

    pub static ref CONSENSUS_VOTES: CounterVec = register_counter_vec!(
        "cipherbft_consensus_votes_total",
        "Total votes by type",
        &["type"]  // prevote, precommit
    ).unwrap();

    pub static ref CONSENSUS_ROUND_DURATION: Histogram = register_histogram!(
        "cipherbft_consensus_round_duration_seconds",
        "Duration of consensus rounds"
    ).unwrap();

    // DCL metrics
    pub static ref DCL_CARS_CREATED: Counter = register_counter!(
        "cipherbft_dcl_cars_created_total",
        "Total Cars created"
    ).unwrap();

    pub static ref DCL_ATTESTATIONS_RECEIVED: Counter = register_counter!(
        "cipherbft_dcl_attestations_received_total",
        "Total attestations received"
    ).unwrap();

    pub static ref DCL_ATTESTATION_LATENCY: Histogram = register_histogram!(
        "cipherbft_dcl_attestation_latency_seconds",
        "Time to collect f+1 attestations"
    ).unwrap();

    // Mempool metrics
    pub static ref MEMPOOL_SIZE: Gauge = register_gauge!(
        "cipherbft_mempool_size",
        "Current mempool transaction count"
    ).unwrap();

    pub static ref MEMPOOL_PENDING: Gauge = register_gauge!(
        "cipherbft_mempool_pending",
        "Pending transactions in mempool"
    ).unwrap();

    pub static ref MEMPOOL_QUEUED: Gauge = register_gauge!(
        "cipherbft_mempool_queued",
        "Queued transactions in mempool"
    ).unwrap();

    // P2P metrics
    pub static ref P2P_PEERS: Gauge = register_gauge!(
        "cipherbft_p2p_peers",
        "Current peer count"
    ).unwrap();

    pub static ref P2P_MESSAGES_SENT: CounterVec = register_counter_vec!(
        "cipherbft_p2p_messages_sent_total",
        "Messages sent by type",
        &["type"]
    ).unwrap();

    pub static ref P2P_MESSAGES_RECEIVED: CounterVec = register_counter_vec!(
        "cipherbft_p2p_messages_received_total",
        "Messages received by type",
        &["type"]
    ).unwrap();

    // EVM metrics
    pub static ref EVM_BLOCKS_EXECUTED: Counter = register_counter!(
        "cipherbft_evm_blocks_executed_total",
        "Total blocks executed"
    ).unwrap();

    pub static ref EVM_TRANSACTIONS_EXECUTED: Counter = register_counter!(
        "cipherbft_evm_transactions_executed_total",
        "Total transactions executed"
    ).unwrap();

    pub static ref EVM_GAS_USED: Counter = register_counter!(
        "cipherbft_evm_gas_used_total",
        "Total gas used"
    ).unwrap();

    pub static ref EVM_EXECUTION_TIME: Histogram = register_histogram!(
        "cipherbft_evm_execution_time_seconds",
        "Block execution time"
    ).unwrap();

    // Storage metrics
    pub static ref STORAGE_BLOCKS: Gauge = register_gauge!(
        "cipherbft_storage_blocks",
        "Total blocks stored"
    ).unwrap();

    pub static ref STORAGE_SIZE_BYTES: Gauge = register_gauge!(
        "cipherbft_storage_size_bytes",
        "Database size in bytes"
    ).unwrap();
}
```

### Health Check Endpoint

```rust
// crates/rpc/src/health.rs

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: HealthStatus,
    pub version: String,
    pub syncing: bool,
    pub latest_block: u64,
    pub peer_count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

impl HealthHandler {
    pub async fn health(&self) -> HealthResponse {
        let syncing = self.sync_status().await;
        let peer_count = self.network.peer_count();
        let latest_block = self.storage.latest_block_height().unwrap_or(0);

        let status = if syncing && peer_count == 0 {
            HealthStatus::Unhealthy
        } else if syncing {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        HealthResponse {
            status,
            version: env!("CARGO_PKG_VERSION").to_string(),
            syncing,
            latest_block,
            peer_count,
        }
    }
}
```

## Consequences

### Backwards Compatibility

N/A - greenfield implementation.

### Positive

1. **Simple onboarding**: Single init command creates everything
2. **Standard formats**: TOML and JSON are widely understood
3. **Full observability**: 50+ metrics for production monitoring
4. **Health checks**: Ready for load balancer integration
5. **Graceful shutdown**: Clean state on termination

### Negative

1. **Config migration**: Schema changes require migration
2. **Key management**: Manual key backup required
3. **No hot reload**: Config changes require restart

### Neutral

1. **Single binary**: All commands in one executable
2. **Local keys**: No external key management integration
3. **File-based config**: No remote configuration server

## Test Cases

1. **init**: Creates all directories and files
2. **init --validator**: Generates valid key pairs
3. **start**: Loads config and starts all components
4. **start with overrides**: CLI flags override config file
5. **reset**: Clears data directory, preserves config
6. **status**: Returns current node status
7. **Health check**: Returns correct status based on state
8. **Metrics**: All registered metrics accessible via Prometheus
9. **Logging**: JSON format parseable by log aggregators
10. **Graceful shutdown**: Clean exit on SIGTERM

## References

* [TOML Specification](https://toml.io/)
* [tracing-subscriber](https://docs.rs/tracing-subscriber)
* [Prometheus Rust Client](https://github.com/prometheus/client_rust)
* [Clap Command-Line Parser](https://docs.rs/clap)
