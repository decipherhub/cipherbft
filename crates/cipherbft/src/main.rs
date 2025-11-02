//! CipherBFT consensus engine binary.

use clap::Parser;

#[derive(Parser)]
#[command(name = "cipherbft")]
#[command(about = "CipherBFT Consensus Engine", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Parser)]
enum Commands {
    /// Initialize node configuration
    Init {
        /// Home directory for node data
        #[arg(long, default_value = ".cipherbft")]
        home: String,
    },
    /// Start the consensus node
    Start {
        /// Home directory for node data
        #[arg(long, default_value = ".cipherbft")]
        home: String,
    },
    /// Display version information
    Version,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { home } => {
            println!("Initializing node in: {}", home);
            // TODO: Implement initialization
        }
        Commands::Start { home } => {
            println!("Starting node from: {}", home);
            // TODO: Implement node startup
        }
        Commands::Version => {
            println!("cipherbft {}", env!("CARGO_PKG_VERSION"));
        }
    }
}
