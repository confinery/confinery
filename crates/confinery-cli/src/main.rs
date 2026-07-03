//! Confinery command-line entry point.

mod cli;
mod commands;
mod templates;

use clap::Parser;

use cli::{Cli, Command};
use confinery_core::logging::{self, LogFormat};

fn main() {
    let cli = Cli::parse();

    let format: LogFormat = cli.log_format.parse().unwrap_or_default();
    logging::init(format, &cli.log_level);

    let result = match cli.command {
        Command::Run(args) => commands::run::run(args),
        Command::Profile(command) => commands::profile::run(command),
        Command::Doctor => commands::doctor::run(),
        Command::Init(args) => commands::init::run(args),
    };

    match result {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("confinery: {err:#}");
            std::process::exit(1);
        }
    }
}
