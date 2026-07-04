//! Confinery command-line entry point.

mod cli;
mod commands;
mod templates;

use clap::{CommandFactory, Parser};
use clap_complete::generate;

use cli::{Cli, Command};
use confinery_core::logging;

fn main() {
    let cli = Cli::parse();

    logging::init(cli.log_format.into(), &cli.log_level);

    let result = match cli.command {
        Command::Run(args) => commands::run::run(args),
        Command::Profile(command) => commands::profile::run(command),
        Command::Doctor => commands::doctor::run(),
        Command::Init(args) => commands::init::run(args),
        Command::Completions { shell } => {
            let mut app = Cli::command();
            let name = app.get_name().to_string();
            generate(shell, &mut app, name, &mut std::io::stdout());
            Ok(0)
        }
    };

    match result {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("confinery: {err:#}");
            std::process::exit(1);
        }
    }
}
