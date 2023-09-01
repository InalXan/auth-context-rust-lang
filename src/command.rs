use clap::{Arg, ArgAction, Command};

pub fn get_commands() -> Command {
    Command::new("asan")
        .about("Azerbaijan Service and Assessment Network")
        .version("0.1.1")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("prepare")
                .short_flag('p')
                .long_flag("prepare")
                .about("Prepare asan project for running.")
                .arg(
                    Arg::new("database")
                        .short('d')
                        .long("database")
                        .help("Create database for ASAN project.")
                        .action(ArgAction::Set)
                        .num_args(1..),
                )
        )
        .subcommand(
            Command::new("runserver")
                .short_flag('r')
                .long_flag("runserver")
                .about("Run Web Development Server.")
                .arg(
                    Arg::new("port")
                        .short('p')
                        .long("port")
                        .action(ArgAction::Set)
                        .num_args(1..)
                        .help("open web server on port"),
                ),
        )
}
