//! `concord`'s command line: serve by default, or manage API users and tokens.

use std::io::{BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use crate::users::{Role, Users, MAX_PASSWORD};

#[derive(Parser, Debug)]
#[command(name = "concord", version, about = "Concord's orchestrator")]
pub struct Cli {
    /// Configuration file.
    #[arg(
        long,
        env = "CONCORD_CONFIG",
        default_value = "/etc/concord/concord.toml",
        global = true
    )]
    pub config: PathBuf,
    /// Without one, serve.
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// People who log in with a password.
    #[command(subcommand)]
    User(UserCommand),
    /// Secrets for scripts and concordctl.
    #[command(subcommand)]
    Token(TokenCommand),
}

#[derive(Subcommand, Debug)]
pub enum UserCommand {
    /// The password is asked for, or read as one line from standard input.
    Add {
        name: String,
        #[arg(long)]
        role: Role,
    },
    /// Ends the user's sessions too.
    Remove { name: String },
    /// Users and tokens.
    List,
}

#[derive(Subcommand, Debug)]
pub enum TokenCommand {
    /// Prints the secret, this once.
    Add {
        name: String,
        #[arg(long)]
        role: Role,
    },
    Remove {
        name: String,
    },
}

pub fn manage(command: &Command, users_file: &Path, out: &mut dyn Write) -> anyhow::Result<()> {
    match command {
        Command::User(UserCommand::Add { name, role }) => {
            let password = password()?;
            Users::add_user(users_file, name, *role, &password)?;
        }
        Command::User(UserCommand::Remove { name }) => Users::remove_user(users_file, name)?,
        Command::User(UserCommand::List) => {
            let f = Users::load(users_file)?;
            for u in &f.users {
                writeln!(out, "user   {}  {}", u.name, u.role)?;
            }
            for t in &f.tokens {
                writeln!(out, "token  {}  {}", t.name, t.role)?;
            }
        }
        Command::Token(TokenCommand::Add { name, role }) => {
            let secret = Users::add_token(users_file, name, *role)?;
            writeln!(out, "{}", secret.as_str())?;
        }
        Command::Token(TokenCommand::Remove { name }) => Users::remove_token(users_file, name)?,
    }
    Ok(())
}

// Never an argument: those are visible to every process on the machine.
fn password() -> anyhow::Result<Zeroizing<String>> {
    if std::io::stdin().is_terminal() {
        let first = Zeroizing::new(rpassword::prompt_password("Password: ")?);
        let again = Zeroizing::new(rpassword::prompt_password("Again: ")?);
        if *first != *again {
            bail!("the passwords differ");
        }
        return Ok(first);
    }
    // One byte past the limit and a line ending, so an overlong password is
    // refused rather than cut.
    let mut line = Zeroizing::new(String::with_capacity(MAX_PASSWORD + 3));
    std::io::stdin()
        .lock()
        .take(MAX_PASSWORD as u64 + 3)
        .read_line(&mut line)
        .context("reading the password")?;
    let s = line.strip_suffix('\n').unwrap_or(&line);
    Ok(Zeroizing::new(
        s.strip_suffix('\r').unwrap_or(s).to_string(),
    ))
}
