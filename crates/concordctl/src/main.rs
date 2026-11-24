use clap::Parser;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = concordctl::Cli::parse();
    let mut out = std::io::stdout();
    match concordctl::run(&cli, &mut out).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("concordctl: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
