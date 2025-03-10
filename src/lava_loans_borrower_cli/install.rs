use std::fs::remove_file;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use tracing::{error, info};

pub fn install(cli_file_path: &Path) -> Result<()> {
    // Remove existing loans-borrower-cli if it exists.
    // This ensures we always download and run the latest version.
    if cli_file_path.exists() {
        remove_file(cli_file_path)?;
    }

    install_dependencies();

    download_borrower_cli()?;

    make_cli_executable()?;

    info!("loans-borrower-cli installation completed");
    Ok(())
}

fn install_dependencies() {
    match std::env::consts::OS {
        "macos" => install_macos_dependencies(),
        "linux" => install_linux_dependencies(),
        _ => {} // No dependencies for other platforms
    }
}

fn install_macos_dependencies() {
    info!("Installing dependencies for macOS");
    if let Err(e) = Command::new("brew").arg("install").arg("libpq").output() {
        error!("Failed to execute `brew install libpq` command: {e}");
    }
}

fn install_linux_dependencies() {
    info!("Installing dependencies for Linux");
    if let Err(e) = Command::new("sudo").arg("apt-get").arg("update").output() {
        error!("Failed to execute `sudo apt-get update` command: {e}");
    }

    if let Err(e) = Command::new("sudo")
        .arg("apt-get")
        .arg("install")
        .arg("libpq-dev")
        .output()
    {
        error!("Failed to execute `sudo install libpq-dev` command: {e}");
    }
}

fn download_borrower_cli() -> Result<()> {
    info!("Downloading loans-borrower-cli...");

    let download_url = get_download_url()?;

    let output = Command::new("curl")
        .arg("-o")
        .arg("loans-borrower-cli")
        .arg(download_url)
        .output()
        .context("Failed to download loans-borrower-cli")?;

    if output.status.success() {
        info!("Downloaded loans-borrower-cli successfully");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("Failed to download loans-borrower-cli: {stderr}");
        Err(anyhow::anyhow!(
            "Failed to download loans-borrower-cli: {}",
            stderr
        ))
    }
}

fn get_download_url() -> Result<&'static str> {
    match std::env::consts::OS {
        "macos" => Ok("https://loans-borrower-cli.s3.amazonaws.com/loans-borrower-cli-mac"),
        "linux" => Ok("https://loans-borrower-cli.s3.amazonaws.com/loans-borrower-cli-linux"),
        os => {
            error!("Unsupported OS: {os}");
            Err(anyhow::anyhow!("Unsupported OS: {}", os))
        }
    }
}

fn make_cli_executable() -> Result<()> {
    let output = Command::new("chmod")
        .arg("+x")
        .arg("./loans-borrower-cli")
        .output()
        .context("Failed to execute chmod command")?;

    if output.status.success() {
        info!("Set executable permissions on loans-borrower-cli");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("Failed to set executable permissions: {stderr}");
        Err(anyhow::anyhow!(
            "Failed to set executable permissions: {}",
            stderr
        ))
    }
}
