use bitcoin::Txid as BtcTxid;
use std::fs::{File, remove_file};
use std::io::BufReader;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{error, info};

use crate::{LavaTestError, MAX_RETRIES};

mod install;

pub struct LavaLoansBorrowerCli {
    cli_file_path: PathBuf,
    mnemonic: bip39::Mnemonic,
}

impl LavaLoansBorrowerCli {
    pub fn new(cli_file_path: PathBuf, mnemonic: bip39::Mnemonic) -> Result<Self> {
        if let Err(e) = install::install(&cli_file_path) {
            error!("Failed to install lava loans borrower CLI: {e}");
            return Err(e);
        }

        Ok(Self {
            cli_file_path,
            mnemonic,
        })
    }

    pub fn borrow(&self) -> Result<String> {
        info!("Initiating lava loan...");

        for i in 1..=MAX_RETRIES {
            if let Ok(contract_id) = self.borrow_inner() {
                info!("Lava loan initiated, contract ID: {contract_id}");
                return Ok(contract_id);
            }

            info!("Lava loan initiation failed. Retrying... ({i} of {MAX_RETRIES})");
            sleep(Duration::from_millis(1000));
        }

        error!("Lava loan initiation failed. Max retries reached.");
        Err(LavaTestError::LoanInitiationFailed.into())
    }

    fn borrow_inner(&self) -> Result<String> {
        let output = Command::new(&self.cli_file_path)
            .env("MNEMONIC", self.mnemonic.to_string())
            .arg("--testnet")
            .arg("--disable-backup-contracts")
            .arg("borrow")
            .arg("init")
            .arg("--loan-capital-asset")
            .arg("solana-lava-usd")
            .arg("--ltv-ratio-bp")
            .arg("5000")
            .arg("--loan-duration-days")
            .arg("4")
            .arg("--loan-amount")
            .arg("2")
            .arg("--finalize")
            .stdout(Stdio::piped())
            .output()
            .context("Failed to execute `loans-borrower-cli borrow init` command")?;

        let re = regex::Regex::new(r"New contract ID: ([0-9a-f]{64})\n").unwrap();

        // TODO: Figure out why we have to check stderr rather than stdout.
        let Some(contract_id) = re
            .captures(&String::from_utf8_lossy(&output.stderr))
            .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))
        else {
            return Err(anyhow::anyhow!(
                "Failed to extract contract ID from `loans-borrower-cli borrow init` command"
            ));
        };

        Ok(contract_id)
    }

    pub fn repay(&self, contract_id: &str) -> Result<()> {
        let mut i = 0;
        loop {
            if self.repay_inner(contract_id).is_ok() {
                info!("Loan repaid successfully");
                return Ok(());
            }

            i += 1;

            if i > MAX_RETRIES {
                error!("Unable to repay lava loan after {MAX_RETRIES} retries");
                return Err(LavaTestError::LoanRepaymentFailed(MAX_RETRIES).into());
            }

            info!("Lava loan repayment failed. Retrying... ({i} of {MAX_RETRIES})");
            sleep(Duration::from_millis(1000));
        }
    }

    fn repay_inner(&self, contract_id: &str) -> Result<()> {
        let output = Command::new(&self.cli_file_path)
            .env("MNEMONIC", self.mnemonic.to_string())
            .arg("--testnet")
            .arg("--disable-backup-contracts")
            .arg("borrow")
            .arg("repay")
            .arg("--contract-id")
            .arg(contract_id)
            .stdout(Stdio::piped())
            .output()
            .context("Failed to execute `loans-borrower-cli borrow` command")?;

        if String::from_utf8_lossy(&output.stderr).contains("The collateral has been reclaimed!") {
            Ok(())
        } else {
            // Instead of returning the Output, we'll return a more descriptive error
            Err(anyhow::anyhow!(
                "Loan repayment failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    pub fn wait_for_contract_to_be_closed(&self, contract_id: &str) -> Result<BtcTxid> {
        info!("Waiting for confirmation");

        let closed_json_object = loop {
            let contract_data = self
                .get_contract(contract_id)
                .context("Failed to get contract data")?;

            if let Some(closed_json) = contract_data
                .as_object()
                .and_then(|obj| obj.get("Closed"))
                .and_then(|closed| closed.as_object())
            {
                break closed_json.clone();
            }

            sleep(Duration::from_millis(1000));
        };

        let collateral_repayment_txid_str = closed_json_object
            .get("outcome")
            .and_then(|o| o.as_object())
            .and_then(|o| o.get("repayment"))
            .and_then(|r| r.as_object())
            .and_then(|r| r.get("collateral_repayment_txid"))
            .and_then(|t| t.as_str())
            .ok_or_else(|| {
                LavaTestError::DataExtractionFailed(
                    "Failed to extract collateral repayment txid".into(),
                )
            })?;

        BtcTxid::from_str(collateral_repayment_txid_str).context(
            "Failed to parse 'collateral_repayment_txid' in Lava closed contract JSON data",
        )
    }

    fn get_contract(&self, contract_id: &str) -> Result<serde_json::Value> {
        let contract_json_file_path = format!("./{contract_id}.json");

        Command::new(&self.cli_file_path)
            .env("MNEMONIC", self.mnemonic.to_string())
            .arg("--testnet")
            .arg("--disable-backup-contracts")
            .arg("get-contract")
            .arg("--contract-id")
            .arg(contract_id)
            .arg("--verbose")
            .arg("--output-file")
            .arg(&contract_json_file_path)
            .stdout(Stdio::piped())
            .output()
            .context("Failed to execute `loans-borrower-cli get-contract` command")?;

        // Using the ? operator with anyhow's context for better error handling
        let file = File::open(&contract_json_file_path).context(format!(
            "Failed to open contract file: {contract_json_file_path}"
        ))?;
        let reader = BufReader::new(file);
        let value = serde_json::from_reader(reader).context("Failed to parse contract JSON")?;

        // Still use unwrap here as this cleanup operation failing is not critical to the success of the function
        // If needed, we could add better error handling here too
        remove_file(&contract_json_file_path).unwrap_or_else(|e| {
            info!("Failed to remove temporary contract file: {e}");
        });

        Ok(value)
    }
}
