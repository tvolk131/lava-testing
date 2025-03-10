#![warn(clippy::nursery)]
#![warn(clippy::pedantic)]

use std::fs::{File, remove_file};
use std::io::BufReader;
use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use std::{process::Command, str::FromStr};
use tokio::sync::Mutex;

use anyhow::{Context, Result};
use axum::{Router, extract::State, http::StatusCode, routing::get};
use bitcoin::bip32::{DerivationPath as BtcDerivationPath, Xpriv};
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::Message;
use bitcoin::sighash::SighashCache;
use bitcoin::transaction::Version;
use bitcoin::{
    Address as BtcAddress, Amount as BtcAmount, EcdsaSighashType, Network, OutPoint, PrivateKey,
    PublicKey as BtcPublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid as BtcTxid,
    Witness,
};
use solana_sdk::derivation_path::DerivationPath as SolanaDerivationPath;
use solana_sdk::pubkey::Pubkey as SolanaPubkey;
use solana_sdk::signature::Signature as SolanaSignature;
use solana_sdk::signer::{SeedDerivable, Signer};
use thiserror::Error;
use tower_http::trace::TraceLayer;
use tracing::{error, info};

#[derive(Error, Debug)]
pub enum LavaTestError {
    #[error("Failed to generate mnemonic: {0}")]
    MnemonicGeneration(#[source] bip39::Error),

    #[error("Bitcoin faucet error: {0}")]
    BitcoinFaucet(String),

    #[error("Solana faucet error: {0}")]
    SolanaFaucet(String),

    #[error("Loan initiation failed after maximum retries")]
    LoanInitiationFailed,

    #[error("Unable to repay loan after {0} retries")]
    LoanRepaymentFailed(i32),

    #[error("Failed to extract data: {0}")]
    DataExtractionFailed(String),

    #[error("Funds return failed: {0}")]
    FundsReturnFailed(String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

const NETWORK: Network = Network::Testnet4;
const FAUCET_REFUND_ADDRESS_STR: &str = "tb1qd8cg49sy99cln5tq2tpdm7xs4p9s5v6le4jx4c";
const MIN_RELAY_FEE: u64 = 110;
const MAX_RETRIES: i32 = 10;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    info!("Starting Lava Testing HTTP server");

    // Create a shared flag to track if a test is currently running
    let test_lock = Arc::new(Mutex::new(()));

    // Build our application with a route
    let app = Router::new()
        .route("/run-test", get(run_test_handler))
        .route("/health", get(health_check))
        .layer(TraceLayer::new_for_http())
        .with_state(test_lock);

    // Run our app
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    info!("Listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("Failed to bind to address")?;

    axum::serve(listener, app)
        .await
        .context("Failed to start server")?;

    Ok(())
}

// Lock to be shared between handlers.
type AppState = Arc<Mutex<()>>;

#[axum::debug_handler]
async fn health_check() -> StatusCode {
    StatusCode::OK
}

#[axum::debug_handler]
async fn run_test_handler(State(state): State<AppState>) -> (StatusCode, String) {
    let Ok(test_lock_guard) = state.try_lock() else {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "A test is already running. Please try again later.".to_string(),
        );
    };

    // Run test in a separate blocking task to avoid blocking the HTTP server.
    let result = tokio::task::spawn_blocking(run_test).await;

    drop(test_lock_guard);

    match result {
        Ok(Ok(contract_id)) => (
            StatusCode::OK,
            format!("Test passed successfully! Contract ID: {contract_id}"),
        ),
        Ok(Err(err)) => {
            error!("Test error: {err:?}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Test failed: {err}"),
            )
        }
        Err(join_err) => {
            error!("Test panic: {join_err}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Test task panicked: {join_err}"),
            )
        }
    }
}

fn run_test() -> Result<String> {
    info!("Starting Lava test run...");

    if let Err(e) = install_lava_loans_borrower_cli() {
        error!("Failed to install LAVA loans borrower CLI: {e}");
        return Err(e);
    }

    let (mnemonic, root_priv_key) = initialize_wallet()?;

    let btc_recv_derivation_path = "m/84'/1'/0'/0/0"
        .parse::<BtcDerivationPath>()
        .context("Invalid derivation path")?;

    let btc_change_derivation_path = "m/84'/1'/0'/1/0"
        .parse::<BtcDerivationPath>()
        .context("Invalid derivation path")?;

    let sol_recv_derivation_path = SolanaDerivationPath::from_absolute_path_str("m/44'/501'/0'/0")
        .context("Invalid Solana derivation path")?;

    request_funds_from_faucets(
        &mnemonic,
        root_priv_key,
        &btc_recv_derivation_path,
        sol_recv_derivation_path,
        BtcAmount::from_sat(50000),
    )?;

    let contract_id = match create_loan_contract(&mnemonic) {
        Ok(id) => id,
        Err(err) => {
            send_funds_to_faucet(root_priv_key, NETWORK, &btc_recv_derivation_path)
                .context("Failed to send funds back to faucet")?;
            return Err(err);
        }
    };

    repay_loan_contract(&mnemonic, &contract_id)?;

    wait_for_contract_to_be_closed(&mnemonic, &contract_id)?;

    info!("Contract ID: {contract_id}");

    // Return remaining funds to faucet.
    send_funds_to_faucet(root_priv_key, NETWORK, &btc_change_derivation_path)
        .context("Failed to send funds back to faucet")?;

    info!("Test completed successfully!");

    Ok(contract_id)
}

fn initialize_wallet() -> Result<(bip39::Mnemonic, Xpriv)> {
    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy).context("Failed to generate random entropy")?;

    let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
        .map_err(LavaTestError::MnemonicGeneration)
        .context("Failed to generate mnemonic")?;

    info!("Mnemonic generated");

    let root_priv_key = Xpriv::new_master(NETWORK, &mnemonic.to_seed(""))
        .context("Failed to create root private key")?;

    Ok((mnemonic, root_priv_key))
}

fn request_funds_from_faucets(
    mnemonic: &bip39::Mnemonic,
    root_priv_key: Xpriv,
    btc_recv_derivation_path: &BtcDerivationPath,
    sol_recv_derivation_path: SolanaDerivationPath,
    amount: BtcAmount,
) -> Result<(BtcTxid, SolanaSignature)> {
    let (_, btc_recv_pubkey) = derive_keypair(root_priv_key, NETWORK, btc_recv_derivation_path);

    let btc_recv_address = BtcAddress::p2wpkh(
        &bitcoin::CompressedPublicKey(btc_recv_pubkey.inner),
        NETWORK,
    );

    info!("Requesting BTC from faucet");
    let btc_recv_txid =
        get_mutinynet_btc(&btc_recv_address, amount).context("Failed to get BTC from faucet")?;

    let keypair = solana_sdk::signature::Keypair::from_seed_and_derivation_path(
        &mnemonic.to_seed(""),
        Some(sol_recv_derivation_path),
    )
    .map_err(|e| anyhow::anyhow!("Failed to derive keypair: {}", e))?;

    info!("Requesting Lava USD from faucet");
    let sol_recv_signature =
        get_test_lava_usd(keypair.pubkey()).context("Failed to get LAVA USD")?;

    info!("Bitcoin Receive TxID: {btc_recv_txid}");
    info!("Solana Receive Signature: {sol_recv_signature}");

    Ok((btc_recv_txid, sol_recv_signature))
}

fn create_loan_contract(mnemonic: &bip39::Mnemonic) -> Result<String> {
    info!("Initiating lava loan...");

    for i in 1..=MAX_RETRIES {
        if let Ok(contract_id) = lava_loans_borrower_cli_borrow(mnemonic) {
            info!("Lava loan initiated, contract ID: {contract_id}");
            return Ok(contract_id);
        }

        info!("Lava loan initiation failed. Retrying... ({i} of {MAX_RETRIES})");
        sleep(Duration::from_millis(1000));
    }

    error!("Lava loan initiation failed. Max retries reached.");
    Err(LavaTestError::LoanInitiationFailed.into())
}

fn repay_loan_contract(mnemonic: &bip39::Mnemonic, contract_id: &str) -> Result<()> {
    let mut i = 0;
    loop {
        if lava_loans_borrower_cli_repay(mnemonic, contract_id).is_ok() {
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

fn wait_for_contract_to_be_closed(
    mnemonic: &bip39::Mnemonic,
    contract_id: &str,
) -> Result<BtcTxid> {
    info!("Waiting for confirmation");

    let closed_json_object = loop {
        let contract_data = lava_loans_borrower_cli_get_contract(mnemonic, contract_id)
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

    BtcTxid::from_str(collateral_repayment_txid_str)
        .context("Failed to parse 'collateral_repayment_txid' in Lava closed contract JSON data")
}

fn get_mutinynet_btc(address: &BtcAddress, amount: BtcAmount) -> Result<BtcTxid> {
    let output = Command::new("curl")
        .arg("-X")
        .arg("POST")
        .arg("https://faucet.testnet.lava.xyz/mint-mutinynet")
        .arg("-H")
        .arg("Content-Type: application/json")
        .arg("-d")
        .arg(format!(
            "{{ \"address\": \"{address}\", \"sats\": {} }}",
            amount.to_sat()
        ))
        .output()
        .context("Failed to execute curl command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(LavaTestError::BitcoinFaucet(format!(
            "Mutinynet faucet request failed: {stderr}"
        ))
        .into());
    }

    let json_output = serde_json::Value::from_str(&String::from_utf8_lossy(&output.stdout))
        .context("Failed to parse faucet response as JSON")?;

    let txid_str = json_output
        .as_object()
        .and_then(|obj| obj.get("txid"))
        .and_then(|txid_value| txid_value.as_str())
        .ok_or_else(|| {
            let output_str = format!("{output:?}");
            LavaTestError::BitcoinFaucet(format!(
                "Failed to parse txid from Mutinynet faucet response. This likely means the faucet is down or empty. Full response:\n{output_str}"
            ))
        })?;

    BtcTxid::from_str(txid_str).context("Failed to parse 'txid' in Mutinynet faucet response")
}

fn get_test_lava_usd(pubkey: SolanaPubkey) -> Result<SolanaSignature> {
    let output = Command::new("curl")
        .arg("-X")
        .arg("POST")
        .arg("https://faucet.testnet.lava.xyz/transfer-lava-usd")
        .arg("-H")
        .arg("Content-Type: application/json")
        .arg("-d")
        .arg(format!("{{ \"pubkey\": \"{pubkey}\" }}"))
        .output()
        .context("Failed to execute curl command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(LavaTestError::SolanaFaucet(format!(
            "Lava USD faucet request failed: {stderr}"
        ))
        .into());
    }

    let json_output = serde_json::Value::from_str(&String::from_utf8_lossy(&output.stdout))
        .context("Failed to parse faucet response as JSON")?;

    let signature_str = json_output
        .as_object()
        .ok_or_else(|| {
            LavaTestError::SolanaFaucet("Solana USD faucet response is not a JSON object".into())
        })?
        .get("signature")
        .ok_or_else(|| {
            LavaTestError::SolanaFaucet(
                "Failed to find 'signature' field in Solana USD faucet response".into(),
            )
        })?
        .as_str()
        .ok_or_else(|| {
            LavaTestError::SolanaFaucet(
                "Failed to parse 'signature' in Solana USD faucet response".into(),
            )
        })?;

    SolanaSignature::from_str(signature_str)
        .context("Failed to parse 'signature' in Solana USD faucet response")
}

// Get the download URL for the current platform
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

fn install_lava_loans_borrower_cli() -> Result<()> {
    // Remove existing loans-borrower-cli if it exists.
    // This ensures we always download and run the latest version.
    if std::path::Path::new("./loans-borrower-cli").exists() {
        remove_file("./loans-borrower-cli")?;
    }

    install_dependencies();

    download_borrower_cli()?;

    make_cli_executable()?;

    info!("loans-borrower-cli installation completed");
    Ok(())
}

// Install dependencies for the borrower CLI
fn install_dependencies() {
    match std::env::consts::OS {
        "macos" => install_macos_dependencies(),
        "linux" => install_linux_dependencies(),
        _ => {} // No dependencies for other platforms
    }
}

// Install macOS dependencies
fn install_macos_dependencies() {
    info!("Installing dependencies for macOS");
    if let Err(e) = Command::new("brew").arg("install").arg("libpq").output() {
        error!("Failed to execute `brew install libpq` command: {e}");
    }
}

// Install Linux dependencies
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

// Download the borrower CLI for current platform
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

fn lava_loans_borrower_cli_borrow(mnemonic: &bip39::Mnemonic) -> Result<String> {
    let output = Command::new("./loans-borrower-cli")
        .env("MNEMONIC", mnemonic.to_string())
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

fn lava_loans_borrower_cli_repay(mnemonic: &bip39::Mnemonic, contract_id: &str) -> Result<()> {
    let output = Command::new("./loans-borrower-cli")
        .env("MNEMONIC", mnemonic.to_string())
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

fn lava_loans_borrower_cli_get_contract(
    mnemonic: &bip39::Mnemonic,
    contract_id: &str,
) -> Result<serde_json::Value> {
    let file_path = format!("./{contract_id}.json");

    Command::new("./loans-borrower-cli")
        .env("MNEMONIC", mnemonic.to_string())
        .arg("--testnet")
        .arg("--disable-backup-contracts")
        .arg("get-contract")
        .arg("--contract-id")
        .arg(contract_id)
        .arg("--verbose")
        .arg("--output-file")
        .arg(&file_path)
        .stdout(Stdio::piped())
        .output()
        .context("Failed to execute `loans-borrower-cli get-contract` command")?;

    // Using the ? operator with anyhow's context for better error handling
    let file =
        File::open(&file_path).context(format!("Failed to open contract file: {file_path}"))?;
    let reader = BufReader::new(file);
    let value = serde_json::from_reader(reader).context("Failed to parse contract JSON")?;

    // Still use unwrap here as this cleanup operation failing is not critical to the success of the function
    // If needed, we could add better error handling here too
    remove_file(&file_path).unwrap_or_else(|e| {
        info!("Failed to remove temporary contract file: {e}");
    });

    Ok(value)
}

fn derive_keypair(
    root_priv_key: Xpriv,
    network: Network,
    derivation_path: &BtcDerivationPath,
) -> (PrivateKey, BtcPublicKey) {
    let secp = Secp256k1::new();
    // We're using expect here because this function is internal and should never fail
    // with valid inputs, which we control
    let child_priv_key = root_priv_key
        .derive_priv(&secp, &derivation_path)
        .expect("Failed to derive child private key");

    let private_key = PrivateKey::new(child_priv_key.private_key, network);
    let public_key = BtcPublicKey::from_private_key(&secp, &private_key);

    (private_key, public_key)
}

fn send_funds_to_faucet(
    root_priv_key: Xpriv,
    network: Network,
    derivation_path: &BtcDerivationPath,
) -> Result<Transaction> {
    info!("Sending funds back to faucet...");

    let (btc_private_key, btc_pubkey) = derive_keypair(root_priv_key, network, derivation_path);

    let btc_address = BtcAddress::p2wpkh(&bitcoin::CompressedPublicKey(btc_pubkey.inner), NETWORK);

    let esplora_client = esplora_client::Builder::new("https://mutinynet.com/api").build_blocking();

    let mut i = 0;
    let (txo_sum, tx) = loop {
        match esplora_client.get_address_stats(&btc_address) {
            Ok(change_info) => {
                if let Ok(change_txs) = esplora_client.get_address_txs(&btc_address, None) {
                    if let Some(change_tx) = change_txs.first().cloned() {
                        if change_info.chain_stats.funded_txo_sum > 0 {
                            break (change_info.chain_stats.funded_txo_sum, change_tx);
                        }
                    }
                }
            }
            Err(e) => {
                info!("Failed to get address stats: {e}");
            }
        }

        i += 1;

        if i > MAX_RETRIES {
            return Err(LavaTestError::FundsReturnFailed(format!(
                "Failed to retrieve change transaction after {MAX_RETRIES} retries"
            ))
            .into());
        }

        sleep(Duration::from_millis(1000));
    };

    let faucet_refund_address = BtcAddress::from_str(FAUCET_REFUND_ADDRESS_STR)
        .context("Invalid faucet refund address")?
        .assume_checked();

    let (vout, _) = tx
        .vout
        .iter()
        .enumerate()
        .find(|txout| txout.1.scriptpubkey == btc_address.script_pubkey())
        .ok_or_else(|| {
            LavaTestError::FundsReturnFailed("Failed to find matching vout in transaction".into())
        })?;

    let mut faucet_funding_tx = Transaction {
        version: Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: tx.txid,
                vout: vout.try_into().context("Invalid vout index")?,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: BtcAmount::from_sat(txo_sum - MIN_RELAY_FEE),
            script_pubkey: faucet_refund_address.script_pubkey(),
        }],
    };

    let secp = Secp256k1::new();

    let mut cache = SighashCache::new(&faucet_funding_tx);
    let sighash = cache
        .p2wpkh_signature_hash(
            0,
            &btc_address.script_pubkey(),
            BtcAmount::from_sat(txo_sum),
            EcdsaSighashType::All,
        )
        .context("Sighash failed")?;

    let message = Message::from_digest_slice(&sighash[..]).context("Invalid sighash")?;

    let signature = secp.sign_ecdsa(&message, &btc_private_key.inner);
    let mut sig_with_hashtype = signature.serialize_der().to_vec();
    sig_with_hashtype.push(EcdsaSighashType::All as u8);
    faucet_funding_tx.input[0].witness.push(sig_with_hashtype);
    faucet_funding_tx.input[0]
        .witness
        .push(btc_pubkey.to_bytes());

    esplora_client
        .broadcast(&faucet_funding_tx)
        .context("Failed to broadcast transaction")?;

    info!("Funds sent back to faucet");

    Ok(faucet_funding_tx)
}
