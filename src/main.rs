use std::fs::{File, remove_file};
use std::io::BufReader;
use std::process::{Output, Stdio};
use std::{process::Command, str::FromStr};

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::Message;
use bitcoin::sighash::SighashCache;
use bitcoin::transaction::Version;
use bitcoin::{
    Address as BtcAddress, Amount as BtcAmount, EcdsaSighashType, Network, OutPoint, PrivateKey,
    PublicKey as BtcPublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid as BtcTxid,
    Witness,
};
use rand::Rng;
use solana_sdk::pubkey::Pubkey as SolanaPubkey;
use solana_sdk::signature::Signature as SolanaSignature;
use solana_sdk::signer::{SeedDerivable, Signer};

const NETWORK: Network = Network::Testnet4;
const FAUCET_REFUND_ADDRESS_STR: &str = "tb1qd8cg49sy99cln5tq2tpdm7xs4p9s5v6le4jx4c";
const MIN_RELAY_FEE: u64 = 110;

fn main() {
    let mut entropy = [0u8; 32];
    let mut rng = rand::rng();
    rng.fill(&mut entropy);

    let mnemonic = bip39::Mnemonic::from_entropy(&entropy).expect("Failed to generate mnemonic");

    println!("Mnemonic: {}", mnemonic);

    let root_priv_key = Xpriv::new_master(NETWORK, &mnemonic.to_seed(""))
        .expect("Failed to create root private key");

    let (_, btc_recv_pubkey) = derive_keypair(
        root_priv_key,
        NETWORK,
        "m/84'/1'/0'/0/0"
            .parse::<DerivationPath>()
            .expect("Invalid derivation path"),
    );

    let btc_recv_address = BtcAddress::p2wpkh(
        &bitcoin::CompressedPublicKey(btc_recv_pubkey.inner),
        NETWORK,
    );

    let btc_recv_txid = get_mutinynet_btc(btc_recv_address, BtcAmount::from_sat(50000));

    let derivation_path =
        solana_sdk::derivation_path::DerivationPath::from_absolute_path_str("m/44'/501'/0'/0")
            .expect("Invalid derivation path");
    let keypair = solana_sdk::signature::Keypair::from_seed_and_derivation_path(
        &mnemonic.to_seed(""),
        Some(derivation_path),
    )
    .expect("Failed to derive keypair");

    let sol_recv_signature = get_test_lava_usd(keypair.pubkey());

    println!("Bitcoin Receive TxID: {}", btc_recv_txid);
    println!("Solana Receive Signature: {}", sol_recv_signature);

    install_lava_loans_borrower_cli();

    println!("Initiating lava loan...");
    const MAX_RETRIES: i32 = 5;
    let mut i = 0;
    let contract_id = loop {
        let contract_id_or = lava_loans_borrower_cli_borrow(&mnemonic);

        if let Some(contract_id) = contract_id_or {
            break contract_id;
        }

        i += 1;

        if i > MAX_RETRIES {
            println!(
                "Lava loan initiation failed. Max retries reached. Sending funds back to faucet..."
            );
            send_funds_to_faucet(
                root_priv_key,
                NETWORK,
                "m/84'/1'/0'/0/0"
                    .parse::<DerivationPath>()
                    .expect("Invalid derivation path"),
            );
            println!("Funds sent back to faucet.");

            std::process::exit(1);
        }

        println!("Lava loan initiation failed. Retrying... ({i} of {MAX_RETRIES})");
    };

    let mut i = 0;
    loop {
        if lava_loans_borrower_cli_repay(&mnemonic, &contract_id).is_ok() {
            break;
        }

        i += 1;

        if i > MAX_RETRIES {
            panic!("Unable to repay lava loan after {MAX_RETRIES} retries");
        }

        println!("Lava loan repayment failed. Retrying... ({i} of {MAX_RETRIES})");
    }

    let closed_json_object = loop {
        if let Some(closed_json) = lava_loans_borrower_cli_get_contract(&mnemonic, &contract_id)
            .as_object()
            .unwrap()
            .get("Closed")
        {
            break closed_json.as_object().unwrap().clone();
        }
    };

    let collateral_repayment_txid = closed_json_object
        .get("outcome")
        .unwrap()
        .as_object()
        .unwrap()
        .get("repayment")
        .unwrap()
        .as_object()
        .unwrap()
        .get("collateral_repayment_txid")
        .unwrap()
        .as_str()
        .unwrap();

    println!("Contract ID: {:?}", contract_id);
    println!("Collateral Repayment TxID: {:?}", collateral_repayment_txid);

    println!("Sending funds back to faucet...");
    send_funds_to_faucet(
        root_priv_key,
        NETWORK,
        "m/84'/1'/0'/1/0"
            .parse::<DerivationPath>()
            .expect("Invalid derivation path"),
    );
    println!("Funds sent back to faucet.");
}

fn get_mutinynet_btc(address: BtcAddress, amount: BtcAmount) -> BtcTxid {
    let output = Command::new("curl")
        .arg("-X")
        .arg("POST")
        .arg("https://faucet.testnet.lava.xyz/mint-mutinynet")
        .arg("-H")
        .arg("Content-Type: application/json")
        .arg("-d")
        .arg(format!(
            "{{ \"address\": \"{}\", \"sats\": {} }}",
            address,
            amount.to_sat()
        ))
        .output()
        .expect("Failed to execute curl command");

    let json_output =
        serde_json::Value::from_str(&String::from_utf8_lossy(&output.stdout)).unwrap();

    let txid_str = json_output
        .as_object()
        .expect("Mutinynet faucet response is not a JSON object")
        .get("txid")
        .expect("Failed to find 'txid' field in Mutinynet faucet response")
        .as_str()
        .expect("Failed to parse 'txid' in Mutinynet faucet response");

    BtcTxid::from_str(txid_str).expect("Failed to parse 'txid' in Mutinynet faucet response")
}

fn get_test_lava_usd(pubkey: SolanaPubkey) -> SolanaSignature {
    let output = Command::new("curl")
        .arg("-X")
        .arg("POST")
        .arg("https://faucet.testnet.lava.xyz/transfer-lava-usd")
        .arg("-H")
        .arg("Content-Type: application/json")
        .arg("-d")
        .arg(format!("{{ \"pubkey\": \"{}\" }}", pubkey))
        .output()
        .expect("Failed to execute curl command");

    let json_output =
        serde_json::Value::from_str(&String::from_utf8_lossy(&output.stdout)).unwrap();

    let signature_str = json_output
        .as_object()
        .expect("Solana USD faucet response is not a JSON object")
        .get("signature")
        .expect("Failed to find 'signature' field in Solana USD faucet response")
        .as_str()
        .expect("Failed to parse 'signature' in Solana USD faucet response");

    SolanaSignature::from_str(signature_str)
        .expect("Failed to parse 'signature' in Solana USD faucet response")
}

fn install_lava_loans_borrower_cli() {
    let _ = Command::new("brew")
        .arg("install")
        .arg("libpq")
        .output()
        .expect("Failed to execute `brew install libpq` command");

    let _ = Command::new("curl")
        .arg("-o")
        .arg("loans-borrower-cli")
        .arg("https://loans-borrower-cli.s3.amazonaws.com/loans-borrower-cli-mac")
        .output()
        .expect("Failed to install loans-borrower-cli");

    let _ = Command::new("chmod")
        .arg("+x")
        .arg("./loans-borrower-cli")
        .output()
        .expect("Failed to execute `chmod +x loans-borrower-cli` command");
}

fn lava_loans_borrower_cli_borrow(mnemonic: &bip39::Mnemonic) -> Option<String> {
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
        .expect("Failed to execute `loans-borrower-cli borrow` command");

    let re = regex::Regex::new(r"New contract ID: ([0-9a-f]{64})\n").unwrap();

    // TODO: Figure out why we have to check stderr rather than stdout.
    re.captures(&String::from_utf8_lossy(&output.stderr))
        .map(|caps| caps.get(1).map(|m| m.as_str().to_string()))?
}

fn lava_loans_borrower_cli_repay(
    mnemonic: &bip39::Mnemonic,
    contract_id: &str,
) -> Result<(), Output> {
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
        .expect("Failed to execute `loans-borrower-cli borrow` command");

    if String::from_utf8_lossy(&output.stderr).contains("The collateral has been reclaimed!") {
        Ok(())
    } else {
        Err(output)
    }
}

fn lava_loans_borrower_cli_get_contract(
    mnemonic: &bip39::Mnemonic,
    contract_id: &str,
) -> serde_json::Value {
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
        .expect("Failed to execute `loans-borrower-cli borrow` command");

    let file = File::open(&file_path).expect("Failed to open file");
    let reader = BufReader::new(file);
    let value = serde_json::from_reader(reader).expect("Failed to parse JSON");
    remove_file(&file_path).unwrap();

    value
}

fn derive_keypair(
    root_priv_key: Xpriv,
    network: Network,
    derivation_path: DerivationPath,
) -> (PrivateKey, BtcPublicKey) {
    let secp = Secp256k1::new();
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
    derivation_path: DerivationPath,
) -> Transaction {
    let (btc_private_key, btc_pubkey) = derive_keypair(root_priv_key, network, derivation_path);

    let btc_address = BtcAddress::p2wpkh(&bitcoin::CompressedPublicKey(btc_pubkey.inner), NETWORK);

    let esplora_client = esplora_client::Builder::new("https://mutinynet.com/api").build_blocking();

    const MAX_RETRIES: i32 = 5;
    let mut i = 0;
    let (txo_sum, tx) = loop {
        let change_info = esplora_client.get_address_stats(&btc_address).unwrap();

        if let Ok(change_txs) = esplora_client.get_address_txs(&btc_address, None) {
            if let Some(change_tx) = change_txs.first().cloned() {
                if change_info.chain_stats.funded_txo_sum > 0 {
                    break (change_info.chain_stats.funded_txo_sum, change_tx);
                }
            }
        }

        i += 1;

        if i > MAX_RETRIES {
            panic!(
                "Failed to retrieve change transaction after {} retries",
                MAX_RETRIES
            );
        }
    };

    let faucet_refund_address = BtcAddress::from_str(FAUCET_REFUND_ADDRESS_STR)
        .unwrap()
        .assume_checked();

    let (vout, _) = tx
        .vout
        .iter()
        .enumerate()
        .find(|txout| txout.1.scriptpubkey == btc_address.script_pubkey())
        .unwrap();

    let mut faucet_funding_tx = Transaction {
        version: Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: tx.txid,
                vout: vout as u32,
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
        .expect("Sighash failed");
    let message = Message::from_digest_slice(&sighash[..]).expect("Invalid sighash");
    let signature = secp.sign_ecdsa(&message, &btc_private_key.inner);
    let mut sig_with_hashtype = signature.serialize_der().to_vec();
    sig_with_hashtype.push(EcdsaSighashType::All as u8);
    faucet_funding_tx.input[0].witness.push(sig_with_hashtype);
    faucet_funding_tx.input[0]
        .witness
        .push(btc_pubkey.to_bytes());

    // Publish transaction.
    esplora_client.broadcast(&faucet_funding_tx).unwrap();

    faucet_funding_tx
}
