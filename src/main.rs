use std::process::Stdio;
use std::{process::Command, str::FromStr};

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::key::Secp256k1;
use bitcoin::{
    Address as BtcAddress, Amount as BtcAmount, Network, PrivateKey, PublicKey as BtcPublicKey,
    Txid as BtcTxid,
};
use rand::Rng;
use solana_sdk::pubkey::Pubkey as SolanaPubkey;
use solana_sdk::signature::Signature as SolanaSignature;
use solana_sdk::signer::{SeedDerivable, Signer};

fn main() {
    let mut entropy = [0u8; 32];
    let mut rng = rand::rng();
    rng.fill(&mut entropy);

    let mnemonic = bip39::Mnemonic::from_entropy(&entropy).expect("Failed to generate mnemonic");

    println!("Mnemonic: {}", mnemonic);

    let network = Network::Testnet4;
    let root_priv_key = Xpriv::new_master(network, &mnemonic.to_seed(""))
        .expect("Failed to create root private key");

    let derivation_path = "m/84'/1'/0'/0/0"
        .parse::<DerivationPath>()
        .expect("Invalid derivation path");
    let secp = Secp256k1::new();
    let child_priv_key = root_priv_key
        .derive_priv(&secp, &derivation_path)
        .expect("Failed to derive child private key");

    let public_key = BtcPublicKey::from_private_key(
        &secp,
        &PrivateKey::new(child_priv_key.private_key, network),
    );
    let address = BtcAddress::p2wpkh(&bitcoin::CompressedPublicKey(public_key.inner), network);

    let txid = get_mutinynet_btc(address, BtcAmount::from_sat(50000));

    let derivation_path =
        solana_sdk::derivation_path::DerivationPath::from_absolute_path_str("m/44'/501'/0'/0")
            .expect("Invalid derivation path");
    let keypair = solana_sdk::signature::Keypair::from_seed_and_derivation_path(
        &mnemonic.to_seed(""),
        Some(derivation_path),
    )
    .expect("Failed to derive keypair");

    let signature = get_test_lava_usd(keypair.pubkey());

    println!("Transaction ID: {}", txid);
    println!("Signature: {}", signature);

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
            panic!(
                "Unable to parse contract ID from lava borrow command after {MAX_RETRIES} retries"
            );
        }

        println!("Lava loan initiation failed. Retrying... ({i} of {MAX_RETRIES})");
    };

    println!("Contract ID: {:?}", contract_id);
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
