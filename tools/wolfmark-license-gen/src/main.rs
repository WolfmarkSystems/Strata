use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, NaiveDate, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::path::{Path, PathBuf};
use strata_license::{
    ENTERPRISE_FEATURES, FREE_FEATURES, LicenseTier, PRO_FEATURES, StrataLicense, TRIAL_FEATURES,
};

#[derive(Parser, Debug)]
#[command(name = "wolfmark-license-gen")]
#[command(about = "Internal Wolfmark license generation utility", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    GenerateKeypair,
    Issue {
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        licensee_name: String,
        #[arg(long)]
        licensee_org: String,
        #[arg(long)]
        machine_id: String,
        #[arg(long)]
        tier: TierArg,
        #[arg(long)]
        expires: Option<String>,
        #[arg(long)]
        product: String,
        #[arg(long)]
        output: PathBuf,
    },
    IssueTrial {
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        licensee_name: String,
        #[arg(long)]
        licensee_org: String,
        #[arg(long)]
        machine_id: String,
        #[arg(long)]
        days: u32,
        #[arg(long)]
        product: String,
        #[arg(long)]
        output: PathBuf,
    },
    Verify {
        #[arg(long)]
        public_key: String,
        #[arg(long)]
        license: PathBuf,
    },
    ListFeatures {
        #[arg(long)]
        tier: TierArg,
    },
}

#[derive(Clone, Debug, ValueEnum)]
enum TierArg {
    Free,
    Trial,
    Professional,
    Enterprise,
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        eprintln!("{}", err);
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Commands::GenerateKeypair => cmd_generate_keypair(),
        Commands::Issue {
            private_key,
            licensee_name,
            licensee_org,
            machine_id,
            tier,
            expires,
            product,
            output,
        } => {
            validate_machine_id(&machine_id)?;
            let signing_key = decode_private_key(&private_key)?;
            let tier = tier_to_license_tier(&tier);
            let expires_at = match expires {
                Some(value) => Some(parse_utc_date(&value)?),
                None => None,
            };

            let license = issue_license(
                &signing_key,
                &licensee_name,
                &licensee_org,
                &machine_id,
                tier,
                expires_at,
                &product,
            )?;
            write_license_file(&output, &license)?;
            verify_with_public_key(signing_key.verifying_key(), &license)?;
            print_license_summary("ISSUED", &output, &license);
            Ok(())
        }
        Commands::IssueTrial {
            private_key,
            licensee_name,
            licensee_org,
            machine_id,
            days,
            product,
            output,
        } => {
            validate_machine_id(&machine_id)?;
            if days == 0 {
                return Err("Trial days must be greater than 0".to_string());
            }

            let signing_key = decode_private_key(&private_key)?;
            let expires_at = Utc::now() + chrono::Duration::days(i64::from(days));
            let license = issue_license(
                &signing_key,
                &licensee_name,
                &licensee_org,
                &machine_id,
                LicenseTier::Trial,
                Some(expires_at),
                &product,
            )?;

            write_license_file(&output, &license)?;
            verify_with_public_key(signing_key.verifying_key(), &license)?;
            print_license_summary("TRIAL ISSUED", &output, &license);
            Ok(())
        }
        Commands::Verify {
            public_key,
            license,
        } => {
            let verifying_key = decode_public_key(&public_key)?;
            let raw = std::fs::read_to_string(&license)
                .map_err(|err| format!("Failed to read license file: {}", err))?;
            let parsed: StrataLicense = serde_json::from_str(&raw)
                .map_err(|err| format!("Malformed license JSON: {}", err))?;

            verify_with_public_key(verifying_key, &parsed)?;
            print_license_summary("VALID", &license, &parsed);
            Ok(())
        }
        Commands::ListFeatures { tier } => {
            let list = features_for_tier(&tier_to_license_tier(&tier));
            println!("Tier: {}", tier_label(&tier_to_license_tier(&tier)));
            for feature in list {
                println!("- {}", feature);
            }
            Ok(())
        }
    }
}

fn cmd_generate_keypair() -> Result<(), String> {
    let mut secret = [0u8; 32];
    let first = uuid::Uuid::new_v4();
    let second = uuid::Uuid::new_v4();
    secret[..16].copy_from_slice(first.as_bytes());
    secret[16..].copy_from_slice(second.as_bytes());

    let signing_key = SigningKey::from_bytes(&secret);
    let verifying_key = signing_key.verifying_key();

    let private_b64 = STANDARD.encode(signing_key.to_bytes());
    let public_b64 = STANDARD.encode(verifying_key.to_bytes());

    println!("PRIVATE_KEY_BASE64={}", private_b64);
    println!("PUBLIC_KEY_BASE64={}", public_b64);
    println!("Do not store private keys in this repository.");
    Ok(())
}

fn issue_license(
    signing_key: &SigningKey,
    licensee_name: &str,
    licensee_org: &str,
    machine_id: &str,
    tier: LicenseTier,
    expires_at: Option<DateTime<Utc>>,
    product: &str,
) -> Result<StrataLicense, String> {
    let mut license = StrataLicense {
        license_id: uuid::Uuid::new_v4().to_string(),
        product: product.to_string(),
        tier: tier.clone(),
        licensee_name: licensee_name.to_string(),
        licensee_org: licensee_org.to_string(),
        machine_id: machine_id.to_string(),
        issued_at: Utc::now(),
        expires_at,
        features: features_for_tier(&tier)
            .iter()
            .map(|f| (*f).to_string())
            .collect(),
        signature: String::new(),
    };

    let payload = license
        .signing_payload()
        .map_err(|err| format!("Failed to serialize license payload: {}", err))?;
    let signature = signing_key.sign(&payload);
    license.signature = STANDARD.encode(signature.to_bytes());
    Ok(license)
}

fn write_license_file(path: &Path, license: &StrataLicense) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("Failed to create output directory: {}", err))?;
    }

    let json = serde_json::to_string_pretty(license)
        .map_err(|err| format!("Failed to encode license JSON: {}", err))?;
    std::fs::write(path, json).map_err(|err| format!("Failed to write license file: {}", err))
}

fn verify_with_public_key(key: VerifyingKey, license: &StrataLicense) -> Result<(), String> {
    let signature_bytes = STANDARD
        .decode(license.signature.as_bytes())
        .map_err(|_| "INVALID: signature is not valid base64".to_string())?;

    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| "INVALID: signature bytes are malformed".to_string())?;

    let payload = license
        .signing_payload()
        .map_err(|err| format!("INVALID: payload serialization failed: {}", err))?;

    key.verify(&payload, &signature)
        .map_err(|_| "INVALID: signature verification failed".to_string())?;

    if let Some(expires_at) = license.expires_at
        && expires_at <= Utc::now()
    {
        return Err("INVALID: license has expired".to_string());
    }

    Ok(())
}

fn decode_private_key(input: &str) -> Result<SigningKey, String> {
    let bytes = STANDARD
        .decode(input.as_bytes())
        .map_err(|_| "Invalid private key format".to_string())?;

    let secret = if bytes.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    } else if bytes.len() == 64 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes[0..32]);
        out
    } else {
        return Err("Invalid private key format".to_string());
    };

    Ok(SigningKey::from_bytes(&secret))
}

fn decode_public_key(input: &str) -> Result<VerifyingKey, String> {
    let bytes = STANDARD
        .decode(input.as_bytes())
        .map_err(|_| "Invalid public key format".to_string())?;
    if bytes.len() != 32 {
        return Err("Invalid public key format".to_string());
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&key).map_err(|_| "Invalid public key format".to_string())
}

fn parse_utc_date(value: &str) -> Result<DateTime<Utc>, String> {
    let date = NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .map_err(|_| "Date must be YYYY-MM-DD format".to_string())?;

    let naive = date
        .and_hms_opt(23, 59, 59)
        .ok_or_else(|| "Date must be YYYY-MM-DD format".to_string())?;
    Ok(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
}

fn validate_machine_id(machine_id: &str) -> Result<(), String> {
    let trimmed = machine_id.trim();
    let is_hex = trimmed.chars().all(|c| c.is_ascii_hexdigit());
    if trimmed.len() != 64 || !is_hex {
        return Err("Machine ID must be 64 hex chars".to_string());
    }
    Ok(())
}

fn tier_to_license_tier(tier: &TierArg) -> LicenseTier {
    match tier {
        TierArg::Free => LicenseTier::Free,
        TierArg::Trial => LicenseTier::Trial,
        TierArg::Professional => LicenseTier::Professional,
        TierArg::Enterprise => LicenseTier::Enterprise,
    }
}

fn tier_label(tier: &LicenseTier) -> &'static str {
    match tier {
        LicenseTier::Free => "Free",
        LicenseTier::Trial => "Trial",
        LicenseTier::Professional => "Professional",
        LicenseTier::Enterprise => "Enterprise",
    }
}

fn features_for_tier(tier: &LicenseTier) -> &'static [&'static str] {
    match tier {
        LicenseTier::Free => FREE_FEATURES,
        LicenseTier::Trial => TRIAL_FEATURES,
        LicenseTier::Professional => PRO_FEATURES,
        LicenseTier::Enterprise => ENTERPRISE_FEATURES,
    }
}

fn print_license_summary(prefix: &str, output: &Path, license: &StrataLicense) {
    println!("{}: {}", prefix, output.display());
    println!("License ID: {}", license.license_id);
    println!("Product: {}", license.product);
    println!("Tier: {}", tier_label(&license.tier));
    println!(
        "Licensee: {} ({})",
        license.licensee_name, license.licensee_org
    );
    println!("Machine ID: {}", license.machine_id);
    println!(
        "Expires: {}",
        license
            .expires_at
            .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
            .unwrap_or_else(|| "Perpetual".to_string())
    );
    println!("Features: {}", license.features.len());
}
