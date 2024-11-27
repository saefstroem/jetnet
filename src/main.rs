mod types;

use axum::{routing::get, Router};
use axum_server::tls_rustls::RustlsConfig;
use dotenvy::dotenv;
use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::elliptic_curve::rand_core::OsRng;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use std::fs::{self, File};
use std::io::Write;
use std::net::{SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use types::setup::Config;

fn generate_certificate(
    cert_path: &Path,
    key_path: &Path,
    domains: Vec<String>,
) -> std::io::Result<()> {
    // Create directory if it doesn't exist
    if let Some(dir) = cert_path.parent() {
        fs::create_dir_all(dir)?;
    }
    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(domains).unwrap();

    let cert = cert.pem();
    let key_pair = key_pair.serialize_pem();

    // Save private key
    let mut key_file = File::create(key_path)?;
    key_file.write_all(key_pair.as_bytes())?;

    // Save certificate
    let mut cert_file = File::create(cert_path)?;
    cert_file.write_all(cert.as_bytes())?;

    Ok(())
}

async fn hello() -> &'static str {
    "JetNet Edge Node"
}

fn update_config(config: &Config) {
    let file = File::create("config.json").expect("Unable to create file");
    serde_json::to_writer_pretty(file, &config).expect("Unable to serialize");
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let mut config = {
        let file = std::fs::read_to_string("config.json");
        if let Ok(file) = file {
            serde_json::from_str(&file).expect("Unable to deserialize")
        } else {
            tracing::warn!("Unable to read config file. Generating default config...");
            Config::default()
        }
    };

    let public_key = {
        if let Some(public_key) = &config.pk {
            VerifyingKey::from_sec1_bytes(public_key.as_slice())
                .expect("Unable to deserialize public key")
        } else {
            tracing::warn!("Missing private key! Generating...");
            let signing_key = SigningKey::random(&mut OsRng);
            let public_key = signing_key.verifying_key();
            // Store public key in config
            config.pk = Some(public_key.to_sec1_bytes().to_vec());

            let private_key = signing_key.to_bytes();
            let serialized_private_key = serde_json::to_string(&private_key.to_vec())
                .expect("Unable to serialize private key");
            // Save private key to .env file
            let mut file = File::create(".env").expect("Unable to create .env file");
            file.write_all(format!("SK=\"{:?}\"", private_key).as_bytes())
                .expect("Unable to write .env data");

            // Set environment variable
            std::env::set_var("SK", serialized_private_key);
            update_config(&config);
            *public_key
        }
    };

    // Load private key from environment
    let private_key = {
        let private_key = std::env::var("SK");
        if let Ok(private_key) = private_key {
            let bytes = serde_json::from_str::<Vec<u8>>(&private_key)
                .expect("Unable to deserialize private key");
            SigningKey::from_bytes(bytes.as_slice().into())
                .expect("Unable to deserialize private key")
        } else {
            tracing::error!("Private key not found in environment, but a public key was found in the config file.");
            std::process::exit(1);
        }
    };

    assert_eq!(
        public_key,
        *private_key.verifying_key(),
        "Public and private keys do not match"
    );
    // Define certificate paths
    let cert_path = PathBuf::from("self_signed_certs").join("cert.pem");
    let key_path = PathBuf::from("self_signed_certs").join("key.pem");

    // Generate certificate if it doesn't exist
    if !cert_path.exists() || !key_path.exists() {
        tracing::info!("Generating self-signed certificate...");
        if let Err(e) = generate_certificate(&cert_path, &key_path, config.domains.clone()) {
            tracing::error!("Failed to generate certificate: {}", e);
            std::process::exit(1);
        }
        tracing::info!("Certificate generated successfully");
    } else {
        tracing::info!("Using existing certificate");
    }

    let handle = axum_server::Handle::new();

    // Resolve address
    let addr = SocketAddr::from(
        format!("{}:{}", &config.host, &config.port)
            .parse::<SocketAddrV4>()
            .unwrap(),
    );

    // Configure TLS
    let tls_config = RustlsConfig::from_pem_file(&cert_path, &key_path)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Failed to load TLS configuration: {}", e);
            std::process::exit(1);
        });

    let locked_config = Arc::new(RwLock::new(config));

    let app = Router::new()
        .route("/", get(hello))
        .with_state(locked_config);

    tracing::info!("listening on {addr}");

    axum_server::bind_rustls(addr, tls_config)
        .handle(handle)
        .serve(app.into_make_service())
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Server error: {}", e);
            std::process::exit(1);
        });
}
