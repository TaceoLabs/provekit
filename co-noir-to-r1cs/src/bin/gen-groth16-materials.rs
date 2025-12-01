use std::{path::PathBuf, process::ExitCode};

use ark_serialize::CanonicalSerialize;
use circom_types::groth16::ConstraintMatricesWrapper;
use clap::Parser;
use co_noir_to_r1cs::{
    circom::solidity_verifier,
    noir::{r1cs, ultrahonk},
};

#[derive(Parser, Debug)]
pub struct Config {
    /// The path to the noir program artifact
    #[clap(long, env = "PROGRAM_ARTIFACT")]
    pub program_artifact: PathBuf,

    /// Output path to the matrices file.
    #[clap(long, env = "MATRICES_PATH", default_value = "matrices.bin")]
    pub matrices_path: PathBuf,

    /// Output path to the proving key file.
    #[clap(long, env = "PROVING_KEY_PATH", default_value = "pk.bin")]
    pub pk_path: PathBuf,

    /// Output path to proof schema file
    #[clap(long, env = "PROOF_SCHEMA_PATH", default_value = "proof_schema.json")]
    pub proof_schema_path: PathBuf,

    /// Output path to the solidity verifier
    #[clap(
        long,
        env = "SOLIDITY_VERIFIER_PATH",
        default_value = "Groth16Verifier.sol"
    )]
    pub solidity_verifier_path: PathBuf,

    /// Use uncompressed serialization
    #[clap(long, env = "UNCOMPRESSED")]
    pub uncompressed: bool,
}

fn main() -> eyre::Result<ExitCode> {
    let config = Config::parse();
    let mut rng = rand::thread_rng();

    let program = ultrahonk::get_program_artifact(&config.program_artifact)?;
    let (proof_schema, pk, cs) = r1cs::setup_r1cs(program, &mut rng)?;

    let proof_schema_bytes = serde_json::to_vec(&proof_schema)?;
    std::fs::write(&config.proof_schema_path, proof_schema_bytes)?;
    tracing::info!(
        "serialized proof schema to {}",
        config.proof_schema_path.display()
    );

    let mode = if config.uncompressed {
        ark_serialize::Compress::No
    } else {
        ark_serialize::Compress::Yes
    };

    let mut pk_bytes = Vec::new();
    pk.serialize_with_mode(&mut pk_bytes, mode)?;
    std::fs::write(&config.pk_path, pk_bytes)?;
    tracing::info!("serialized pk to {}", config.proof_schema_path.display());

    let mut matrices_bytes = Vec::new();
    ConstraintMatricesWrapper(cs).serialize_with_mode(&mut matrices_bytes, mode)?;
    std::fs::write(&config.matrices_path, matrices_bytes)?;
    tracing::info!(
        "serialized matrices to {}",
        config.proof_schema_path.display()
    );

    let mut solidity_verifier_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&config.solidity_verifier_path)?;
    solidity_verifier::export_solidity_verifier(&pk.vk, &mut solidity_verifier_file)?;
    tracing::info!(
        "wrote solidity verifier to {}",
        config.solidity_verifier_path.display()
    );

    Ok(ExitCode::SUCCESS)
}
