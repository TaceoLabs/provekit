pub mod proof_schema;
pub mod proving_key;
pub mod solidity_verifier;
pub mod zkey;

use ark_ff::PrimeField;
use ark_relations::r1cs::SynthesisError;

pub(crate) fn h_query_scalars<F: PrimeField>(
    max_power: usize,
    t: F,
    zt: F,
    delta_inverse: F,
) -> Result<Vec<F>, SynthesisError> {
    let scalars = (0..max_power)
        .map(|i| zt * delta_inverse * t.pow([i as u64]))
        .collect::<Vec<_>>();
    Ok(scalars)
}
