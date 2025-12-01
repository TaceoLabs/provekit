pub mod file;
mod interner;
mod noir_proof_scheme;
mod r1cs;
mod sparse_matrix;
pub mod utils;
pub mod witness;

use crate::{
    interner::{InternedFieldElement, Interner},
    sparse_matrix::{HydratedSparseMatrix, SparseMatrix},
};
pub use {
    acir::FieldElement as NoirElement, ark_bn254::Fr as FieldElement,
    noir_proof_scheme::NoirProofScheme, r1cs::R1CS,
};

#[cfg(test)]
mod tests {}
