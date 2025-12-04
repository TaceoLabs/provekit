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
    acir::FieldElement as NoirElement, noir_proof_scheme::NoirProofScheme, r1cs::R1CS,
    whir::crypto::fields::Field256 as FieldElement,
};

#[cfg(test)]
mod tests {}
