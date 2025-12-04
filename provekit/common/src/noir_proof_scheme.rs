use {
    crate::{witness::NoirWitnessGenerator, NoirElement, R1CS},
    acir::circuit::Program,
    serde::{Deserialize, Serialize},
};

/// A scheme for proving a Noir program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoirProofScheme {
    pub program:           Program<NoirElement>,
    pub r1cs:              R1CS,
    pub witness_generator: NoirWitnessGenerator,
}

impl NoirProofScheme {
    #[must_use]
    pub const fn size(&self) -> (usize, usize) {
        (self.r1cs.num_constraints(), self.r1cs.num_witnesses())
    }
}
