use {
    crate::{
        witness::{NoirWitnessGenerator, WitnessBuilder},
        R1CS,
    },
    noirc_artifacts::program::ProgramArtifact,
    serde::{Deserialize, Serialize},
    std::num::NonZero,
};

/// A scheme for proving a Noir program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoirProofScheme {
    pub program:              ProgramArtifact,
    pub r1cs:                 R1CS,
    pub witness_generator:    NoirWitnessGenerator,
    pub witness_builders:     Vec<WitnessBuilder>,
    pub public_input_indices: Vec<NonZero<u32>>, // Does not include the index 0
}

impl NoirProofScheme {
    #[must_use]
    pub const fn size(&self) -> (usize, usize) {
        (self.r1cs.num_constraints(), self.r1cs.num_witnesses())
    }
}
