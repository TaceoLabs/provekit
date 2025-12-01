#[cfg(test)]
use anyhow::{ensure, Result};
use co_acvm::{Rep3AcvmSolver, Rep3AcvmType};
use mpc_core::protocols::rep3::Rep3PrimeFieldShare;
use mpc_net::Network;
use provekit_common::witness::MockTranscript;
use {
    crate::witness::witness_builder::WitnessBuilderSolver,
    acir::native_types::WitnessMap,
    provekit_common::{witness::WitnessBuilder, FieldElement, NoirElement, R1CS},
    tracing::instrument,
};

pub trait R1CSSolver {
    fn solve_witness_vec(
        &self,
        witness_builder_vec: &[WitnessBuilder],
        acir_map: &WitnessMap<NoirElement>,
        transcript: &mut MockTranscript,
    ) -> Vec<Option<FieldElement>>;

    #[cfg(test)]
    fn test_witness_satisfaction(&self, witness: &[FieldElement]) -> Result<()>;

    fn solve_witness_vec_rep3<N: Network>(
        &self,
        witness_builder_vec: &[WitnessBuilder],
        acir_witness_idx_to_value_map: &WitnessMap<Rep3AcvmType<FieldElement>>,
        driver: &mut Rep3AcvmSolver<FieldElement, N>,
    ) -> eyre::Result<Vec<Option<Rep3AcvmType<FieldElement>>>>;

    fn solve_witness_vec_rep3_with_bitdecomp_witness<N: Network>(
        &self,
        witness_builder_vec: &[WitnessBuilder],
        acir_witness_idx_to_value_map: &WitnessMap<Rep3AcvmType<FieldElement>>,
        bitdecomps: Vec<Rep3PrimeFieldShare<FieldElement>>,
        driver: &mut Rep3AcvmSolver<FieldElement, N>,
    ) -> eyre::Result<Vec<Option<Rep3AcvmType<FieldElement>>>>;
}

impl R1CSSolver for R1CS {
    /// Solves the R1CS witness vector using layered execution with batch
    /// inversion.
    ///
    /// Executes witness builders in segments: each segment consists of a PRE
    /// phase (non-inverse operations) followed by a batch inversion phase.
    /// This approach minimizes expensive field inversions by batching them
    /// using Montgomery's trick.
    ///
    /// # Algorithm
    ///
    /// For each segment:
    /// 1. Execute all PRE builders (non-inverse operations) serially
    /// 2. Collect denominators from pending inverse operations
    /// 3. Perform batch inversion using Montgomery's algorithm
    /// 4. Write inverse results to witness vector
    ///
    /// # Panics
    ///
    /// Panics if a denominator witness is not set when needed for inversion.
    /// This indicates a bug in the layer scheduling algorithm.
    #[instrument(skip_all)]
    fn solve_witness_vec(
        &self,
        witness_builder_vec: &[WitnessBuilder],
        acir_witness_idx_to_value_map: &WitnessMap<NoirElement>,
        transcript: &mut MockTranscript,
    ) -> Vec<Option<FieldElement>> {
        let mut witness = vec![None; self.num_witnesses()];
        witness_builder_vec.iter().for_each(|witness_builder| {
            witness_builder.solve_and_append_to_transcript(
                acir_witness_idx_to_value_map,
                &mut witness,
                transcript,
            );
        });
        witness
    }

    // Tests R1CS Witness satisfaction given the constraints provided by the
    // R1CS Matrices.
    #[cfg(test)]
    #[instrument(skip_all, fields(size = witness.len()))]
    fn test_witness_satisfaction(&self, witness: &[FieldElement]) -> Result<()> {
        ensure!(
            witness.len() == self.num_witnesses(),
            "Witness size does not match"
        );

        // Verify
        let a = self.a() * witness;
        let b = self.b() * witness;
        let c = self.c() * witness;
        for (row, ((a, b), c)) in a
            .into_iter()
            .zip(b.into_iter())
            .zip(c.into_iter())
            .enumerate()
        {
            ensure!(a * b == c, "Constraint {row} failed");
        }
        Ok(())
    }

    fn solve_witness_vec_rep3<N: Network>(
        &self,
        witness_builder_vec: &[WitnessBuilder],
        acir_witness_idx_to_value_map: &WitnessMap<Rep3AcvmType<FieldElement>>,
        driver: &mut Rep3AcvmSolver<FieldElement, N>,
    ) -> eyre::Result<Vec<Option<Rep3AcvmType<FieldElement>>>> {
        let mut witness = vec![None; self.num_witnesses()];
        for witness_builder in witness_builder_vec.iter() {
            witness_builder.solve_rep3(acir_witness_idx_to_value_map, &mut witness, driver)?;
        }
        Ok(witness)
    }

    fn solve_witness_vec_rep3_with_bitdecomp_witness<N: Network>(
        &self,
        witness_builder_vec: &[WitnessBuilder],
        acir_witness_idx_to_value_map: &WitnessMap<Rep3AcvmType<FieldElement>>,
        bitdecomps: Vec<Rep3PrimeFieldShare<FieldElement>>,
        driver: &mut Rep3AcvmSolver<FieldElement, N>,
    ) -> eyre::Result<Vec<Option<Rep3AcvmType<FieldElement>>>> {
        let mut bitdecomps_iter = bitdecomps.into_iter();
        let mut witness = vec![None; self.num_witnesses()];
        for witness_builder in witness_builder_vec.iter() {
            witness_builder.solve_rep3_with_bitdecomp_witness(
                acir_witness_idx_to_value_map,
                &mut witness,
                &mut bitdecomps_iter,
                driver,
            )?;
        }
        assert!(
            bitdecomps_iter.next().is_none(),
            "Too many bit decomposition witnesses provided"
        );
        Ok(witness)
    }
}
