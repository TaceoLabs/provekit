pub mod poseidon2;
pub mod poseidon2_rep3;

use ark_ff::PrimeField;
use co_acvm::Rep3AcvmType;
use mpc_core::protocols::rep3::{Rep3PrimeFieldShare, Rep3State};
use mpc_net::Network;

pub trait TraceHasher<F: PrimeField>: Default {
    fn hash(&self, data: [F; 2]) -> F;
    fn hash_generate_noir_trace(&self, data: [F; 2]) -> (F, Vec<F>);
    fn num_multiplications(&self) -> usize;
    fn num_rounds(&self) -> usize;
}

pub trait MpcTraceHasher<F: PrimeField>: TraceHasher<F> {
    type Precomputation;

    fn precompute_rep3<N: Network>(
        &self,
        num_poseidon: usize,
        net: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<Self::Precomputation>;

    fn hash_rep3<N: Network>(
        &self,
        data: [Rep3PrimeFieldShare<F>; 2],
        precomp: &mut Self::Precomputation,
        net: &N,
    ) -> eyre::Result<Rep3PrimeFieldShare<F>>;

    fn hash_rep3_generate_noir_trace<N: Network>(
        &self,
        data: [Rep3PrimeFieldShare<F>; 2],
        precomp: &mut Self::Precomputation,
        net: &N,
    ) -> eyre::Result<(Rep3PrimeFieldShare<F>, Vec<Rep3AcvmType<F>>)>;

    // L is the number of hashes we want to compute, L2 = 2 * L the size of the input array
    #[expect(clippy::type_complexity)]
    fn hash_rep3_generate_noir_trace_many<N: Network, const L: usize, const L2: usize>(
        &self,
        data: [Rep3PrimeFieldShare<F>; L2],
        precomp: &mut Self::Precomputation,
        net: &N,
    ) -> eyre::Result<([Rep3PrimeFieldShare<F>; L], [Vec<Rep3AcvmType<F>>; L])>;

    // Same as hash_rep3_generate_noir_trace_many but works on vectors instead of arrays
    #[expect(clippy::type_complexity)]
    fn hash_rep3_generate_noir_trace_vec<N: Network>(
        &self,
        data: Vec<Rep3PrimeFieldShare<F>>,
        precomp: &mut Self::Precomputation,
        net: &N,
    ) -> eyre::Result<(Vec<Rep3PrimeFieldShare<F>>, Vec<Vec<Rep3AcvmType<F>>>)>;
}
