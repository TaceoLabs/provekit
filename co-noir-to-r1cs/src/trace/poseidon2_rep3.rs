use std::array;

use ark_ff::PrimeField;
use co_acvm::Rep3AcvmType;
use itertools::izip;
use mpc_core::{
    gadgets::poseidon2::{Poseidon2, Poseidon2Precomputations},
    protocols::rep3::{self, id::PartyID, Rep3PrimeFieldShare, Rep3State},
};
use mpc_net::Network;

use crate::trace::MpcTraceHasher;

fn sbox_rep3_precomp_post_with_noir_trace<F: PrimeField>(
    y: F,
    precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
    precomp_offset: usize,
    trace: &mut Vec<Rep3AcvmType<F>>,
    id: PartyID,
) -> Rep3PrimeFieldShare<F> {
    let (r, r2, r3, r4, r5) = precomp.get(precomp_offset);

    let y2 = y.square();
    let y3 = y2 * y;
    let y4 = y2.square();
    let five = F::from(5u64);
    let ten = F::from(10u64);
    let two = F::from(2u64);
    let four = F::from(4u64);
    let six = F::from(6u64);

    // Trace
    let input = rep3::arithmetic::add_public(*r, y, id);
    let input_square = rep3::arithmetic::add_public(*r2 + r * y * two, y2, id);
    let input_quad =
        rep3::arithmetic::add_public(*r4 + *r3 * y * four + r2 * y2 * six + r * y3 * four, y4, id);
    trace.push(input.into());
    trace.push(input_square.into());
    trace.push(input_quad.into());

    let mut res = *r5;
    res += r4 * (five * y);
    res += r3 * (ten * y2);
    res += r2 * (ten * y3);
    res += r * (five * y4);

    if id == PartyID::ID0 {
        let y5 = y4 * y;
        res.a += y5;
    } else if id == PartyID::ID1 {
        let y5 = y4 * y;
        res.b += y5;
    }
    res
}

fn sbox_rep3_precomp_with_noir_trace<F: PrimeField, N: Network>(
    input: &mut [Rep3PrimeFieldShare<F>],
    precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
    traces: &mut [Vec<Rep3AcvmType<F>>],
    net: &N,
) -> eyre::Result<()> {
    let num_parallel = traces.len();
    assert_eq!(input.len() % num_parallel, 0);
    let statesize = input.len() / num_parallel;
    let offset = precomp.get_offset();

    for (i, inp) in input.iter_mut().enumerate() {
        *inp -= *precomp.get_r(offset + i);
    }

    // Open
    let y = rep3::arithmetic::open_vec(input, net)?;
    let id = PartyID::try_from(net.id())?;

    let mut count = 0;
    for (inp, y, trace) in izip!(
        input.chunks_exact_mut(statesize),
        y.chunks_exact(statesize),
        traces.iter_mut()
    ) {
        for (inp, y) in inp.iter_mut().zip(y) {
            *inp = sbox_rep3_precomp_post_with_noir_trace(*y, precomp, offset + count, trace, id);
            count += 1;
        }
    }

    precomp.increment_offset(input.len());

    Ok(())
}

fn single_sbox_rep3_precomp_with_noir_trace<F: PrimeField, N: Network>(
    input: &mut Rep3PrimeFieldShare<F>,
    precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
    trace: &mut Vec<Rep3AcvmType<F>>,
    net: &N,
) -> eyre::Result<()> {
    let offset = precomp.get_offset();

    *input -= *precomp.get_r(offset);

    // Open
    let y = rep3::arithmetic::open(*input, net)?;
    let id = PartyID::try_from(net.id())?;

    *input = sbox_rep3_precomp_post_with_noir_trace(y, precomp, offset, trace, id);

    precomp.increment_offset(1);

    Ok(())
}

fn single_sbox_rep3_precomp_packed_with_noir_trace<F: PrimeField, const T: usize, N: Network>(
    input: &mut [Rep3PrimeFieldShare<F>],
    precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
    traces: &mut [Vec<Rep3AcvmType<F>>],
    net: &N,
) -> eyre::Result<()> {
    debug_assert_eq!(input.len() % T, 0);
    let mut vec = input.iter().cloned().step_by(T).collect::<Vec<_>>();
    sbox_rep3_precomp_with_noir_trace(&mut vec, precomp, traces, net)?;

    for (inp, r) in input.iter_mut().step_by(T).zip(vec) {
        *inp = r;
    }

    Ok(())
}

fn add_rc_external_packed<F: PrimeField, const T: usize, const D: u64>(
    poseidon2: &Poseidon2<F, T, D>,
    state: &mut [Rep3PrimeFieldShare<F>],
    r: usize,
    id: PartyID,
) {
    assert_eq!(state.len() % T, 0);
    if id == PartyID::ID0 {
        for state in state.chunks_exact_mut(T) {
            for (s, rc) in state
                .iter_mut()
                .zip(poseidon2.params.round_constants_external[r].iter())
            {
                s.a += rc;
            }
        }
    } else if id == PartyID::ID1 {
        for state in state.chunks_exact_mut(T) {
            for (s, rc) in state
                .iter_mut()
                .zip(poseidon2.params.round_constants_external[r].iter())
            {
                s.b += rc;
            }
        }
    }
}

fn add_rc_internal_packed<F: PrimeField, const T: usize, const D: u64>(
    poseidon2: &Poseidon2<F, T, D>,
    state: &mut [Rep3PrimeFieldShare<F>],
    r: usize,
    id: PartyID,
) {
    if id == PartyID::ID0 {
        for s in state.chunks_exact_mut(T) {
            s[0].a += poseidon2.params.round_constants_internal[r];
        }
    } else if id == PartyID::ID1 {
        for s in state.chunks_exact_mut(T) {
            s[0].b += poseidon2.params.round_constants_internal[r];
        }
    }
}

impl<F: PrimeField> MpcTraceHasher<F> for Poseidon2<F, 2, 5> {
    type Precomputation = Poseidon2Precomputations<Rep3PrimeFieldShare<F>>;

    fn precompute_rep3<N: Network>(
        &self,
        num_poseidon: usize,
        net: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<Self::Precomputation> {
        self.precompute_rep3(num_poseidon, net, rep3_state)
    }

    fn hash_rep3<N: Network>(
        &self,
        mut data: [Rep3PrimeFieldShare<F>; 2],
        precomp: &mut Self::Precomputation,
        net: &N,
    ) -> eyre::Result<Rep3PrimeFieldShare<F>> {
        let left = data[0];
        self.rep3_permutation_in_place_with_precomputation(&mut data, precomp, net)?;
        Ok(data[0] + left)
    }

    fn hash_rep3_generate_noir_trace<N: Network>(
        &self,
        data: [Rep3PrimeFieldShare<F>; 2],
        precomp: &mut Self::Precomputation,
        net: &N,
    ) -> eyre::Result<(Rep3PrimeFieldShare<F>, Vec<Rep3AcvmType<F>>)> {
        let witness_size = 3 * self.num_sbox() + self.num_rounds();
        let mut trace = [Vec::with_capacity(witness_size)];
        let mut state = data;
        let left = state[0];

        let offset = precomp.get_offset();
        let id = PartyID::try_from(net.id())?;

        // Linear layer at beginning
        Self::matmul_external_rep3(&mut state);

        // First set of external rounds
        for r in 0..self.params.rounds_f_beginning {
            self.add_rc_external_rep3(&mut state, r, id);
            sbox_rep3_precomp_with_noir_trace(&mut state, precomp, &mut trace, net)?;
            trace[0].push(state[0].into());
            Self::matmul_external_rep3(&mut state);
        }

        // Internal rounds
        for r in 0..self.params.rounds_p {
            let id = PartyID::try_from(net.id())?;
            if id == PartyID::ID0 {
                state[0].a += self.params.round_constants_internal[r];
            } else if id == PartyID::ID1 {
                state[0].b += self.params.round_constants_internal[r];
            }
            single_sbox_rep3_precomp_with_noir_trace(&mut state[0], precomp, &mut trace[0], net)?;
            trace[0].push(state[1].into());
            self.matmul_internal_rep3(&mut state);
        }

        // Remaining external rounds
        for r in self.params.rounds_f_beginning
            ..self.params.rounds_f_beginning + self.params.rounds_f_end
        {
            self.add_rc_external_rep3(&mut state, r, id);
            sbox_rep3_precomp_with_noir_trace(&mut state, precomp, &mut trace, net)?;
            trace[0].push(state[0].into());
            Self::matmul_external_rep3(&mut state);
        }

        let [trace] = trace;
        debug_assert_eq!(trace.len(), witness_size);
        debug_assert_eq!(precomp.get_offset() - offset, self.num_sbox());

        Ok((state[0] + left, trace))
    }

    // L is the number of hashes we want to compute, L2 = 2 * L the size of the input array
    fn hash_rep3_generate_noir_trace_many<N: Network, const L: usize, const L2: usize>(
        &self,
        data: [Rep3PrimeFieldShare<F>; L2],
        precomp: &mut Self::Precomputation,
        net: &N,
    ) -> eyre::Result<([Rep3PrimeFieldShare<F>; L], [Vec<Rep3AcvmType<F>>; L])> {
        const T: usize = 2;
        assert_eq!(L2, T * L);
        let witness_size = 3 * self.num_sbox() + self.num_rounds();
        let mut traces = array::from_fn(|_| Vec::with_capacity(witness_size));
        let mut state = data;
        let mut left: [_; L] = array::from_fn(|i| state[i * T]);

        let offset = precomp.get_offset();
        let id = PartyID::try_from(net.id())?;

        // Linear layer at beginning
        for s in state.chunks_exact_mut(T) {
            Self::matmul_external_rep3(s.try_into().unwrap());
        }

        // First set of external rounds
        for r in 0..self.params.rounds_f_beginning {
            add_rc_external_packed(self, &mut state, r, id);
            sbox_rep3_precomp_with_noir_trace(&mut state, precomp, &mut traces, net)?;
            for (s, trace) in state.chunks_exact_mut(T).zip(traces.iter_mut()) {
                trace.push(s[0].into());
                Self::matmul_external_rep3(s.try_into().unwrap());
            }
        }

        // Internal rounds
        for r in 0..self.params.rounds_p {
            add_rc_internal_packed(self, &mut state, r, id);
            single_sbox_rep3_precomp_packed_with_noir_trace::<_, T, _>(
                &mut state,
                precomp,
                &mut traces,
                net,
            )?;
            for (s, trace) in state.chunks_exact_mut(T).zip(traces.iter_mut()) {
                trace.push(s[1].into());
                self.matmul_internal_rep3(s.try_into().unwrap());
            }
        }

        // Remaining external rounds
        for r in self.params.rounds_f_beginning
            ..self.params.rounds_f_beginning + self.params.rounds_f_end
        {
            add_rc_external_packed(self, &mut state, r, id);
            sbox_rep3_precomp_with_noir_trace(&mut state, precomp, &mut traces, net)?;
            for (s, trace) in state.chunks_exact_mut(T).zip(traces.iter_mut()) {
                trace.push(s[0].into());
                Self::matmul_external_rep3(s.try_into().unwrap());
            }
        }

        for trace in traces.iter() {
            debug_assert_eq!(trace.len(), witness_size);
        }
        debug_assert_eq!(precomp.get_offset() - offset, self.num_sbox() * L);

        // Feed forward
        for (src, des) in state.iter().step_by(T).zip(left.iter_mut()) {
            *des += src;
        }

        Ok((left, traces))
    }

    fn hash_rep3_generate_noir_trace_vec<N: Network>(
        &self,
        data: Vec<Rep3PrimeFieldShare<F>>,
        precomp: &mut Self::Precomputation,
        net: &N,
    ) -> eyre::Result<(Vec<Rep3PrimeFieldShare<F>>, Vec<Vec<Rep3AcvmType<F>>>)> {
        const T: usize = 2;
        let l2 = data.len();
        assert_eq!(l2 % T, 0);
        let l = l2 / T;
        let witness_size = 3 * self.num_sbox() + self.num_rounds();
        let mut traces = (0..l)
            .map(|_| Vec::with_capacity(witness_size))
            .collect::<Vec<_>>();
        let mut state = data;
        let mut left = (0..l).map(|i| state[i * T]).collect::<Vec<_>>();

        let offset = precomp.get_offset();
        let id = PartyID::try_from(net.id())?;

        // Linear layer at beginning
        for s in state.chunks_exact_mut(T) {
            Self::matmul_external_rep3(s.try_into().unwrap());
        }

        // First set of external rounds
        for r in 0..self.params.rounds_f_beginning {
            add_rc_external_packed(self, &mut state, r, id);
            sbox_rep3_precomp_with_noir_trace(&mut state, precomp, &mut traces, net)?;
            for (s, trace) in state.chunks_exact_mut(T).zip(traces.iter_mut()) {
                trace.push(s[0].into());
                Self::matmul_external_rep3(s.try_into().unwrap());
            }
        }

        // Internal rounds
        for r in 0..self.params.rounds_p {
            add_rc_internal_packed(self, &mut state, r, id);
            single_sbox_rep3_precomp_packed_with_noir_trace::<_, T, _>(
                &mut state,
                precomp,
                &mut traces,
                net,
            )?;
            for (s, trace) in state.chunks_exact_mut(T).zip(traces.iter_mut()) {
                trace.push(s[1].into());
                self.matmul_internal_rep3(s.try_into().unwrap());
            }
        }

        // Remaining external rounds
        for r in self.params.rounds_f_beginning
            ..self.params.rounds_f_beginning + self.params.rounds_f_end
        {
            add_rc_external_packed(self, &mut state, r, id);
            sbox_rep3_precomp_with_noir_trace(&mut state, precomp, &mut traces, net)?;
            for (s, trace) in state.chunks_exact_mut(T).zip(traces.iter_mut()) {
                trace.push(s[0].into());
                Self::matmul_external_rep3(s.try_into().unwrap());
            }
        }

        for trace in traces.iter() {
            debug_assert_eq!(trace.len(), witness_size);
        }
        debug_assert_eq!(precomp.get_offset() - offset, self.num_sbox() * l);

        // Feed forward
        for (src, des) in state.iter().step_by(T).zip(left.iter_mut()) {
            *des += src;
        }

        Ok((left, traces))
    }
}
