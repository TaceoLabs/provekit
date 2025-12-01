use crate::trace::TraceHasher;
use ark_ff::PrimeField;
use mpc_core::gadgets::poseidon2::Poseidon2;

fn single_sbox_generate_noir_trace<F: PrimeField>(state: &mut F, trace: &mut Vec<F>) {
    trace.push(*state);
    let square = state.square();
    trace.push(square);
    let quad = square.square();
    trace.push(quad);
    *state *= quad;
}

fn sbox_generate_noir_trace<F: PrimeField, const T: usize>(state: &mut [F; T], trace: &mut Vec<F>) {
    state.iter_mut().for_each(|x| {
        single_sbox_generate_noir_trace(x, trace);
    });
}

impl<F: PrimeField> TraceHasher<F> for Poseidon2<F, 2, 5> {
    fn hash(&self, mut data: [F; 2]) -> F {
        let left = data[0];
        self.permutation_in_place(&mut data);
        data[0] + left
    }

    fn hash_generate_noir_trace(&self, data: [F; 2]) -> (F, Vec<F>) {
        let witness_size = 3 * self.num_sbox() + self.num_rounds();
        let mut trace = Vec::with_capacity(witness_size);
        let mut state = data;
        let left = state[0];

        // Linear layer at beginning
        Self::matmul_external(&mut state);

        // First set of external rounds
        for r in 0..self.params.rounds_f_beginning {
            self.add_rc_external(&mut state, r);
            sbox_generate_noir_trace(&mut state, &mut trace);
            trace.push(state[0]);
            Self::matmul_external(&mut state);
        }

        // Internal rounds
        for r in 0..self.params.rounds_p {
            self.add_rc_internal(&mut state, r);
            single_sbox_generate_noir_trace(&mut state[0], &mut trace);
            trace.push(state[1]);
            self.matmul_internal(&mut state);
        }

        // Remaining external rounds
        for r in self.params.rounds_f_beginning
            ..self.params.rounds_f_beginning + self.params.rounds_f_end
        {
            self.add_rc_external(&mut state, r);
            sbox_generate_noir_trace(&mut state, &mut trace);
            trace.push(state[0]);
            Self::matmul_external(&mut state);
        }
        debug_assert_eq!(trace.len(), witness_size);

        (state[0] + left, trace)
    }

    fn num_multiplications(&self) -> usize {
        self.num_sbox() * 3 // Each sbox has 3 multiplications
    }

    fn num_rounds(&self) -> usize {
        self.num_rounds() // Each sbox has 3 multiplications
    }
}
