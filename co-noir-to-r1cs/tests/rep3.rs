use co_noir::Rep3AcvmType;
use co_noir_to_r1cs::{
    noir::{r1cs, ultrahonk},
    trace::MpcTraceHasher,
};
use itertools::izip;
use mpc_core::{
    gadgets::poseidon2::Poseidon2,
    protocols::rep3::{conversion::A2BType, Rep3State},
};
use mpc_net::local::LocalNetwork;
use std::{fs::File, sync::Arc};
type F = ark_bn254::Fr;

pub fn proof_and_verify_test(name: &str, needs_poseidon_trace: bool) {
    let root = std::env!("CARGO_MANIFEST_DIR");

    let prover_toml = format!("{root}/tests/test_vectors/{name}/Prover.toml");
    let circuit_file = format!("{root}/tests/test_vectors/{name}/kat/{name}.json");

    // Init Groth16
    // Read constraint system
    let pa = ultrahonk::get_program_artifact(circuit_file).unwrap();

    let inputs = noir_types::partially_read_abi_bn254(
        File::open(&prover_toml).unwrap(),
        &pa.abi,
        &pa.bytecode.functions[0].public_inputs().indices(),
    )
    .unwrap();
    let shares = co_noir::split_input_rep3::<F>(inputs);
    let flat_shares = {
        let mut shares_: [Vec<Rep3AcvmType<F>>; 3] = [const { Vec::new() }; 3];
        for (i, share) in shares.into_iter().enumerate() {
            for s in share.into_iter() {
                shares_[i].push(s.1.into());
            }
        }
        shares_
    };

    // Get the R1CS proof schema
    let mut rng = rand::thread_rng();

    let (proof_schema, pk, cs) = r1cs::setup_r1cs(pa, &mut rng).unwrap();
    let proof_schema = Arc::new(proof_schema);
    let pk = Arc::new(pk);
    let cs = Arc::new(cs);
    let size = proof_schema.size();
    println!(
        "R1CS size: constraints = {}, witnesses = {}",
        size.0, size.1
    );

    let mut threads = Vec::with_capacity(3);

    // Init networks
    let test_network0 = LocalNetwork::new(3);
    let test_network1 = LocalNetwork::new(3);

    for (net0, net1, shares) in izip!(
        test_network0.into_iter(),
        test_network1.into_iter(),
        flat_shares
    ) {
        let proof_schema = proof_schema.clone();
        let cs = cs.clone();
        let pk = pk.clone();

        threads.push(std::thread::spawn(move || {
            let mut rep3_state = Rep3State::new(&net0, A2BType::default()).unwrap();
            let traces = if needs_poseidon_trace {
                let hasher = Poseidon2::<F, 2, 5>::default();
                let mut hasher_precomp = hasher.precompute_rep3(1, &net0, &mut rep3_state).unwrap();
                let (_, traces) = hasher
                    .hash_rep3_generate_noir_trace::<_>(
                        shares
                            .iter()
                            .map(|x| match x {
                                Rep3AcvmType::Shared(v) => *v,
                                Rep3AcvmType::Public(_) => panic!("Expected shared input"),
                            })
                            .collect::<Vec<_>>()
                            .try_into()
                            .unwrap(), // This is very brittle, the needs_poseidon_trace flag works only if all inputs are for poseidon (and shared, see match above)
                        &mut hasher_precomp,
                        &net0,
                    )
                    .unwrap();
                vec![traces]
            } else {
                vec![]
            };

            let r1cs = r1cs::trace_to_r1cs_witness(
                shares,
                traces,
                &proof_schema,
                &net0,
                &net1,
                &mut rep3_state,
            )
            .unwrap();
            let witness = r1cs::r1cs_witness_to_cogroth16(&proof_schema, r1cs, rep3_state.id);

            let (proof, public_inputs) = r1cs::prove(&cs, &pk, witness, &net0, &net1).unwrap();
            (proof, public_inputs)
        }))
    }
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    let mut proofs = results
        .iter()
        .map(|(proof, _)| proof.to_owned())
        .collect::<Vec<_>>();
    let proof = proofs.pop().unwrap();
    for p in proofs {
        assert_eq!(proof, p);
    }
    let mut public_inputs = results
        .iter()
        .map(|(_, public_input)| public_input.to_owned())
        .collect::<Vec<_>>();
    let public_input = public_inputs.pop().unwrap();
    for p in public_inputs {
        assert_eq!(public_input, p);
    }

    assert!(r1cs::verify(&pk.vk, &proof, &public_input).unwrap());
}

#[test]
fn add3_proof_and_verify_test() {
    proof_and_verify_test("add3", false);
}

#[test]
fn range_check_proof_and_verify_test() {
    proof_and_verify_test("range_check", false);
}

#[test]
fn poseidon2_proof_and_verify_test() {
    proof_and_verify_test("poseidon2", true);
}
