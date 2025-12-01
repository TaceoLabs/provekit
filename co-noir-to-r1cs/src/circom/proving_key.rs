use ark_ec::{scalar_mul::BatchMulPreprocessing, CurveGroup};
use ark_ff::{Field, PrimeField, UniformRand, Zero};
use ark_relations::r1cs::SynthesisError;
use co_circom::ProvingKey;
use co_groth16::VerifyingKey;
use co_noir::Pairing;
use rand::{CryptoRng, Rng};

pub struct QapReduction<F: PrimeField> {
    pub a: Vec<F>,
    pub b: Vec<F>,
    pub c: Vec<F>,
    pub zt: F,
    pub qap_num_variables: usize,
    pub m_raw: usize,
}

// This is extracted from ark-groth (generate_random_parameters_with_reduction)
// TODO make a ceremnoy out of this
pub fn generate_proving_key<P: Pairing, R: Rng + CryptoRng>(
    rng: &mut R,
    t: P::ScalarField,
    num_public_inputs: usize,
    qap: QapReduction<P::ScalarField>,
) -> eyre::Result<ProvingKey<P>> {
    let alpha = P::ScalarField::rand(rng);
    let beta = P::ScalarField::rand(rng);
    let gamma = P::ScalarField::rand(rng);
    let delta = P::ScalarField::rand(rng);

    let g1_generator = P::G1::rand(rng);
    let g2_generator = P::G2::rand(rng);

    generate_proving_key_with_randomness(
        alpha,
        beta,
        gamma,
        delta,
        g1_generator,
        g2_generator,
        t,
        num_public_inputs,
        qap,
    )
}

// This is extracted from ark-groth16 (generate_parameters_with_qap)
#[expect(clippy::too_many_arguments)]
pub fn generate_proving_key_with_randomness<P: Pairing>(
    alpha: P::ScalarField,
    beta: P::ScalarField,
    gamma: P::ScalarField,
    delta: P::ScalarField,
    g1_generator: P::G1,
    g2_generator: P::G2,
    t: P::ScalarField,
    num_public_inputs: usize,
    qap: QapReduction<P::ScalarField>,
) -> eyre::Result<ProvingKey<P>> {
    // Following is the mapping of symbols from the Groth16 paper to this implementation
    // l -> num_instance_variables
    // m -> qap_num_variables
    // x -> t
    // t(x) - zt
    // u_i(x) -> a
    // v_i(x) -> b
    // w_i(x) -> c

    let num_instance_variables = num_public_inputs;

    // Compute query densities
    let non_zero_a: usize = (0..qap.qap_num_variables)
        .map(|i| usize::from(!qap.a[i].is_zero()))
        .sum();

    let non_zero_b: usize = (0..qap.qap_num_variables)
        .map(|i| usize::from(!qap.b[i].is_zero()))
        .sum();

    let gamma_inverse = gamma.inverse().ok_or(SynthesisError::UnexpectedIdentity)?;
    let delta_inverse = delta.inverse().ok_or(SynthesisError::UnexpectedIdentity)?;

    let gamma_abc = qap.a[..num_instance_variables]
        .iter()
        .zip(&qap.b[..num_instance_variables])
        .zip(&qap.c[..num_instance_variables])
        .map(|((a, b), c)| (beta * a + (alpha * b) + c) * gamma_inverse)
        .collect::<Vec<_>>();

    let l = qap.a[num_instance_variables..]
        .iter()
        .zip(&qap.b[num_instance_variables..])
        .zip(&qap.c[num_instance_variables..])
        .map(|((a, b), c)| (beta * a + (alpha * b) + c) * delta_inverse)
        .collect::<Vec<_>>();

    drop(qap.c);

    // Compute B window table
    let g2_table = BatchMulPreprocessing::new(g2_generator, non_zero_b);

    // Compute the B-query in G2
    let b_g2_query = g2_table.batch_mul(&qap.b);
    drop(g2_table);

    // Compute G window table
    let num_scalars = non_zero_a + non_zero_b + qap.qap_num_variables + qap.m_raw + 1;
    let g1_table = BatchMulPreprocessing::new(g1_generator, num_scalars);

    // Generate the R1CS proving key
    let alpha_g1 = g1_generator * alpha;
    let beta_g1 = g1_generator * beta;
    let beta_g2 = g2_generator * beta;
    let delta_g1 = g1_generator * delta;
    let delta_g2 = g2_generator * delta;

    // Compute the A-query
    let a_query = g1_table.batch_mul(&qap.a);
    drop(qap.a);

    // Compute the B-query in G1
    let b_g1_query = g1_table.batch_mul(&qap.b);
    drop(qap.b);

    // Compute the H-query
    let h_scalars = super::h_query_scalars(qap.m_raw - 1, t, qap.zt, delta_inverse)?;
    let h_query = g1_table.batch_mul(&h_scalars);

    // Compute the L-query
    let l_query = g1_table.batch_mul(&l);
    drop(l);

    // Generate R1CS verification key
    let gamma_g2 = g2_generator * gamma;
    let gamma_abc_g1 = g1_table.batch_mul(&gamma_abc);
    drop(g1_table);

    let vk = VerifyingKey::<P> {
        alpha_g1: alpha_g1.into_affine(),
        beta_g2: beta_g2.into_affine(),
        gamma_g2: gamma_g2.into_affine(),
        delta_g2: delta_g2.into_affine(),
        gamma_abc_g1,
    };

    Ok(ProvingKey {
        vk,
        beta_g1: beta_g1.into_affine(),
        delta_g1: delta_g1.into_affine(),
        a_query,
        b_g1_query,
        b_g2_query,
        h_query,
        l_query,
    })
}
