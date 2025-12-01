use crate::circom::proof_schema::CircomProofSchema;
use co_circom::Groth16ZKey;
use co_noir::Pairing;

#[derive(Clone, Debug)]
pub struct HeaderGroth<P: Pairing> {
    pub n_vars: usize,
    pub n_public: usize,
    pub domain_size: u32,
    pub pow: usize,
    pub alpha_g1: P::G1Affine,
    pub beta_g1: P::G1Affine,
    pub beta_g2: P::G2Affine,
    pub gamma_g2: P::G2Affine,
    pub delta_g1: P::G1Affine,
    pub delta_g2: P::G2Affine,
}

impl<P: Pairing> HeaderGroth<P> {
    pub fn from_zkey(zkey: &Groth16ZKey<P>) -> Self {
        Self {
            n_vars: zkey.a_query.len(),
            n_public: zkey.n_public,
            domain_size: zkey.pow as u32,
            pow: zkey.pow,
            alpha_g1: zkey.alpha_g1,
            beta_g1: zkey.beta_g1,
            beta_g2: zkey.beta_g2,
            gamma_g2: zkey.gamma_g2,
            delta_g1: zkey.delta_g1,
            delta_g2: zkey.delta_g2,
        }
    }
}

impl<P> CircomProofSchema<P>
where
    P: Pairing,
{
    pub fn to_zkey(&self) -> Groth16ZKey<P> {
        let domain_size = self.matrices.num_constraints.next_power_of_two();
        Groth16ZKey {
            n_public: self.matrices.num_instance_variables - 1,
            pow: domain_size.ilog2() as usize,
            num_constraints: self.matrices.num_constraints,
            beta_g1: self.pk.beta_g1,
            delta_g1: self.pk.delta_g1,
            a_query: self.pk.a_query.to_owned(),
            b_g1_query: self.pk.b_g1_query.to_owned(),
            b_g2_query: self.pk.b_g2_query.to_owned(),
            h_query: self.pk.h_query.to_owned(),
            l_query: self.pk.l_query.to_owned(),
            alpha_g1: self.pk.vk.alpha_g1,
            beta_g2: self.pk.vk.beta_g2,
            delta_g2: self.pk.vk.delta_g2,
            gamma_g2: self.pk.vk.gamma_g2,
            ic: self.pk.vk.gamma_abc_g1.to_owned(),
            a_matrix: self.matrices.a.to_owned(),
            b_matrix: self.matrices.b.to_owned(),
        }
    }
}
