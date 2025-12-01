use crate::circom::proving_key::QapReduction;
use ark_ff::Zero;
use ark_groth16::ProvingKey;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::SynthesisError;
use co_noir::Pairing;
use provekit_common::{FieldElement, R1CS};
use rand::{CryptoRng, Rng};

pub trait Groth16R1CS {
    // This is extracted from ark-groth (generate_random_parameters_with_reduction)
    // TODO make a ceremnoy out of this
    fn generate_proving_key<P: Pairing<ScalarField = FieldElement>, R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> eyre::Result<ProvingKey<P>>;

    // Copied from ark-groth16 (instance_map_with_evaluation)
    fn qap_reduction<D: EvaluationDomain<FieldElement>>(
        &self,
        t: FieldElement,
    ) -> eyre::Result<QapReduction<FieldElement>>;
}

impl Groth16R1CS for R1CS {
    // This is extracted from ark-groth (generate_random_parameters_with_reduction)
    // TODO make a ceremnoy out of this
    fn generate_proving_key<P: Pairing<ScalarField = FieldElement>, R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> eyre::Result<ProvingKey<P>> {
        type D<F> = GeneralEvaluationDomain<F>;

        let domain_size = self.num_constraints() + self.num_public_inputs;
        let domain =
            D::<FieldElement>::new(domain_size).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let t = domain.sample_element_outside_domain(rng);

        let qap = self.qap_reduction::<D<FieldElement>>(t)?;
        crate::circom::proving_key::generate_proving_key(rng, t, self.num_public_inputs, qap)
    }

    // Copied from ark-groth16 (instance_map_with_evaluation)
    fn qap_reduction<D: EvaluationDomain<FieldElement>>(
        &self,
        t: FieldElement,
    ) -> eyre::Result<QapReduction<FieldElement>> {
        let domain_size = self.num_constraints() + self.num_public_inputs;
        let domain = D::new(domain_size).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_size = domain.size();

        let zt = domain.evaluate_vanishing_polynomial(t);

        // Evaluate all Lagrange polynomials

        let u = domain.evaluate_all_lagrange_coefficients(t);

        let qap_num_variables = self.num_witnesses() - 1;

        let mut a = vec![FieldElement::zero(); qap_num_variables + 1];
        let mut b = vec![FieldElement::zero(); qap_num_variables + 1];
        let mut c = vec![FieldElement::zero(); qap_num_variables + 1];

        {
            let start = 0;
            let end = self.num_public_inputs;
            let num_constraints = self.num_constraints();
            a[start..end].copy_from_slice(&u[(start + num_constraints)..(end + num_constraints)]);
        }

        for (i, u_i) in u.iter().enumerate().take(self.num_constraints()) {
            for (index, coeff) in self.a().iter_row(i) {
                a[index] += &(*u_i * coeff);
            }
            for (index, coeff) in self.b().iter_row(i) {
                b[index] += &(*u_i * coeff);
            }
            for (index, coeff) in self.c().iter_row(i) {
                c[index] += &(*u_i * coeff);
            }
        }

        Ok(QapReduction {
            a,
            b,
            c,
            zt,
            qap_num_variables,
            m_raw: domain_size,
        })
    }
}
