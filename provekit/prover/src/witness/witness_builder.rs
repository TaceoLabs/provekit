use {
    crate::witness::{digits::DigitalDecompositionWitnessesSolver, ram::SpiceWitnessesSolver},
    acir::native_types::WitnessMap,
    ark_ff::{BigInteger, PrimeField},
    ark_std::Zero,
    co_acvm::{mpc::NoirWitnessExtensionProtocol, Rep3AcvmSolver, Rep3AcvmType},
    mpc_core::protocols::rep3::Rep3PrimeFieldShare,
    mpc_net::Network,
    provekit_common::{
        utils::noir_to_native,
        witness::{
            ConstantOrR1CSWitness, ConstantTerm, MockTranscript, ProductLinearTerm, SumTerm,
            WitnessBuilder, WitnessCoefficient, BINOP_ATOMIC_BITS,
        },
        FieldElement, NoirElement,
    },
};

pub trait WitnessBuilderSolver {
    fn solve(
        &self,
        acir_witness_idx_to_value_map: &WitnessMap<NoirElement>,
        witness: &mut [Option<FieldElement>],
        transcript: &mut MockTranscript,
    );

    /// As per solve(), but additionally appends the solved witness values to
    /// the transcript.
    fn solve_and_append_to_transcript(
        &self,
        acir_witness_idx_to_value_map: &WitnessMap<NoirElement>,
        witness: &mut [Option<FieldElement>],
        transcript: &mut MockTranscript,
    );

    /// Solves for the witness value(s) specified by this builder and writes
    /// them to the witness vector.
    fn solve_rep3<N: Network>(
        &self,
        acir_witness_idx_to_value_map: &WitnessMap<Rep3AcvmType<FieldElement>>,
        witness: &mut [Option<Rep3AcvmType<FieldElement>>],
        driver: &mut Rep3AcvmSolver<FieldElement, N>,
    ) -> eyre::Result<()>;

    /// Solves for the witness value(s) specified by this builder and writes
    /// them to the witness vector.
    /// Gets an extra argument to handle bit decomposition more efficiently.
    fn solve_rep3_with_bitdecomp_witness<N: Network>(
        &self,
        acir_witness_idx_to_value_map: &WitnessMap<Rep3AcvmType<FieldElement>>,
        witness: &mut [Option<Rep3AcvmType<FieldElement>>],
        bitdecomps_iter: &mut impl Iterator<Item = Rep3PrimeFieldShare<FieldElement>>,
        driver: &mut Rep3AcvmSolver<FieldElement, N>,
    ) -> eyre::Result<()>;
}

impl WitnessBuilderSolver for WitnessBuilder {
    fn solve(
        &self,
        acir_witness_idx_to_value_map: &WitnessMap<NoirElement>,
        witness: &mut [Option<FieldElement>],
        transcript: &mut MockTranscript,
    ) {
        match self {
            WitnessBuilder::Constant(ConstantTerm(witness_idx, c)) => {
                witness[*witness_idx] = Some(*c);
            }
            WitnessBuilder::Acir(witness_idx, acir_witness_idx) => {
                witness[*witness_idx] = Some(noir_to_native(
                    *acir_witness_idx_to_value_map
                        .get_index(*acir_witness_idx as u32)
                        .unwrap(),
                ));
            }
            WitnessBuilder::Sum(witness_idx, operands) => {
                witness[*witness_idx] = Some(
                    operands
                        .iter()
                        .map(|SumTerm(coeff, witness_idx)| {
                            if let Some(coeff) = coeff {
                                *coeff * witness[*witness_idx].unwrap()
                            } else {
                                witness[*witness_idx].unwrap()
                            }
                        })
                        .fold(FieldElement::zero(), |acc, x| acc + x),
                );
            }
            WitnessBuilder::Product(witness_idx, operand_idx_a, operand_idx_b) => {
                let a: FieldElement = witness[*operand_idx_a].unwrap();
                let b: FieldElement = witness[*operand_idx_b].unwrap();
                witness[*witness_idx] = Some(a * b);
            }
            WitnessBuilder::Inverse(..) => {
                unreachable!("Inverse should not be called")
            }
            WitnessBuilder::IndexedLogUpDenominator(
                witness_idx,
                sz_challenge,
                WitnessCoefficient(index_coeff, index),
                rs_challenge,
                value,
            ) => {
                let index = witness[*index].unwrap();
                let value = witness[*value].unwrap();
                let rs_challenge = witness[*rs_challenge].unwrap();
                let sz_challenge = witness[*sz_challenge].unwrap();
                witness[*witness_idx] =
                    Some(sz_challenge - (*index_coeff * index + rs_challenge * value));
            }
            WitnessBuilder::MultiplicitiesForRange(start_idx, range_size, value_witnesses) => {
                let mut multiplicities = vec![0u32; *range_size];
                for value_witness_idx in value_witnesses {
                    // If the value is representable as just a u64, then it should be the least
                    // significant value in the BigInt representation.
                    let value = witness[*value_witness_idx].unwrap().into_bigint().0[0];
                    multiplicities[value as usize] += 1;
                }
                for (i, count) in multiplicities.iter().enumerate() {
                    witness[start_idx + i] = Some(FieldElement::from(*count));
                }
            }
            WitnessBuilder::Challenge(witness_idx) => {
                witness[*witness_idx] = Some(transcript.draw_challenge());
            }
            WitnessBuilder::LogUpDenominator(
                witness_idx,
                sz_challenge,
                WitnessCoefficient(value_coeff, value),
            ) => {
                witness[*witness_idx] = Some(
                    witness[*sz_challenge].unwrap() - (*value_coeff * witness[*value].unwrap()),
                );
            }
            WitnessBuilder::ProductLinearOperation(
                witness_idx,
                ProductLinearTerm(x, a, b),
                ProductLinearTerm(y, c, d),
            ) => {
                witness[*witness_idx] =
                    Some((*a * witness[*x].unwrap() + *b) * (*c * witness[*y].unwrap() + *d));
            }
            WitnessBuilder::DigitalDecomposition(dd_struct) => {
                dd_struct.solve(witness);
            }
            WitnessBuilder::SpiceMultisetFactor(
                witness_idx,
                sz_challenge,
                rs_challenge,
                WitnessCoefficient(addr, addr_witness),
                value,
                WitnessCoefficient(timer, timer_witness),
            ) => {
                witness[*witness_idx] = Some(
                    witness[*sz_challenge].unwrap()
                        - (*addr * witness[*addr_witness].unwrap()
                            + witness[*rs_challenge].unwrap() * witness[*value].unwrap()
                            + witness[*rs_challenge].unwrap()
                                * witness[*rs_challenge].unwrap()
                                * *timer
                                * witness[*timer_witness].unwrap()),
                );
            }
            WitnessBuilder::SpiceWitnesses(spice_witnesses) => {
                spice_witnesses.solve(witness);
            }
            WitnessBuilder::BinOpLookupDenominator(
                witness_idx,
                sz_challenge,
                rs_challenge,
                rs_challenge_sqrd,
                lhs,
                rhs,
                output,
            ) => {
                let lhs = match lhs {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(witness_idx) => witness[*witness_idx].unwrap(),
                };
                let rhs = match rhs {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(witness_idx) => witness[*witness_idx].unwrap(),
                };
                let output = match output {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(witness_idx) => witness[*witness_idx].unwrap(),
                };
                witness[*witness_idx] = Some(
                    witness[*sz_challenge].unwrap()
                        - (lhs
                            + witness[*rs_challenge].unwrap() * rhs
                            + witness[*rs_challenge_sqrd].unwrap() * output),
                );
            }
            WitnessBuilder::MultiplicitiesForBinOp(witness_idx, operands) => {
                let mut multiplicities = vec![0u32; 2usize.pow(2 * BINOP_ATOMIC_BITS as u32)];
                for (lhs, rhs) in operands {
                    let lhs = match lhs {
                        ConstantOrR1CSWitness::Constant(c) => *c,
                        ConstantOrR1CSWitness::Witness(witness_idx) => {
                            witness[*witness_idx].unwrap()
                        }
                    };
                    let rhs = match rhs {
                        ConstantOrR1CSWitness::Constant(c) => *c,
                        ConstantOrR1CSWitness::Witness(witness_idx) => {
                            witness[*witness_idx].unwrap()
                        }
                    };
                    let index =
                        (lhs.into_bigint().0[0] << BINOP_ATOMIC_BITS) + rhs.into_bigint().0[0];
                    multiplicities[index as usize] += 1;
                }
                for (i, count) in multiplicities.iter().enumerate() {
                    witness[witness_idx + i] = Some(FieldElement::from(*count));
                }
            }
            WitnessBuilder::U32Addition(result_witness_idx, carry_witness_idx, a, b) => {
                let a_val = match a {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(idx) => witness[*idx].unwrap(),
                };
                let b_val = match b {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(idx) => witness[*idx].unwrap(),
                };
                assert!(
                    a_val.into_bigint().num_bits() <= 32,
                    "a_val must be less than or equal to 32 bits, got {}",
                    a_val.into_bigint().num_bits()
                );
                assert!(
                    b_val.into_bigint().num_bits() <= 32,
                    "b_val must be less than or equal to 32 bits, got {}",
                    b_val.into_bigint().num_bits()
                );
                let sum = a_val + b_val;
                let sum_big = sum.into_bigint();
                let two_pow_32 = 1u64 << 32;
                let remainder = sum_big.0[0] % two_pow_32; // result
                let quotient = sum_big.0[0] / two_pow_32; // carry
                assert!(
                    quotient == 0 || quotient == 1,
                    "quotient must be 0 or 1, got {}",
                    quotient
                );
                witness[*result_witness_idx] = Some(FieldElement::from(remainder));
                witness[*carry_witness_idx] = Some(FieldElement::from(quotient));
            }
            WitnessBuilder::And(result_witness_idx, lh, rh) => {
                let lh_val = match lh {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(witness_idx) => witness[*witness_idx].unwrap(),
                };
                let rh_val = match rh {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(witness_idx) => witness[*witness_idx].unwrap(),
                };
                assert!(
                    lh_val.into_bigint().num_bits() <= 32,
                    "lh_val must be less than or equal to 32 bits, got {}",
                    lh_val.into_bigint().num_bits()
                );
                assert!(
                    rh_val.into_bigint().num_bits() <= 32,
                    "rh_val must be less than or equal to 32 bits, got {}",
                    rh_val.into_bigint().num_bits()
                );
                witness[*result_witness_idx] = Some(FieldElement::new(
                    lh_val.into_bigint() & rh_val.into_bigint(),
                ));
            }
            WitnessBuilder::Xor(result_witness_idx, lh, rh) => {
                let lh_val = match lh {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(witness_idx) => witness[*witness_idx].unwrap(),
                };
                let rh_val = match rh {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(witness_idx) => witness[*witness_idx].unwrap(),
                };
                assert!(
                    lh_val.into_bigint().num_bits() <= 32,
                    "lh_val must be less than or equal to 32 bits, got {}",
                    lh_val.into_bigint().num_bits()
                );
                assert!(
                    rh_val.into_bigint().num_bits() <= 32,
                    "rh_val must be less than or equal to 32 bits, got {}",
                    rh_val.into_bigint().num_bits()
                );
                witness[*result_witness_idx] = Some(FieldElement::new(
                    lh_val.into_bigint() ^ rh_val.into_bigint(),
                ));
            }
            WitnessBuilder::BitDecomposition(src, des) => {
                let src: FieldElement = witness[*src].unwrap();
                let mut bits = src.into_bigint();
                for d in des.iter() {
                    let bit = bits.as_ref()[0] & 1;
                    bits >>= 1;
                    witness[*d] = Some(FieldElement::from(bit));
                }
            }
        }
    }

    fn solve_and_append_to_transcript(
        &self,
        acir_witness_idx_to_value_map: &WitnessMap<NoirElement>,
        witness: &mut [Option<FieldElement>],
        transcript: &mut MockTranscript,
    ) {
        self.solve(acir_witness_idx_to_value_map, witness, transcript);

        for i in 0..self.num_witnesses() {
            transcript.append(witness[self.first_witness_idx() + i].unwrap());
        }
    }

    fn solve_rep3<N: Network>(
        &self,
        acir_witness_idx_to_value_map: &WitnessMap<Rep3AcvmType<FieldElement>>,
        witness: &mut [Option<Rep3AcvmType<FieldElement>>],
        driver: &mut Rep3AcvmSolver<FieldElement, N>,
    ) -> eyre::Result<()> {
        match self {
            WitnessBuilder::Constant(ConstantTerm(witness_idx, c)) => {
                witness[*witness_idx] = Some((*c).into());
            }
            WitnessBuilder::Acir(witness_idx, acir_witness_idx) => {
                witness[*witness_idx] = Some(
                    acir_witness_idx_to_value_map
                        .get_index(*acir_witness_idx as u32)
                        .unwrap()
                        .to_owned(),
                );
            }
            WitnessBuilder::Sum(witness_idx, operands) => {
                let mut sum = Rep3AcvmType::default();

                for SumTerm(coeff, witness_idx) in operands.iter() {
                    let val = if let Some(coeff) = coeff {
                        driver.mul_with_public(*coeff, witness[*witness_idx].to_owned().unwrap())
                    } else {
                        witness[*witness_idx].to_owned().unwrap()
                    };
                    sum = driver.add(sum, val);
                }
                witness[*witness_idx] = Some(sum);
            }
            WitnessBuilder::Product(witness_idx, operand_idx_a, operand_idx_b) => {
                let a = witness[*operand_idx_a].to_owned().unwrap();
                let b = witness[*operand_idx_b].to_owned().unwrap();
                let mul = driver.mul(a, b)?;
                witness[*witness_idx] = Some(mul);
            }
            WitnessBuilder::Inverse(witness_idx, operand_idx) => {
                let operand = witness[*operand_idx].to_owned().unwrap();
                let inv = driver.invert(operand)?;
                witness[*witness_idx] = Some(inv);
            }
            WitnessBuilder::BitDecomposition(src, des) => {
                let src = witness[*src].to_owned().unwrap();
                match src {
                    Rep3AcvmType::Public(val) => {
                        let mut bits = val.into_bigint();
                        for d in des.iter() {
                            let bit = bits.as_ref()[0] & 1;
                            bits >>= 1;
                            witness[*d] = Some(Rep3AcvmType::from(FieldElement::from(bit)));
                        }
                    }
                    Rep3AcvmType::Shared(val) => {
                        let decomp = driver.decompose_arithmetic(val, des.len(), 1)?;
                        debug_assert_eq!(des.len(), decomp.len());
                        for (d, bit) in des.iter().zip(decomp) {
                            witness[*d] = Some(Rep3AcvmType::from(bit));
                        }
                    }
                }
            }
            x => panic!("Unsupported operation for Rep3 solving: {x:?}"),
        }
        Ok(())
    }

    fn solve_rep3_with_bitdecomp_witness<N: Network>(
        &self,
        acir_witness_idx_to_value_map: &WitnessMap<Rep3AcvmType<FieldElement>>,
        witness: &mut [Option<Rep3AcvmType<FieldElement>>],
        bitdecomps_iter: &mut impl Iterator<Item = Rep3PrimeFieldShare<FieldElement>>,
        driver: &mut Rep3AcvmSolver<FieldElement, N>,
    ) -> eyre::Result<()> {
        match self {
            WitnessBuilder::Constant(ConstantTerm(witness_idx, c)) => {
                witness[*witness_idx] = Some((*c).into());
            }
            WitnessBuilder::Acir(witness_idx, acir_witness_idx) => {
                witness[*witness_idx] = Some(
                    acir_witness_idx_to_value_map
                        .get_index(*acir_witness_idx as u32)
                        .unwrap()
                        .to_owned(),
                );
            }
            WitnessBuilder::Sum(witness_idx, operands) => {
                let mut sum = Rep3AcvmType::default();

                for SumTerm(coeff, witness_idx) in operands.iter() {
                    let val = if let Some(coeff) = coeff {
                        driver.mul_with_public(*coeff, witness[*witness_idx].to_owned().unwrap())
                    } else {
                        witness[*witness_idx].to_owned().unwrap()
                    };
                    sum = driver.add(sum, val);
                }
                witness[*witness_idx] = Some(sum);
            }
            WitnessBuilder::Product(witness_idx, operand_idx_a, operand_idx_b) => {
                let a = witness[*operand_idx_a].to_owned().unwrap();
                let b = witness[*operand_idx_b].to_owned().unwrap();
                let mul = driver.mul(a, b)?;
                witness[*witness_idx] = Some(mul);
            }
            WitnessBuilder::Inverse(witness_idx, operand_idx) => {
                let operand = witness[*operand_idx].to_owned().unwrap();
                let inv = driver.invert(operand)?;
                witness[*witness_idx] = Some(inv);
            }
            WitnessBuilder::BitDecomposition(src, des) => {
                let src = witness[*src].to_owned().unwrap();
                match src {
                    Rep3AcvmType::Public(val) => {
                        let mut bits = val.into_bigint();
                        for d in des.iter() {
                            let bit = bits.as_ref()[0] & 1;
                            bits >>= 1;
                            witness[*d] = Some(Rep3AcvmType::from(FieldElement::from(bit)));
                        }
                    }
                    Rep3AcvmType::Shared(_) => {
                        for d in des.iter() {
                            let bit = bitdecomps_iter
                                .next()
                                .expect("Not enough bit decomposition witnesses provided");
                            witness[*d] = Some(Rep3AcvmType::from(bit));
                        }
                    }
                }
            }
            x => panic!("Unsupported operation for Rep3 solving: {x:?}"),
        }

        Ok(())
    }
}
