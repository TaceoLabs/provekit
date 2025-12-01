use {
    anyhow::Result,
    co_acvm::Rep3AcvmType,
    co_noir_types::Rep3Type,
    mpc_core::protocols::rep3::{self, Rep3State},
    provekit_common::FieldElement,
    rand::{thread_rng, Rng},
    tracing::{info, instrument},
};

mod digits;
mod ram;
pub(crate) mod witness_builder;

/// Complete a partial witness with random values.
#[instrument(skip_all, fields(size = witness.len()))]
#[expect(unused)]
pub(crate) fn fill_witness(witness: Vec<Option<FieldElement>>) -> Result<Vec<FieldElement>> {
    // TODO: Use better entropy source and proper sampling.
    let mut rng = thread_rng();
    let mut count = 0;
    let witness = witness
        .iter()
        .map(|f| {
            f.unwrap_or_else(|| {
                count += 1;
                FieldElement::from(rng.gen::<u128>())
            })
        })
        .collect::<Vec<_>>();
    info!("Filled witness with {count} random values");
    Ok(witness)
}

pub fn fill_witness_rep3(
    witness: Vec<Option<Rep3AcvmType<FieldElement>>>,
    rep3_state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3Type<FieldElement>>> {
    let mut count = 0;
    let witness = witness
        .iter()
        .map(|f| match f {
            Some(f) => match f {
                Rep3AcvmType::Public(v) => Rep3Type::Public(*v),
                Rep3AcvmType::Shared(v) => Rep3Type::Shared(*v),
            },
            None => {
                count += 1;
                rep3::arithmetic::rand(rep3_state).into()
            }
        })
        .collect::<Vec<_>>();
    info!("Filled witness with {count} random values");
    Ok(witness)
}
