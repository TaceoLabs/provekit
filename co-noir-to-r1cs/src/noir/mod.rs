pub mod r1cs;
pub mod ultrahonk;

use acir::native_types::WitnessMap;

pub(crate) fn vec_to_witness_map<T>(inputs: Vec<T>) -> WitnessMap<T> {
    let mut result = WitnessMap::new();
    for (i, v) in inputs.into_iter().enumerate() {
        result.insert((i as u32).into(), v);
    }
    result
}
