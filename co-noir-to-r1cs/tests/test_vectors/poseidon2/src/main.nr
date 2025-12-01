use dep::poseidon2;

#[oracle(__debug_poseidon_start)]
unconstrained fn __debug_poseidon_start() {}
#[oracle(__debug_poseidon_end)]
unconstrained fn __debug_poseidon_end() {}

unconstrained fn mark_poseidon_start() {
    __debug_poseidon_start()
}
unconstrained fn mark_poseidon_end() {
    __debug_poseidon_end()
}

fn safe_mark_poseidon_start() {
    // Safety: This function is only a marker
    unsafe {
        mark_poseidon_start();
    }
}
fn safe_mark_poseidon_end() {
    // Safety: This function is only a marker
    unsafe {
        mark_poseidon_end();
    }
}

fn main(plains: [Field; 2]) -> pub Field {
    safe_mark_poseidon_start();
    let res = poseidon2::bn254::hash_2(plains);
    safe_mark_poseidon_end();
    plains[0] + res
}
