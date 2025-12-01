global BIT_SIZE: u32 = 32;

fn main(x: Field) {
    x.assert_max_bit_size::<BIT_SIZE>();
}
