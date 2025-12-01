use ark_ec::AffineRepr;
use ark_ff::Field;
use co_groth16::VerifyingKey;
use co_noir::Pairing;
use std::io::Write;

pub fn export_solidity_verifier<P: Pairing, W: Write>(
    vk: &VerifyingKey<P>,
    writer: &mut W,
) -> eyre::Result<()> {
    let num_public = vk.gamma_abc_g1.len() - 1;

    const ROOT: &str = std::env!("CARGO_MANIFEST_DIR");
    let path = format!("{}{}", ROOT, "/src/circom/solidity_template.sol.template");

    let mut text = std::fs::read_to_string(&path)?;
    let (x, y) = vk.alpha_g1.xy().unwrap_or_default();
    text = text.replace("<%= vk_alpha_1[0]    %>", x.to_string().as_str());
    text = text.replace("<%= vk_alpha_1[1]    %>", y.to_string().as_str());

    // TODO order might be wrong for the g2 stuff
    let (x, y) = vk.beta_g2.xy().unwrap_or_default();
    for x in x.to_base_prime_field_elements().enumerate() {
        text = text.replace(
            format!("<%= vk_beta_2[0][{}]  %>", x.0).as_str(),
            x.1.to_string().as_str(),
        );
    }
    for y in y.to_base_prime_field_elements().enumerate() {
        text = text.replace(
            format!("<%= vk_beta_2[1][{}]  %>", y.0).as_str(),
            y.1.to_string().as_str(),
        );
    }

    // TODO order might be wrong for the g2 stuff
    let (x, y) = vk.gamma_g2.xy().unwrap_or_default();
    for x in x.to_base_prime_field_elements().enumerate() {
        text = text.replace(
            format!("<%= vk_gamma_2[0][{}] %>", x.0).as_str(),
            x.1.to_string().as_str(),
        );
    }
    for y in y.to_base_prime_field_elements().enumerate() {
        text = text.replace(
            format!("<%= vk_gamma_2[1][{}] %>", y.0).as_str(),
            y.1.to_string().as_str(),
        );
    }

    // TODO order might be wrong for the g2 stuff
    let (x, y) = vk.delta_g2.xy().unwrap_or_default();
    for x in x.to_base_prime_field_elements().enumerate() {
        text = text.replace(
            format!("<%= vk_delta_2[0][{}] %>", x.0).as_str(),
            x.1.to_string().as_str(),
        );
    }
    for y in y.to_base_prime_field_elements().enumerate() {
        text = text.replace(
            format!("<%= vk_delta_2[1][{}] %>", y.0).as_str(),
            y.1.to_string().as_str(),
        );
    }

    let mut ic_string = String::new();
    for (i, val) in vk.gamma_abc_g1.iter().enumerate() {
        let (x, y) = val.xy().unwrap_or_default();
        ic_string.push_str(&format!(
            "    uint256 constant IC{}x = {};\n",
            i,
            x.to_string().as_str(),
        ));
        ic_string.push_str(&format!(
            "    uint256 constant IC{}y = {};\n\n",
            i,
            y.to_string().as_str(),
        ));
    }

    text = text.replace("    <% for (let i=0; i<IC.length; i++) { %>\n    uint256 constant IC<%=i%>x = <%=IC[i][0]%>;\n    uint256 constant IC<%=i%>y = <%=IC[i][1]%>;\n    <% } %>", ic_string.as_str());

    text = text.replace("<%=IC.length-1%>", num_public.to_string().as_str());

    let mut linear_comb_string = String::new();
    for i in 1..=num_public {
        linear_comb_string.push_str(&format!(
            "                g1_mulAccC(_pVk, IC{}x, IC{}y, calldataload(add(pubSignals, {})))\n",
            i,
            i,
            (i - 1) * 32
        ));
    }

    text = text.replace(
        "                <% for (let i = 1; i <= nPublic; i++) { %>\n                g1_mulAccC(_pVk, IC<%=i%>x, IC<%=i%>y, calldataload(add(pubSignals, <%=(i-1)*32%>)))\n                <% } %>",
        linear_comb_string.as_str(),
    );

    let mut evaluation_check = String::new();

    for i in 0..num_public {
        evaluation_check.push_str(&format!(
            "            checkField(calldataload(add(_pubSignals, {})))\n",
            i * 32
        ));
    }

    text = text.replace(
        "            <% for (let i=0; i<nPublic; i++) { %>\n            checkField(calldataload(add(_pubSignals, <%=i*32%>)))\n            <% } %>",
        evaluation_check.as_str(),
    );

    writer.write_all(text.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod test {
    use std::{fs::File, io::Read};

    use super::*;
    use co_circom::{CheckElement, Groth16ZKey};
    use co_noir::Bn254;

    #[test]
    fn kat() {
        const ROOT: &str = std::env!("CARGO_MANIFEST_DIR");
        let path = format!("{}{}", ROOT, "/src/circom/test_vector/circuit.zkey");

        let should_output_path = format!("{}{}", ROOT, "/src/circom/test_vector/verifier.sol");
        let mut should_output_file = File::open(should_output_path).unwrap();
        let mut should_output = Vec::new();
        should_output_file.read_to_end(&mut should_output).unwrap();

        let zkey = File::open(path).unwrap();
        let zkey = Groth16ZKey::<Bn254>::from_reader(zkey, CheckElement::No).unwrap();
        let (_, pk) = zkey.into();
        let vk = pk.vk;
        let mut output = Vec::new();
        export_solidity_verifier(&vk, &mut output).unwrap();

        assert_eq!(should_output, output);
    }
}
