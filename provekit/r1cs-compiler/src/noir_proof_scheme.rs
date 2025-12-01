use {
    crate::{noir_to_r1cs, witness_generator::NoirWitnessGeneratorBuilder},
    eyre::{ensure, Context},
    noirc_artifacts::program::ProgramArtifact,
    provekit_common::{utils::PrintAbi, witness::NoirWitnessGenerator, NoirProofScheme},
    std::{fs::File, path::Path},
    tracing::{info, instrument},
};

pub trait NoirProofSchemeBuilder {
    fn from_file(path: impl AsRef<Path> + std::fmt::Debug) -> eyre::Result<Self>
    where
        Self: Sized;

    fn from_program(program: ProgramArtifact) -> eyre::Result<Self>
    where
        Self: Sized;

    /// Reorder the R1CS instance so that the public inputs are at the
    /// beginning.
    fn reorder_for_public_inputs(&mut self);

    /// Reorder the witness so that the public inputs are at the beginning.
    fn reorder_witness_for_public_inputs<D>(&self, witness: &mut [D]);
}

impl NoirProofSchemeBuilder for NoirProofScheme {
    #[instrument(fields(size = path.as_ref().metadata().map(|m| m.len()).ok()))]
    fn from_file(path: impl AsRef<Path> + std::fmt::Debug) -> eyre::Result<Self> {
        let file = File::open(path).context("while opening Noir program")?;
        let program = serde_json::from_reader(file).context("while reading Noir program")?;

        Self::from_program(program)
    }

    #[instrument(skip_all)]
    fn from_program(program: ProgramArtifact) -> eyre::Result<Self> {
        info!("Program noir version: {}", program.noir_version);
        info!("Program entry point: fn main{};", PrintAbi(&program.abi));
        ensure!(
            program.bytecode.functions.len() == 1,
            "Program must have one entry point."
        );

        // Extract bits from Program Artifact.
        let main = &program.bytecode.functions[0];
        info!(
            "ACIR: {} witnesses, {} opcodes.",
            main.current_witness_index,
            main.opcodes.len()
        );

        // Compile to R1CS schemes
        let (r1cs, witness_map, witness_builders, public_inputs) = noir_to_r1cs(main)?;
        info!(
            "R1CS {} constraints, {} witnesses, A {} entries, B {} entries, C {} entries",
            r1cs.num_constraints(),
            r1cs.num_witnesses(),
            r1cs.a.num_entries(),
            r1cs.b.num_entries(),
            r1cs.c.num_entries()
        );

        // Translate the public inputs with the witness map.
        let mut public_input_indices = Vec::with_capacity(public_inputs.len());
        for p in public_inputs {
            let index = witness_map[p as usize].expect("Must be there");
            public_input_indices.push(index);
        }

        // Configure witness generator
        let witness_generator =
            NoirWitnessGenerator::new(&program, witness_map, r1cs.num_witnesses());

        Ok(Self {
            program,
            r1cs,
            witness_builders,
            witness_generator,
            public_input_indices,
        })
    }

    fn reorder_for_public_inputs(&mut self) {
        let num_rows = self.r1cs.num_constraints();

        for (i, pub_index) in self.public_input_indices.iter().enumerate() {
            let src_index = pub_index.get();
            let target_index = i as u32 + 1; // +1 because index 0 is reserved for the constant 1

            for row in 0..num_rows {
                // Swap the entries in A, B, C matrices
                self.r1cs.a.swap_indices(row, src_index, target_index);
                self.r1cs.b.swap_indices(row, src_index, target_index);
                self.r1cs.c.swap_indices(row, src_index, target_index);
            }
        }
    }

    fn reorder_witness_for_public_inputs<D>(&self, witness: &mut [D]) {
        for (i, pub_index) in self.public_input_indices.iter().enumerate() {
            let src_index = pub_index.get() as usize;
            let target_index = i + 1; // +1 because index 0 is reserved for the constant 1
            witness.swap(src_index, target_index);
        }
    }
}
