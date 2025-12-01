use ark_ff::Zero;
use ark_relations::r1cs::ConstraintMatrices;
use {
    crate::{FieldElement, HydratedSparseMatrix, Interner, SparseMatrix},
    serde::{Deserialize, Serialize},
};

/// Represents a R1CS constraint system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct R1CS {
    pub num_public_inputs: usize,
    pub interner: Interner,
    pub a: SparseMatrix,
    pub b: SparseMatrix,
    pub c: SparseMatrix,
}

impl Default for R1CS {
    fn default() -> Self {
        Self::new()
    }
}

impl R1CS {
    #[must_use]
    pub fn new() -> Self {
        Self {
            num_public_inputs: 1,
            interner: Interner::new(),
            a: SparseMatrix::new(0, 0),
            b: SparseMatrix::new(0, 0),
            c: SparseMatrix::new(0, 0),
        }
    }

    #[must_use]
    pub const fn a(&self) -> HydratedSparseMatrix<'_> {
        self.a.hydrate(&self.interner)
    }

    #[must_use]
    pub const fn b(&self) -> HydratedSparseMatrix<'_> {
        self.b.hydrate(&self.interner)
    }

    #[must_use]
    pub const fn c(&self) -> HydratedSparseMatrix<'_> {
        self.c.hydrate(&self.interner)
    }

    /// The number of constraints in the R1CS instance.
    pub const fn num_constraints(&self) -> usize {
        self.a.num_rows
    }

    /// The number of witnesses in the R1CS instance (including the constant one
    /// witness).
    pub const fn num_witnesses(&self) -> usize {
        self.a.num_cols
    }

    // Increase the size of the R1CS matrices to the specified dimensions.
    pub fn grow_matrices(&mut self, num_rows: usize, num_cols: usize) {
        self.a.grow(num_rows, num_cols);
        self.b.grow(num_rows, num_cols);
        self.c.grow(num_rows, num_cols);
    }

    /// Add a new witnesses to the R1CS instance.
    pub fn add_witnesses(&mut self, count: usize) {
        self.grow_matrices(self.num_constraints(), self.num_witnesses() + count);
    }

    /// Add an R1CS constraint.
    pub fn add_constraint(
        &mut self,
        a: &[(FieldElement, usize)],
        b: &[(FieldElement, usize)],
        c: &[(FieldElement, usize)],
    ) {
        let next_constraint_idx = self.num_constraints();
        self.grow_matrices(self.num_constraints() + 1, self.num_witnesses());

        for (coeff, witness_idx) in a.iter().copied() {
            self.a.set(
                next_constraint_idx,
                witness_idx,
                self.interner.intern(coeff),
            );
        }
        for (coeff, witness_idx) in b.iter().copied() {
            self.b.set(
                next_constraint_idx,
                witness_idx,
                self.interner.intern(coeff),
            );
        }
        for (coeff, witness_idx) in c.iter().copied() {
            self.c.set(
                next_constraint_idx,
                witness_idx,
                self.interner.intern(coeff),
            );
        }
    }

    fn matrix_to_ark_matrix(
        mat: HydratedSparseMatrix<'_>,
    ) -> (Vec<Vec<(FieldElement, usize)>>, usize) {
        let num_constraints = mat.matrix.num_rows;
        let mut res_mat = vec![Vec::new(); num_constraints];
        let mut num_non_zero = 0;

        for ((row, col), val) in mat.iter() {
            if val.is_zero() {
                continue;
            }
            num_non_zero += 1;
            res_mat[row].push((val, col));
        }

        (res_mat, num_non_zero)
    }

    pub fn to_ark_constraint_matrix(&self) -> ConstraintMatrices<FieldElement> {
        let num_constraints = self.num_constraints();
        let num_witnesses = self.num_witnesses();
        let num_public_inputs = self.num_public_inputs;

        let (a, a_num_non_zero) = Self::matrix_to_ark_matrix(self.a());
        let (b, b_num_non_zero) = Self::matrix_to_ark_matrix(self.b());
        let (c, c_num_non_zero) = Self::matrix_to_ark_matrix(self.c());

        ConstraintMatrices {
            num_instance_variables: num_public_inputs,
            num_witness_variables: num_witnesses - num_public_inputs,
            num_constraints,
            a_num_non_zero,
            b_num_non_zero,
            c_num_non_zero,
            a,
            b,
            c,
        }
    }
}
