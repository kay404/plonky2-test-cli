use plonky2::gates::arithmetic_base::ArithmeticGate;
use plonky2::gates::arithmetic_extension::ArithmeticExtensionGate;
use plonky2_field::extension::Extendable;

use plonky2::gates::base_sum::BaseSumGate;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

pub trait CircuitBuilderSplit<F: RichField + Extendable<D>, const D: usize> {
    fn split_le_base<const B: usize>(&mut self, x: Target, num_limbs: usize) -> Vec<Target>;
    fn assert_leading_zeros(&mut self, x: Target, leading_zeros: u32);
    fn num_ext_arithmetic_ops_per_gate(&self) -> usize;
    fn num_base_arithmetic_ops_per_gate(&self) -> usize;
    // fn le_sum(&mut self, bits: impl Iterator<Item = impl Borrow<BoolTarget>>) -> Target;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderSplit<F, D>
    for CircuitBuilder<F, D>
{
    /// Split the given element into a list of targets, where each one represents a
    /// base-B limb of the element, with little-endian ordering.
    fn split_le_base<const B: usize>(&mut self, x: Target, num_limbs: usize) -> Vec<Target> {
        let gate_type = BaseSumGate::<B>::new(num_limbs);
        let gate = self.add_gate(gate_type, vec![]);
        let sum = Target::wire(gate, BaseSumGate::<B>::WIRE_SUM);
        self.connect(x, sum);

        Target::wires_from_range(gate, gate_type.limbs())
    }

    /// Asserts that `x`'s big-endian bit representation has at least `leading_zeros` leading zeros.
    fn assert_leading_zeros(&mut self, x: Target, leading_zeros: u32) {
        self.range_check(x, (64 - leading_zeros) as usize);
    }

    fn num_ext_arithmetic_ops_per_gate(&self) -> usize {
        ArithmeticExtensionGate::<D>::new_from_config(&self.config).num_ops
    }

    fn num_base_arithmetic_ops_per_gate(&self) -> usize {
        if self.config.use_base_arithmetic_gate {
            ArithmeticGate::new_from_config(&self.config).num_ops
        } else {
            self.num_ext_arithmetic_ops_per_gate()
        }
    }
}
