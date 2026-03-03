#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WhirParams {
    pub pow_bits: u32,
    pub folding_factor: usize,
    pub starting_log_inv_rate: usize,
    pub rs_domain_initial_reduction_factor: usize,
}

impl Default for WhirParams {
    fn default() -> Self {
        Self {
            pow_bits: 0,
            folding_factor: 4,
            starting_log_inv_rate: 1,
            rs_domain_initial_reduction_factor: 1,
        }
    }
}
