pub struct Policy {
    pub n: usize,
    pub m: usize,
}

impl Policy {
    pub fn new(n: usize, m: usize) -> Policy {
        Policy { n, m }
    }
}
