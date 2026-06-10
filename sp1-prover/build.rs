// Build the guest program (./program) for the zkVM target and expose its ELF
// to `include_elf!` in the host crate.
fn main() {
    sp1_build::build_program_with_args("program", Default::default());
}
