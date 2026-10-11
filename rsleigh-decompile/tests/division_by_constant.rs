//! Compilers divide by constants with a multiply-high and shifts; the
//! decompiler prints the division (checked numerically before rewriting).

use rsleigh_api::{Architecture, Decoder};

fn decompile_x64(bytes: &'static [u8]) -> String {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(move || {
            let mut dec = Decoder::new(Architecture::X86_64);
            let (mut insts, mut off) = (Vec::new(), 0usize);
            while off < bytes.len() {
                let inst = dec.decode(&bytes[off..], off as u64).unwrap();
                off += inst.len as usize;
                insts.push(((off - inst.len as usize) as u64, inst));
            }
            rsleigh_decompile::decompile(Architecture::X86_64, &insts)
        })
        .unwrap()
        .join()
        .unwrap()
}

#[test]
fn unsigned_divide_by_three_multiply_high() {
    // mov eax, edi ; mov edx, 0xaaaaaaab ; imul rax, rdx ; shr rax, 33 ; ret
    static BYTES: [u8; 16] = [
        0x89, 0xf8, 0xba, 0xab, 0xaa, 0xaa, 0xaa, 0x48, 0x0f, 0xaf, 0xc2, 0x48, 0xc1, 0xe8, 0x21,
        0xc3,
    ];
    let text = decompile_x64(&BYTES);
    assert!(text.contains("/ 3"), "{text}");
    assert!(!text.contains("0xaaaaaaab"), "{text}");
}

#[test]
fn near_miss_multiplier_is_not_rewritten() {
    // Same shape with a multiplier that divides by nothing exactly.
    static BYTES: [u8; 16] = [
        0x89, 0xf8, 0xba, 0x01, 0x00, 0x00, 0x90, 0x48, 0x0f, 0xaf, 0xc2, 0x48, 0xc1, 0xe8, 0x21,
        0xc3,
    ];
    let text = decompile_x64(&BYTES);
    assert!(!text.contains(" / "), "{text}");
}
