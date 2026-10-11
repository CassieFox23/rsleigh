//! SLEIGH `build` statements emit a subtable's P-code where the statement
//! stands. x86-64 `MOV r32, r32` is `{ Rmr32 = Reg32; build check_Rmr32_dest; }`,
//! so the zero extension into the 64-bit register follows the 32-bit write;
//! ARM `stmdb` computes each address before storing to it.

use rsleigh_api::{AddressSpaceId, Architecture, Decoder, PcodeOp};

fn writes(op: &PcodeOp, offset: u64, size: u32) -> bool {
    pcode_ir::get_output(op).is_some_and(|o| {
        o.space == AddressSpaceId::Register && o.offset == offset && o.size == size
    })
}

#[test]
fn x86_64_32bit_write_zero_extends_after_the_write() {
    // mov ecx, eax
    let inst = Decoder::new(Architecture::X86_64)
        .decode_unoptimized(&[0x89, 0xc1], 0x1000)
        .unwrap();
    let ecx = inst
        .ops
        .iter()
        .position(|op| writes(op, 8, 4))
        .expect("ECX write");
    let rcx = inst
        .ops
        .iter()
        .position(|op| writes(op, 8, 8))
        .expect("RCX write");
    assert!(ecx < rcx, "{:#?}", inst.ops);
}

#[test]
fn arm32_stmdb_computes_each_address_before_storing() {
    // stmdb sp!, {r4-r11, lr}
    let inst = Decoder::new(Architecture::ARM32)
        .decode_unoptimized(&[0xf0, 0x4f, 0x2d, 0xe9], 0x0)
        .unwrap();
    let first_store = inst
        .ops
        .iter()
        .position(|op| matches!(op, PcodeOp::Store { .. }))
        .expect("store");
    assert!(
        inst.ops[..first_store]
            .iter()
            .any(|op| matches!(op, PcodeOp::IntSub { .. })),
        "{:#?}",
        inst.ops
    );
}
