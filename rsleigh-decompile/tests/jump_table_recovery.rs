//! Jump tables whose base is set far before the jump, and tables with more
//! than 256 entries, are recovered.
//! Fixture: test-harness/fixtures/elf/jump_tables (stripped x86-64 ELF).

use rsleigh_api::{Architecture, Decoder};
use rsleigh_decompile::jump_table::{find, ImageMemory, JumpTable};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../test-harness/fixtures/elf/jump_tables/jump_tables.elf"
);
/// Start and size of `.text`.
const TEXT: (u64, usize) = (0x4016c4, 0xad);
/// The computed jump in far_base, wide_table and offset_index.
const FAR_BASE_JUMP: u64 = 0x40170a;
const WIDE_TABLE_JUMP: u64 = 0x401733;
const OFFSET_INDEX_JUMP: u64 = 0x401760;

fn tables() -> Vec<JumpTable> {
    let image = std::fs::read(FIXTURE).unwrap();
    let memory = ImageMemory::new(&image);
    let bytes = memory.read(TEXT.0, TEXT.1).unwrap();
    let mut decoder = Decoder::new(Architecture::X86_64);
    let mut instructions = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let address = TEXT.0 + offset as u64;
        let inst = decoder.decode(&bytes[offset..], address).unwrap();
        offset += inst.len as usize;
        instructions.push((address, inst));
    }
    find(&instructions, &|va, len| memory.read(va, len))
}

fn table_at(jump: u64) -> JumpTable {
    tables()
        .into_iter()
        .find(|t| t.jump == jump)
        .unwrap_or_else(|| panic!("no table recovered for the jump at {jump:#x}"))
}

#[test]
fn table_base_set_twenty_instructions_before_the_jump() {
    // lea rdx, [table] ; 20 x nop ; cmp edi, 2 ; ja ; ... ; jmp rax
    assert_eq!(table_at(FAR_BASE_JUMP).targets.len(), 3);
}

#[test]
fn table_with_more_than_256_entries_keeps_every_entry() {
    // cmp edi, 299 ; ja: 300 entries, the last one a case of its own.
    let table = table_at(WIDE_TABLE_JUMP);
    assert_eq!(table.targets.len(), 300);
    assert_ne!(table.targets[299], table.targets[298]);
}

#[test]
fn index_built_by_add_and_overwritten_by_the_table_load() {
    // add edi, 5 ; cmp edi, 2 ; ja ; movsxd rdi, [rdx + rdi*4] ; add rdi, rdx ; jmp rdi
    let table = table_at(OFFSET_INDEX_JUMP);
    assert_eq!(table.targets.len(), 3);
}
