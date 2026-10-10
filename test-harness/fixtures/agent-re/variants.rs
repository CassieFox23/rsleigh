//! Deterministic seed.rs variants for comparison and investigation workflows
//! (Apache-2.0). Every mutation and its ground truth is described inline;
//! seed.asm documents the unmodified functions.
#![allow(dead_code)]
use super::re_seed as seed;

/// File offset of a seed virtual address (.text maps 0x401000 to 0x200).
fn offset(address: u64) -> usize {
    (address - 0x401000 + 0x200) as usize
}

/// Re-target the `call rel32` at `site` to `target`.
fn call(bytes: &mut [u8], site: u64, target: u64) {
    let at = offset(site);
    let displacement = target.wrapping_sub(site + 5) as u32;
    bytes[at + 1..at + 5].copy_from_slice(&displacement.to_le_bytes());
}

/// `calls` moves from 0x401020 to 0x4010a0 with its rel32 calls re-targeted
/// to `helper` and its export updated: identical code at a new address. Its
/// raw bytes change only in the two call displacements.
pub fn relocated() -> Vec<u8> {
    let mut bytes = seed::binary();
    let code = bytes[offset(0x401020)..offset(0x401039)].to_vec();
    bytes[offset(0x401020)..offset(0x401039)].fill(0x90);
    bytes[offset(0x4010a0)..offset(0x4010b9)].copy_from_slice(&code);
    call(&mut bytes, 0x4010a4, 0x401080);
    call(&mut bytes, 0x4010b0, 0x401080);
    bytes[0x32c..0x330].copy_from_slice(&0x10a0u32.to_le_bytes());
    bytes
}

/// `constant` returns 8 instead of 7 (`mov eax, 8`).
pub fn changed_constant() -> Vec<u8> {
    let mut bytes = seed::binary();
    bytes[offset(0x401001)] = 8;
    bytes
}

/// The second call in `calls` (0x401030) targets `constant`, not `helper`.
pub fn changed_callee() -> Vec<u8> {
    let mut bytes = seed::binary();
    call(&mut bytes, 0x401030, 0x401000);
    bytes
}

/// `load`'s export name points at "helper": two exports share one name.
pub fn duplicate_name() -> Vec<u8> {
    let mut bytes = seed::binary();
    bytes[0x348..0x34c].copy_from_slice(&(0x37eu32 + 0xe00).to_le_bytes());
    bytes
}

/// `load` is exported as "lode"; its code is unchanged.
pub fn renamed() -> Vec<u8> {
    let mut bytes = seed::binary();
    bytes[0x379..0x37d].copy_from_slice(b"lode");
    bytes
}

/// `load` becomes `call eax; ret`: its return value comes from an
/// unresolved indirect call (boundary `unknown_call`).
pub fn indirect_call() -> Vec<u8> {
    let mut bytes = seed::binary();
    bytes[offset(0x401060)..offset(0x401063)].copy_from_slice(b"\xff\xd0\xc3");
    bytes
}

/// `load` loses its `ret` and falls through NOPs into a lone 0x0f at
/// 0x40107f: its reachable body cannot be fully decoded.
pub fn truncated() -> Vec<u8> {
    let mut bytes = seed::binary();
    bytes[offset(0x401062)..offset(0x401080)].fill(0x90);
    bytes[offset(0x40107f)] = 0x0f;
    bytes
}
