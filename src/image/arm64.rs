use exarmo_aarch64::{
    BranchKind, Instruction, Mnemonic, Operand, Reg, Shift_Lsl0_Lsl12, Writeback, operands::Offset,
};

use crate::Result;

pub fn assembly(bytes: &[u8], address: u64) -> String {
    bytes
        .chunks(4)
        .enumerate()
        .map(|(index, bytes)| {
            let address = address + index as u64 * 4;
            exarmo_aarch64::decode_bytes(bytes).map_or_else(
                |_| format!("{bytes:02X?}"),
                |instruction| instruction.at(address).to_string(),
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn register(register: Reg) -> Option<usize> {
    match register {
        Reg::W(register) => (!register.is_zr()).then_some(register.num() as usize),
        Reg::X(register) => (!register.is_zr()).then_some(register.num() as usize),
        Reg::WX(register) => (!register.is_zr()).then_some(register.num() as usize),
        Reg::WSp(register) => Some(register.num() as usize),
        Reg::XSp(register) => Some(register.num() as usize),
        Reg::WXSp(register) => Some(register.num() as usize),
        _ => None,
    }
}

pub fn references(
    bytes: &[u8],
    address: u64,
    mut record: impl FnMut(u64, u64) -> Result<()>,
) -> Result<()> {
    let mut values = [None; 32];
    for (index, bytes) in bytes.as_chunks::<4>().0.iter().enumerate() {
        let address = address + index as u64 * 4;
        let Ok(instruction) = exarmo_aarch64::decode_word(u32::from_le_bytes(*bytes)) else {
            values.fill(None);
            continue;
        };
        let operands = instruction.operands();
        let label = operands.iter().find_map(|operand| match operand {
            Operand::Label { offset, pc } => Some(pc.target(address, *offset, 64)),
            _ => None,
        });
        if let Some(target) = label {
            record(address, target)?;
        }
        let value = match instruction {
            Instruction::AdrOnlyPcreladdr { Xd, .. }
            | Instruction::AdrpOnlyPcreladdr { Xd, .. } => label
                .filter(|_| !Xd.is_zr())
                .map(|target| (Xd.num() as usize, target)),
            Instruction::Add64AddsubImm { Xd, Xn, imm, shift } => {
                values[Xn.num() as usize].map(|base: u64| {
                    let shift = match shift {
                        Shift_Lsl0_Lsl12::Lsl0 => 0,
                        Shift_Lsl0_Lsl12::Lsl12 => 12,
                    };
                    (
                        Xd.num() as usize,
                        base.wrapping_add(u64::from(imm) << shift),
                    )
                })
            }
            Instruction::MovAdd64AddsubImm { Xd, Xn } => {
                values[Xn.num() as usize].map(|value| (Xd.num() as usize, value))
            }
            Instruction::MovOrr64LogShift { Xd, Xm } if !Xd.is_zr() && !Xm.is_zr() => {
                values[Xm.num() as usize].map(|value| (Xd.num() as usize, value))
            }
            _ => None,
        };
        for operand in &operands {
            if let Operand::Mem(memory) = operand
                && let Some(index) = register(memory.base)
                && let Some(base) = values[index]
            {
                let offset = match (memory.writeback, memory.offset) {
                    (Writeback::Post, _) | (_, Offset::None) => Some(0),
                    (
                        _,
                        Offset::Imm {
                            value,
                            mul_vl: false,
                        },
                    ) => Some(value),
                    _ => None,
                };
                if let Some(offset) = offset {
                    record(address, base.wrapping_add_signed(offset))?;
                }
                if memory.writeback != Writeback::None {
                    values[index] = None;
                }
            }
        }
        let branch = instruction.branch();
        if branch.kind == BranchKind::None
            && !matches!(
                instruction.mnemonic(),
                Mnemonic::Cmp
                    | Mnemonic::Cmn
                    | Mnemonic::Tst
                    | Mnemonic::Ccmp
                    | Mnemonic::Ccmn
                    | Mnemonic::Str
                    | Mnemonic::Strb
                    | Mnemonic::Strh
                    | Mnemonic::Stur
                    | Mnemonic::Sturb
                    | Mnemonic::Sturh
                    | Mnemonic::Stp
                    | Mnemonic::Stnp
                    | Mnemonic::Stlr
                    | Mnemonic::Stlrb
                    | Mnemonic::Stlrh
            )
        {
            if let Some(Operand::Reg(operand)) = operands.first()
                && let Some(index) = register(operand.reg)
            {
                values[index] = None;
            }
            if let Some(Operand::Reg(operand)) = operands.get(1)
                && operands
                    .iter()
                    .any(|operand| matches!(operand, Operand::Mem(_)))
                && let Some(index) = register(operand.reg)
            {
                values[index] = None;
            }
        }
        if let Some((index, target)) = value {
            values[index] = Some(target);
            if label != Some(target) {
                record(address, target)?;
            }
        }
        if matches!(
            branch.kind,
            BranchKind::DirectCall | BranchKind::IndirectCall
        ) {
            values[..19].fill(None);
            values[30] = None;
        } else if branch.kind != BranchKind::None
            || operands.is_empty() && instruction.mnemonic() != Mnemonic::Nop
        {
            values.fill(None);
        }
    }
    Ok(())
}
