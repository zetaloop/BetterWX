use std::{
    cell::OnceCell,
    collections::{BTreeMap, BTreeSet, hash_map::Entry},
    ffi::CStr,
    num::NonZero,
    ops::Range,
    sync::Arc,
};

use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderOptions, FastFormatter, Instruction,
    InstructionBlock, Mnemonic, OpKind, Register, code_asm::CodeAssembler,
};
use object::endian::LittleEndian as LE;
use object::read::macho::{FatArch, MachOFatFile32, MachOFatFile64, Section};
use object::read::pe::Import;
use object::read::{ExportTarget, NameOrOrdinal, Object, ObjectSection, ObjectSegment};
use object::{Architecture, FileKind, SectionKind, macho, pe};
use rustc_hash::FxHashMap;

use crate::{Result, data::Data, feature::Edit, progress::Progress, xlog::Records};

mod arm64;

pub type Symbols = BTreeMap<String, Vec<u64>>;

pub struct ExceptionState {
    pub instruction: u64,
    pub offset: usize,
    pub state: i32,
}

pub fn assembly(bytes: &[u8], address: u64) -> String {
    format(Decoder::with_ip(64, bytes, address, DecoderOptions::NONE))
}

pub fn calls(body: &[Instruction]) -> impl DoubleEndedIterator<Item = (usize, u64)> + '_ {
    body.iter().enumerate().filter_map(|(index, instruction)| {
        (instruction.code() == Code::Call_rel32_64)
            .then_some((index, instruction.near_branch_target()))
    })
}

pub fn argument(body: &[Instruction], index: usize, register: Register) -> Result<Instruction> {
    body[..index]
        .iter()
        .rev()
        .take_while(|instruction| instruction.mnemonic() != Mnemonic::Call)
        .find(|instruction| {
            instruction.op0_kind() == OpKind::Register
                && instruction.op0_register().full_register() == register.full_register()
        })
        .copied()
        .ok_or_else(|| format!("找不到参数寄存器 {register:?}").into())
}

pub fn literal(body: &[Instruction], index: usize, register: Register) -> Result<u64> {
    let argument = argument(body, index, register)?;
    if argument.mnemonic() != Mnemonic::Lea || !argument.is_ip_rel_memory_operand() {
        return Err("参数不是静态地址".into());
    }
    Ok(argument.ip_rel_memory_address())
}

fn format(instructions: impl IntoIterator<Item = Instruction>) -> String {
    let mut formatter = FastFormatter::new();
    instructions
        .into_iter()
        .map(|instruction| {
            let mut text = String::new();
            formatter.format(&instruction, &mut text);
            text
        })
        .collect::<Vec<_>>()
        .chunk_by(|left, right| left == right)
        .map(|run| {
            if run.len() == 1 {
                run[0].clone()
            } else {
                format!("{} × {}", run[0], run.len())
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

pub struct References {
    functions: Arc<[Range<u64>]>,
    targets: FxHashMap<u64, Callers>,
    entries: Vec<Reference>,
}

struct Callers {
    first: u32,
    last: u32,
}

struct Reference {
    function: u32,
    next: Option<NonZero<u32>>,
}

impl References {
    pub fn get(&self, address: u64) -> Option<impl Iterator<Item = &Range<u64>>> {
        self.targets.get(&address).map(|callers| {
            std::iter::successors(Some(callers.first as usize), |index| {
                self.entries[*index]
                    .next
                    .map(|next| next.get() as usize - 1)
            })
            .map(|index| &self.functions[self.entries[index].function as usize])
        })
    }

    fn insert(&mut self, address: u64, function: usize) {
        let index = u32::try_from(self.entries.len()).expect("reference index overflow");
        let function = u32::try_from(function).expect("function index overflow");
        match self.targets.entry(address) {
            Entry::Occupied(mut entry) => {
                let callers = entry.get_mut();
                if self.entries[callers.last as usize].function == function {
                    return;
                }
                self.entries[callers.last as usize].next = NonZero::new(index + 1);
                callers.last = index;
            }
            Entry::Vacant(entry) => {
                entry.insert(Callers {
                    first: index,
                    last: index,
                });
            }
        }
        self.entries.push(Reference {
            function,
            next: None,
        });
    }
}

pub fn functions(
    name: &str,
    symbols: &Symbols,
    references: &References,
) -> BTreeMap<u64, Range<u64>> {
    symbols[name]
        .iter()
        .filter_map(|address| references.get(*address))
        .flatten()
        .map(|function| (function.start, function.clone()))
        .collect()
}

pub struct Image<'a> {
    file: object::File<'a>,
    range: Range<usize>,
    base: u64,
    end: u64,
    functions: OnceCell<std::result::Result<Arc<[Range<u64>]>, String>>,
    pub logs: OnceCell<std::result::Result<Records, String>>,
}

impl<'a> Image<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Vec<Self>> {
        let ranges: Vec<_> = match FileKind::parse(data)? {
            FileKind::MachOFat32 => MachOFatFile32::parse(data)?
                .arches()
                .iter()
                .map(FatArch::file_range)
                .collect(),
            FileKind::MachOFat64 => MachOFatFile64::parse(data)?
                .arches()
                .iter()
                .map(FatArch::file_range)
                .collect(),
            _ => vec![(0, data.len() as u64)],
        };
        if ranges.is_empty() {
            return Err("文件没有可分析的映像".into());
        }
        ranges
            .into_iter()
            .map(|(offset, size)| {
                let start = usize::try_from(offset)?;
                let end = start
                    .checked_add(usize::try_from(size)?)
                    .ok_or("映像范围溢出")?;
                let range = start..end;
                let bytes = data.get(range.clone()).ok_or("映像范围超出文件")?;
                let file = object::File::parse(bytes)?;
                let (base, end) = match &file {
                    object::File::Pe64(file) => {
                        let base = file.relative_address_base();
                        let size =
                            u64::from(file.nt_headers().optional_header.size_of_image.get(LE));
                        (base, base.checked_add(size).ok_or("映像地址溢出")?)
                    }
                    object::File::MachO64(file) => {
                        let base = file
                            .segments()
                            .find(|segment| segment.name() == Ok(Some("__TEXT")))
                            .ok_or("找不到 Mach-O 代码段")?
                            .address();
                        let end = file
                            .segments()
                            .try_fold(base, |end, segment| -> Result<_> {
                                Ok(end.max(
                                    segment
                                        .address()
                                        .checked_add(segment.size())
                                        .ok_or("映像地址溢出")?,
                                ))
                            })?;
                        (base, end)
                    }
                    _ => return Err("需要 64 位 PE 或 Mach-O 文件".into()),
                };
                Ok(Self {
                    file,
                    range,
                    base,
                    end,
                    functions: OnceCell::new(),
                    logs: OnceCell::new(),
                })
            })
            .collect()
    }

    pub fn architecture(&self) -> Architecture {
        self.file.architecture()
    }

    pub fn contains(&self, offset: usize) -> bool {
        self.range.contains(&offset)
    }

    pub fn assembly(&self, bytes: &[u8], address: u64) -> String {
        match self.architecture() {
            Architecture::Aarch64 => arm64::assembly(bytes, address),
            _ => assembly(bytes, address),
        }
    }

    pub fn base(&self) -> u64 {
        self.base
    }

    pub fn end(&self) -> u64 {
        self.end
    }

    pub fn imports(&self) -> Result<Symbols> {
        match &self.file {
            object::File::MachO64(file) => {
                let mut found = Symbols::new();
                let endian = file.endian();
                let symbols = file.macho_symbol_table();
                let mut commands = file.macho_load_commands()?;
                while let Some(command) = commands.next()? {
                    let Some(table) = command.dysymtab()? else {
                        continue;
                    };
                    let indirect = table.indirect_symbols(endian, file.data())?;
                    for section in file.sections() {
                        let raw = section.macho_section();
                        let size = match raw.symbol_stub_size(endian) {
                            0 => 8,
                            size => size,
                        };
                        for (index, symbol) in
                            raw.indirect_symbols(endian, indirect)?.iter().enumerate()
                        {
                            let Some(symbol) = symbol.get(endian).index() else {
                                continue;
                            };
                            let symbol = symbols.symbol(object::SymbolIndex(symbol as usize))?;
                            let name = symbols.symbol_name(endian, symbol)?;
                            found
                                .entry(std::str::from_utf8(name)?.to_owned())
                                .or_default()
                                .push(section.address() + index as u64 * u64::from(size));
                        }
                    }
                }
                Ok(found)
            }
            object::File::Pe64(file) => self.pe_imports(file),
            _ => unreachable!(),
        }
    }

    fn pe_imports(&self, file: &object::read::pe::PeFile64<'a>) -> Result<Symbols> {
        let mut found = Symbols::new();
        if let Some(table) = file.import_table()? {
            let mut descriptors = table.descriptors()?;
            while let Some(descriptor) = descriptors.next()? {
                let lookup = descriptor.original_first_thunk.get(LE);
                let mut address = self.base() + u64::from(descriptor.first_thunk.get(LE));
                let mut thunks = table.thunks(if lookup == 0 {
                    descriptor.first_thunk.get(LE)
                } else {
                    lookup
                })?;
                while let Some(thunk) = thunks.next::<pe::ImageNtHeaders64>()? {
                    if let Import::Name(_, name) = table.import::<pe::ImageNtHeaders64>(thunk)? {
                        found
                            .entry(std::str::from_utf8(name)?.to_owned())
                            .or_default()
                            .push(address);
                    }
                    address += 8;
                }
            }
        }
        if let Some(table) = file.delay_load_import_table()? {
            let mut descriptors = table.descriptors()?;
            while let Some(descriptor) = descriptors.next()? {
                if descriptor.attributes.get(LE) & pe::IMAGE_DELAYLOAD_RVA_BASED == 0 {
                    return Err("延迟导入表使用了无法识别的地址格式".into());
                }
                let mut address =
                    self.base() + u64::from(descriptor.import_address_table_rva.get(LE));
                let mut thunks = table.thunks(descriptor.import_name_table_rva.get(LE))?;
                while let Some(thunk) = thunks.next::<pe::ImageNtHeaders64>()? {
                    if let Import::Name(_, name) = table.import::<pe::ImageNtHeaders64>(thunk)? {
                        found
                            .entry(std::str::from_utf8(name)?.to_owned())
                            .or_default()
                            .push(address);
                    }
                    address += 8;
                }
            }
        }
        Ok(found)
    }

    pub fn sections(&self) -> Result<Vec<(u64, &'a [u8])>> {
        self.file
            .sections()
            .map(|section| Ok((section.address(), section.data()?)))
            .collect()
    }

    pub fn data(&self, address: u64, size: usize) -> Result<&'a [u8]> {
        for section in self.file.sections() {
            if let Some(offset) = address.checked_sub(section.address()) {
                let data = section.data()?;
                if let Some(end) = (offset as usize).checked_add(size)
                    && let Some(bytes) = data.get(offset as usize..end)
                {
                    return Ok(bytes);
                }
            }
        }
        Err(format!("地址 {address:#x} 的数据不在文件中").into())
    }

    pub fn offset(&self, address: u64) -> Result<usize> {
        for section in self.file.sections() {
            if let Some(offset) = address.checked_sub(section.address())
                && let Some((start, size)) = section.file_range()
                && offset < size
            {
                return Ok(self.range.start + (start + offset) as usize);
            }
        }
        Err(format!("地址 {address:#x} 没有对应的文件位置").into())
    }

    pub fn address(&self, offset: usize) -> Result<u64> {
        let position = offset
            .checked_sub(self.range.start)
            .ok_or("文件位置不在映像中")?;
        self.file
            .sections()
            .find_map(|section| {
                let (start, size) = section.file_range()?;
                let offset = (position as u64).checked_sub(start)?;
                (offset < size).then_some(section.address() + offset)
            })
            .ok_or_else(|| format!("文件位置 {offset:#x} 没有对应的地址").into())
    }

    pub fn difference(&self, range: &Range<usize>, before: &Data, after: &Data) -> Result<String> {
        let address = self.address(range.start).ok();
        let mut start = address;
        let mut values = Vec::new();
        for data in [before, after] {
            if let Some(address) = address
                && let Some(function) = self.function(address)?
                && address + range.len() as u64 <= function.end
            {
                let offset = self.offset(function.start)?;
                let end = offset + (function.end - function.start) as usize;
                let bytes = data
                    .get(offset.min(data.len())..end.min(data.len()))
                    .expect("function content range");
                if self.architecture() == Architecture::Aarch64 {
                    let first = (address - function.start) as usize / 4 * 4;
                    let end = ((address - function.start) as usize + range.len())
                        .next_multiple_of(4)
                        .min(bytes.len());
                    start = Some(function.start + first as u64);
                    values.push(self.assembly(
                        &bytes[first.min(bytes.len())..end],
                        function.start + first as u64,
                    ));
                    continue;
                }
                let mut instructions =
                    Decoder::with_ip(64, &bytes, function.start, DecoderOptions::NONE)
                        .into_iter()
                        .take_while(|instruction| instruction.ip() < address + range.len() as u64)
                        .filter(|instruction| instruction.next_ip() > address)
                        .peekable();
                if let Some(instruction) = instructions.peek() {
                    start = start.map(|address| address.min(instruction.ip()));
                }
                values.push(format(instructions));
            } else {
                values.push(format!(
                    "{:02X?}",
                    data.get(range.start.min(data.len())..range.end.min(data.len()))
                        .expect("content range")
                ));
            }
        }
        let location = start.map_or_else(
            || format!("offset 0x{:08X}", range.start),
            |address| format!("RVA 0x{:08X}", address - self.base()),
        );
        Ok(format!("{location}；{} → {}", values[0], values[1]))
    }

    pub fn instructions(&self, function: &Range<u64>) -> Result<Vec<Instruction>> {
        if self.architecture() != Architecture::X86_64 {
            return Err("该分析需要 x64 指令".into());
        }
        let bytes = self.data(function.start, (function.end - function.start) as usize)?;
        Ok(
            Decoder::with_ip(64, bytes, function.start, DecoderOptions::NONE)
                .into_iter()
                .collect(),
        )
    }

    pub fn unwind_info(&self, address: u64) -> Result<u64> {
        let entry = self
            .unwind()?
            .iter()
            .find(|entry| {
                self.base()
                    + u32::from_le_bytes(entry[..4].try_into().expect("function RVA")) as u64
                    == address
            })
            .ok_or("找不到函数展开记录")?;
        Ok(self.base() + u32::from_le_bytes(entry[8..].try_into()?) as u64)
    }

    pub fn replace_function(
        &self,
        function: &Range<u64>,
        code: &mut CodeAssembler,
        unwind: &[u8],
    ) -> Result<Vec<Edit>> {
        let bytes = code.assemble(function.start)?;
        let size = usize::try_from(function.end - function.start)?;
        if bytes.len() > size {
            return Err(format!(
                "RVA {:#x} 的指令空间不足：需要 {} 字节，可用 {size} 字节",
                function.start - self.base(),
                bytes.len(),
            )
            .into());
        }
        let offset = self.offset(function.start)?;
        let mut edits = vec![Edit {
            range: offset..offset + bytes.len(),
            bytes,
        }];
        let address = self.unwind_info(function.start)?;
        if self.data(address, unwind.len())? != unwind {
            let header = self.data(address, 4)?;
            let size = (4 + usize::from(header[2]) * 2).next_multiple_of(4);
            let shared = self
                .unwind()?
                .iter()
                .filter(|entry| {
                    u32::from_le_bytes(entry[8..].try_into().expect("unwind RVA")) as u64
                        == address - self.base()
                })
                .count();
            if shared != 1 || unwind.len() > size {
                return Err("原函数的展开信息无法原位改写".into());
            }
            let offset = self.offset(address)?;
            let mut bytes = unwind.to_vec();
            bytes.resize(size, 0);
            edits.push(Edit {
                range: offset..offset + size,
                bytes,
            });
        }
        Ok(edits)
    }

    pub fn exception_states(&self, address: u64) -> Result<Vec<ExceptionState>> {
        let unwind = self.unwind_info(address)?;
        let header = self.data(unwind, 4)?;
        let flags = header[0] >> 3;
        if flags & 4 != 0 {
            return Err("函数使用了链式展开信息".into());
        }
        if flags & 3 == 0 {
            return Ok(Vec::new());
        }
        let offset = (4 + usize::from(header[2]) * 2).next_multiple_of(4);
        let info = self.base()
            + u64::from(u32::from_le_bytes(
                self.data(unwind + offset as u64 + 4, 4)?.try_into()?,
            ));
        let header = self.data(info, 40)?;
        if u32::from_le_bytes(header[..4].try_into()?) & 0x1fff_ffff != 0x1993_0522 {
            return Err("无法识别函数的 C++ 异常状态信息".into());
        }
        let count = u32::from_le_bytes(header[20..24].try_into()?) as usize;
        if count == 0 {
            return Ok(Vec::new());
        }
        let table = self.base() + u64::from(u32::from_le_bytes(header[24..28].try_into()?));
        let offset = self.offset(table)?;
        self.data(table, count.checked_mul(8).ok_or("异常状态表长度溢出")?)?
            .as_chunks::<8>()
            .0
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                Ok(ExceptionState {
                    instruction: self.base()
                        + u64::from(u32::from_le_bytes(entry[..4].try_into()?)),
                    offset: offset + index * 8,
                    state: i32::from_le_bytes(entry[4..].try_into()?),
                })
            })
            .collect()
    }

    pub fn reencode(
        &self,
        function: &Range<u64>,
        instructions: &[Instruction],
    ) -> Result<Vec<Edit>> {
        let result = BlockEncoder::encode(
            64,
            InstructionBlock::new(instructions, function.start),
            BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
        )?;
        let bytes = result.code_buffer;
        let length = usize::try_from(function.end - function.start)?;
        if bytes.len() > length {
            return Err(format!(
                "RVA {:#x} 的指令空间不足：需要 {} 字节，可用 {length} 字节",
                function.start - self.base(),
                bytes.len(),
            )
            .into());
        }
        let unwind = self.data(self.unwind_info(function.start)?, 4)?;
        let prologue = usize::from(unwind[1]);
        if bytes.get(..prologue) != Some(self.data(function.start, prologue)?) {
            return Err("重排后的函数序言与展开信息不符".into());
        }
        let mut locations = BTreeMap::new();
        for (instruction, offset) in instructions.iter().zip(result.new_instruction_offsets) {
            if offset == u32::MAX {
                return Err("指令展开后无法对应原异常状态".into());
            }
            if locations
                .insert(instruction.ip(), function.start + u64::from(offset))
                .is_some()
            {
                return Err("待重排指令的位置重复".into());
            }
        }
        locations.insert(function.end, function.start + bytes.len() as u64);
        let offset = self.offset(function.start)?;
        let mut edits = vec![Edit {
            range: offset..offset + bytes.len(),
            bytes,
        }];
        for state in self.exception_states(function.start)? {
            if !function.contains(&state.instruction) && state.instruction != function.end {
                continue;
            }
            let address = *locations
                .get(&state.instruction)
                .ok_or("找不到异常状态对应的指令")?;
            if address != state.instruction {
                edits.push(Edit {
                    range: state.offset..state.offset + 4,
                    bytes: u32::try_from(address - self.base())?.to_le_bytes().to_vec(),
                });
            }
        }
        Ok(edits)
    }

    pub fn find(&self, name: &str, value: &[u8], progress: &Progress) -> Result<Vec<u64>> {
        Ok(self
            .find_many([(name, value)], progress)?
            .remove(name)
            .expect("search result"))
    }

    pub fn find_many<'b, T: AsRef<[u8]>>(
        &self,
        values: impl IntoIterator<Item = (&'b str, T)>,
        progress: &Progress,
    ) -> Result<Symbols> {
        let values: Vec<_> = values.into_iter().collect();
        let Some((name, _)) = values.first() else {
            return Ok(Symbols::new());
        };
        let overlap = values
            .iter()
            .map(|(_, value)| value.as_ref().len())
            .max()
            .unwrap_or_default()
            .saturating_sub(1);
        let step = progress.activity("查找字符串");
        let target = name.trim_end_matches('\0');
        step.detail(target.to_owned());
        let mut addresses = vec![Vec::new(); values.len()];
        let mut next = vec![0; values.len()];
        for (address, data) in self.sections()? {
            next.fill(0);
            for start in (0..=data.len()).step_by(1024 * 1024) {
                progress.check()?;
                let end = (start + 1024 * 1024).min(data.len());
                let limit = end.saturating_add(overlap).min(data.len());
                for (index, (name, value)) in values.iter().enumerate() {
                    let cursor = next[index].max(start);
                    if cursor > limit {
                        continue;
                    }
                    if step.sample() {
                        step.detail(format!(
                            "{}；{} 处匹配\n搜索 RVA {:#x}",
                            name.trim_end_matches('\0'),
                            addresses[index].len(),
                            address + cursor as u64 - self.base()
                        ));
                    }
                    let value = value.as_ref();
                    for offset in memchr::memmem::find_iter(&data[cursor..limit], value) {
                        let offset = cursor + offset;
                        if offset >= end && end != data.len() {
                            break;
                        }
                        step.record(format!(
                            "{} → RVA {:#x}",
                            name.trim_end_matches('\0'),
                            address + offset as u64 - self.base()
                        ));
                        addresses[index].push(address + offset as u64);
                        next[index] = offset + value.len().max(1);
                    }
                }
            }
        }
        let multiple = values.len() > 1;
        let count = addresses.iter().map(Vec::len).sum::<usize>();
        let summary = if multiple {
            format!("{} 个目标；{count} 处匹配", values.len())
        } else if count == 0 {
            format!("{target}：未找到")
        } else {
            format!("{target}：{count} 处匹配")
        };
        let mut symbols = Symbols::new();
        for ((name, _), addresses) in values.into_iter().zip(addresses) {
            if multiple && addresses.len() != 1 {
                let target = name.trim_end_matches('\0');
                step.record(if addresses.is_empty() {
                    format!("{target}：未找到")
                } else {
                    format!("{target}：{} 处匹配", addresses.len())
                });
            }
            symbols.insert(name.to_owned(), addresses);
        }
        step.finish(summary);
        Ok(symbols)
    }

    pub fn references(
        &self,
        name: &str,
        labels: BTreeMap<u64, String>,
        progress: &Progress,
        mut visit: impl FnMut(&References, &Range<u64>, &BTreeSet<u64>) -> Result<()>,
    ) -> Result<References> {
        let mut exports = BTreeMap::new();
        for export in self.file.exports()? {
            let export = export?;
            if let (NameOrOrdinal::Name(name), ExportTarget::Address { address }) =
                (export.name(), export.target())
            {
                exports.insert(address, String::from_utf8_lossy(name).into_owned());
            }
        }
        let mut references = References {
            functions: self.functions()?,
            targets: FxHashMap::default(),
            entries: Vec::new(),
        };
        let step = progress.start("分析代码引用", references.functions.len() as u64, "函数");
        step.detail(name);
        for index in 0..references.functions.len() {
            let function = references.functions[index].clone();
            progress.check()?;
            let bytes = self.data(function.start, (function.end - function.start) as usize)?;
            let mut changed = BTreeSet::new();
            let mut record = |address, length, target| -> Result<()> {
                references.insert(target, index);
                let symbol = labels.get(&target);
                if symbol.is_some() {
                    changed.insert(target);
                }
                let sampled = step.sample();
                if sampled || symbol.is_some() {
                    let bytes = self.data(address, length)?;
                    let label = exports.get(&function.start).or(symbol);
                    let mut detail = name.to_owned();
                    if let Some(symbol) = label {
                        detail.push_str(&format!("；{symbol}"));
                    }
                    detail.push_str(&format!(
                        "；RVA 0x{:08X}；{} → {}",
                        address - self.base(),
                        bytes
                            .iter()
                            .map(|byte| format!("{byte:02X}"))
                            .collect::<Vec<_>>()
                            .join(" "),
                        self.assembly(bytes, address),
                    ));
                    if let Some(symbol) = symbol.or_else(|| exports.get(&target)) {
                        if Some(symbol) != label {
                            detail.push_str(&format!("；{symbol}"));
                        }
                    } else if let Some(value) = self.string(target) {
                        detail.push_str(&format!("；{value:?}"));
                    }
                    step.detail(detail);
                }
                Ok(())
            };
            match self.architecture() {
                Architecture::X86_64 => {
                    let mut decoder =
                        Decoder::with_ip(64, bytes, function.start, DecoderOptions::NONE);
                    let mut instruction = Instruction::default();
                    while decoder.can_decode() {
                        decoder.decode_out(&mut instruction);
                        let target = if instruction.is_ip_rel_memory_operand() {
                            instruction.ip_rel_memory_address()
                        } else if instruction.op0_kind() == OpKind::NearBranch64 {
                            instruction.near_branch_target()
                        } else {
                            continue;
                        };
                        record(instruction.ip(), instruction.len(), target)?;
                    }
                }
                Architecture::Aarch64 => {
                    arm64::references(bytes, function.start, |address, target| {
                        record(address, 4, target)
                    })?;
                }
                _ => return Err("无法分析该架构的代码引用".into()),
            }
            step.set(index as u64 + 1);
            if !changed.is_empty() {
                visit(&references, &function, &changed)?;
            }
        }
        step.finish(format!(
            "{name}；{} 函数；{} 目标；{} 引用",
            references.functions.len(),
            references.targets.len(),
            references.entries.len(),
        ));
        Ok(references)
    }

    fn string(&self, address: u64) -> Option<&str> {
        for section in self.file.sections() {
            let Some(offset) = address.checked_sub(section.address()) else {
                continue;
            };
            let Some(data) = section.data().ok()?.get(offset as usize..) else {
                continue;
            };
            let text = CStr::from_bytes_until_nul(data).ok()?.to_str().ok()?;
            if text.chars().count() > 1 && text.chars().all(|character| !character.is_control()) {
                return Some(text);
            }
        }
        None
    }

    fn unwind(&self) -> Result<&'a [[u8; 12]]> {
        let object::File::Pe64(file) = &self.file else {
            return Err("该映像不使用 PE 异常展开目录".into());
        };
        if self.architecture() != Architecture::X86_64 {
            return Err("无法读取该架构的 PE 异常展开目录".into());
        }
        let directory = file
            .data_directory(pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION)
            .ok_or("找不到异常展开目录")?;
        Ok(self
            .data(
                self.base() + u64::from(directory.virtual_address.get(LE)),
                directory.size.get(LE) as usize,
            )?
            .as_chunks::<12>()
            .0)
    }

    pub fn function(&self, address: u64) -> Result<Option<Range<u64>>> {
        let functions = self.functions()?;
        let index = functions.partition_point(|function| function.start <= address);
        Ok(index
            .checked_sub(1)
            .and_then(|index| functions.get(index))
            .filter(|function| function.contains(&address))
            .cloned())
    }

    pub fn functions(&self) -> Result<Arc<[Range<u64>]>> {
        self.functions
            .get_or_init(|| {
                self.read_functions()
                    .map(Arc::from)
                    .map_err(|error| error.to_string())
            })
            .as_ref()
            .cloned()
            .map_err(|error| error.clone().into())
    }

    fn read_functions(&self) -> Result<Vec<Range<u64>>> {
        if let object::File::MachO64(file) = &self.file {
            let mut commands = file.macho_load_commands()?;
            while let Some(command) = commands.next()? {
                if command.cmd() != macho::LC_FUNCTION_STARTS {
                    continue;
                }
                let command = command.data::<macho::LinkeditDataCommand<object::Endianness>>()?;
                let starts = command
                    .function_starts(file.endian(), file.data(), self.base())?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                let sections = file
                    .sections()
                    .filter(|section| section.kind() == SectionKind::Text)
                    .map(|section| {
                        Ok(section.address()
                            ..section
                                .address()
                                .checked_add(section.size())
                                .ok_or("代码节地址溢出")?)
                    })
                    .collect::<Result<Vec<_>>>()?;
                return starts
                    .iter()
                    .enumerate()
                    .map(|(index, &start)| {
                        let section = sections
                            .iter()
                            .find(|section| section.contains(&start))
                            .ok_or("函数起点不在代码节中")?;
                        let end = starts.get(index + 1).copied().unwrap_or(section.end);
                        Ok(start..end.min(section.end))
                    })
                    .collect();
            }
            return Err("找不到 Mach-O 函数起点表".into());
        }
        let mut functions = Vec::new();
        for entry in self.unwind()? {
            let start = u32::from_le_bytes(entry[..4].try_into()?) as u64;
            let end = u32::from_le_bytes(entry[4..8].try_into()?) as u64;
            if start < end {
                functions.push(self.base() + start..self.base() + end);
            }
        }
        Ok(functions)
    }
}
