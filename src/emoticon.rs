use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

use iced_x86::{
    Code, Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register,
    code_asm::{
        AsmMemoryOperand, CodeAssembler, al, bl, byte_ptr, dword_ptr, eax, ebx, ecx, edx, esi, ptr,
        qword_ptr, r8, r8d, r9, r9b, r9d, r12, r14, rax, rbp, rbx, rcx, rdi, rdx, rsi, word_ptr,
        xmm0, xmm6,
    },
};

use crate::{
    Result,
    feature::{Analysis, Edit, Feature, Mode, Target},
    image::{Image, References, Symbols, argument, calls, functions, literal},
    progress::Progress,
    xlog,
};

const MENU: &str = "virtual mmui::ChatEmoticonItemViewModel::BuildContextMenuCustomizePart";
const CONSTRUCT: &str = "ChatEmoticonItemViewModel";
const CLICK: &str = "virtual mmui::ChatImageItemViewModel::OnBubbleClicked";
const RECORD: &str = "mmui::BaseMessageViewModel::OpenRecordPreview";
const PREVIEW: &str = "PreviewChatDownload";
const COPY: &str =
    "mmui::BaseChatMessageItemViewModel::OnMenuCopyMessageResource()::(lambda)::operator()";
const EXPORT: &str = "kernel::service::FileService::CopyToWriteAblePath(const kernel::MessageWrapper &)::(lambda)::operator()";
const DOWNLOAD: &str = "mmui::ChatFileItemViewModel::AddDownloadAction";
const BUFFER: &str = "kernel::manager::EmoticonManager::GetEmoticonDataWithMd5";
const INFO: &str = "kernel::EmoticonMsgInfo::GenMsgInfoFromMessage";
const EXTRA: &str = "virtual kernel::EmoticonMessageExtInfo::CopyFromOriginOnForward";
const READ: &str = "kernel::manager::ReadEmoticonData";
const SYNC_READ: &str = "kernel::manager::SyncReadEmoticonData";
const CONVERT: &str = "kernel::imageutil::ConvertWxam2Jpg";
const IMAGE_COPY: &str = "kernel::imageutil::CopyImage2Jpeg";
const FORMAT: &str = "kernel::imageutil::GetImageFormat";
const EXTENSION: &str = "kernel::imageutil::GetImageFormatStr";
const WRITE: &str = "kernel::fileutil::WriteFile";
const TEMP: &str = "RWTemp";
const NAMES: &[&str] = &[
    MENU, CONSTRUCT, CLICK, RECORD, PREVIEW, COPY, EXPORT, DOWNLOAD, BUFFER, INFO, EXTRA, READ,
    SYNC_READ, CONVERT, IMAGE_COPY, FORMAT, EXTENSION, WRITE,
];

pub const FEATURE: Feature = Feature {
    id: "emoticon",
    name: "表情复制为图片",
    description: "预览和复制动画表情",
    targets: &[Target {
        file: None,
        find,
        scan,
    }],
};

struct Scan {
    symbols: Symbols,
}

struct Native {
    menu: Range<u64>,
    copy: Range<u64>,
    schedule: Range<u64>,
    worker: Range<u64>,
    convert: Range<u64>,
    encoder: Range<u64>,
    filename: Range<u64>,
    click: Range<u64>,
    delegate: Range<u64>,
    preview: Range<u64>,
    loader: u64,
    info: u64,
    info_field: i64,
    message_field: i64,
    copy_table: u64,
    copy_text: u64,
    copy_blocked: u64,
    path: u64,
    exists: u64,
    path_destroy: u64,
    string_destroy: u64,
    shared_destroy: u64,
    shared_move: u64,
    set_destroy: u64,
    data_destroy: u64,
    utf8: u64,
    md5: u64,
    key: u64,
    read: u64,
    image_check: u64,
    format: u64,
    extension: u64,
    write: u64,
    image_copy: u64,
}

struct Body<'a, 'b> {
    image: &'a Image<'b>,
    function: Range<u64>,
    original: Vec<Instruction>,
    instructions: Vec<Instruction>,
    cursor: u64,
}

impl<'a, 'b> Body<'a, 'b> {
    fn new(image: &'a Image<'b>, function: &Range<u64>) -> Result<Self> {
        let original = image.instructions(function)?;
        Ok(Self {
            image,
            function: function.clone(),
            instructions: original.clone(),
            original,
            cursor: image.end(),
        })
    }

    fn replace(&mut self, range: Range<usize>, code: &mut CodeAssembler) -> Result<()> {
        let address = self.original[range.start].ip();
        let end = if range.end == self.original.len() {
            self.function.end
        } else {
            self.original[range.end].ip()
        };
        code.add_instruction(Instruction::with(Code::Zero_bytes))?;
        let bytes = code.assemble(self.cursor)?;
        let mut added = Decoder::with_ip(64, &bytes, self.cursor, DecoderOptions::NONE)
            .into_iter()
            .collect::<Vec<_>>();
        let mut end_label = Instruction::with(Code::Zero_bytes);
        end_label.set_ip(self.cursor + bytes.len() as u64);
        added.push(end_label);
        self.cursor += bytes.len() as u64 + 1;
        for instruction in &mut self.instructions {
            if address <= instruction.ip() && instruction.ip() < end {
                let ip = instruction.ip();
                *instruction = Instruction::with(Code::Zero_bytes);
                instruction.set_ip(ip);
            }
        }
        let index = self
            .instructions
            .iter()
            .position(|instruction| instruction.ip() == address)
            .ok_or("找不到待替换指令")?;
        self.instructions.splice(index + 1..index + 1, added);
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<Edit>> {
        let unwind = self
            .image
            .data(self.image.unwind_info(self.function.start)?, 4)?;
        let prologue = self.function.start + u64::from(unwind[1]);
        for instruction in &mut self.instructions {
            if instruction.ip() >= prologue && instruction.mnemonic() == Mnemonic::Nop {
                let ip = instruction.ip();
                *instruction = Instruction::with(Code::Zero_bytes);
                instruction.set_ip(ip);
            }
        }
        self.image.reencode(&self.function, &self.instructions)
    }
}

fn unique<T>(values: Vec<T>, name: &str) -> Result<T> {
    let count = values.len();
    let [value]: [T; 1] = values
        .try_into()
        .map_err(|_| format!("无法唯一定位{name}：找到 {count} 处"))?;
    Ok(value)
}

fn pointed(image: &Image<'_>, address: u64) -> Result<u64> {
    Ok(u64::from_le_bytes(image.data(address, 8)?.try_into()?))
}

fn function(image: &Image<'_>, address: u64) -> Result<Range<u64>> {
    image
        .function(address)?
        .filter(|function| function.start == address)
        .ok_or_else(|| format!("找不到函数：{address:#x}").into())
}

fn call(body: &[Instruction], target: u64) -> Result<usize> {
    unique(
        calls(body)
            .filter_map(|(index, address)| (address == target).then_some(index))
            .collect(),
        "原生函数调用",
    )
}

fn stack_argument(body: &[Instruction], index: usize, register: Register) -> Result<i64> {
    let argument = argument(body, index, register)?;
    if argument.mnemonic() != Mnemonic::Lea
        || argument.memory_base() != Register::RBP
        || argument.memory_index() != Register::None
    {
        return Err("无法识别参数的栈位置".into());
    }
    Ok(argument.memory_displacement64() as i64)
}

fn referenced(body: &[Instruction]) -> BTreeSet<u64> {
    body.iter()
        .filter(|instruction| instruction.is_ip_rel_memory_operand())
        .map(Instruction::ip_rel_memory_address)
        .collect()
}

fn callers(references: &References, address: u64) -> Vec<Range<u64>> {
    references
        .get(address)
        .into_iter()
        .flatten()
        .map(|function| (function.start, function.clone()))
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect()
}

fn transfer(image: &Image<'_>, progress: &Progress) -> Result<u64> {
    let mut found = Vec::new();
    for function in image.functions()?.iter() {
        progress.check()?;
        let bytes = image.data(function.start, (function.end - function.start) as usize)?;
        let mut prefix = Decoder::with_ip(64, bytes, function.start, DecoderOptions::NONE)
            .into_iter()
            .take_while(|instruction| instruction.mnemonic() != Mnemonic::Call);
        let Some(value) = prefix.find(|instruction| {
            instruction.code() == Code::Movups_xmm_xmmm128
                && instruction.memory_base() == Register::RDX
                && instruction.memory_index() == Register::None
                && instruction.memory_displacement64() == 0
        }) else {
            continue;
        };
        let Some(zero) = prefix.find(|instruction| {
            instruction.mnemonic() == Mnemonic::Xorps
                && instruction.op0_register() == instruction.op1_register()
                && instruction.op0_register() != value.op0_register()
        }) else {
            continue;
        };
        if !prefix.any(|instruction| {
            instruction.code() == Code::Movups_xmmm128_xmm
                && instruction.memory_base() == Register::RDX
                && instruction.memory_index() == Register::None
                && instruction.memory_displacement64() == 0
                && instruction.op1_register() == zero.op0_register()
        }) {
            continue;
        }
        let Some(owner) = prefix.find(|instruction| {
            instruction.code() == Code::Mov_r64_rm64
                && instruction.memory_base() == Register::RCX
                && instruction.memory_index() == Register::None
                && instruction.memory_displacement64() == 8
        }) else {
            continue;
        };
        if !prefix.any(|instruction| {
            instruction.code() == Code::Movups_xmmm128_xmm
                && instruction.memory_base() == Register::RCX
                && instruction.memory_index() == Register::None
                && instruction.memory_displacement64() == 0
                && instruction.op1_register() == value.op0_register()
        }) {
            continue;
        }
        let body = image.instructions(function)?;
        if calls(&body).next().is_some()
            || body.iter().any(|instruction| {
                instruction.op0_kind() == OpKind::Memory
                    && instruction.memory_base() == Register::RCX
                    && instruction.memory_displacement64() != 0
            })
        {
            continue;
        }
        let counters = body
            .iter()
            .filter(|instruction| {
                instruction.code() == Code::Dec_rm32
                    && instruction.has_lock_prefix()
                    && instruction.memory_base() == owner.op0_register()
            })
            .map(Instruction::memory_displacement64)
            .collect::<Vec<_>>();
        if counters == [8, 12] {
            found.push(function.start);
        }
    }
    unique(found, "共享对象移动赋值")
}

fn cleanup(image: &Image<'_>, range: &Range<u64>, state: i32) -> Result<Vec<Instruction>> {
    let state = usize::try_from(state)?;
    let unwind = image.unwind_info(range.start)?;
    let header = image.data(unwind, 4)?;
    let offset = (4 + usize::from(header[2]) * 2).next_multiple_of(4);
    let info = image.base()
        + u64::from(u32::from_le_bytes(
            image.data(unwind + offset as u64 + 4, 4)?.try_into()?,
        ));
    let header = image.data(info, 12)?;
    if u32::from_le_bytes(header[..4].try_into()?) & 0x1fff_ffff != 0x1993_0522
        || state >= u32::from_le_bytes(header[4..8].try_into()?) as usize
    {
        return Err("无法识别对象清理记录".into());
    }
    let table = image.base() + u64::from(u32::from_le_bytes(header[8..12].try_into()?));
    let target = image.base()
        + u64::from(u32::from_le_bytes(
            image.data(table + (state * 8 + 4) as u64, 4)?.try_into()?,
        ));
    image.instructions(&function(image, target)?)
}

fn tables(image: &Image<'_>, body: &[Instruction]) -> Result<Vec<u64>> {
    let mut result = Vec::new();
    for address in referenced(body) {
        let Ok(locator) = pointed(image, address - 8) else {
            continue;
        };
        let Ok(data) = image.data(locator, 24) else {
            continue;
        };
        if u32::from_le_bytes(data[..4].try_into()?) != 1
            || image.base() + u64::from(u32::from_le_bytes(data[20..24].try_into()?)) != locator
        {
            continue;
        }
        let Ok(target) = pointed(image, address + 16) else {
            continue;
        };
        if image.data(target, 1).is_ok() {
            result.push(address);
        }
    }
    Ok(result)
}

fn containing_callback(
    image: &Image<'_>,
    references: &References,
    target: u64,
    progress: &Progress,
) -> Result<Range<u64>> {
    let mut found = BTreeMap::new();
    for address in image.find("回调入口", &target.to_le_bytes(), progress)? {
        if address % 8 != 0 {
            continue;
        }
        for function in callers(references, address - 16) {
            found.insert(function.start, function);
        }
    }
    unique(found.into_values().collect(), "回调所属函数")
}

fn find(image: &Image<'_>, progress: &Progress) -> Result<Symbols> {
    let mut symbols = xlog::find(image, NAMES, progress)?;
    let name: Vec<_> = TEMP
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    symbols.insert(TEMP.to_owned(), image.find(TEMP, &name, progress)?);
    Ok(symbols)
}

fn scan(symbols: Symbols) -> Box<dyn Analysis> {
    Box::new(Scan { symbols })
}

impl Native {
    fn find(
        image: &Image<'_>,
        symbols: &Symbols,
        references: &References,
        progress: &Progress,
    ) -> Result<Self> {
        let named = |name: &str| {
            unique(
                functions(name, symbols, references).into_values().collect(),
                name,
            )
        };
        let menu = named(MENU)?;
        let construct = named(CONSTRUCT)?;
        let click = named(CLICK)?;
        let loader = named(PREVIEW)?.start;
        let schedule = named(EXPORT)?;
        let extension = named(EXTENSION)?.start;
        let copy = containing_callback(image, references, named(COPY)?.start, progress)?;
        let copy_body = image.instructions(&copy)?;
        let message_field = unique(
            copy_body
                .iter()
                .take_while(|instruction| instruction.mnemonic() != Mnemonic::Call)
                .filter_map(|instruction| {
                    (instruction.code() == Code::Lea_r64_m
                        && instruction.op0_register() == Register::RSI
                        && instruction.memory_base() == Register::RCX)
                        .then_some(instruction.memory_displacement64() as i64)
                })
                .collect(),
            "消息对象位置",
        )?;
        let menu_body = image.instructions(&menu)?;
        let info_field = unique(
            menu_body
                .windows(2)
                .filter_map(|window| {
                    (window[0].code() == Code::Mov_r64_rm64
                        && window[0].op0_register() == Register::RAX
                        && window[0].memory_base() == Register::RSI
                        && window[1].mnemonic() == Mnemonic::Cmp
                        && window[1].memory_base() == Register::RAX
                        && window[1].memory_displacement64() == 32)
                        .then_some(window[0].memory_displacement64() as i64)
                })
                .collect(),
            "表情信息位置",
        )?;
        let constructor = image.instructions(&construct)?;
        let info = unique(
            calls(&constructor)
                .filter_map(|(index, target)| {
                    argument(&constructor, index, Register::RCX)
                        .ok()
                        .filter(|argument| {
                            (argument.mnemonic() == Mnemonic::Lea
                                && argument.memory_base() == Register::RDI
                                && argument.memory_displacement64() as i64 == info_field)
                                || (argument.mnemonic() == Mnemonic::Add
                                    && argument.op1_kind() == OpKind::Immediate32to64
                                    && argument.immediate32to64() == info_field)
                        })
                        .map(|_| target)
                })
                .collect(),
            "消息表情信息构造",
        )?;
        let mut workers = BTreeMap::new();
        for address in referenced(&image.instructions(&schedule)?) {
            if let Ok(function) = function(image, address)
                && calls(&image.instructions(&function)?).any(|(_, target)| target == extension)
            {
                workers.insert(function.start, function);
            }
        }
        let worker = unique(workers.into_values().collect(), "资源复制工作函数")?;
        let worker_body = image.instructions(&worker)?;
        let temporary = functions(TEMP, symbols, references);
        let filename = unique(
            calls(&worker_body)
                .filter_map(|(_, target)| temporary.get(&target).cloned())
                .collect(),
            "复制文件命名函数",
        )?;
        let format_call = call(&worker_body, extension)?;
        let text = stack_argument(&worker_body, format_call, Register::RDX)?;
        let utf8 = unique(
            calls(&worker_body[..format_call])
                .filter_map(|(index, target)| {
                    stack_argument(&worker_body, index, Register::RDX)
                        .is_ok_and(|slot| slot == text)
                        .then_some(target)
                })
                .collect(),
            "资源路径文字转换",
        )?;
        let convert = named(CONVERT)?;
        let convert_body = image.instructions(&convert)?;
        let encoder = unique(
            calls(&convert_body)
                .filter_map(|(index, target)| {
                    argument(&convert_body, index, Register::R8D)
                        .is_ok_and(|argument| {
                            argument.code() == Code::Mov_r32_imm32 && argument.immediate32() == 3
                        })
                        .then_some(target)
                })
                .collect(),
            "WXGF 编码接口",
        )?;
        let encoder = function(image, encoder)?;
        let data_destroy = unique(
            calls(&cleanup(image, &encoder, 0)?)
                .map(|(_, target)| target)
                .collect(),
            "图像数据清理函数",
        )?;
        let filename_call = call(&worker_body, filename.start)?;
        let check = unique(
            worker_body
                .windows(2)
                .enumerate()
                .filter_map(|(index, window)| {
                    (window[0].mnemonic() == Mnemonic::Test
                        && window[0].op0_register() == Register::AL
                        && window[0].op1_register() == Register::AL
                        && window[1].mnemonic() == Mnemonic::Je
                        && window[1].near_branch_target() > worker_body[format_call].ip()
                        && window[1].near_branch_target() < worker_body[filename_call].ip())
                    .then_some(index)
                })
                .collect(),
            "图片扩展名分支",
        )?;
        let image_check = calls(&worker_body[..check])
            .next_back()
            .ok_or("找不到图片类型检查")?;
        let record = named(RECORD)?;
        let delegate = unique(callers(references, record.start), "媒体预览分派")?;
        let delegate_body = image.instructions(&delegate)?;
        let constructors: BTreeMap<_, _> = callers(references, loader)
            .into_iter()
            .map(|function| (function.start, function))
            .collect();
        let preview = unique(
            calls(&delegate_body)
                .filter_map(|(_, target)| constructors.get(&target).cloned())
                .collect(),
            "消息预览构造",
        )?;
        let file_menu = unique(callers(references, named(DOWNLOAD)?.start), "文件消息菜单")?;
        let file_body = image.instructions(&file_menu)?;
        let mut copy_tables = Vec::new();
        for table in tables(image, &file_body)? {
            let method = pointed(image, table + 16)?;
            if let Ok(function) = function(image, method)
                && calls(&image.instructions(&function)?).any(|(_, target)| target == copy.start)
            {
                copy_tables.push(table);
            }
        }
        let copy_table = unique(copy_tables, "原生复制菜单回调")?;
        let table_index = unique(
            file_body
                .iter()
                .enumerate()
                .filter_map(|(index, instruction)| {
                    (instruction.is_ip_rel_memory_operand()
                        && instruction.ip_rel_memory_address() == copy_table)
                        .then_some(index)
                })
                .collect(),
            "复制菜单回调构造",
        )?;
        let copy_text = calls(&file_body[table_index..])
            .next()
            .ok_or("找不到复制菜单文字")?
            .1;
        let copy_blocked = calls(&file_body[..table_index])
            .next_back()
            .ok_or("找不到复制菜单条件")?
            .1;
        let wrapper = image.instructions(&named(BUFFER)?)?;
        let readers = functions(READ, symbols, references);
        let (read_call, read) = unique(
            calls(&wrapper)
                .filter(|(_, target)| readers.contains_key(target))
                .collect(),
            "表情数据读取",
        )?;
        let key_slot = stack_argument(&wrapper, read_call, Register::R8)?;
        let key = unique(
            calls(&wrapper[..read_call])
                .filter_map(|(index, target)| {
                    stack_argument(&wrapper, index, Register::RCX)
                        .is_ok_and(|slot| slot == key_slot)
                        .then_some(target)
                })
                .collect(),
            "表情密钥获取",
        )?;
        let read_body = image.instructions(&readers[&read])?;
        let mut caches: BTreeMap<u64, BTreeSet<bool>> = BTreeMap::new();
        for (index, target) in calls(&read_body) {
            let Ok(value) = argument(&read_body, index, Register::R8) else {
                continue;
            };
            let value = if value.mnemonic() == Mnemonic::Xor
                && value.op0_register() == value.op1_register()
            {
                Some(false)
            } else if value.mnemonic() == Mnemonic::Mov {
                match value.op1_kind() {
                    OpKind::Immediate8 if value.immediate8() <= 1 => Some(value.immediate8() != 0),
                    OpKind::Immediate32 if value.immediate32() <= 1 => {
                        Some(value.immediate32() != 0)
                    }
                    _ => None,
                }
            } else {
                None
            };
            if let Some(value) = value {
                caches.entry(target).or_default().insert(value);
            }
        }
        let cache = unique(
            caches
                .into_iter()
                .filter_map(|(target, values)| (values.len() == 2).then_some(target))
                .collect(),
            "表情缓存路径",
        )?;
        let metadata = named(INFO)?;
        let info_body = image.instructions(&metadata)?;
        let text = image
            .sections()?
            .into_iter()
            .map(|(start, data)| start..start + data.len() as u64)
            .find(|range| range.contains(&metadata.start))
            .ok_or("找不到表情信息代码节")?;
        let mut paths = BTreeSet::new();
        for mut cursor in tables(image, &info_body)? {
            loop {
                let method = pointed(image, cursor)?;
                if !text.contains(&method) {
                    break;
                }
                cursor += 8;
                let Ok(method) = function(image, method) else {
                    continue;
                };
                let body = image.instructions(&method)?;
                if calls(&body).filter(|(_, target)| *target == cache).count() == 1
                    && body.iter().any(|instruction| {
                        instruction.code() == Code::Call_rm64
                            && instruction.op0_kind() == OpKind::Memory
                            && !instruction.is_ip_rel_memory_operand()
                    })
                {
                    paths.insert(method.start);
                }
            }
        }
        let path = unique(paths.into_iter().collect(), "可用表情缓存路径")?;
        let path_body = image.instructions(&function(image, path)?)?;
        let exists = unique(
            calls(&path_body)
                .filter_map(|(index, target)| {
                    path_body[index + 1..]
                        .iter()
                        .find(|instruction| instruction.mnemonic() != Mnemonic::Nop)
                        .filter(|instruction| {
                            instruction.mnemonic() == Mnemonic::Test
                                && instruction.op0_register() == Register::AL
                                && instruction.op1_register() == Register::AL
                        })
                        .map(|_| target)
                })
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            "资源路径检查",
        )?;
        let states = image.exception_states(worker.start)?;
        let initial = states
            .iter()
            .rev()
            .find(|state| state.instruction <= worker_body[image_check.0].ip())
            .ok_or("找不到资源结果构造后的异常状态")?;
        let destination = states
            .iter()
            .find(|state| state.instruction > worker_body[filename_call].ip())
            .ok_or("找不到复制目标构造后的异常状态")?;
        let copied = unique(
            calls(&worker_body)
                .filter_map(|(index, _)| {
                    worker_body[index + 1..]
                        .iter()
                        .find(|instruction| instruction.mnemonic() != Mnemonic::Nop)
                        .filter(|instruction| {
                            instruction.mnemonic() == Mnemonic::Mov
                                && instruction.op0_register() == Register::EBX
                                && instruction.op1_register() == Register::EAX
                        })
                        .map(|_| worker_body[index].ip())
                })
                .collect(),
            "原生资源复制调用",
        )?;
        let formats = states
            .iter()
            .rev()
            .find(|state| state.instruction <= copied)
            .ok_or("找不到图片格式集合的异常状态")?;
        let destructors = cleanup(image, &worker, initial.state)?;
        let destructors: Vec<_> = calls(&destructors).map(|(_, target)| target).collect();
        let [string_destroy, shared_destroy] = destructors[..] else {
            return Err("无法识别复制资源清理函数".into());
        };
        let path_destroy = unique(
            calls(&cleanup(image, &worker, destination.state)?)
                .map(|(_, target)| target)
                .collect(),
            "路径清理函数",
        )?;
        let set_destroy = unique(
            calls(&cleanup(image, &worker, formats.state)?)
                .map(|(_, target)| target)
                .collect(),
            "图片格式集合清理函数",
        )?;
        let mut formats = BTreeSet::new();
        for (_, target) in calls(&image.instructions(&named(FORMAT)?)?) {
            let Ok(function) = function(image, target) else {
                continue;
            };
            let header = image.instructions(&function)?;
            if header.iter().any(|instruction| {
                instruction.mnemonic() == Mnemonic::Cmp
                    && instruction.op1_kind() == OpKind::Immediate32
                    && instruction.immediate32() == 0xff
            }) && header.iter().any(|instruction| {
                instruction.mnemonic() == Mnemonic::Cmp
                    && instruction.op0_kind() == OpKind::Memory
                    && instruction.memory_displacement64() == 1
                    && instruction.op1_kind() == OpKind::Immediate8
                    && instruction.immediate8() == 0xd8
            }) {
                formats.insert(target);
            }
        }
        let format = unique(formats.into_iter().collect(), "图片文件头识别")?;
        let mut writes = Vec::new();
        for function in functions(WRITE, symbols, references).into_values() {
            let body = image.instructions(&function)?;
            if body
                .iter()
                .take_while(|instruction| instruction.mnemonic() != Mnemonic::Call)
                .any(|instruction| {
                    instruction.code() == Code::Mov_rm32_r32
                        && instruction.memory_base() == Register::RBP
                        && instruction.op1_register() == Register::R8D
                })
                && body.iter().any(|instruction| {
                    instruction.code() == Code::Mov_r32_rm32
                        && instruction.op0_register() == Register::R8D
                        && instruction.memory_base() == Register::RDI
                        && instruction.memory_displacement64() == 16
                })
            {
                writes.push(function.start);
            }
        }
        let write = unique(writes, "图片缓冲写入")?;
        let (extra_table, _) = table(image, named(EXTRA)?.start, progress)?;
        let locator = pointed(image, extra_table - 8)?;
        let emoticon_type =
            image.base() + u64::from(u32::from_le_bytes(image.data(locator + 12, 4)?.try_into()?));
        let casts = calls(&info_body)
            .filter_map(|(index, target)| {
                let source = literal(&info_body, index, Register::R8).ok()?;
                let destination = literal(&info_body, index, Register::R9).ok()?;
                let zero = argument(&info_body, index, Register::EDX).ok()?;
                (destination == emoticon_type
                    && zero.mnemonic() == Mnemonic::Xor
                    && zero.op1_register() == Register::EDX)
                    .then_some((target, source))
            })
            .collect::<BTreeSet<_>>();
        let (cast, base_type) = unique(casts.into_iter().collect(), "表情消息类型转换")?;
        let types = calls(&info_body)
            .filter(|(_, target)| *target == cast)
            .filter_map(|(index, _)| {
                (literal(&info_body, index, Register::R8).ok() == Some(base_type))
                    .then(|| literal(&info_body, index, Register::R9).ok())
                    .flatten()
            })
            .collect::<BTreeSet<_>>();
        let mut getters = Vec::new();
        for candidate in callers(references, emoticon_type) {
            let body = image.instructions(&candidate)?;
            if calls(&body).next().map(|(_, target)| target) != Some(cast) {
                continue;
            }
            let casts = calls(&body)
                .filter(|(_, target)| *target == cast)
                .collect::<Vec<_>>();
            let destinations = casts
                .iter()
                .filter_map(|(index, _)| {
                    (literal(&body, *index, Register::R8).ok() == Some(base_type))
                        .then(|| literal(&body, *index, Register::R9).ok())
                        .flatten()
                })
                .collect::<BTreeSet<_>>();
            if casts.len() == types.len() && destinations == types {
                getters.push(candidate.start);
            }
        }
        let md5 = unique(getters, "消息表情 MD5 获取")?;
        Ok(Self {
            menu,
            copy,
            schedule,
            worker,
            convert,
            encoder,
            filename,
            click,
            delegate,
            preview,
            loader,
            info,
            info_field,
            message_field,
            copy_table,
            copy_text,
            copy_blocked,
            path,
            exists,
            path_destroy,
            string_destroy,
            shared_destroy,
            shared_move: transfer(image, progress)?,
            set_destroy,
            data_destroy,
            utf8,
            md5,
            key,
            read: named(SYNC_READ)?.start,
            image_check: image_check.1,
            format,
            extension,
            write,
            image_copy: named(IMAGE_COPY)?.start,
        })
    }
}

fn position(body: &[Instruction], address: u64) -> Result<usize> {
    body.iter()
        .position(|instruction| instruction.ip() == address)
        .ok_or_else(|| format!("找不到指令位置：{address:#x}").into())
}

fn epilogue(body: &[Instruction]) -> Result<usize> {
    body.iter()
        .rposition(|instruction| {
            instruction.mnemonic() == Mnemonic::Add && instruction.op0_register() == Register::RSP
        })
        .ok_or_else(|| "找不到函数返回位置".into())
}

fn string_cleanups(body: &[Instruction], slot: i64) -> Result<Vec<Range<usize>>> {
    let mut result = Vec::new();
    for (index, window) in body.windows(3).enumerate() {
        if window[0].code() == Code::Mov_r64_rm64
            && window[0].op0_register() == Register::RAX
            && window[0].memory_base() == Register::RBP
            && window[0].memory_displacement64() as i64 == slot + 24
            && window[1].mnemonic() == Mnemonic::Cmp
            && window[1].op0_register() == Register::RAX
            && window[1].op1_kind() == OpKind::Immediate8to64
            && window[1].immediate8to64() == 16
            && window[2].mnemonic() == Mnemonic::Jb
        {
            let target = window[2].near_branch_target();
            let mut end = position(body, target)?;
            if end <= index {
                let Some(jump) = body[index + 3..].iter().position(|instruction| {
                    instruction.mnemonic() == Mnemonic::Jmp
                        && instruction.near_branch_target() == target
                }) else {
                    continue;
                };
                end = index + 3 + jump;
            }
            result.push(index..end);
        }
    }
    Ok(result)
}

fn destroy(body: &mut Body<'_, '_>, range: Range<usize>, slot: i64, target: u64) -> Result<()> {
    let mut code = CodeAssembler::new(64)?;
    code.lea(rcx, ptr(rbp + slot))?;
    code.call(target)?;
    body.replace(range, &mut code)
}

fn compare(code: &mut CodeAssembler, message: AsmMemoryOperand) -> Result<()> {
    let mut ready = code.create_label();
    code.cmp(message + 8, 47)?;
    code.je(ready)?;
    code.cmp(message + 8, 49)?;
    code.jne(ready)?;
    code.cmp(message + 12, 8)?;
    code.set_label(&mut ready)?;
    Ok(())
}

fn worker(image: &Image<'_>, native: &Native, references: &References) -> Result<Vec<Edit>> {
    let mut output = Body::new(image, &native.worker)?;
    let body = output.original.clone();
    let image_check = call(&body, native.image_check)?;
    let format = call(&body, native.extension)?;
    let filename = call(&body, native.filename.start)?;
    let suffix = stack_argument(&body, filename, Register::R8)?;
    let destination = stack_argument(&body, filename, Register::RCX)?;
    let temporary = stack_argument(&body, format, Register::RDX)?;
    let formats = stack_argument(&body, format, Register::RCX)?;
    let utf8 = call(&body, native.utf8)?;
    let utf8_start = argument(&body, utf8, Register::RCX)?
        .ip()
        .min(argument(&body, utf8, Register::RDX)?.ip());
    let utf8_start = position(&body, utf8_start)?;
    let format_start = argument(&body, format, Register::RCX)?
        .ip()
        .min(argument(&body, format, Register::RDX)?.ip())
        .min(argument(&body, format, Register::R8)?.ip());
    let format_start = position(&body, format_start)?;
    let check = body[image_check + 1..]
        .iter()
        .position(|instruction| {
            instruction.mnemonic() == Mnemonic::Test
                && instruction.op0_register() == Register::AL
                && instruction.op1_register() == Register::AL
        })
        .map(|index| image_check + 1 + index)
        .ok_or("找不到图片类型检查结果")?;
    if body[check + 1].mnemonic() != Mnemonic::Je || check + 2 >= utf8_start {
        return Err("无法识别图片格式处理分支".into());
    }
    for (slot, before) in [(suffix, image_check), (destination, format)] {
        if !body[..before].iter().any(|instruction| {
            instruction.code() == Code::Mov_rm64_imm32
                && instruction.memory_base() == Register::RBP
                && instruction.memory_displacement64() as i64 == slot + 24
                && instruction.immediate32to64() == 15
        }) {
            return Err("无法识别图片后缀的内联存储".into());
        }
    }
    let owner = unique(
        body[..image_check]
            .iter()
            .filter_map(|instruction| {
                (instruction.mnemonic() == Mnemonic::Mov
                    && instruction.op0_kind() == OpKind::Memory
                    && instruction.memory_base() == Register::RBP
                    && instruction.op1_register() == Register::RDI)
                    .then_some(instruction.memory_displacement64() as i64)
            })
            .collect(),
        "资源结果对象存储",
    )?;
    let zero = unique(
        body[..image_check]
            .iter()
            .enumerate()
            .filter_map(|(index, instruction)| {
                (instruction.mnemonic() == Mnemonic::Movups
                    && instruction.op0_kind() == OpKind::Memory
                    && instruction.memory_base() == Register::RCX
                    && instruction.op1_register() == Register::XMM0)
                    .then_some(index)
            })
            .collect(),
        "资源结果所有权转移",
    )?;
    if body[image_check - 1].mnemonic() != Mnemonic::Mov
        || body[image_check - 1].op0_register() != Register::RCX
        || body[image_check - 1].op1_register() != Register::R14
    {
        return Err("无法识别复制消息参数".into());
    }
    let suffix_cleanup = string_cleanups(&body, suffix)?;
    let [initial, final_cleanup] = &suffix_cleanup[..] else {
        return Err("无法识别资源后缀清理".into());
    };
    let failed = body[final_cleanup.start].ip();
    let temporary_cleanup = unique(string_cleanups(&body, temporary)?, "资源路径文字清理")?;
    let mut code = CodeAssembler::new(64)?;
    let mut transfer = code.create_label();
    let mut ready = code.create_label();
    code.mov(esi, -1)?;
    compare(&mut code, dword_ptr(r14))?;
    code.jne(transfer)?;
    code.xor(esi, esi)?;
    code.movups(ptr(rbp + owner), xmm0)?;
    code.jmp(ready)?;
    code.set_label(&mut transfer)?;
    code.add_instruction(body[zero])?;
    code.set_label(&mut ready)?;
    output.replace(zero..zero + 1, &mut code)?;

    let mut code = CodeAssembler::new(64)?;
    let mut prepare = code.create_label();
    code.add_instruction(body[check])?;
    code.jne(prepare)?;
    code.test(esi, esi)?;
    code.js(body[check + 1].near_branch_target())?;
    code.set_label(&mut prepare)?;
    output.replace(check..check + 2, &mut code)?;

    let mut code = CodeAssembler::new(64)?;
    let mut key = code.create_label();
    let mut ready = code.create_label();
    code.test(esi, esi)?;
    code.jns(key)?;
    for instruction in &body[check + 2..utf8_start] {
        code.add_instruction(*instruction)?;
    }
    code.jmp(ready)?;
    code.set_label(&mut key)?;
    code.lea(rcx, ptr(rbp + destination))?;
    code.call(native.key)?;
    code.set_label(&mut ready)?;
    output.replace(check + 2..utf8_start, &mut code)?;

    let mut code = CodeAssembler::new(64)?;
    let mut md5 = code.create_label();
    let mut ready = code.create_label();
    code.test(esi, esi)?;
    code.jns(md5)?;
    for instruction in &body[utf8_start..format_start] {
        code.add_instruction(*instruction)?;
    }
    code.jmp(ready)?;
    code.set_label(&mut md5)?;
    code.lea(rcx, ptr(rbp + temporary))?;
    code.mov(rdx, r14)?;
    code.call(native.md5)?;
    code.set_label(&mut ready)?;
    output.replace(utf8_start..format_start, &mut code)?;

    let mut code = CodeAssembler::new(64)?;
    let mut data = code.create_label();
    let mut data_failed = code.create_label();
    let mut gif = code.create_label();
    let mut assigned = code.create_label();
    code.test(esi, esi)?;
    code.jns(data)?;
    for instruction in &body[format_start..initial.start] {
        code.add_instruction(*instruction)?;
    }
    code.jmp(body[initial.end].ip())?;
    code.set_label(&mut data)?;
    code.cmp(qword_ptr(rbp + temporary + 16), 0)?;
    code.je(data_failed)?;
    code.lea(rcx, ptr(rbp + owner))?;
    code.lea(rdx, ptr(rbp + temporary))?;
    code.lea(r8, ptr(rbp + destination))?;
    code.xor(r9d, r9d)?;
    code.call(native.read)?;
    code.mov(rbx, qword_ptr(rax))?;
    code.test(rbx, rbx)?;
    code.jz(data_failed)?;
    code.cmp(qword_ptr(rbx + 16), 12)?;
    code.jb(data_failed)?;
    code.mov(rcx, rbx)?;
    code.cmp(qword_ptr(rbx + 24), 16)?;
    code.cmovae(rcx, qword_ptr(rbx))?;
    code.call(native.format)?;
    code.mov(edx, 4)?;
    code.xor(r9d, r9d)?;
    let mut original = code.create_label();
    code.add_instruction(Instruction::with2(Code::Cmp_rm32_imm8, Register::EAX, 7)?)?;
    code.jne(original)?;
    code.inc(esi)?;
    code.jmp(gif)?;
    code.set_label(&mut original)?;
    let mut previous = "";
    for (kind, extension) in [
        (1, ".jpg"),
        (2, ".png"),
        (4, ".bmp"),
        (3, ".tiff"),
        (5, ".heic"),
        (6, ".heif"),
        (8, ".webp"),
    ] {
        let bytes = extension.as_bytes();
        if extension.len() == 5 && previous.len() == 4 {
            code.inc(edx)?;
        }
        if previous.as_bytes().get(..4) != Some(&bytes[..4]) {
            code.mov(ecx, u32::from_le_bytes(bytes[..4].try_into()?))?;
        }
        if let Some(&last) = bytes.get(4)
            && previous.as_bytes().get(4) != Some(&last)
        {
            code.mov(r9b, i32::from(last))?;
        }
        code.add_instruction(Instruction::with2(
            Code::Cmp_rm32_imm8,
            Register::EAX,
            kind,
        )?)?;
        code.je(assigned)?;
        previous = extension;
    }
    code.mov(rcx, rbx)?;
    code.cmp(qword_ptr(rbx + 24), 16)?;
    code.cmovae(rcx, qword_ptr(rbx))?;
    code.cmp(dword_ptr(rcx), 0x3846_4947)?;
    code.jne(data_failed)?;
    code.cmp(word_ptr(rcx + 4), 0x6137)?;
    code.je(gif)?;
    code.cmp(word_ptr(rcx + 4), 0x6139)?;
    code.jne(data_failed)?;
    code.set_label(&mut gif)?;
    code.mov(ecx, 0x6669_672e)?;
    code.mov(edx, 4)?;
    code.xor(r9d, r9d)?;
    code.set_label(&mut assigned)?;
    code.mov(dword_ptr(rbp + formats), ecx)?;
    code.mov(byte_ptr(rbp + formats + 4), r9b)?;
    code.mov(byte_ptr(rbp + formats + 5), 0)?;
    code.mov(qword_ptr(rbp + formats + 16), rdx)?;
    code.mov(qword_ptr(rbp + formats + 24), 15)?;
    code.jmp(body[initial.end].ip())?;
    code.set_label(&mut data_failed)?;
    code.xor(ebx, ebx)?;
    code.jmp(body[temporary_cleanup.start].ip())?;
    output.replace(format_start..initial.start, &mut code)?;

    output.replace(initial.clone(), &mut CodeAssembler::new(64)?)?;
    let reset = unique(
        body.windows(3)
            .enumerate()
            .filter_map(|(index, window)| {
                (window[0].code() == Code::Mov_rm64_imm32
                    && window[0].memory_base() == Register::RBP
                    && window[0].memory_displacement64() as i64 == formats + 16
                    && window[0].immediate32to64() == 0
                    && window[1].code() == Code::Mov_rm64_imm32
                    && window[1].memory_base() == Register::RBP
                    && window[1].memory_displacement64() as i64 == formats + 24
                    && window[1].immediate32to64() == 15
                    && window[2].code() == Code::Mov_rm8_imm8
                    && window[2].memory_base() == Register::RBP
                    && window[2].memory_displacement64() as i64 == formats
                    && window[2].immediate8() == 0)
                    .then_some(index)
            })
            .collect(),
        "已转移的图片格式临时值",
    )?;
    output.replace(reset..reset + 3, &mut CodeAssembler::new(64)?)?;
    destroy(
        &mut output,
        temporary_cleanup,
        temporary,
        native.string_destroy,
    )?;
    let mut code = CodeAssembler::new(64)?;
    code.lea(rcx, ptr(rbp + destination))?;
    code.call(native.string_destroy)?;
    code.test(rbx, rbx)?;
    code.je(failed)?;
    output.replace(
        unique(string_cleanups(&body, destination)?, "默认图片后缀清理")?,
        &mut code,
    )?;
    destroy(
        &mut output,
        final_cleanup.clone(),
        suffix,
        native.string_destroy,
    )?;
    destroy(
        &mut output,
        final_cleanup.end..epilogue(&body)?,
        owner,
        native.shared_destroy,
    )?;
    let states = image.exception_states(native.worker.start)?;
    let construction = states
        .iter()
        .find(|state| state.instruction > body[filename].ip())
        .ok_or("找不到复制目标构造后的异常状态")?
        .instruction;
    let construction = position(&body, construction)?;
    let copied = unique(
        body.windows(2)
            .enumerate()
            .filter_map(|(index, window)| {
                (window[0].mnemonic() == Mnemonic::Test
                    && window[0].op0_register() == Register::BL
                    && window[0].op1_register() == Register::BL
                    && window[1].mnemonic() == Mnemonic::Je)
                    .then_some(index)
            })
            .collect(),
        "资源复制完成检查",
    )?;
    let mut code = CodeAssembler::new(64)?;
    let mut original = code.create_label();
    code.test(esi, esi)?;
    code.js(original)?;
    code.lea(rcx, ptr(rbp + destination))?;
    code.mov(rdx, rbx)?;
    code.mov(r8d, 1)?;
    code.call(native.write)?;
    code.cdqe()?;
    code.cmp(rax, qword_ptr(rbx + 16))?;
    code.sete(bl)?;
    code.jne(body[copied].ip())?;
    code.test(esi, esi)?;
    code.je(body[copied].ip())?;
    code.lea(rcx, ptr(rbp + destination))?;
    code.mov(rdx, rcx)?;
    code.mov(r8d, 92)?;
    code.mov(r9d, esi)?;
    code.call(native.image_copy)?;
    code.mov(bl, al)?;
    code.jmp(body[copied].ip())?;
    code.set_label(&mut original)?;
    code.add_instruction(body[construction])?;
    output.replace(construction..construction + 1, &mut code)?;
    let status = body[..copied]
        .iter()
        .rposition(|instruction| {
            instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_register() == Register::EBX
                && instruction.op1_register() == Register::EAX
        })
        .ok_or("找不到复制结果存储")?;
    destroy(&mut output, status + 1..copied, formats, native.set_destroy)?;
    let tail = body
        .iter()
        .rposition(|instruction| instruction.mnemonic() == Mnemonic::Ret)
        .ok_or("找不到复制工作函数返回")?
        + 1;
    if tail < body.len() {
        let removed = body[tail].ip()..native.worker.end;
        if output.instructions.iter().any(|instruction| {
            instruction.op0_kind() == OpKind::NearBranch64
                && removed.contains(&instruction.near_branch_target())
        }) || body[tail..].iter().any(|instruction| {
            callers(references, instruction.ip())
                .iter()
                .any(|function| function.start != native.worker.start)
        }) {
            return Err("复制工作函数尾部仍有引用".into());
        }
        output.replace(tail..body.len(), &mut CodeAssembler::new(64)?)?;
    }
    output.finish()
}

fn compact_data(body: &mut Body<'_, '_>, destroy: u64) -> Result<()> {
    let function = function(body.image, destroy)?;
    let targets: Vec<_> = body
        .image
        .instructions(&function)?
        .iter()
        .filter(|instruction| {
            matches!(instruction.mnemonic(), Mnemonic::Call | Mnemonic::Jmp)
                && instruction.op0_kind() == OpKind::NearBranch64
                && !function.contains(&instruction.near_branch_target())
        })
        .map(Instruction::near_branch_target)
        .collect();
    if targets.is_empty() {
        return Err("找不到图像数据清理调用".into());
    }
    let original = body.original.clone();
    for (index, window) in original.windows(3).enumerate() {
        let register = window[0].op0_register();
        if window[0].code() != Code::Mov_r64_rm64
            || window[0].op1_kind() != OpKind::Memory
            || window[1].mnemonic() != Mnemonic::Test
            || window[1].op0_register() != register
            || window[1].op1_register() != register
            || window[2].mnemonic() != Mnemonic::Je
        {
            continue;
        }
        let target = window[2].near_branch_target();
        let mut end = position(&original, target)?;
        if end <= index {
            let Some(jump) = original[index + 3..].iter().position(|instruction| {
                instruction.mnemonic() == Mnemonic::Jmp
                    && instruction.near_branch_target() == target
            }) else {
                continue;
            };
            end = index + 4 + jump;
        }
        let cleanup = &original[index..end];
        if calls(cleanup).map(|(_, target)| target).collect::<Vec<_>>() != targets {
            continue;
        }
        let saved = cleanup.iter().find(|instruction| {
            instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register
                && instruction.op1_register() == Register::EAX
        });
        let mut code = CodeAssembler::new(64)?;
        if let Some(saved) = saved {
            code.add_instruction(*saved)?;
        }
        let mut address = window[0];
        address.set_code(Code::Lea_r64_m);
        address.set_op0_register(Register::RCX);
        code.add_instruction(address)?;
        code.call(destroy)?;
        if let Some(saved) = saved {
            code.add_instruction(Instruction::with2(
                Code::Mov_r32_rm32,
                Register::EAX,
                saved.op0_register(),
            )?)?;
        }
        if original[end - 1].mnemonic() == Mnemonic::Jmp {
            code.add_instruction(original[end - 1])?;
        }
        body.replace(index..end, &mut code)?;
    }
    Ok(())
}

fn encoder(image: &Image<'_>, native: &Native) -> Result<Vec<Edit>> {
    let mut output = Body::new(image, &native.encoder)?;
    let body = output.original.clone();
    let guard = unique(
        body.windows(2)
            .enumerate()
            .filter_map(|(index, window)| {
                (window[0].mnemonic() == Mnemonic::Cmp
                    && window[0].op0_register() == Register::R8D
                    && window[0].op1_kind() == OpKind::Immediate8to32
                    && window[0].immediate8to32() == 3
                    && window[1].mnemonic() == Mnemonic::Jne)
                    .then_some(index)
            })
            .collect(),
        "WXGF 输出格式条件",
    )?;
    let options = unique(
        body.iter()
            .enumerate()
            .filter_map(|(index, instruction)| {
                (instruction.mnemonic() == Mnemonic::Movaps
                    && instruction.op0_register() == Register::XMM6
                    && instruction.is_ip_rel_memory_operand())
                .then_some(index)
            })
            .collect(),
        "WXGF 编码选项",
    )?;
    let mut code = CodeAssembler::new(64)?;
    code.add_instruction(body[options])?;
    code.add_instruction(body[guard])?;
    code.je(body[guard + 1].next_ip())?;
    code.cmp(r8d, 1)?;
    code.jne(body[guard + 1].near_branch_target())?;
    code.mov(eax, 3)?;
    code.movd(xmm6, eax)?;
    output.replace(guard..guard + 2, &mut code)?;
    output.replace(options..options + 1, &mut CodeAssembler::new(64)?)?;
    compact_data(&mut output, native.data_destroy)?;
    output.finish()
}

fn convert(image: &Image<'_>, native: &Native) -> Result<Vec<Edit>> {
    let mut output = Body::new(image, &native.convert)?;
    let body = output.original.clone();
    if !body
        .iter()
        .take_while(|instruction| instruction.mnemonic() != Mnemonic::Call)
        .any(|instruction| {
            instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register
                && instruction.op0_register() == Register::RDI
                && instruction.op1_register() == Register::RDX
        })
    {
        return Err("无法识别图像转换目标路径".into());
    }
    let parameter = argument(&body, call(&body, native.encoder.start)?, Register::R8D)?;
    if parameter.code() != Code::Mov_r32_imm32 || parameter.immediate32() != 3 {
        return Err("无法识别图像转换格式参数".into());
    }
    let index = position(&body, parameter.ip())?;
    let mut code = CodeAssembler::new(64)?;
    let mut ready = code.create_label();
    code.add_instruction(parameter)?;
    code.mov(r9, qword_ptr(rdi + 16))?;
    code.cmp(r9, 4)?;
    code.jb(ready)?;
    code.mov(rax, rdi)?;
    code.cmp(qword_ptr(rdi + 24), 16)?;
    code.cmovae(rax, qword_ptr(rdi))?;
    code.mov(eax, dword_ptr(rax + r9 - 4))?;
    code.or(eax, 0x2020_2000)?;
    code.cmp(eax, 0x6669_672e)?;
    code.jne(ready)?;
    code.mov(r8d, 1)?;
    code.set_label(&mut ready)?;
    output.replace(index..index + 1, &mut code)?;
    compact_data(&mut output, native.data_destroy)?;
    output.finish()
}

fn compact_string(body: &mut Body<'_, '_>, destroy: u64) -> Result<()> {
    let mut found = Vec::new();
    for instruction in &body.original {
        if instruction.code() == Code::Mov_r64_rm64
            && instruction.op0_register() == Register::RAX
            && instruction.memory_base() == Register::RBP
        {
            let slot = instruction.memory_displacement64() as i64 - 24;
            for range in string_cleanups(&body.original, slot)? {
                if body.original[range.clone()].iter().any(|instruction| {
                    instruction.mnemonic() == Mnemonic::Lea
                        && instruction.op0_register() == Register::RDX
                        && instruction.memory_base() == Register::RAX
                        && instruction.memory_displacement64() == 1
                }) {
                    found.push((range.start, range.end, slot));
                }
            }
        }
    }
    found.sort_unstable();
    found.dedup();
    let &(start, end, slot) = found.last().ok_or("找不到可复用的字符串清理")?;
    let mut code = CodeAssembler::new(64)?;
    code.lea(rcx, ptr(rbp + slot))?;
    code.call(destroy)?;
    body.replace(start..end, &mut code)
}

fn schedule(image: &Image<'_>, native: &Native) -> Result<Vec<Edit>> {
    let mut output = Body::new(image, &native.schedule)?;
    let body = output.original.clone();
    let exists = call(&body, native.exists)?;
    let test = body[exists + 1..]
        .iter()
        .position(|instruction| instruction.mnemonic() == Mnemonic::Test)
        .map(|index| exists + 1 + index)
        .ok_or("找不到资源路径检查结果")?;
    if body[test].op0_register() != Register::AL
        || body[test].op1_register() != Register::AL
        || body[test + 1].mnemonic() != Mnemonic::Je
    {
        return Err("无法识别资源路径检查分支".into());
    }
    let mut code = CodeAssembler::new(64)?;
    code.add_instruction(body[test])?;
    code.jne(body[test + 1].next_ip())?;
    compare(&mut code, dword_ptr(rdi))?;
    code.jne(body[test + 1].near_branch_target())?;
    output.replace(test..test + 2, &mut code)?;
    output.finish()
}

fn filename(image: &Image<'_>, native: &Native) -> Result<Vec<Edit>> {
    let mut output = Body::new(image, &native.filename)?;
    let body = output.original.clone();
    let branch = unique(
        body.windows(2)
            .enumerate()
            .filter_map(|(index, window)| {
                (window[0].mnemonic() == Mnemonic::Cmp
                    && window[0].op0_register() == Register::RAX
                    && window[0].op1_kind() == OpKind::Immediate8to64
                    && window[0].immediate8to64() == 3
                    && window[1].mnemonic() == Mnemonic::Je)
                    .then_some(index)
            })
            .collect(),
        "图片文件命名分支",
    )?;
    let (message, start) = unique(
        body[..branch]
            .windows(3)
            .filter_map(|window| {
                (window[0].code() == Code::Mov_r32_rm32
                    && window[0].op0_register() == Register::EAX
                    && window[0].memory_displacement64() == 8
                    && window[1].mnemonic() == Mnemonic::Cmp
                    && window[1].op0_register() == Register::RAX
                    && window[1].op1_kind() == OpKind::Immediate8to64
                    && window[1].immediate8to64() == 49
                    && window[2].mnemonic() == Mnemonic::Jne)
                    .then_some((window[0].memory_base(), window[2].near_branch_target()))
            })
            .collect(),
        "消息类型合成",
    )?;
    let start = position(&body, start)?;
    let mut code = CodeAssembler::new(64)?;
    compare(&mut code, dword_ptr(message))?;
    code.je(body[branch + 1].near_branch_target())?;
    code.add_instruction(body[start])?;
    output.replace(start..start + 1, &mut code)?;
    compact_string(&mut output, native.string_destroy)?;
    output.finish()
}

fn clipboard(image: &Image<'_>, native: &Native) -> Result<Vec<Edit>> {
    let mut output = Body::new(image, &native.copy)?;
    let body = output.original.clone();
    let index = call(&body, native.image_check)? + 1;
    if body[index].mnemonic() != Mnemonic::Mov
        || body[index].op0_register() != Register::BL
        || body[index].op1_register() != Register::AL
    {
        return Err("无法识别剪贴板图片标志".into());
    }
    let mut code = CodeAssembler::new(64)?;
    compare(&mut code, dword_ptr(rsi))?;
    code.sete(bl)?;
    code.or(bl, al)?;
    output.replace(index..index + 1, &mut code)?;
    output.finish()
}

fn menu(image: &Image<'_>, native: &Native) -> Result<Vec<Edit>> {
    let mut output = Body::new(image, &native.menu)?;
    let body = output.original.clone();
    let table = unique(tables(image, &body)?, "表情菜单回调")?;
    let table_index = unique(
        body.iter()
            .enumerate()
            .filter_map(|(index, instruction)| {
                (instruction.is_ip_rel_memory_operand()
                    && instruction.ip_rel_memory_address() == table)
                    .then_some(index)
            })
            .collect(),
        "表情菜单回调构造",
    )?;
    let callback = &body[table_index + 1];
    if callback.mnemonic() != Mnemonic::Mov
        || callback.memory_base() != Register::RBP
        || callback.op1_register() != Register::RAX
    {
        return Err("无法识别表情菜单回调存储".into());
    }
    let storage = callback.memory_displacement64() as i64;
    let role = body[table_index..]
        .iter()
        .position(|instruction| {
            instruction.code() == Code::Mov_rm32_imm32
                && instruction.memory_base() == Register::RBP
                && instruction.immediate32() == 11
        })
        .map(|index| table_index + index)
        .ok_or("找不到表情菜单类型")?;
    let role_slot = body[role].memory_displacement64() as i64;
    let (text, text_getter) = calls(&body[role..])
        .next()
        .map(|(index, target)| (role + index, target))
        .ok_or("找不到表情菜单文字")?;
    let action = unique(
        body.iter()
            .enumerate()
            .filter_map(|(index, instruction)| {
                (instruction.code() == Code::Mov_r32_imm32
                    && instruction.op0_register() == Register::EDX
                    && instruction.immediate32() == 0x3f9)
                    .then_some(index)
            })
            .collect(),
        "添加表情菜单项",
    )?;
    let append = calls(&body[action..])
        .next()
        .map(|(index, _)| action + index)
        .ok_or("找不到表情菜单添加调用")?;
    let finish = body
        .iter()
        .rposition(|instruction| instruction.code() == Code::Jmp_rel32_64)
        .ok_or("找不到菜单构造返回")?;
    let returned = body[finish].near_branch_target();
    let mut inherited = Vec::new();
    for (index, target) in calls(&body[..table_index]) {
        let bytes = image.data(target, 16)?;
        if Decoder::with_ip(64, bytes, target, DecoderOptions::NONE)
            .into_iter()
            .any(|instruction| {
                instruction.code() == Code::Mov_r64_rm64
                    && instruction.op0_register() == Register::RSI
                    && instruction.memory_base() == Register::RDX
                    && instruction.memory_displacement64() == 8
            })
        {
            inherited.push(index);
        }
    }
    let inherited = unique(inherited, "继承菜单调用")?;
    let initialize = body[..inherited]
        .iter()
        .rposition(|instruction| {
            instruction.mnemonic() == Mnemonic::Xorps
                && instruction.op0_register() == Register::XMM0
        })
        .ok_or("找不到继承菜单参数初始化")?;
    let context = calls(&body[inherited + 1..])
        .next()
        .map(|(index, _)| inherited + 1 + index)
        .ok_or("找不到菜单上下文")?;
    let context_start = context - 2;
    let information = body[context + 1..]
        .iter()
        .position(|instruction| {
            instruction.code() == Code::Mov_r64_rm64
                && instruction.op0_register() == Register::RAX
                && instruction.memory_base() == Register::RSI
                && instruction.memory_displacement64() as i64 == native.info_field
        })
        .map(|index| context + 1 + index)
        .ok_or("找不到表情可用性检查")?;
    let available = information + 3;
    if body[available].mnemonic() != Mnemonic::Lea
        || body[available].op0_register() != Register::RCX
        || body[available].memory_base() != Register::RSI
        || body[available].memory_displacement64() as i64 != native.message_field
    {
        return Err("无法识别表情收藏条件".into());
    }
    let mut code = CodeAssembler::new(64)?;
    code.mov(dword_ptr(rbp + role_slot), 1)?;
    output.replace(initialize..inherited + 1, &mut code)?;
    let mut code = CodeAssembler::new(64)?;
    let mut favorite = code.create_label();
    let mut favorite_only = code.create_label();
    code.cmp(dword_ptr(rbp + role_slot), 1)?;
    code.jne(favorite)?;
    code.lea(rcx, ptr(rsi + native.message_field))?;
    code.call(native.copy_blocked)?;
    code.test(al, al)?;
    code.jne(favorite_only)?;
    code.mov(rcx, qword_ptr(rsi + native.info_field))?;
    code.lea(rdx, ptr(rbp + storage))?;
    code.call(native.path)?;
    code.mov(rbx, qword_ptr(rbp + storage + 16))?;
    code.lea(rcx, ptr(rbp + storage))?;
    code.call(native.path_destroy)?;
    code.test(rbx, rbx)?;
    code.jne(body[table_index].ip())?;
    code.set_label(&mut favorite_only)?;
    code.mov(dword_ptr(rbp + role_slot), 11)?;
    code.set_label(&mut favorite)?;
    code.add_instruction(body[available])?;
    output.replace(available..available + 1, &mut code)?;
    let mut code = CodeAssembler::new(64)?;
    let mut chosen = code.create_label();
    code.add_instruction(body[table_index])?;
    code.cmp(dword_ptr(rbp + role_slot), 1)?;
    code.jne(chosen)?;
    code.lea(rax, ptr(Register::RIP) + native.copy_table)?;
    code.set_label(&mut chosen)?;
    output.replace(table_index..table_index + 1, &mut code)?;
    output.replace(role..role + 1, &mut CodeAssembler::new(64)?)?;
    let mut code = CodeAssembler::new(64)?;
    let mut original = code.create_label();
    let mut ready = code.create_label();
    code.cmp(dword_ptr(rbp + role_slot), 1)?;
    code.jne(original)?;
    code.call(native.copy_text)?;
    code.jmp(ready)?;
    code.set_label(&mut original)?;
    code.call(text_getter)?;
    code.set_label(&mut ready)?;
    output.replace(text..text + 1, &mut code)?;
    let mut code = CodeAssembler::new(64)?;
    let mut ready = code.create_label();
    code.add_instruction(body[action])?;
    code.cmp(dword_ptr(rbp + role_slot), 1)?;
    code.jne(ready)?;
    code.mov(edx, 0x3f0)?;
    code.set_label(&mut ready)?;
    output.replace(action..action + 1, &mut code)?;
    for (index, instruction) in body.iter().enumerate().take(finish).skip(append + 1) {
        if matches!(instruction.mnemonic(), Mnemonic::Je | Mnemonic::Jne)
            && instruction.near_branch_target() == returned
        {
            let mut branch = *instruction;
            branch.set_near_branch64(body[finish].ip());
            let mut code = CodeAssembler::new(64)?;
            code.add_instruction(branch)?;
            output.replace(index..index + 1, &mut code)?;
        }
    }
    let mut code = CodeAssembler::new(64)?;
    code.cmp(dword_ptr(rbp + role_slot), 1)?;
    code.jne(returned)?;
    code.mov(dword_ptr(rbp + role_slot), 11)?;
    code.jmp(body[context_start].ip())?;
    output.replace(finish..finish + 1, &mut code)?;
    compact_string(&mut output, native.string_destroy)?;
    output.finish()
}

fn table(image: &Image<'_>, method: u64, progress: &Progress) -> Result<(u64, u64)> {
    let mut found = Vec::new();
    for slot in image.find("虚函数入口", &method.to_le_bytes(), progress)? {
        if slot % 8 != 0 {
            continue;
        }
        let mut cursor = slot;
        while cursor >= image.base() + 8 {
            let pointer = pointed(image, cursor - 8)?;
            let Ok(locator) = image.data(pointer, 24) else {
                break;
            };
            if u32::from_le_bytes(locator[..4].try_into()?) == 1
                && image.base() + u64::from(u32::from_le_bytes(locator[20..24].try_into()?))
                    == pointer
            {
                if u32::from_le_bytes(locator[4..8].try_into()?) == 0 {
                    found.push((cursor, slot - cursor));
                }
                break;
            }
            cursor -= 8;
        }
    }
    unique(found, "消息视图虚函数表")
}

fn click(image: &Image<'_>, native: &Native, progress: &Progress) -> Result<Vec<Edit>> {
    let (emoticon, _) = table(image, native.menu.start, progress)?;
    let (_, slot) = table(image, native.click.start, progress)?;
    let address = emoticon + slot;
    let original = pointed(image, address)?;
    let mut decoder = Decoder::with_ip(
        64,
        image.data(original, 16)?,
        original,
        DecoderOptions::NONE,
    );
    if decoder.decode().mnemonic() != Mnemonic::Ret {
        return Err("表情点击入口包含无法复用的逻辑".into());
    }
    let offset = image.offset(address)?;
    let mut edits = vec![Edit {
        range: offset..offset + 8,
        bytes: native.click.start.to_le_bytes().to_vec(),
    }];
    let mut output = Body::new(image, &native.click)?;
    let body = output.original.clone();
    let invoked = unique(
        body.iter()
            .enumerate()
            .filter_map(|(index, instruction)| {
                (instruction.code() == Code::Call_rm64
                    && instruction.op0_kind() == OpKind::Memory
                    && instruction.memory_displacement64() == 0x48)
                    .then_some(index)
            })
            .collect(),
        "图片预览分派调用",
    )?;
    let mut code = CodeAssembler::new(64)?;
    compare(&mut code, dword_ptr(rsi + native.message_field))?;
    code.je(body[epilogue(&body)?].ip())?;
    code.add_instruction(body[invoked + 1])?;
    output.replace(invoked + 1..invoked + 2, &mut code)?;
    compact_string(&mut output, native.string_destroy)?;
    edits.extend(output.finish()?);
    let mut output = Body::new(image, &native.delegate)?;
    let body = output.original.clone();
    let kinds: BTreeSet<_> = body
        .iter()
        .filter(|instruction| {
            instruction.mnemonic() == Mnemonic::Cmp
                && instruction.op0_register() == Register::EAX
                && instruction.op1_kind() == OpKind::Immediate8to32
        })
        .map(Instruction::immediate8to32)
        .collect();
    if kinds != BTreeSet::from([10, 11, 12, 13, 26]) {
        return Err("无法识别媒体预览类型集合".into());
    }
    let branch = unique(
        body.windows(2)
            .enumerate()
            .filter_map(|(index, window)| {
                (window[0].mnemonic() == Mnemonic::Cmp
                    && window[0].op0_register() == Register::EAX
                    && window[0].op1_kind() == OpKind::Immediate8to32
                    && window[0].immediate8to32() == 10
                    && window[1].mnemonic() == Mnemonic::Je)
                    .then_some(index)
            })
            .collect(),
        "图片预览类型检查",
    )?;
    let start = unique(
        body.windows(2)
            .filter_map(|window| {
                (window[0].mnemonic() == Mnemonic::Cmp
                    && window[0].op0_register() == Register::EAX
                    && window[0].op1_kind() == OpKind::Immediate8to32
                    && window[0].immediate8to32() == 26
                    && window[1].mnemonic() == Mnemonic::Jne)
                    .then_some(window[1].near_branch_target())
            })
            .collect(),
        "普通消息预览分派",
    )?;
    let start = position(&body, start)?;
    let accepted = body[branch + 1].near_branch_target();
    let end = position(&body, accepted)?;
    let returned = body
        .last()
        .filter(|instruction| instruction.mnemonic() == Mnemonic::Jmp)
        .ok_or("找不到预览分派返回")?
        .near_branch_target();
    let mut code = CodeAssembler::new(64)?;
    code.lea(edx, ptr(rax - 10))?;
    code.cmp(edx, 3)?;
    code.jbe(accepted)?;
    code.cmp(eax, 22)?;
    code.je(accepted)?;
    code.jmp(returned)?;
    output.replace(start..end, &mut code)?;
    let tail = body
        .iter()
        .rposition(|instruction| instruction.mnemonic() == Mnemonic::Ret)
        .ok_or("找不到预览分派结束位置")?
        + 1;
    output.replace(tail..body.len(), &mut CodeAssembler::new(64)?)?;
    edits.extend(output.finish()?);
    Ok(edits)
}

fn preview(image: &Image<'_>, native: &Native, references: &References) -> Result<Vec<Edit>> {
    let mut output = Body::new(image, &native.preview)?;
    let body = output.original.clone();
    let mut types = Vec::new();
    for (index, target) in calls(&body) {
        let Ok(function) = function(image, target) else {
            continue;
        };
        types.extend(
            image
                .instructions(&function)?
                .iter()
                .take_while(|instruction| instruction.mnemonic() != Mnemonic::Call)
                .filter_map(|instruction| {
                    (instruction.code() == Code::Mov_rm32_r32
                        && instruction.op0_kind() == OpKind::Memory
                        && instruction.memory_base() == Register::RCX
                        && instruction.memory_index() == Register::None
                        && instruction.op1_register() == Register::EDX)
                        .then_some((index, target, instruction.memory_displacement64() as i64))
                }),
        );
    }
    let (type_call, type_setter, kind) = unique(types, "预览项目类型设置")?;
    let mut setters = BTreeSet::new();
    for caller in callers(references, type_setter) {
        let instructions = image.instructions(&caller)?;
        let emoticon = calls(&instructions).any(|(index, target)| {
            target == type_setter
                && argument(&instructions, index, Register::EDX).is_ok_and(|argument| {
                    argument.code() == Code::Mov_r32_imm32 && argument.immediate32() == 3
                })
        });
        if !emoticon {
            continue;
        }
        for (_, target) in calls(&instructions) {
            let Ok(function) = function(image, target) else {
                continue;
            };
            let setter = image.instructions(&function)?;
            if calls(&setter).next().is_some()
                || !setter
                    .iter()
                    .take_while(|instruction| instruction.mnemonic() != Mnemonic::Call)
                    .any(|instruction| {
                        instruction.code() == Code::Mov_r64_rm64
                            && instruction.memory_base() == Register::RDX
                            && instruction.memory_displacement64() == 8
                    })
            {
                continue;
            }
            let Some(receiver) = setter
                .iter()
                .take_while(|instruction| instruction.mnemonic() != Mnemonic::Call)
                .find(|instruction| {
                    instruction.mnemonic() == Mnemonic::Mov
                        && instruction.op0_kind() == OpKind::Register
                        && instruction.op1_kind() == OpKind::Register
                        && instruction.op1_register() == Register::RCX
                })
            else {
                continue;
            };
            let fields = setter
                .iter()
                .filter_map(|instruction| {
                    (instruction.code() == Code::Mov_rm64_r64
                        && instruction.op0_kind() == OpKind::Memory
                        && instruction.memory_base() == receiver.op0_register()
                        && instruction.memory_index() == Register::None)
                        .then_some(instruction.memory_displacement64() as i64)
                })
                .collect::<Vec<_>>();
            if let [value, owner] = fields.as_slice()
                && *owner == value + 8
            {
                setters.insert((target, *value));
            }
        }
    }
    let (_, information) = unique(setters.into_iter().collect(), "预览表情信息设置")?;
    let constructor = call(&body, native.loader)?;
    let (binding, _) = calls(&body[constructor + 1..])
        .next()
        .map(|(index, target)| (constructor + 1 + index, target))
        .ok_or("找不到预览下载器绑定")?;
    let parameter = stack_argument(&body, binding, Register::RDX)?;
    let allocation = calls(&body[..constructor])
        .next_back()
        .ok_or("找不到预览下载器分配")?
        .0;
    let allocation = allocation - 1;
    if body[allocation].code() != Code::Mov_r32_imm32
        || body[allocation].op0_register() != Register::ECX
    {
        return Err("无法识别预览下载器分配参数".into());
    }
    let mut code = CodeAssembler::new(64)?;
    let mut ready = code.create_label();
    compare(&mut code, dword_ptr(r14))?;
    code.jne(ready)?;
    code.mov(edx, 3)?;
    code.set_label(&mut ready)?;
    code.call(type_setter)?;
    output.replace(type_call..type_call + 1, &mut code)?;
    let mut code = CodeAssembler::new(64)?;
    let mut original = code.create_label();
    code.cmp(dword_ptr(r12 + kind), 3)?;
    code.jne(original)?;
    code.lea(rcx, ptr(rbp + parameter))?;
    code.mov(rdx, r14)?;
    code.call(native.info)?;
    code.lea(rcx, ptr(r12 + information))?;
    code.lea(rdx, ptr(rbp + parameter))?;
    code.call(native.shared_move)?;
    code.mov(rax, r12)?;
    code.jmp(body[binding].next_ip())?;
    code.set_label(&mut original)?;
    code.add_instruction(body[allocation])?;
    output.replace(allocation..allocation + 1, &mut code)?;
    compact_string(&mut output, native.string_destroy)?;
    output.finish()
}

impl Analysis for Scan {
    fn visit(
        &mut self,
        _image: &Image<'_>,
        _function: &Range<u64>,
        _references: &References,
        _progress: &Progress,
    ) -> Result<Vec<Edit>> {
        Ok(Vec::new())
    }

    fn finish(
        self: Box<Self>,
        image: &Image<'_>,
        references: &References,
        progress: &Progress,
    ) -> Result<Vec<Mode>> {
        let native = Native::find(image, &self.symbols, references, progress)?;
        let step = progress.activity("准备表情补丁");
        let mut edits = click(image, &native, progress)?;
        edits.extend(preview(image, &native, references)?);
        edits.extend(menu(image, &native)?);
        edits.extend(encoder(image, &native)?);
        edits.extend(convert(image, &native)?);
        edits.extend(worker(image, &native, references)?);
        edits.extend(filename(image, &native)?);
        edits.extend(clipboard(image, &native)?);
        edits.extend(schedule(image, &native)?);
        step.finish(format!("{} 处修改", edits.len()));
        Ok(vec![Mode::enabled(edits)])
    }
}
