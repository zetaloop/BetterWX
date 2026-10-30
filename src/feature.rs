use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::{
    Result, appex, browser, coexist, credentials,
    data::Data,
    emoticon, icon,
    image::{Image, References, Symbols},
    inherit, login, notify,
    progress::Progress,
    remote, resources, revoke, sound,
    store::{self, Content, Store},
    time, timestamps, tray, uia, updates, writable,
};

pub type Edits = BTreeMap<PathBuf, Vec<Edit>>;
pub type Resources = BTreeMap<String, Range<usize>>;

pub struct Feature {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub targets: &'static [Target],
}

pub struct Target {
    pub file: Option<&'static str>,
    pub find: fn(&Image<'_>, &Progress) -> Result<Symbols>,
    pub scan: fn(Symbols) -> Box<dyn Analysis>,
}

pub trait Analysis {
    fn resources(&self) -> Resources {
        Resources::new()
    }

    fn visit(
        &mut self,
        image: &Image<'_>,
        function: &Range<u64>,
        references: &References,
        progress: &Progress,
    ) -> Result<Vec<Edit>>;

    fn finish(
        self: Box<Self>,
        image: &Image<'_>,
        references: &References,
        progress: &Progress,
    ) -> Result<Vec<Mode>>;
}

impl Target {
    fn path(&self, primary: &Path) -> Result<PathBuf> {
        match self.file {
            Some(file) => Ok(primary.parent().ok_or("目标文件缺少父目录")?.join(file)),
            None => Ok(primary.to_owned()),
        }
    }
}

#[derive(Clone)]
pub struct Edit {
    pub range: Range<usize>,
    pub bytes: Vec<u8>,
}

pub struct Mode<T = Vec<Edit>> {
    pub id: &'static str,
    pub name: &'static str,
    pub edits: T,
}

impl<T> Mode<T> {
    pub fn enabled(edits: T) -> Self {
        Self {
            id: "enabled",
            name: "已启用",
            edits,
        }
    }
}

pub struct Prepared {
    pub feature: &'static Feature,
    pub edits: std::result::Result<Vec<Mode<Edits>>, String>,
    pub resources: BTreeMap<PathBuf, Resources>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum State {
    Disabled,
    Enabled(usize),
    Partial,
}

impl State {
    pub fn enabled(self) -> bool {
        matches!(self, Self::Enabled(_))
    }
}

impl Prepared {
    pub fn issue<'a>(&'a self, store: &'a Store) -> Option<&'a String> {
        match &self.edits {
            Err(error) => Some(error),
            Ok(modes) => modes
                .iter()
                .flat_map(|mode| mode.edits.keys())
                .find_map(|target| store.files[target].issue.as_ref()),
        }
    }

    pub fn state(&self, store: &Store) -> State {
        let Ok(modes) = &self.edits else {
            return State::Disabled;
        };
        let states: BTreeSet<_> = modes
            .iter()
            .flat_map(|mode| mode.edits.keys())
            .map(|target| store.files[target].enabled.get(self.feature.id).copied())
            .collect();
        match states.into_iter().collect::<Vec<_>>().as_slice() {
            [] | [None] => State::Disabled,
            [Some(mode)] => State::Enabled(*mode),
            _ => State::Partial,
        }
    }

    pub fn label(&self, state: State) -> &'static str {
        match state {
            State::Disabled => "未启用",
            State::Enabled(mode) => self.edits.as_ref().expect("mode not prepared")[mode].name,
            State::Partial => "部分启用",
        }
    }

    pub fn outdated(&self, store: &Store) -> bool {
        let Ok(modes) = &self.edits else {
            return false;
        };
        store.files.iter().any(|(target, file)| {
            let Some(mode) = file.enabled.get(self.feature.id) else {
                return false;
            };
            modes[*mode].edits.get(target).is_some_and(|edits| {
                edits
                    .iter()
                    .any(|edit| file.current.matches(edit.range.start, &edit.bytes) != Some(true))
            })
        })
    }

    pub fn status(&self, store: &Store) -> String {
        if let Err(error) = &self.edits {
            return format!("不可用：{error}");
        }
        let label = self.label(self.state(store));
        if self.outdated(store) {
            format!("{label}，待更新")
        } else {
            label.to_owned()
        }
    }

    pub fn next(&self, store: &Store) -> Option<usize> {
        match self.state(store) {
            State::Enabled(mode) if mode + 1 == self.edits.as_ref().expect("modes").len() => None,
            State::Enabled(mode) => Some(mode + 1),
            _ => Some(0),
        }
    }

    pub fn targets(&self, store: &Store, mode: Option<usize>) -> Result<Vec<PathBuf>> {
        Ok(self
            .edits
            .as_ref()
            .map_err(|error| error.clone())?
            .iter()
            .flat_map(|mode| mode.edits.keys())
            .filter(|target| store.files[*target].enabled.get(self.feature.id).copied() != mode)
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect())
    }
}

pub const FEATURES: &[Feature] = &[
    login::FEATURE,
    credentials::FEATURE,
    revoke::FEATURE,
    notify::FEATURE,
    time::FEATURE,
    timestamps::FEATURE,
    emoticon::FEATURE,
    writable::FEATURE,
    resources::FEATURE,
    browser::FEATURE,
    appex::FEATURE,
    uia::FEATURE,
    remote::FEATURE,
    updates::FEATURE,
    coexist::FEATURE,
    sound::FEATURE,
    icon::FEATURE,
    tray::FEATURE,
];

pub fn targets(target: &Path) -> Result<Vec<PathBuf>> {
    Ok(FEATURES
        .iter()
        .flat_map(|feature| feature.targets)
        .filter(|target| target.file.is_some())
        .map(|entry| entry.path(target))
        .collect::<Result<BTreeSet<_>>>()?
        .into_iter()
        .collect())
}

pub fn find(id: &str) -> Result<&'static Feature> {
    FEATURES
        .iter()
        .find(|feature| feature.id == id)
        .ok_or_else(|| format!("未知功能：{id}").into())
}

pub fn scan(store: &mut Store, progress: &Progress) -> Result<Vec<Prepared>> {
    analyze(store, FEATURES, progress)
}

pub fn analyze(
    store: &mut Store,
    features: &'static [Feature],
    progress: &Progress,
) -> Result<Vec<Prepared>> {
    prepare(store, features, progress, |_| true)
}

pub fn prepare(
    store: &mut Store,
    features: &'static [Feature],
    progress: &Progress,
    selected: impl Fn(&Path) -> bool,
) -> Result<Vec<Prepared>> {
    let mut prepared: Vec<_> = features
        .iter()
        .map(|feature| Prepared {
            feature,
            edits: Ok(Vec::new()),
            resources: BTreeMap::new(),
        })
        .collect();
    let mut files: BTreeMap<PathBuf, Vec<(usize, &Target)>> = BTreeMap::new();
    for (index, feature) in features.iter().enumerate() {
        for target in feature.targets {
            progress.check()?;
            let path = target.path(&store.target)?;
            if !selected(&path) {
                continue;
            }
            match store.load(&path, progress) {
                Ok(file) => files
                    .entry(file.target.clone())
                    .or_default()
                    .push((index, target)),
                Err(error) => {
                    prepared[index].edits =
                        Err(format!("无法读取 {}：{error}", store::display(&path)))
                }
            }
        }
    }
    for (path, targets) in files {
        progress.check()?;
        let images = match Image::parse(&store.files[&path].original) {
            Ok(images) => images,
            Err(error) => {
                for (index, _) in targets {
                    prepared[index].edits = Err(format!("{}：{error}", store::display(&path)));
                }
                continue;
            }
        };
        for image in &images {
            let mut found = Vec::new();
            for (index, target) in targets.iter().copied() {
                if prepared[index].edits.is_err() {
                    continue;
                }
                progress.check()?;
                match (target.find)(image, progress) {
                    Ok(symbols) => {
                        let analysis = (target.scan)(symbols.clone());
                        found.push((index, symbols, analysis, Vec::new()));
                    }
                    Err(error) => {
                        let error = error.to_string();
                        progress.fail(&error);
                        prepared[index].edits = Err(error);
                    }
                }
            }
            if found.is_empty() {
                continue;
            }
            let labels = found
                .iter()
                .flat_map(|(_, symbols, _, _)| symbols)
                .flat_map(|(name, addresses)| {
                    addresses
                        .iter()
                        .map(move |address| (*address, name.trim_end_matches('\0').to_owned()))
                })
                .collect();
            let mut listeners: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
            for (index, (_, symbols, _, _)) in found.iter().enumerate() {
                for address in symbols.values().flatten() {
                    listeners.entry(*address).or_default().push(index);
                }
            }
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            let references =
                match image.references(&name, labels, progress, |references, function, changed| {
                    let listeners: BTreeSet<_> = changed
                        .iter()
                        .flat_map(|address| &listeners[address])
                        .copied()
                        .collect();
                    for listener in listeners {
                        progress.check()?;
                        let (index, _, analysis, common) = &mut found[listener];
                        if prepared[*index].edits.is_err() {
                            continue;
                        }
                        let progress = progress.group(features[*index].name);
                        match analysis.visit(image, function, references, &progress) {
                            Ok(edits) => common.extend(edits),
                            Err(error) => {
                                let error = error.to_string();
                                progress.fail(&error);
                                prepared[*index].edits = Err(error);
                            }
                        }
                    }
                    Ok(())
                }) {
                    Ok(references) => references,
                    Err(error) => {
                        progress.fail(&error.to_string());
                        for (index, _, _, _) in found {
                            prepared[index].edits = Err(error.to_string());
                        }
                        continue;
                    }
                };
            for (index, _, analysis, common) in found {
                progress.check()?;
                if prepared[index].edits.is_err() {
                    continue;
                }
                let progress = progress.group(features[index].name);
                let resources = analysis.resources();
                match analysis.finish(image, &references, &progress) {
                    Ok(modes) => {
                        if let Ok(choices) = &mut prepared[index].edits {
                            for mode in modes {
                                let choice =
                                    match choices.iter().position(|choice| choice.id == mode.id) {
                                        Some(index) => &mut choices[index],
                                        None => {
                                            choices.push(Mode {
                                                id: mode.id,
                                                name: mode.name,
                                                edits: Edits::new(),
                                            });
                                            choices.last_mut().expect("mode")
                                        }
                                    };
                                let edits = choice.edits.entry(path.clone()).or_default();
                                edits.extend(common.iter().cloned());
                                edits.extend(mode.edits);
                            }
                        }
                        if !resources.is_empty() {
                            prepared[index].resources.insert(path.clone(), resources);
                        }
                    }
                    Err(error) => {
                        let error = error.to_string();
                        progress.fail(&error);
                        prepared[index].edits = Err(error);
                    }
                }
            }
        }
    }
    Ok(prepared)
}

fn recognize<'a>(
    original: &[u8],
    current: &Data,
    modes: impl Iterator<Item = (usize, &'a [Edit])>,
) -> Option<usize> {
    let mut touched = false;
    let mut matches = Vec::new();
    for (mode, edits) in modes {
        let mut matched = 0;
        let mut applied = !edits.is_empty();
        for edit in edits {
            let before = original.get(edit.range.clone());
            let equal = current.matches(edit.range.start, &edit.bytes) == Some(true);
            applied &= equal;
            touched |= before
                .is_some_and(|original| current.matches(edit.range.start, original) == Some(false));
            if equal && before != Some(edit.bytes.as_slice()) {
                matched += 1;
            }
        }
        if applied {
            return Some(mode);
        }
        matches.push((mode, matched));
    }
    if !touched {
        return None;
    }
    let best = matches.iter().map(|(_, count)| *count).max();
    let candidates: Vec<_> = matches
        .iter()
        .filter(|(_, count)| Some(*count) == best)
        .map(|(mode, _)| *mode)
        .collect();
    Some(match candidates.as_slice() {
        [mode] => *mode,
        _ => 0,
    })
}

pub fn inspect(store: &mut Store, prepared: &[Prepared], progress: &Progress) -> Result<()> {
    for (target, file) in &mut store.files {
        let name = target.file_name().unwrap_or_default().to_string_lossy();
        let step = progress.start("识别当前补丁", file.current.len() as u64, "字节");
        step.detail(name.as_ref());
        let mut enabled = BTreeMap::new();
        for patch in prepared {
            progress.check()?;
            let Ok(modes) = &patch.edits else {
                continue;
            };
            let choices = modes.iter().enumerate().filter_map(|(mode, choice)| {
                choice
                    .edits
                    .get(target)
                    .map(|edits| (mode, edits.as_slice()))
            });
            if let Some(mode) = recognize(&file.original, &file.current, choices) {
                enabled.insert(patch.feature.id.to_owned(), mode);
            }
        }
        let expected = generate(&file.original, &enabled, prepared, target)?;
        let difference = expected.difference(&file.current);
        file.issue = difference.map(|offset| {
            format!(
                "{} 与当前补丁内容不同，首处差异位于 {offset:#x}",
                store::display(target)
            )
        });
        let state = if let Some(issue) = &file.issue {
            issue.clone()
        } else if enabled.is_empty() {
            "原始状态".to_owned()
        } else {
            prepared
                .iter()
                .filter_map(|patch| {
                    enabled.get(patch.feature.id).map(|mode| {
                        if patch.edits.as_ref().expect("modes").len() == 1 {
                            patch.feature.name.to_owned()
                        } else {
                            format!(
                                "{}：{}",
                                patch.feature.name,
                                patch.label(State::Enabled(*mode))
                            )
                        }
                    })
                })
                .collect::<Vec<_>>()
                .join("、")
        };
        step.finish(format!("{name}；{state}"));
        file.enabled = enabled;
    }
    Ok(())
}

pub fn change(
    store: &Store,
    patch: &Prepared,
    mode: Option<usize>,
    prepared: &[Prepared],
    progress: &Progress,
) -> Result<BTreeMap<PathBuf, Content>> {
    if let Some(issue) = patch.issue(store) {
        return Err(issue.clone().into());
    }
    let targets = patch.targets(store, mode)?;
    sources(store, targets.iter())?;
    if mode.is_some() {
        initialize(store, patch, progress)?;
    }
    let mut contents = BTreeMap::new();
    for target in targets {
        let file = &store.files[&target];
        let mut enabled = file.enabled.clone();
        if let Some(mode) = mode {
            enabled.insert(patch.feature.id.to_owned(), mode);
        } else {
            enabled.remove(patch.feature.id);
        }
        let data = generate(&file.original, &enabled, prepared, &target)?;
        contents.insert(target, Content { data, enabled });
    }
    Ok(contents)
}

fn sources<'a>(store: &Store, targets: impl Iterator<Item = &'a PathBuf>) -> Result<()> {
    for target in targets {
        let file = &store.files[target];
        if !file.confirmed
            && let Some(issue) = &file.source_issue
        {
            return Err(format!("{issue}\n使用 --force 可继续使用当前文件").into());
        }
    }
    Ok(())
}

fn initialize(store: &Store, patch: &Prepared, progress: &Progress) -> Result<()> {
    match patch.feature.id {
        id if id == sound::FEATURE.id => sound::initialize(store, patch, progress),
        id if id == icon::FEATURE.id => icon::initialize(store, patch, progress),
        id if id == notify::FEATURE.id => notify::initialize(progress),
        _ => Ok(()),
    }
}

pub fn rebuild(
    store: &Store,
    prepared: &[Prepared],
    inherited: Option<&inherit::Source>,
    progress: &Progress,
) -> Result<BTreeMap<PathBuf, Content>> {
    sources(store, store.files.keys())?;
    let mut enabled = Vec::new();
    for patch in prepared {
        let mode = if let Some(source) = inherited {
            let Some(mode) = source.modes.get(patch.feature.id) else {
                continue;
            };
            patch
                .edits
                .as_ref()
                .map_err(|error| format!("{}：{error}", patch.feature.name))?
                .iter()
                .position(|choice| choice.id == *mode)
                .ok_or_else(|| format!("{} 找不到模式：{mode}", patch.feature.name))?
        } else {
            match patch.state(store) {
                State::Disabled => continue,
                State::Enabled(mode) => mode,
                State::Partial => 0,
            }
        };
        enabled.push((patch, mode));
    }
    let mut contents = BTreeMap::new();
    for (target, file) in &store.files {
        progress.check()?;
        let selected = enabled
            .iter()
            .filter(|(patch, mode)| {
                patch.edits.as_ref().expect("mode not prepared")[*mode]
                    .edits
                    .contains_key(target)
            })
            .map(|(patch, mode)| (patch.feature.id.to_owned(), *mode))
            .collect();
        let data = generate(&file.original, &selected, prepared, target)?;
        if file.current != data {
            contents.insert(
                target.clone(),
                Content {
                    data,
                    enabled: selected,
                },
            );
        }
    }
    Ok(contents)
}

pub fn update(
    store: &mut Store,
    contents: BTreeMap<PathBuf, Content>,
    prepared: &[Prepared],
    inherited: Option<&inherit::Source>,
    progress: &Progress,
) -> Result<()> {
    sources(store, contents.keys())?;
    if let Some(source) = inherited {
        source.copy(store, &contents, progress)?;
    }
    for patch in prepared {
        if contents
            .values()
            .any(|content| content.enabled.contains_key(patch.feature.id))
        {
            initialize(store, patch, progress)?;
        }
    }
    describe(store, &contents, prepared, progress)?;
    store.save(contents, progress)
}

pub fn describe(
    store: &Store,
    contents: &BTreeMap<PathBuf, Content>,
    prepared: &[Prepared],
    progress: &Progress,
) -> Result<()> {
    for (target, content) in contents {
        let file = &store.files[target];
        let name = target.file_name().unwrap_or_default().to_string_lossy();
        for patch in prepared {
            let Ok(modes) = &patch.edits else {
                continue;
            };
            let previous = file.enabled.get(patch.feature.id).copied();
            let current = content.enabled.get(patch.feature.id).copied();
            let Some(mode) = current.or(previous) else {
                continue;
            };
            let Some(edits) = modes[mode].edits.get(target) else {
                continue;
            };
            if edits.iter().all(|edit| {
                file.current.get(edit.range.clone()) == content.data.get(edit.range.clone())
            }) {
                continue;
            }
            let images = Image::parse(&file.original)?;
            let step = progress.group(patch.feature.name).activity("生成文件内容");
            let mut size = 0;
            for edit in edits {
                progress.check()?;
                let before = file
                    .current
                    .get(
                        edit.range.start.min(file.current.len())
                            ..edit.range.end.min(file.current.len()),
                    )
                    .expect("current content range");
                let after = content
                    .data
                    .get(
                        edit.range.start.min(content.data.len())
                            ..edit.range.end.min(content.data.len()),
                    )
                    .expect("updated content range");
                if before != after {
                    let image = images
                        .iter()
                        .find(|image| image.contains(edit.range.start))
                        .ok_or("修改位置不在映像中")?;
                    step.record(format!(
                        "{name}；{}",
                        image.difference(&edit.range, &file.current, &content.data)?
                    ));
                    size += before
                        .iter()
                        .zip(after.iter())
                        .filter(|(left, right)| left != right)
                        .count()
                        + before.len().abs_diff(after.len());
                }
            }
            step.finish(format!(
                "{name}；{}；差异 {size} 字节",
                patch.label(current.map_or(State::Disabled, State::Enabled)),
            ));
        }
    }
    Ok(())
}

fn edits<'a>(
    enabled: &BTreeMap<String, usize>,
    prepared: &'a [Prepared],
    target: &Path,
) -> Result<Vec<&'a Edit>> {
    let mut edits = Vec::new();
    for (id, mode) in enabled {
        let patch = prepared
            .iter()
            .find(|patch| patch.feature.id == id)
            .ok_or_else(|| format!("未知功能：{id}"))?;
        let modes = patch
            .edits
            .as_ref()
            .map_err(|error| format!("{}：{error}", patch.feature.name))?;
        let mode = modes.get(*mode).ok_or("找不到所选功能模式")?;
        if let Some(changes) = mode.edits.get(target) {
            edits.extend(changes);
        }
    }
    edits.sort_by_key(|edit| edit.range.start);
    for pair in edits.windows(2) {
        if pair[0].range.end > pair[1].range.start {
            return Err("所选功能的修改位置重叠".into());
        }
    }
    Ok(edits)
}

fn generate(
    original: &Arc<Vec<u8>>,
    enabled: &BTreeMap<String, usize>,
    prepared: &[Prepared],
    target: &Path,
) -> Result<Data> {
    let edits = edits(enabled, prepared, target)?;
    let mut output = Data::default();
    let mut position = 0;
    for edit in edits {
        output.push(original.clone(), position..edit.range.start);
        if original.get(edit.range.clone()) == Some(edit.bytes.as_slice()) {
            output.push(original.clone(), edit.range.clone());
        } else {
            output.push(Arc::new(edit.bytes.clone()), 0..edit.bytes.len());
        }
        position = edit.range.end;
    }
    output.push(original.clone(), position..original.len());
    Ok(output)
}
