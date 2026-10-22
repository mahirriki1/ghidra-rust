//! Ghidra function-start byte patterns, matched against immutable executable
//! bytes. The vendored upstream XML is compiled into the binary and parsed once;
//! matches are only candidates that the caller must validate before use.
use std::sync::OnceLock;

/// Vendored unchanged from Ghidra; see `data/function-starts/README.md`.
const GCC_X86_64: &str = include_str!("../data/function-starts/x86-64gcc_patterns.xml");
const WINDOWS_X86_64: &str = include_str!("../data/function-starts/x86-64win_patterns.xml");

/// Longest compiled pattern, in bytes; chunked scans keep this much overlap.
pub(crate) const MAX_PATTERN_BYTES: usize = 128;
const MAX_PATTERNS: usize = 4_096;
const MAX_NESTING: usize = 8;

/// Which upstream pattern file applies to an image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PatternSet {
    /// `x86-64gcc_patterns.xml`, for x86-64 ELF.
    GccX86_64,
    /// `x86-64win_patterns.xml`, for x86-64 PE.
    WindowsX86_64,
}

impl PatternSet {
    /// The pattern set for an architecture and container, if supported.
    pub(crate) fn select(architecture: &str, format: &str) -> Option<Self> {
        match (architecture, format) {
            ("x86-64", "ELF") => Some(Self::GccX86_64),
            ("x86-64", "PE") => Some(Self::WindowsX86_64),
            _ => None,
        }
    }

    /// The compiled patterns; vendored data that fails to parse is an error.
    pub(crate) fn patterns(self) -> Result<&'static Patterns, String> {
        static GCC: OnceLock<Result<Patterns, String>> = OnceLock::new();
        static WINDOWS: OnceLock<Result<Patterns, String>> = OnceLock::new();
        let (cell, text) = match self {
            Self::GccX86_64 => (&GCC, GCC_X86_64),
            Self::WindowsX86_64 => (&WINDOWS, WINDOWS_X86_64),
        };
        cell.get_or_init(|| Patterns::parse(text))
            .as_ref()
            .map_err(Clone::clone)
    }
}

/// Whether function-start patterns apply to an image.
pub fn supported(architecture: &str, format: &str) -> bool {
    PatternSet::select(architecture, format).is_some()
}

/// What a match requires before its marked address may start a function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FunctionStart {
    /// Upstream `after="defined"`: something established must end exactly at
    /// the marked address, or it must begin its memory region.
    pub after_defined: bool,
    /// Upstream numeric `validcode`: the minimum decoded instructions.
    pub min_instructions: usize,
}

/// One masked byte sequence. `marker` is the offset of the function start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Pattern {
    values: Vec<u8>,
    masks: Vec<u8>,
    marker: usize,
    /// Upstream `<align mark bits>`: `match + mark` has `bits` low zero bits.
    align: Option<(usize, u32)>,
    pub start: FunctionStart,
}

impl Pattern {
    fn matches(&self, bytes: &[u8]) -> bool {
        bytes.len() >= self.values.len()
            && self
                .values
                .iter()
                .zip(&self.masks)
                .zip(bytes)
                .all(|((value, mask), byte)| byte & mask == *value)
    }

    fn fixed_bits(&self) -> u32 {
        self.masks.iter().map(|mask| mask.count_ones()).sum()
    }
}

/// A function-start match: the pattern's index, where its bytes begin, and
/// its marked address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Match {
    pub pattern: usize,
    pub at: u64,
    pub start: u64,
}

/// Compiled patterns indexed by their first byte. Only `funcstart` actions are
/// kept; `codeboundary`, `possiblefuncstart`, `setcontext` and patterns that
/// require an existing function (`validcode="function"`) never nominate one.
#[derive(Debug)]
pub(crate) struct Patterns {
    pub patterns: Vec<Pattern>,
    first: Vec<Vec<u16>>,
}

impl Patterns {
    /// All matches whose bytes lie in `bytes`, which begins at `address`, with
    /// a match position in `positions` (offsets into `bytes`). A match needs its
    /// whole pattern inside `bytes`; callers keep region boundaries.
    pub(crate) fn scan(
        &self,
        bytes: &[u8],
        address: u64,
        positions: std::ops::Range<usize>,
        found: &mut Vec<Match>,
        limit: usize,
    ) -> bool {
        for offset in positions {
            let Some(&first) = bytes.get(offset) else {
                break;
            };
            for &index in &self.first[first as usize] {
                let pattern = &self.patterns[index as usize];
                if !pattern.matches(&bytes[offset..]) {
                    continue;
                }
                let Some(at) = address.checked_add(offset as u64) else {
                    continue;
                };
                if let Some((mark, bits)) = pattern.align
                    && at
                        .checked_add(mark as u64)
                        .is_none_or(|aligned| aligned & ((1u64 << bits) - 1) != 0)
                {
                    continue;
                }
                let Some(start) = at.checked_add(pattern.marker as u64) else {
                    continue;
                };
                if found.len() == limit {
                    return false;
                }
                found.push(Match {
                    pattern: index as usize,
                    at,
                    start,
                });
            }
        }
        true
    }

    fn parse(text: &str) -> Result<Self, String> {
        let mut patterns = Vec::new();
        let mut parser = Parser { text, position: 0 };
        let root = parser.element(0)?.ok_or("Empty pattern file")?;
        if root.name != "patternlist" || parser.element(0)?.is_some() {
            return Err("Pattern file must contain one patternlist".into());
        }
        for child in &root.children {
            match child.name {
                "pattern" => {
                    let mut sequences = Vec::new();
                    let mut start = None;
                    let mut align = None;
                    for item in &child.children {
                        match item.name {
                            "data" => sequences.push(sequence(&item.text)?),
                            _ => action(item, &mut start, &mut align)?,
                        }
                    }
                    if let Some(start) = start {
                        for (values, masks, marker) in sequences {
                            push(
                                &mut patterns,
                                values,
                                masks,
                                marker.unwrap_or(0),
                                align,
                                start,
                            )?;
                        }
                    }
                }
                "patternpairs" => {
                    let total = child.number("totalbits")?;
                    let post_bits = child.number("postbits")?;
                    let mut pre = Vec::new();
                    let mut post = Vec::new();
                    let mut start = None;
                    let mut align = None;
                    for list in &child.children {
                        for item in &list.children {
                            match (list.name, item.name) {
                                ("prepatterns", "data") => pre.push(sequence(&item.text)?),
                                ("postpatterns", "data") => post.push(sequence(&item.text)?),
                                ("postpatterns", _) => action(item, &mut start, &mut align)?,
                                _ => return Err(format!("Unexpected {}", item.name)),
                            }
                        }
                    }
                    let Some(start) = start else {
                        continue;
                    };
                    // As Ghidra's PatternPairSet: thresholds count fixed bits.
                    for (post_values, post_masks, marker) in &post {
                        if marker.is_some() {
                            return Err("A paired post pattern has its own marker".into());
                        }
                        let post_fixed: u32 = post_masks.iter().map(|m| m.count_ones()).sum();
                        if post_fixed < post_bits {
                            continue;
                        }
                        for (pre_values, pre_masks, pre_marker) in &pre {
                            let pre_fixed: u32 = pre_masks.iter().map(|m| m.count_ones()).sum();
                            if pre_marker.is_some() || pre_fixed + post_fixed < total {
                                continue;
                            }
                            push(
                                &mut patterns,
                                [pre_values.as_slice(), post_values].concat(),
                                [pre_masks.as_slice(), post_masks].concat(),
                                pre_values.len(),
                                align,
                                start,
                            )?;
                        }
                    }
                }
                other => return Err(format!("Unexpected {other}")),
            }
        }
        let mut first = vec![Vec::new(); 256];
        for (index, pattern) in patterns.iter().enumerate() {
            for byte in 0..=255u8 {
                if byte & pattern.masks[0] == pattern.values[0] {
                    first[byte as usize].push(index as u16);
                }
            }
        }
        Ok(Self { patterns, first })
    }
}

fn push(
    patterns: &mut Vec<Pattern>,
    values: Vec<u8>,
    masks: Vec<u8>,
    marker: usize,
    align: Option<(usize, u32)>,
    start: FunctionStart,
) -> Result<(), String> {
    if values.is_empty() || values.len() > MAX_PATTERN_BYTES || marker >= values.len() {
        return Err("Pattern length or marker is out of range".into());
    }
    if patterns.len() == MAX_PATTERNS {
        return Err("Too many patterns".into());
    }
    let pattern = Pattern {
        values,
        masks,
        marker,
        align,
        start,
    };
    // Duplicate upstream lines add no evidence.
    if pattern.fixed_bits() > 0 && !patterns.contains(&pattern) {
        patterns.push(pattern);
    }
    Ok(())
}

/// Records a match action; only supported `funcstart` actions nominate a function.
fn action(
    item: &Element<'_>,
    start: &mut Option<FunctionStart>,
    align: &mut Option<(usize, u32)>,
) -> Result<(), String> {
    match item.name {
        "funcstart" => {
            let mut nominated = FunctionStart {
                after_defined: false,
                min_instructions: 0,
            };
            let mut supported = true;
            for &(name, value) in &item.attributes {
                match (name, value) {
                    ("after", "defined") => nominated.after_defined = true,
                    ("validcode", "function") => supported = false,
                    ("validcode", count) => {
                        nominated.min_instructions = count
                            .parse()
                            .map_err(|_| format!("Unsupported validcode {count:?}"))?;
                    }
                    // Labels only accompany validcode="function" upstream.
                    ("label", _) => {}
                    _ => return Err(format!("Unsupported funcstart {name}={value:?}")),
                }
            }
            *start = supported.then_some(nominated);
        }
        "codeboundary" | "possiblefuncstart" | "setcontext" => {}
        "align" => {
            let mark = item.number("mark")? as usize;
            let bits = item.number("bits")?;
            if bits >= 64 {
                return Err("Alignment is out of range".into());
            }
            *align = Some((mark, bits));
        }
        other => return Err(format!("Unexpected {other}")),
    }
    Ok(())
}

type Sequence = (Vec<u8>, Vec<u8>, Option<usize>);

/// Parses Ghidra's ditted-bit notation: `0x` hex with `.` nibble wildcards,
/// eight-character binary groups with `.` bit wildcards, and `*` as the marker.
fn sequence(text: &str) -> Result<Sequence, String> {
    let (mut values, mut masks, mut marker) = (Vec::new(), Vec::new(), None);
    for token in text.split_whitespace() {
        if token == "*" {
            if marker.replace(values.len()).is_some() {
                return Err("Pattern has two markers".into());
            }
        } else if let Some(hex) = token.strip_prefix("0x") {
            let digits = hex.as_bytes();
            if digits.is_empty() || digits.len() % 2 != 0 {
                return Err(format!("Odd hex pattern {token:?}"));
            }
            for pair in digits.chunks(2) {
                let (mut value, mut mask) = (0u8, 0u8);
                for &digit in pair {
                    value <<= 4;
                    mask <<= 4;
                    if digit != b'.' {
                        value |= (digit as char)
                            .to_digit(16)
                            .ok_or_else(|| format!("Bad hex pattern {token:?}"))?
                            as u8;
                        mask |= 0xf;
                    }
                }
                values.push(value);
                masks.push(mask);
            }
        } else {
            let bits = token.as_bytes();
            if bits.is_empty() || bits.len() % 8 != 0 {
                return Err(format!("Binary pattern {token:?} is not whole bytes"));
            }
            for byte in bits.chunks(8) {
                let (mut value, mut mask) = (0u8, 0u8);
                for &bit in byte {
                    value <<= 1;
                    mask <<= 1;
                    match bit {
                        b'0' => mask |= 1,
                        b'1' => {
                            value |= 1;
                            mask |= 1;
                        }
                        b'.' => {}
                        _ => return Err(format!("Bad binary pattern {token:?}")),
                    }
                }
                values.push(value);
                masks.push(mask);
            }
        }
        if values.len() > MAX_PATTERN_BYTES {
            return Err("Pattern is too long".into());
        }
    }
    Ok((values, masks, marker))
}

/// The element subset the pattern files use: nested elements with quoted
/// attributes, text, and comments. Declarations and entities are rejected.
struct Element<'a> {
    name: &'a str,
    attributes: Vec<(&'a str, &'a str)>,
    children: Vec<Element<'a>>,
    text: String,
}

impl Element<'_> {
    fn number(&self, name: &str) -> Result<u32, String> {
        self.attributes
            .iter()
            .find(|(key, _)| *key == name)
            .and_then(|(_, value)| value.parse().ok())
            .ok_or_else(|| format!("{} needs a numeric {name}", self.name))
    }
}

struct Parser<'a> {
    text: &'a str,
    position: usize,
}

impl<'a> Parser<'a> {
    fn rest(&self) -> &'a str {
        &self.text[self.position..]
    }

    /// Skips comments; returns the remaining text before the next tag.
    fn content(&mut self) -> Result<String, String> {
        let start = self.position;
        loop {
            let rest = self.rest();
            if rest.starts_with("<!--") {
                let end = rest.find("-->").ok_or("Unterminated comment")?;
                self.position += end + 3;
            } else if rest.starts_with('<') || rest.is_empty() {
                break;
            } else {
                self.position += rest.find('<').unwrap_or(rest.len());
            }
        }
        let text = strip_comments(&self.text[start..self.position]);
        if text.contains(['&', '>']) {
            return Err("Entities and stray markup are not supported".into());
        }
        Ok(text)
    }

    fn element(&mut self, depth: usize) -> Result<Option<Element<'a>>, String> {
        if depth > MAX_NESTING {
            return Err("Pattern file nesting is too deep".into());
        }
        if !self.content()?.trim().is_empty() {
            return Err("Unexpected text between elements".into());
        }
        let rest = self.rest();
        if rest.is_empty() || rest.starts_with("</") {
            return Ok(None);
        }
        if rest.starts_with("<!") || rest.starts_with("<?") {
            return Err("Declarations are not supported".into());
        }
        let end = rest.find('>').ok_or("Unterminated tag")?;
        let tag = &rest[1..end];
        self.position += end + 1;
        let (tag, empty) = match tag.strip_suffix('/') {
            Some(tag) => (tag, true),
            None => (tag, false),
        };
        let mut parts = tag.trim().splitn(2, char::is_whitespace);
        let name = parts.next().filter(|n| !n.is_empty()).ok_or("Empty tag")?;
        let mut attributes = Vec::new();
        let mut rest = parts.next().unwrap_or("").trim();
        while !rest.is_empty() {
            let (key, value) = rest.split_once('=').ok_or("Malformed attribute")?;
            let value = value
                .trim_start()
                .strip_prefix('"')
                .ok_or("Unquoted attribute")?;
            let close = value.find('"').ok_or("Unterminated attribute")?;
            attributes.push((key.trim(), &value[..close]));
            rest = value[close + 1..].trim_start();
        }
        let mut element = Element {
            name,
            attributes,
            children: Vec::new(),
            text: String::new(),
        };
        if empty {
            return Ok(Some(element));
        }
        loop {
            let text = self.content()?;
            element.text.push_str(&text);
            if let Some(after) = self.rest().strip_prefix("</") {
                let end = after.find('>').ok_or("Unterminated closing tag")?;
                if after[..end].trim() != name {
                    return Err(format!("Mismatched closing tag for {name}"));
                }
                self.position += end + 3;
                return Ok(Some(element));
            }
            match self.element(depth + 1)? {
                Some(child) => element.children.push(child),
                None => return Err(format!("Unterminated {name}")),
            }
        }
    }
}

fn strip_comments(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find("<!--") {
        out.push_str(&rest[..start]);
        rest = rest[start..]
            .find("-->")
            .map_or("", |end| &rest[start + end + 3..]);
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ditted_bits_hex_wildcards_and_markers() {
        let (values, masks, marker) = sequence("0x90 * 0xe9..  01...100").unwrap();
        assert_eq!(values, [0x90, 0xe9, 0x00, 0x44]);
        assert_eq!(masks, [0xff, 0xff, 0x00, 0xc7]);
        assert_eq!(marker, Some(1));
        assert_eq!(sequence("0x5.").unwrap().1, [0xf0]);
        for bad in ["0x9", "0x9g", "0101", "0101010x", "* 0x90 *"] {
            assert!(sequence(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn pairs_count_fixed_bits_and_mark_the_post_pattern() {
        let patterns = Patterns::parse(
            r#"<patternlist>
              <patternpairs totalbits="20" postbits="12">
                <prepatterns><data>0xc3</data><data>0x..</data></prepatterns>
                <postpatterns>
                  <data>0x55 0x48</data>  <!-- 16 fixed bits -->
                  <data>0x5.</data>       <!-- 4 fixed bits: below postbits -->
                  <funcstart/>
                </postpatterns>
              </patternpairs>
              <pattern><data>0xcc * 0x53</data><codeboundary/></pattern>
              <pattern><data>0x41</data><funcstart validcode="function" label="x"/></pattern>
            </patternlist>"#,
        )
        .unwrap();
        // Only RET + PUSH RBP; REX.W reaches 20 fixed bits; a wildcard prefix
        // has 16, and non-funcstart actions nominate nothing.
        assert_eq!(patterns.patterns.len(), 1);
        let pattern = &patterns.patterns[0];
        assert_eq!(
            (pattern.values.as_slice(), pattern.marker),
            ([0xc3, 0x55, 0x48].as_slice(), 1)
        );
        let mut found = Vec::new();
        let bytes = [0x90, 0xc3, 0x55, 0x48, 0xc3, 0x55];
        assert!(patterns.scan(&bytes, 0x1000, 0..bytes.len(), &mut found, 8));
        // The truncated final candidate is not matched.
        assert_eq!(
            found,
            [Match {
                pattern: 0,
                at: 0x1001,
                start: 0x1002
            }]
        );
    }

    #[test]
    fn alignment_applies_to_the_match_not_the_marker() {
        let patterns = Patterns::parse(
            r#"<patternlist><pattern><data>0xcc * 0x55</data>
               <align mark="0" bits="2"/><funcstart after="defined" validcode="3"/>
               </pattern></patternlist>"#,
        )
        .unwrap();
        assert_eq!(
            patterns.patterns[0].start,
            FunctionStart {
                after_defined: true,
                min_instructions: 3
            }
        );
        let bytes = [0xcc, 0x55, 0x00, 0x00, 0xcc, 0x55, 0xcc, 0x55];
        let mut found = Vec::new();
        assert!(patterns.scan(&bytes, 0x1000, 0..bytes.len(), &mut found, 8));
        let starts: Vec<_> = found.iter().map(|m| m.start).collect();
        assert_eq!(starts, [0x1001, 0x1005]);
        // The match limit is reported rather than silently truncating.
        let mut limited = Vec::new();
        assert!(!patterns.scan(&bytes, 0x1000, 0..bytes.len(), &mut limited, 1));
        assert_eq!(limited.len(), 1);
    }

    #[test]
    fn malformed_or_unsupported_files_are_rejected() {
        for text in [
            "",
            "<patternlist>",
            "<!DOCTYPE x><patternlist/>",
            "<patternlist>&amp;</patternlist>",
            "<patternlist><pattern><data>0x90</data><funcstart after=\"function\"/></pattern></patternlist>",
            "<patternlist><pattern><data>0x90</data><other/></pattern></patternlist>",
            "<patternlist></pattern>",
            "<patternlist/><patternlist/>",
        ] {
            assert!(Patterns::parse(text).is_err(), "{text}");
        }
    }

    #[test]
    fn vendored_pattern_files_compile() {
        let gcc = PatternSet::GccX86_64.patterns().unwrap();
        let windows = PatternSet::WindowsX86_64.patterns().unwrap();
        assert!(gcc.patterns.len() > 100, "{}", gcc.patterns.len());
        // The cookie-check pattern requires an existing function and is omitted.
        assert_eq!(windows.patterns.len(), 22);
        // PUSH RBP; MOV RBP,RSP after padding is a GCC function start.
        let bytes = [0x90, 0x90, 0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10];
        let mut found = Vec::new();
        gcc.scan(&bytes, 0x1000, 0..bytes.len(), &mut found, 64);
        assert!(found.iter().any(|m| m.start == 0x1002));
        // Only patterns that need established code right before them match
        // inside the body (SUB RSP, C).
        assert!(
            found
                .iter()
                .all(|m| m.start == 0x1002 || gcc.patterns[m.pattern].start.after_defined)
        );
    }
}
