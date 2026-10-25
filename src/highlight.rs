//! Lexical highlighting of the decompiler's C-like plain text.
//!
//! Colors follow the shared Carbon theme. This deliberately does
//! not infer semantic roles such as parameters, globals, or external functions:
//! those require information beyond the engine's current plain-text response.

use crate::theme;
use std::ops::Range;

use eframe::egui::{Color32, FontId, TextFormat, text::LayoutJob, text::LayoutSection};

// A 2 MiB output can alternate token classes every byte. Limit the GUI cache
// independently of the source length, rather than amplifying that response
// into millions of spans or tens of MiB of span metadata.
const MAX_SYNTAX_SPANS: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Plain,
    Keyword,
    Type,
    Comment,
    Constant,
    Variable,
    Function,
}

impl Kind {
    fn color(self) -> Color32 {
        match self {
            Self::Plain => theme::TEXT,
            Self::Function => theme::SYNTAX_FUNCTION,
            Self::Keyword => theme::SYNTAX_KEYWORD,
            Self::Type => theme::SYNTAX_TYPE,
            Self::Comment => theme::SYNTAX_COMMENT,
            Self::Constant => theme::SYNTAX_CONSTANT,
            Self::Variable => theme::SYNTAX_VARIABLE,
        }
    }
}

#[derive(Debug)]
struct Span {
    range: Range<usize>,
    kind: Kind,
}

/// A cache of byte ranges, with no copy of the decompiler source text.
///
/// Build once when a response arrives, then render only visible line ranges.
/// Construction is linear in the source length. Adjacent equal token classes
/// share a span. At most 65,536 spans are retained; exceeding that budget stops
/// tokenization and replaces the cache with a single plain-text span covering
/// the entire source. Display and copying preserve all original text.
#[derive(Debug, Default)]
pub struct HighlightedCode {
    spans: Vec<Span>,
    source_len: usize,
}

impl HighlightedCode {
    /// Allocation capacity of the span cache, excluding the source text.
    pub fn retained_bytes(&self) -> Option<usize> {
        crate::result_store::Bytes::of::<Self>()
            .slots::<Span>(self.spans.capacity())
            .total()
    }

    pub fn new(text: &str) -> Self {
        let mut code = Self {
            spans: Vec::new(),
            source_len: text.len(),
        };
        let bytes = text.as_bytes();
        let mut cursor = 0;
        while cursor < bytes.len() {
            let start = cursor;
            let kind;
            if bytes[cursor..].starts_with(b"//") {
                cursor += 2;
                while cursor < bytes.len() && bytes[cursor] != b'\n' {
                    cursor += 1;
                }
                kind = Kind::Comment;
            } else if bytes[cursor..].starts_with(b"/*") {
                cursor += 2;
                while cursor < bytes.len() && !bytes[cursor..].starts_with(b"*/") {
                    cursor += 1;
                }
                cursor = (cursor + 2).min(bytes.len());
                kind = Kind::Comment;
            } else if let Some(quote) = literal_start(bytes, cursor) {
                let delimiter = bytes[quote];
                cursor = quote + 1;
                while cursor < bytes.len() {
                    if bytes[cursor] == b'\\' {
                        // Escaped quotes, slashes, and newlines are all literal.
                        // Skip a whole UTF-8 scalar after an escape as well.
                        cursor += 1;
                        if cursor < bytes.len() {
                            cursor += text[cursor..].chars().next().unwrap().len_utf8();
                        }
                    } else if bytes[cursor] == delimiter {
                        cursor += 1;
                        break;
                    } else {
                        cursor += 1;
                    }
                }
                kind = Kind::Constant;
            } else if bytes[cursor].is_ascii_digit()
                || (bytes[cursor] == b'.' && bytes.get(cursor + 1).is_some_and(u8::is_ascii_digit))
            {
                cursor = number_end(bytes, cursor);
                kind = Kind::Constant;
            } else if identifier_start(bytes[cursor]) {
                cursor += 1;
                while cursor < bytes.len() && identifier_continue(bytes[cursor]) {
                    cursor += 1;
                }
                let word = &text[start..cursor];
                kind = if is_keyword(word) {
                    Kind::Keyword
                } else if is_type(word) {
                    Kind::Type
                } else if matches!(word, "true" | "false" | "NULL" | "nullptr") {
                    Kind::Constant
                } else if bytes[cursor..]
                    .iter()
                    .copied()
                    .find(|byte| !byte.is_ascii_whitespace())
                    == Some(b'(')
                {
                    Kind::Function
                } else {
                    Kind::Variable
                };
            } else {
                cursor += 1;
                kind = Kind::Plain;
            }
            if !code.push(start..cursor, kind) {
                return Self {
                    spans: vec![Span {
                        range: 0..text.len(),
                        kind: Kind::Plain,
                    }],
                    source_len: text.len(),
                };
            }
        }
        code
    }

    fn push(&mut self, range: Range<usize>, kind: Kind) -> bool {
        if let Some(last) = self.spans.last_mut()
            && last.kind == kind
        {
            last.range.end = range.end;
        } else {
            if self.spans.len() >= MAX_SYNTAX_SPANS {
                return false;
            }
            self.spans.push(Span { range, kind });
        }
        true
    }

    /// Return the exact call-like identifier under a source byte offset.
    ///
    /// This is lexical information, not a resolved function address: callers
    /// must still resolve the name against known functions before navigating.
    /// Comments, literals, variables, and the bounded plain-text fallback never
    /// produce a name. Namespace qualifiers are outside the returned identifier.
    pub fn function_name_at<'a>(&self, text: &'a str, byte_index: usize) -> Option<&'a str> {
        if self.source_len != text.len() || !text.is_char_boundary(byte_index) {
            return None;
        }
        let index = self
            .spans
            .partition_point(|span| span.range.end <= byte_index);
        let span = self.spans.get(index)?;
        if span.kind != Kind::Function || !span.range.contains(&byte_index) {
            return None;
        }
        text.get(span.range.clone())
    }

    /// Overlay semantic selection while preserving the syntax foreground colors.
    pub fn selected_line_job(
        &self,
        text: &str,
        range: Range<usize>,
        font_size: f32,
        selected: &[Range<usize>],
    ) -> LayoutJob {
        let mut job = self.line_job(text, range.clone(), font_size);
        let first = selected.partition_point(|r| r.end <= range.start);
        let selected: Vec<_> = selected[first..]
            .iter()
            .take_while(|r| r.start < range.end)
            .map(|r| r.start.max(range.start) - range.start..r.end.min(range.end) - range.start)
            .collect();
        if selected.is_empty() {
            return job;
        }
        let mut output = Vec::new();
        for section in job.sections {
            let mut cursor = section.byte_range.start.0;
            let end = section.byte_range.end.0;
            let first = selected.partition_point(|span| span.end <= cursor);
            for span in selected[first..].iter().take_while(|span| span.start < end) {
                let start = span.start.max(cursor);
                let selected_end = span.end.min(end);
                if start >= selected_end {
                    continue;
                }
                if cursor < start {
                    let mut prefix = section.clone();
                    prefix.byte_range = cursor.into()..start.into();
                    output.push(prefix);
                }
                let mut middle = section.clone();
                middle.byte_range = start.into()..selected_end.into();
                middle.format.background = theme::CURRENT_LINE;
                output.push(middle);
                cursor = selected_end;
            }
            if cursor < end {
                let mut suffix = section;
                suffix.byte_range = cursor.into()..end.into();
                output.push(suffix);
            }
        }
        job.sections = output;
        job
    }

    /// Layout a visible range of the same source used by [`Self::new`].
    ///
    /// The caller can exclude the newline and shorten unusually long lines by
    /// passing a range ending on a UTF-8 boundary. No markup is interpreted.
    /// Invalid ranges return an empty job; a mismatched source length or token
    /// boundary falls back to plain text. Work is proportional to the visible
    /// range plus a binary search over cached spans.
    pub fn line_job(&self, text: &str, range: Range<usize>, font_size: f32) -> LayoutJob {
        let Some(line) = text.get(range.clone()) else {
            return LayoutJob::default();
        };
        let mut job = LayoutJob {
            text: line.to_owned(),
            keep_trailing_whitespace: true,
            ..Default::default()
        };
        let plain = || LayoutSection {
            leading_space: 0.0,
            byte_range: 0.into()..line.len().into(),
            format: format(Kind::Plain, font_size),
        };
        if self.source_len != text.len() {
            job.sections.push(plain());
            return job;
        }
        let first = self
            .spans
            .partition_point(|span| span.range.end <= range.start);
        for span in &self.spans[first..] {
            if span.range.start >= range.end {
                break;
            }
            let start = span.range.start.max(range.start);
            let end = span.range.end.min(range.end);
            if !text.is_char_boundary(start) || !text.is_char_boundary(end) {
                job.sections.clear();
                job.sections.push(plain());
                return job;
            }
            job.sections.push(LayoutSection {
                leading_space: 0.0,
                byte_range: (start - range.start).into()..(end - range.start).into(),
                format: format(span.kind, font_size),
            });
        }
        job
    }
}

fn format(kind: Kind, font_size: f32) -> TextFormat {
    TextFormat {
        font_id: FontId::monospace(font_size),
        color: kind.color(),
        ..Default::default()
    }
}

fn identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$' | 128..=255)
}

fn identifier_continue(byte: u8) -> bool {
    identifier_start(byte) || byte.is_ascii_digit()
}

fn literal_start(bytes: &[u8], cursor: usize) -> Option<usize> {
    for prefix in [b"".as_slice(), b"u8", b"u", b"U", b"L"] {
        let rest = &bytes[cursor..];
        if rest.starts_with(prefix) && matches!(rest.get(prefix.len()), Some(b'\'' | b'"')) {
            return Some(cursor + prefix.len());
        }
    }
    None
}

fn number_end(bytes: &[u8], start: usize) -> usize {
    let mut cursor = start;
    let hex = bytes[start..].starts_with(b"0x") || bytes[start..].starts_with(b"0X");
    let binary = bytes[start..].starts_with(b"0b") || bytes[start..].starts_with(b"0B");
    if hex || binary {
        cursor += 2;
    }
    let digit = |byte: u8| {
        if hex {
            byte.is_ascii_hexdigit()
        } else if binary {
            matches!(byte, b'0' | b'1')
        } else {
            byte.is_ascii_digit()
        }
    };
    while cursor < bytes.len() && digit(bytes[cursor]) {
        cursor += 1;
    }
    if !binary && bytes.get(cursor) == Some(&b'.') {
        cursor += 1;
        while cursor < bytes.len() && digit(bytes[cursor]) {
            cursor += 1;
        }
    }
    let exponent = if hex { b"pP" } else { b"eE" };
    if !binary
        && bytes
            .get(cursor)
            .is_some_and(|byte| exponent.contains(byte))
    {
        let mut next = cursor + 1;
        if matches!(bytes.get(next), Some(b'+' | b'-')) {
            next += 1;
        }
        let digits_start = next;
        while bytes.get(next).is_some_and(u8::is_ascii_digit) {
            next += 1;
        }
        if next > digits_start {
            cursor = next;
        }
    }
    while let Some(byte) = bytes.get(cursor) {
        if matches!(byte, b'u' | b'U' | b'l' | b'L')
            || (!hex && !binary && matches!(byte, b'f' | b'F'))
        {
            cursor += 1;
        } else {
            break;
        }
    }
    cursor
}

fn is_keyword(word: &str) -> bool {
    matches!(
        word,
        "alignas"
            | "alignof"
            | "asm"
            | "auto"
            | "break"
            | "case"
            | "catch"
            | "const"
            | "constexpr"
            | "continue"
            | "default"
            | "delete"
            | "do"
            | "else"
            | "enum"
            | "extern"
            | "for"
            | "goto"
            | "if"
            | "inline"
            | "namespace"
            | "new"
            | "noexcept"
            | "register"
            | "restrict"
            | "return"
            | "sizeof"
            | "static"
            | "static_assert"
            | "struct"
            | "switch"
            | "template"
            | "this"
            | "throw"
            | "try"
            | "typedef"
            | "typename"
            | "union"
            | "using"
            | "virtual"
            | "volatile"
            | "while"
            | "__attribute__"
            | "__cdecl"
            | "__fastcall"
            | "__stdcall"
            | "__thiscall"
            | "__vectorcall"
    )
}

fn is_type(word: &str) -> bool {
    if matches!(
        word,
        "bool"
            | "uint"
            | "ulong"
            | "ushort"
            | "uchar"
            | "sbyte"
            | "sword"
            | "sdword"
            | "sqword"
            | "char"
            | "double"
            | "float"
            | "int"
            | "long"
            | "short"
            | "signed"
            | "unsigned"
            | "void"
            | "wchar_t"
            | "char16_t"
            | "char32_t"
            | "size_t"
            | "ssize_t"
            | "ptrdiff_t"
            | "intptr_t"
            | "uintptr_t"
            | "byte"
            | "word"
            | "dword"
            | "qword"
            | "undefined"
            | "unknown"
            | "code"
            | "FILE"
    ) {
        return true;
    }
    ["int", "uint", "undefined", "unknown", "xunknown", "float"]
        .iter()
        .any(|prefix| {
            word.strip_prefix(prefix).is_some_and(|suffix| {
                let digits = suffix.strip_suffix("_t").unwrap_or(suffix);
                !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(text: &str) -> Vec<(&str, Kind)> {
        HighlightedCode::new(text)
            .spans
            .iter()
            .map(|span| (&text[span.range.clone()], span.kind))
            .collect()
    }

    fn assert_partition(text: &str, code: &HighlightedCode) {
        let mut end = 0;
        for span in &code.spans {
            assert_eq!(span.range.start, end);
            assert!(span.range.end > span.range.start);
            assert!(text.get(span.range.clone()).is_some());
            end = span.range.end;
        }
        assert_eq!(end, text.len());
        assert!(code.spans.len() <= text.len());
        assert!(code.spans.len() <= MAX_SYNTAX_SPANS);
    }

    #[test]
    fn utf8_and_untrusted_markup_are_preserved_exactly() {
        let text = "uint8_t café(未知 *名) { return \"<script>λ😀</script>\"; } // 🦀\n";
        let code = HighlightedCode::new(text);
        assert_partition(text, &code);
        let job = code.line_job(text, 0..text.len(), 13.0);
        assert_eq!(job.text, text);
        assert_eq!(job.sections.first().unwrap().byte_range.start, 0.into());
        assert_eq!(
            job.sections.last().unwrap().byte_range.end,
            text.len().into()
        );
        for pair in job.sections.windows(2) {
            assert_eq!(pair[0].byte_range.end, pair[1].byte_range.start);
        }
        assert!(tokens(text).contains(&("café", Kind::Function)));
    }

    #[test]
    fn comments_inside_literals_and_escaped_quotes_remain_literals() {
        let text = r#""// /* \" still string" '\'' '\\' L"wide" u8"λ" /* " */ // '"#;
        let result = tokens(text);
        assert_eq!(result[0], (r#""// /* \" still string""#, Kind::Constant));
        assert!(result.contains(&(r#"'\''"#, Kind::Constant)));
        assert!(result.contains(&(r#"'\\'"#, Kind::Constant)));
        assert!(result.contains(&("L\"wide\"", Kind::Constant)));
        assert!(result.contains(&("u8\"λ\"", Kind::Constant)));
        assert!(result.contains(&("/* \" */", Kind::Comment)));
        assert_eq!(result.last(), Some(&("// '", Kind::Comment)));
    }

    #[test]
    fn multiline_comments_are_colored_even_when_rendering_only_middle_line() {
        let text = "int x; /* begin\n * café // still comment\n end */ return x;";
        let code = HighlightedCode::new(text);
        let start = text.find(" * café").unwrap();
        let end = text[start..].find('\n').unwrap() + start;
        let job = code.line_job(text, start..end, 12.0);
        assert_eq!(job.text, " * café // still comment");
        assert_eq!(job.sections.len(), 1);
        assert_eq!(job.sections[0].format.color, Kind::Comment.color());
        for text in ["/* no closing λ", "\"unfinished 🦀", "'\\λ", "// final"] {
            assert_partition(text, &HighlightedCode::new(text));
        }
    }

    #[test]
    fn numeric_operators_are_not_swallowed_by_constants() {
        let text = "0x10+2-3 1e-3+4 0x1.fp+2-1 .5*2 0b101u|7 12ULL 3.5f 1e+word";
        let result = tokens(text);
        for number in [
            "0x10", "2", "3", "1e-3", "4", "0x1.fp+2", "1", ".5", "0b101u", "7", "12ULL", "3.5f",
        ] {
            assert!(
                result.contains(&(number, Kind::Constant)),
                "{number}: {result:?}"
            );
        }
        assert!(result.contains(&("+", Kind::Plain)));
        assert!(result.contains(&("-", Kind::Plain)));
        assert!(result.contains(&("e", Kind::Variable)));
    }

    #[test]
    fn ghidra_types_keywords_functions_and_default_palette() {
        for word in [
            "int",
            "uint",
            "uint64_t",
            "int4",
            "undefined8",
            "unknown2",
            "xunknown8",
            "float10",
        ] {
            assert_eq!(tokens(word), [(word, Kind::Type)]);
        }
        assert_eq!(tokens("return"), [("return", Kind::Keyword)]);
        assert_eq!(tokens("local_8"), [("local_8", Kind::Variable)]);
        assert!(tokens("FUN_00401000 (local_8)").contains(&("FUN_00401000", Kind::Function)));
        assert_eq!(Kind::Keyword.color(), theme::SYNTAX_KEYWORD);
        assert_eq!(Kind::Type.color(), theme::SYNTAX_TYPE);
        assert_eq!(Kind::Comment.color(), theme::SYNTAX_COMMENT);
        assert_eq!(Kind::Constant.color(), theme::SYNTAX_CONSTANT);
        assert_eq!(Kind::Variable.color(), theme::SYNTAX_VARIABLE);
        assert_eq!(Kind::Function.color(), theme::SYNTAX_FUNCTION);
        assert_eq!(tokens("uintVar"), [("uintVar", Kind::Variable)]);
    }

    #[test]
    fn visible_ranges_are_clipped_without_copying_other_lines() {
        let text = "int long_name;\nreturn long_name;\n";
        let code = HighlightedCode::new(text);
        let job = code.line_job(text, 4..8, 14.0);
        assert_eq!(job.text, "long");
        assert_eq!(job.sections.len(), 1);
        assert_eq!(job.sections[0].byte_range, 0.into()..4.into());
        assert_eq!(job.sections[0].format.color, Kind::Variable.color());
        assert_eq!(job.sections[0].format.font_id, FontId::monospace(14.0));
        assert_eq!(code.line_job(text, 0..0, 14.0).text, "");
        assert_eq!(code.line_job(text, 0..text.len() + 1, 14.0).text, "");
        assert_eq!(code.line_job("λ", 1..2, 14.0).text, "");
    }

    #[test]
    fn whitespace_coalesces_and_adversarial_token_counts_remain_bounded() {
        let blank = " \t\n ".repeat(100);
        let code = HighlightedCode::new(&blank);
        assert_eq!(code.spans.len(), 1);
        let alternating = "a+".repeat(16_384);
        assert_partition(&alternating, &HighlightedCode::new(&alternating));
        assert_partition("", &HighlightedCode::new(""));
    }

    #[test]
    fn token_budget_falls_back_to_plain_text_including_late_visible_ranges() {
        let mut text = "a+".repeat(MAX_SYNTAX_SPANS * 4);
        let late_start = text.len();
        text.push_str("late café = \"🦀\"; // unchanged\n");
        let code = HighlightedCode::new(&text);
        assert_eq!(code.spans.len(), 1);
        assert_eq!(code.spans[0].kind, Kind::Plain);
        assert_eq!(code.spans[0].range, 0..text.len());
        assert_partition(&text, &code);
        let job = code.line_job(&text, late_start..text.len(), 13.0);
        assert_eq!(job.text, "late café = \"🦀\"; // unchanged\n");
        assert_eq!(job.sections.len(), 1);
        assert_eq!(job.sections[0].format.color, theme::TEXT);
        assert_eq!(job.sections[0].byte_range, 0.into()..job.text.len().into());
    }

    #[test]
    fn semantic_background_preserves_syntax_colors_and_utf8_text() {
        let text = "return café + 1;";
        let code = HighlightedCode::new(text);
        let plain = code.line_job(text, 0..text.len(), 13.0);
        let selected =
            code.selected_line_job(text, 0..text.len(), 13.0, std::slice::from_ref(&(7..12)));
        assert_eq!(selected.text, plain.text);
        assert!(
            selected
                .sections
                .iter()
                .any(|s| s.format.background == theme::CURRENT_LINE)
        );
        for section in &selected.sections {
            let original = plain
                .sections
                .iter()
                .find(|s| {
                    s.byte_range.start <= section.byte_range.start
                        && s.byte_range.end >= section.byte_range.end
                })
                .unwrap();
            assert_eq!(section.format.color, original.format.color);
            assert!(text.is_char_boundary(section.byte_range.start.0));
            assert!(text.is_char_boundary(section.byte_range.end.0));
        }
    }

    #[test]
    fn call_lookup_excludes_literals_comments_and_variable_identifiers() {
        let text = "callee(value); callee; \"callee(value)\"; // callee(value)\n/* callee(value) */ next ();";
        let code = HighlightedCode::new(text);
        let positions: Vec<_> = text
            .match_indices("callee")
            .map(|(start, _)| start)
            .collect();
        assert_eq!(code.function_name_at(text, positions[0]), Some("callee"));
        for position in &positions[1..] {
            assert_eq!(code.function_name_at(text, *position), None);
        }
        assert_eq!(
            code.function_name_at(text, text.find("value").unwrap()),
            None
        );
        assert_eq!(
            code.function_name_at(text, text.find("next").unwrap()),
            Some("next")
        );
    }

    #[test]
    fn call_lookup_uses_utf8_byte_offsets_and_exact_token_boundaries() {
        let text = "// 🦀\ncafé (x); plain;";
        let code = HighlightedCode::new(text);
        let start = text.find("café").unwrap();
        for relative in [0, 1, 2, 3] {
            assert_eq!(code.function_name_at(text, start + relative), Some("café"));
        }
        assert_eq!(code.function_name_at(text, start - 1), None);
        assert_eq!(code.function_name_at(text, start + 4), None); // inside é
        assert_eq!(code.function_name_at(text, start + "café".len()), None);
        assert_eq!(code.function_name_at(text, text.find('(').unwrap()), None);
        assert_eq!(code.function_name_at(text, text.len()), None);
        assert_eq!(code.function_name_at(text, text.len() + 1), None);
        assert_eq!(code.function_name_at("different source", 0), None);
    }

    #[test]
    fn call_lookup_does_not_invent_names_from_plain_budget_fallback() {
        let mut text = "a+".repeat(MAX_SYNTAX_SPANS);
        let call = text.len();
        text.push_str("real_call()");
        let code = HighlightedCode::new(&text);
        assert_eq!(code.spans.len(), 1);
        assert_eq!(code.function_name_at(&text, call), None);
    }
}
