//! Worker-only demangling primitives for the upcoming symbol-name table.
//!
//! This module is not wired into loading, transport, presentation or projects.
//! Call it only in a disposable analysis worker, under its existing memory and
//! deadline limits. Input, emitted text, formatter calls and supported parser
//! recursion are bounded here; backend work that emits no text still relies on
//! process containment. Unwinding panics become omissions, not partial names.
//!
//! Raw names and addresses remain the caller's identity. Results are display
//! text only and must never establish types, references or no-return evidence.
//! See docs/demangling.md for the audited versions and the MSVC release gate.

use std::fmt::{self, Write};

use crate::model::{
    MAX_SYMBOL_DISPLAY_BYTES, MAX_SYMBOL_FORMAT_WRITES, MAX_SYMBOL_RAW_BYTES,
    SYMBOL_DEMANGLE_RECURSION_LIMIT,
};

/// Container-specific linker decoration, supplied from validated image metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbolFormat {
    Other,
    MachO,
}

/// Which parser produced display text, not proof of the source language.
/// Some legacy Rust and Itanium encodings are ambiguous; Rust is tried first,
/// matching the pinned engine's existing policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DemangleBackend {
    Rust,
    Itanium,
}

#[derive(Debug, PartialEq, Eq)]
pub struct DemangledName {
    pub text: String,
    pub backend: DemangleBackend,
}

/// Reasons to use the caller's raw/effective fallback in its entirety.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameOmission {
    InputLimit,
    Invalid,
    OutputLimit,
    WorkLimit,
    BackendUnavailable,
    Panicked,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DemangleOutcome {
    /// The name has no supported mangling prefix. No fallback copy is allocated.
    Plain,
    Display(DemangledName),
    Omitted(NameOmission),
}

/// Build a compact qualified name with no function parameter list or return
/// type. `raw` is borrowed, never rewritten. Oversized or invalid output is
/// discarded entirely, including any prefix emitted before a failure.
pub fn demangle(raw: &str, format: SymbolFormat) -> DemangleOutcome {
    if raw.len() > MAX_SYMBOL_RAW_BYTES {
        return DemangleOutcome::Omitted(NameOmission::InputLimit);
    }
    if raw.is_empty() || raw.chars().any(disallowed) {
        return DemangleOutcome::Omitted(NameOmission::Invalid);
    }
    std::panic::catch_unwind(|| demangle_inner(raw, format))
        .unwrap_or(DemangleOutcome::Omitted(NameOmission::Panicked))
}

fn disallowed(c: char) -> bool {
    c.is_control() || matches!(c, '\u{2028}' | '\u{2029}')
}

fn demangle_inner(raw: &str, format: SymbolFormat) -> DemangleOutcome {
    // Remove exactly one container underscore, only for known mangling prefixes.
    // Never normalize the raw identity or an analyst label in place.
    let name =
        if format == SymbolFormat::MachO && (raw.starts_with("__Z") || raw.starts_with("__R")) {
            &raw[1..]
        } else {
            raw
        };
    if name.starts_with('?') {
        // The reviewed published MSVC wrapper bounds recursive parsing, but
        // exposes no AST expansion/work or output budget. Do not call it here.
        return DemangleOutcome::Omitted(NameOmission::BackendUnavailable);
    }
    if !name.starts_with("_R") && !name.starts_with("_Z") {
        return DemangleOutcome::Plain;
    }
    let mut output = CappedName::new();
    if let Ok(symbol) = rustc_demangle::try_demangle(name) {
        let result = write!(&mut output, "{symbol:#}");
        return output.finish(result, DemangleBackend::Rust);
    }
    let options =
        cpp_demangle::ParseOptions::default().recursion_limit(SYMBOL_DEMANGLE_RECURSION_LIMIT);
    let Ok(symbol) = cpp_demangle::Symbol::new_with_options(name.as_bytes(), &options) else {
        return DemangleOutcome::Omitted(NameOmission::Invalid);
    };
    let options = cpp_demangle::DemangleOptions::new()
        .no_params()
        .no_return_type()
        .recursion_limit(SYMBOL_DEMANGLE_RECURSION_LIMIT);
    let result = symbol.structured_demangle(&mut output, &options);
    output.finish(result, DemangleBackend::Itanium)
}

/// A formatting sink rather than a truncation after an unbounded allocation.
/// `write_str` rejects before appending, including when the write straddles a
/// UTF-8 boundary. A sticky failure cannot turn into a successful partial name.
struct CappedName {
    text: String,
    writes: usize,
    failure: Option<NameOmission>,
}

impl CappedName {
    fn new() -> Self {
        Self {
            text: String::with_capacity(MAX_SYMBOL_DISPLAY_BYTES),
            writes: 0,
            failure: None,
        }
    }

    fn finish(self, result: fmt::Result, backend: DemangleBackend) -> DemangleOutcome {
        if let Some(reason) = self.failure {
            return DemangleOutcome::Omitted(reason);
        }
        // The Rust backend can defer a v0 backreference error until printing,
        // reporting it as text while returning Ok. Reject its diagnostics too.
        // False negatives for names spelling these markers are intentional.
        let rust_error = backend == DemangleBackend::Rust
            && [
                "{invalid syntax}",
                "{recursion limit reached}",
                "{size limit reached}",
            ]
            .iter()
            .any(|marker| self.text.contains(marker));
        if result.is_err() || self.text.is_empty() || rust_error {
            DemangleOutcome::Omitted(NameOmission::Invalid)
        } else {
            DemangleOutcome::Display(DemangledName {
                text: self.text,
                backend,
            })
        }
    }
}

impl Write for CappedName {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if self.failure.is_some() {
            return Err(fmt::Error);
        }
        let failure = if self.writes == MAX_SYMBOL_FORMAT_WRITES {
            Some(NameOmission::WorkLimit)
        } else if text.len() > MAX_SYMBOL_DISPLAY_BYTES - self.text.len() {
            Some(NameOmission::OutputLimit)
        } else if text.chars().any(disallowed) {
            Some(NameOmission::Invalid)
        } else {
            None
        };
        if let Some(reason) = failure {
            self.failure = Some(reason);
            return Err(fmt::Error);
        }
        self.writes += 1;
        self.text.push_str(text);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn display(raw: &str, format: SymbolFormat) -> String {
        match demangle(raw, format) {
            DemangleOutcome::Display(name) => name.text,
            other => panic!("{raw}: {other:?}"),
        }
    }

    #[test]
    fn qualified_cpp_names_keep_overloads_separate_by_raw_identity() {
        let names = ["_ZN4demo3fooEi", "_ZN4demo3fooEd"];
        for name in names {
            assert_eq!(display(name, SymbolFormat::Other), "demo::foo");
        }
        assert_ne!(names[0], names[1]);
        for (raw, expected) in [
            ("_ZN4demo3fooIiEEvT_", "demo::foo<int>"),
            ("_ZN4demo6WidgetC1Ev", "demo::Widget::Widget"),
            ("_ZN4demo6WidgetplEi", "demo::Widget::operator+"),
        ] {
            assert_eq!(display(raw, SymbolFormat::Other), expected);
        }
    }

    #[test]
    fn rust_legacy_and_v0_display_without_legacy_hash() {
        for name in ["_ZN4demo3foo17h0123456789abcdefE", "_RNvC4demo3foo"] {
            assert_eq!(display(name, SymbolFormat::Other), "demo::foo");
        }
    }

    #[test]
    fn container_prefix_is_explicit_and_raw_names_stay_untouched() {
        let raw = "__ZN4demo3fooEi".to_owned();
        let original = raw.clone();
        assert_eq!(demangle(&raw, SymbolFormat::Other), DemangleOutcome::Plain);
        assert_eq!(display(&raw, SymbolFormat::MachO), "demo::foo");
        assert_eq!(display("__RNvC4demo3foo", SymbolFormat::MachO), "demo::foo");
        assert_eq!(
            demangle("___ZN4demo3fooEi", SymbolFormat::MachO),
            DemangleOutcome::Plain
        );
        assert_eq!(raw, original);
    }

    #[test]
    fn invalid_oversized_and_unavailable_names_fall_back_without_display() {
        for raw in ["", "_Z!", "_RNv", "_ZN1aE\n", "_Z\0bad"] {
            assert_eq!(
                demangle(raw, SymbolFormat::Other),
                DemangleOutcome::Omitted(NameOmission::Invalid)
            );
        }
        assert_eq!(
            demangle(&"x".repeat(MAX_SYMBOL_RAW_BYTES + 1), SymbolFormat::Other),
            DemangleOutcome::Omitted(NameOmission::InputLimit)
        );
        assert_eq!(
            demangle("?foo@@YAXH@Z", SymbolFormat::Other),
            DemangleOutcome::Omitted(NameOmission::BackendUnavailable)
        );
        assert_eq!(
            demangle("exit", SymbolFormat::Other),
            DemangleOutcome::Plain
        );
        let long = "a".repeat(MAX_SYMBOL_DISPLAY_BYTES + 1);
        assert_eq!(
            demangle(&format!("_Z{}{long}v", long.len()), SymbolFormat::Other),
            DemangleOutcome::Omitted(NameOmission::OutputLimit)
        );
    }

    #[test]
    fn deep_types_and_malformed_prefixes_never_publish_partial_names() {
        let deep = format!("_Z3foo{}i", "P".repeat(1000));
        assert_eq!(
            demangle(&deep, SymbolFormat::Other),
            DemangleOutcome::Omitted(NameOmission::Invalid)
        );
        // Every truncation of representative complex encodings is untrusted.
        for name in [
            "_ZN4demo3fooIiEEvT_",
            "_RNvC4demo3foo",
            "_ZN4demo6WidgetC1Ev",
        ] {
            for end in 1..name.len() {
                if let DemangleOutcome::Display(display) =
                    demangle(&name[..end], SymbolFormat::Other)
                {
                    assert!(!display.text.is_empty());
                    assert!(display.text.len() <= MAX_SYMBOL_DISPLAY_BYTES);
                    assert!(!display.text.chars().any(disallowed));
                }
            }
        }
    }

    #[test]
    fn utf8_and_formatter_work_exhaustion_discard_the_entire_result() {
        let mut sink = CappedName::new();
        sink.write_str(&"a".repeat(MAX_SYMBOL_DISPLAY_BYTES - 1))
            .unwrap();
        assert!(sink.write_str("é").is_err());
        // Even a formatter that swallows the error cannot publish its prefix.
        assert_eq!(
            sink.finish(Ok(()), DemangleBackend::Rust),
            DemangleOutcome::Omitted(NameOmission::OutputLimit)
        );
        let mut sink = CappedName::new();
        for _ in 0..MAX_SYMBOL_FORMAT_WRITES {
            sink.write_str("").unwrap();
        }
        assert!(sink.write_str("").is_err());
        assert_eq!(
            sink.finish(Ok(()), DemangleBackend::Rust),
            DemangleOutcome::Omitted(NameOmission::WorkLimit)
        );
    }

    #[test]
    fn rust_deferred_backreference_errors_are_not_display_names() {
        // The referenced type is hidden inside a valid crate identifier, so
        // the initial parser can accept it; formatting must reject the cycle.
        let depth = 500;
        let mut raw = format!("_RIC{depth}");
        let backref_start = raw.len() - 2;
        raw.push_str(&"R".repeat(depth));
        raw.push('B');
        raw.push(char::from_digit((backref_start - 1) as u32, 36).unwrap());
        raw.push_str("_E");
        assert!(matches!(
            demangle(&raw, SymbolFormat::Other),
            DemangleOutcome::Omitted(_)
        ));
    }
}
