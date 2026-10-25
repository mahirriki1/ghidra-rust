//! Presentation-only annotation rows. Source bytes and semantic ranges stay intact.
use std::collections::{BTreeMap, BTreeSet};

use crate::model::{CodeMapping, Instruction};
use crate::session::Annotation;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CodeRow {
    Source(usize),
    Comment(u64),
    UnmappedHeading,
}

#[derive(Default)]
pub(crate) struct CommentRows {
    pub rows: Vec<CodeRow>,
    /// Raw source line -> first rendered row (including its comments), for
    /// one-shot counterpart scrolling.
    pub source_rows: Vec<usize>,
    pub comment_rows: BTreeMap<u64, usize>,
    pub addresses: BTreeSet<u64>,
}

impl CommentRows {
    pub fn new<'a>(
        entry: Option<u64>,
        lines: &[(usize, usize)],
        mappings: &[CodeMapping],
        listing: impl IntoIterator<Item = &'a Instruction>,
        annotations: &BTreeMap<u64, Annotation>,
    ) -> Self {
        let mut anchors = BTreeMap::new();
        let has_comment = |address: &u64| {
            annotations
                .get(address)
                .is_some_and(|a| !a.comment.is_empty())
        };
        // Each mapping reference is visited once. A repeated PC uses its first
        // genuine print mark; several PCs sharing a statement retain every note.
        for mapping in mappings {
            let line = lines.partition_point(|(_, end)| *end <= mapping.start);
            for address in &mapping.addresses {
                if has_comment(address) {
                    anchors.entry(*address).or_insert(line);
                }
            }
        }
        if let Some(entry) = entry.filter(has_comment) {
            anchors.insert(entry, 0); // A function-entry note belongs at its header.
        }
        for instruction in listing {
            if has_comment(&instruction.address) {
                anchors.entry(instruction.address).or_insert(lines.len());
            }
        }
        let mut by_line = BTreeMap::<usize, Vec<u64>>::new();
        let mut result = Self::default();
        for (address, line) in anchors {
            result.addresses.insert(address);
            by_line.entry(line).or_default().push(address);
        }
        for line in 0..lines.len() {
            result.source_rows.push(result.rows.len());
            if let Some(comments) = by_line.remove(&line) {
                result
                    .rows
                    .extend(comments.into_iter().map(CodeRow::Comment));
            }
            result.rows.push(CodeRow::Source(line));
        }
        if !by_line.is_empty() {
            result.rows.push(CodeRow::UnmappedHeading);
            for comments in by_line.into_values() {
                result
                    .rows
                    .extend(comments.into_iter().map(CodeRow::Comment));
            }
        }
        for (row, kind) in result.rows.iter().enumerate() {
            if let CodeRow::Comment(address) = kind {
                result.comment_rows.insert(*address, row);
            }
        }
        result
    }
}

/// A bounded single-line preview, rendered literally by egui, never parsed as C
/// or markup. The full value remains available in the annotation editor.
pub(crate) fn preview(text: &str, limit: usize) -> String {
    let mut chars = text.chars();
    let mut result: String = chars
        .by_ref()
        .take(limit)
        .map(|ch| {
            if ch.is_control() || matches!(ch, '\u{2028}' | '\u{2029}') {
                ' '
            } else {
                ch
            }
        })
        .collect();
    if chars.next().is_some() {
        result.push('…');
    }
    result
}

pub(crate) struct BrowserEntry {
    pub address: u64,
    pub label: String,
    pub comment: String,
    search: String,
}

#[derive(Default)]
pub(crate) struct AnnotationBrowser {
    key: Option<(u64, u64)>,
    pub query: String,
    query_used: String,
    pub comments_only: bool,
    comments_only_used: bool,
    pub entries: Vec<BrowserEntry>,
    pub filtered: Vec<usize>,
    /// Also shared with listing/CFG to avoid rebuilding previews every frame.
    pub comments: BTreeMap<u64, String>,
}

impl AnnotationBrowser {
    pub fn update(&mut self, generation: u64, revision: u64, notes: &BTreeMap<u64, Annotation>) {
        let changed = self.key != Some((generation, revision));
        if changed {
            self.entries.clear();
            self.comments.clear();
            for (&address, note) in notes {
                if !note.comment.is_empty() {
                    self.comments.insert(address, preview(&note.comment, 160));
                }
                if note.label.is_empty() && note.comment.is_empty() && note.decoded.is_empty() {
                    continue;
                }
                self.entries.push(BrowserEntry {
                    address,
                    label: preview(&note.label, 80),
                    comment: preview(&note.comment, 160),
                    search: format!("{address:08x} {address:#x} {} {}", note.label, note.comment)
                        .to_lowercase(),
                });
            }
            self.key = Some((generation, revision));
        }
        if changed || self.query_used != self.query || self.comments_only_used != self.comments_only
        {
            let query = self.query.to_lowercase();
            self.filtered = self
                .entries
                .iter()
                .enumerate()
                .filter(|(_, entry)| {
                    (!self.comments_only || !entry.comment.is_empty())
                        && (query.is_empty() || entry.search.contains(&query))
                })
                .map(|(index, _)| index)
                .collect();
            self.query_used.clone_from(&self.query);
            self.comments_only_used = self.comments_only;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_statement_comments_use_first_real_mapping_and_never_nearest_pc() {
        let notes = [0x1004, 0x1008, 0x1009]
            .map(|address| {
                (
                    address,
                    Annotation {
                        comment: format!("comment {address:x}"),
                        ..Default::default()
                    },
                )
            })
            .into_iter()
            .collect();
        let mappings = vec![
            CodeMapping {
                start: 4,
                end: 8,
                addresses: vec![0x1004, 0x1008],
            },
            CodeMapping {
                start: 10,
                end: 12,
                addresses: vec![0x1004],
            },
        ];
        let listing = vec![Instruction {
            address: 0x1009,
            bytes: vec![],
            mnemonic: String::new(),
            operands: String::new(),
        }];
        let rows = CommentRows::new(
            Some(0x1000),
            &[(0, 4), (4, 10), (10, 14)],
            &mappings,
            &listing,
            &notes,
        );
        assert_eq!(
            rows.rows,
            vec![
                CodeRow::Source(0),
                CodeRow::Comment(0x1004),
                CodeRow::Comment(0x1008),
                CodeRow::Source(1),
                CodeRow::Source(2),
                CodeRow::UnmappedHeading,
                CodeRow::Comment(0x1009)
            ]
        );
        assert_eq!(rows.source_rows, [0, 1, 4]);
    }

    #[test]
    fn browser_searches_full_comments_and_refreshes_edits_and_deletions() {
        let mut notes = BTreeMap::from([(
            1,
            Annotation {
                comment: format!("{}needle", "é".repeat(200)),
                ..Default::default()
            },
        )]);
        let mut browser = AnnotationBrowser {
            query: "needle".into(),
            ..Default::default()
        };
        browser.update(1, 0, &notes);
        assert_eq!(browser.filtered, [0]);
        assert!(!browser.entries[0].comment.contains("needle"));
        for query in ["0x1", "00000001"] {
            browser.query = query.into();
            browser.update(1, 0, &notes);
            assert_eq!(browser.filtered, [0]);
        }
        browser.query = "needle".into();
        notes.get_mut(&1).unwrap().comment = "changed".into();
        browser.update(1, 1, &notes);
        assert!(browser.filtered.is_empty());
        notes.clear();
        browser.update(1, 2, &notes);
        assert!(browser.entries.is_empty() && browser.comments.is_empty());
        assert_eq!(preview("*/\n\t🦀", 4), "*/  …");
    }
}
