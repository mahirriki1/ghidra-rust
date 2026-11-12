//! Session-only candidate data spans, independent of decoded instructions.
//!
//! Sources: validated `Linkage` import slots (including additional locations),
//! `Discovery::pointer_recovery.admissions`, scanned/project strings, data export
//! targets, `CallIndex` data/address targets, and session labels/comments.
//! Admissions are NOT in `DiscoverySnapshot`: reopened projects have no pointer
//! witnesses until discovery runs again. The GUI can read the crate-visible map
//! or `Discovery::admission(entry)`; on each commit it passes all committed
//! admissions to `add_witnesses`, which ignores ones already present.
//!
//! Build off-thread or once at adoption, never per frame: O(n log n) time and
//! O(n) space. Source caps: MAX_IMPORTS + MAX_LINKAGE_LOCATIONS slots,
//! MAX_FUNCTION_ADMISSIONS witnesses, MAX_PROJECT_STRINGS candidates,
//! MAX_EXPORTS + MAX_DATA_REFERENCES + MAX_ADDRESS_REFERENCES + MAX_ANNOTATIONS
//! plus MAX_PROJECT_STRINGS
//! split marks. Source caps are reused below; no image bytes or decoded runs are
//! retained. Slots win over absolute pointer-table witnesses, which win over
//! strings. Strings prefer longest span, then earliest start, then source index;
//! slots/witnesses break ties by earliest start then lowest index/entry.
//! String/string first claims are resolved before higher-tier filtering, so
//! incremental witnesses never resurrect a previously suppressed string.
//! A loser is omitted whole, never clipped. Spans must fit one file-backed
//! section; split marks need only mapped bytes (including zero-fill).
//!
//! The UI must admit a span only when it lies wholly in one undefined gap;
//! decoded instructions/entries and expanded byte intervals take precedence.
//! Item spans ignore interior marks: marks split only gaps outside admitted
//! items, never clip or suppress an item. Use `marks_within` for row hover data.
//! On annotation label/comment creation call `add_mark`; on clearing both call
//! `remove_mark`. These O(log n) edits preserve reference/export/string marks.
//! On discovery commits call `add_witnesses` (and `add_reference_marks` for
//! the run's extended reference index); rebuild on binary/linkage/string
//! adoption (or reference-report replacement), not on annotation edits.
//! Queries allow skipping whole spans without scanning the evidence inventory.
use std::collections::{BTreeMap, BTreeSet};

use crate::call_analysis::CallIndex;
use crate::linkage::{
    ExportTarget, Linkage, LocationKind, MAX_EXPORTS, MAX_IMPORTS, MAX_LINKAGE_LOCATIONS,
};
use crate::model::{
    AdmissionReason, BinaryInfo, FunctionAdmission, MAX_ADDRESS_REFERENCES, MAX_DATA_REFERENCES,
    MAX_FUNCTION_ADMISSIONS, MAX_PROJECT_STRINGS, MAX_SECTIONS, PointerEncoding, StringEntry,
};
use crate::session::{MAX_ANNOTATIONS, Session};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceKind {
    ImportSlot(u32),
    Pointer { source: u64, entry: u64 },
    String(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub start: u64,
    pub end: u64,
    pub kind: EvidenceKind,
}

#[derive(Default)]
pub struct ListingEvidence {
    items: BTreeMap<u64, Evidence>,
    marks: BTreeMap<u64, u8>,
    annotation_marks: usize,
    // Sorted, validated non-overlapping section bounds: mapped end, backed end.
    sections: Vec<(u64, u64, u64, bool)>,
    witnesses: BTreeSet<(u64, u64)>,
}

impl ListingEvidence {
    /// Inputs normally have already passed worker/project validation. Excess
    /// collections are bounded here too. Invalid section metadata fails closed.
    pub fn build(
        info: &BinaryInfo,
        linkage: Option<&Linkage>,
        admissions: impl IntoIterator<Item = FunctionAdmission>,
        strings: &[StringEntry],
        calls: Option<&CallIndex>,
        session: Option<&Session>,
    ) -> Result<Self, String> {
        if info.sections.len() > MAX_SECTIONS {
            return Err("Evidence section limit exceeded".into());
        }
        let mut index = Self::default();
        for section in &info.sections {
            let end = section
                .address
                .checked_add(section.size)
                .ok_or("Evidence section overflow")?;
            let backed = section
                .address
                .checked_add(section.file_size.min(section.size))
                .ok_or("Evidence file-backed section overflow")?;
            index
                .sections
                .push((section.address, end, backed, section.executable));
        }
        index.sections.sort_unstable();
        if index.sections.windows(2).any(|p| p[0].1 > p[1].0) {
            return Err("Overlapping evidence sections".into());
        }
        let mut slots = Vec::new();
        if let Some(linkage) = linkage {
            if let Some((width, _)) = crate::architecture::properties(&info.architecture) {
                for import in linkage.imports.iter().take(MAX_IMPORTS) {
                    if let Some(start) = import.slot {
                        slots.push((start, import.id));
                    }
                }
                for location in linkage.locations.iter().take(MAX_LINKAGE_LOCATIONS) {
                    if location.kind == LocationKind::Slot {
                        slots.push((location.address, location.import));
                    }
                }
                slots.sort_unstable();
                for (start, id) in slots {
                    index.insert(start, width, EvidenceKind::ImportSlot(id));
                }
            }
            for export in linkage.exports.iter().take(MAX_EXPORTS) {
                if let ExportTarget::Data { address } = export.target {
                    index.mark(address);
                }
            }
        }
        index.add_witnesses(admissions);
        let mut ordered = Vec::new();
        for (id, string) in strings.iter().take(MAX_PROJECT_STRINGS).enumerate() {
            let Ok(length) = string.evidence_length() else {
                continue;
            };
            if let Some(length) = length {
                if let Some(end) = string.address.checked_add(length)
                    && index.section(string.address).is_some_and(|s| end <= s.2)
                {
                    ordered.push((length, string.address, end, id));
                }
            } else {
                index.mark(string.address);
            }
        }
        ordered.sort_by_key(|&(length, start, _, id)| (std::cmp::Reverse(length), start, id));
        // Resolve string/string claims independently of higher tiers, preserving
        // the same candidates when pointer witnesses arrive incrementally.
        let mut claims: BTreeMap<u64, u64> = BTreeMap::new();
        for (length, start, end, id) in ordered {
            if claims
                .range(..end)
                .next_back()
                .is_some_and(|(_, &last)| last > start)
            {
                continue;
            }
            claims.insert(start, end);
            index.insert(start, length, EvidenceKind::String(id as u32));
        }
        if let Some(calls) = calls {
            index.add_reference_marks(calls);
        }
        if let Some(session) = session {
            for (&address, annotation) in session.annotations.iter().take(MAX_ANNOTATIONS) {
                if !annotation.label.is_empty() || !annotation.comment.is_empty() {
                    index.add_mark(address);
                }
            }
        }
        Ok(index)
    }

    /// Mark every data and address reference target of `calls`, as `build`
    /// does, in O(r log n). Marks only grow: use this when a discovery commit
    /// extends the same run's reference index; rebuild when another report
    /// replaces it, since targets it no longer has would stay marked.
    pub fn add_reference_marks(&mut self, calls: &CallIndex) {
        for &address in calls
            .data_incoming
            .keys()
            .take(MAX_DATA_REFERENCES)
            .chain(calls.address_incoming.keys().take(MAX_ADDRESS_REFERENCES))
        {
            self.mark(address);
        }
    }

    fn section(&self, address: u64) -> Option<&(u64, u64, u64, bool)> {
        let i = self.sections.partition_point(|s| s.0 <= address);
        i.checked_sub(1)
            .and_then(|i| self.sections.get(i))
            .filter(|s| address < s.1)
    }

    fn mark(&mut self, address: u64) {
        if self.section(address).is_some() {
            self.marks
                .entry(address)
                .and_modify(|flags| *flags |= 1)
                .or_insert(1);
        }
    }

    /// Add an annotation mark when either its label or comment is nonempty.
    /// Returns false for unmapped addresses or an exhausted annotation budget.
    pub fn add_mark(&mut self, address: u64) -> bool {
        if self.section(address).is_none() {
            return false;
        }
        if self.marks.get(&address).is_some_and(|flags| flags & 2 != 0) {
            return true;
        }
        if self.annotation_marks == MAX_ANNOTATIONS {
            return false;
        }
        *self.marks.entry(address).or_default() |= 2;
        self.annotation_marks += 1;
        true
    }

    /// Clear the annotation mark only after BOTH label and comment are empty.
    /// Marks belonging to references, exports or legacy strings are preserved.
    pub fn remove_mark(&mut self, address: u64) {
        if let Some(flags) = self.marks.get_mut(&address)
            && *flags & 2 != 0
        {
            *flags &= !2;
            self.annotation_marks -= 1;
            if *flags == 0 {
                self.marks.remove(&address);
            }
        }
    }

    /// Raw marks in [start, end), including a mark at the item's start. Interior
    /// marks belong in its hover; they must not split/suppress the item row.
    pub fn marks_within(&self, item: &Evidence) -> impl Iterator<Item = u64> + '_ {
        self.split_marks(item.start, item.end)
    }

    fn insert(&mut self, start: u64, length: u64, kind: EvidenceKind) {
        let Some(end) = start.checked_add(length).filter(|end| *end > start) else {
            return;
        };
        if !self.section(start).is_some_and(|s| end <= s.2) {
            return;
        }
        if self
            .items
            .range(..end)
            .next_back()
            .is_some_and(|(_, item)| item.end > start)
        {
            return;
        }
        self.items.insert(start, Evidence { start, end, kind });
    }

    /// Add committed discovery witnesses in O((b + removed strings) log n).
    /// Aligned 8-byte witnesses cannot partially overlap one another. Same-slot
    /// ties use the lowest entry, so batch order matches a full rebuild. Existing
    /// slots are immutable; newly covered strings are removed whole. The total
    /// unique accepted witness input is capped at MAX_FUNCTION_ADMISSIONS.
    pub fn add_witnesses(&mut self, admissions: impl IntoIterator<Item = FunctionAdmission>) {
        for w in admissions.into_iter().take(MAX_FUNCTION_ADMISSIONS) {
            if w.reason != AdmissionReason::PointerTable
                || w.encoding != PointerEncoding::Absolute
                || w.source % 8 != 0
                || !self.section(w.source).is_some_and(|s| !s.3)
                || w.source
                    .checked_add(8)
                    .is_none_or(|end| !self.section(w.source).is_some_and(|s| end <= s.2))
            {
                continue;
            }
            if self.witnesses.len() == MAX_FUNCTION_ADMISSIONS
                || !self.witnesses.insert((w.source, w.entry))
            {
                continue;
            }
            let end = w.source + 8;
            let mut overlaps = self.within(w.source, end).copied().collect::<Vec<_>>();
            if let Some(item) = self.covering(w.source) {
                overlaps.push(*item);
            }
            if overlaps.iter().any(|item| match item.kind {
                EvidenceKind::ImportSlot(_) => true,
                EvidenceKind::Pointer { entry, .. } => entry <= w.entry,
                EvidenceKind::String(_) => false,
            }) {
                continue;
            }
            let remove = overlaps.iter().map(|item| item.start).collect::<Vec<_>>();
            for start in remove {
                self.items.remove(&start);
            }
            self.insert(
                w.source,
                8,
                EvidenceKind::Pointer {
                    source: w.source,
                    entry: w.entry,
                },
            );
        }
    }

    pub fn covering(&self, address: u64) -> Option<&Evidence> {
        self.items
            .range(..=address)
            .next_back()
            .map(|(_, item)| item)
            .filter(|item| address < item.end)
    }
    /// Strictly later start.
    pub fn next_start_after(&self, address: u64) -> Option<u64> {
        self.items
            .range((
                std::ops::Bound::Excluded(address),
                std::ops::Bound::Unbounded,
            ))
            .next()
            .map(|(&start, _)| start)
    }
    /// Strictly earlier exclusive end (an end equal to address is excluded).
    pub fn prev_end_before(&self, address: u64) -> Option<u64> {
        let mut items = self.items.range(..address).rev();
        let first = items.next()?.1;
        if first.end < address {
            Some(first.end)
        } else {
            items.next().map(|(_, item)| item.end)
        }
    }
    /// Items whose START lies in [lo, hi), O(log n + result count). Use covering
    /// separately when the viewport begins inside an item. Reversed bounds empty.
    pub fn within(&self, lo: u64, hi: u64) -> impl Iterator<Item = &Evidence> {
        self.items.range(lo..hi.max(lo)).map(|(_, item)| item)
    }
    /// Raw marks in [lo, hi). When making gaps, ignore marks inside admitted
    /// items; query their marks separately with `marks_within` for hover data.
    pub fn split_marks(&self, lo: u64, hi: u64) -> impl Iterator<Item = u64> + '_ {
        self.marks
            .range(lo..hi.max(lo))
            .map(|(&address, _)| address)
    }
    pub fn next_split_after(&self, address: u64) -> Option<u64> {
        self.marks
            .range((
                std::ops::Bound::Excluded(address),
                std::ops::Bound::Unbounded,
            ))
            .next()
            .map(|(&address, _)| address)
    }
    pub fn prev_split_before(&self, address: u64) -> Option<u64> {
        self.marks
            .range(..address)
            .next_back()
            .map(|(&address, _)| address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BoundaryEvidence, SectionInfo};

    fn info() -> BinaryInfo {
        serde_json::from_value(serde_json::json!({
            "path":"", "format":"ELF", "architecture":"x86-64", "entry":0,
            "sha256":"", "file_len":0, "sections":[], "functions":[], "functions_truncated":false,"warnings":[]
        }))
        .unwrap()
    }
    fn section(address: u64, size: u64, file_size: u64) -> SectionInfo {
        SectionInfo {
            name: "data".into(),
            address,
            size,
            file_size,
            file_offset: 0,
            executable: false,
        }
    }
    fn witness(source: u64, entry: u64) -> FunctionAdmission {
        FunctionAdmission {
            source,
            entry,
            reason: AdmissionReason::PointerTable,
            encoding: PointerEncoding::Absolute,
            owner: None,
            boundary: BoundaryEvidence::Fde,
            table: None,
        }
    }
    fn string(address: u64, length: Option<u32>, text: &str) -> StringEntry {
        StringEntry {
            address,
            length,
            text: text.into(),
            encoding: "ASCII".into(),
        }
    }
    #[test]
    fn priorities_and_incremental_batches_match_rebuild() {
        let mut info = info();
        info.sections = vec![section(0, 128, 128)];
        let strings = vec![
            string(8, Some(24), "truncated…"),
            string(40, Some(8), "helloooo"),
        ];
        let linkage = Linkage {
            digest: String::new(),
            libraries: Box::new([]),
            exports: Box::new([]),
            gaps: Box::new([]),
            locations: vec![crate::linkage::Location {
                import: 0,
                kind: LocationKind::Slot,
                address: 64,
            }]
            .into_boxed_slice(),
            imports: vec![crate::linkage::Import {
                id: 0,
                raw: None,
                display: None,
                ordinal: None,
                library: None,
                scope: None,
                version: None,
                kind: crate::linkage::ImportKind::Normal,
                weak: false,
                slot: Some(12),
                stub: None,
            }]
            .into_boxed_slice(),
        };
        info.architecture = "x86".into();
        let mut with_slot =
            ListingEvidence::build(&info, Some(&linkage), [], &strings, None, None).unwrap();
        with_slot.add_witnesses([witness(8, 100)]);
        assert_eq!(
            with_slot.covering(12).unwrap().kind,
            EvidenceKind::ImportSlot(0)
        );
        assert_eq!(
            with_slot.covering(67).unwrap().kind,
            EvidenceKind::ImportSlot(0)
        );
        assert!(with_slot.covering(8).is_none());
        let mut incremental =
            ListingEvidence::build(&info, None, [], &strings, None, None).unwrap();
        incremental.add_witnesses([witness(16, 100)]);
        incremental.add_witnesses([witness(16, 80), witness(40, 100)]);
        let full = ListingEvidence::build(
            &info,
            None,
            [witness(40, 100), witness(16, 80), witness(16, 100)],
            &strings,
            None,
            None,
        )
        .unwrap();
        assert_eq!(incremental.items, full.items);
        assert!(full.covering(8).is_none());
        assert!(matches!(
            full.covering(16).unwrap().kind,
            EvidenceKind::Pointer { entry: 80, .. }
        ));
    }
    #[test]
    fn split_marks_include_mapped_zero_fill_but_spans_do_not() {
        let mut info = info();
        info.sections = vec![section(0, 128, 64)];
        let mut session = Session::new(String::new());
        for address in [63, 64, 127, 128] {
            session.annotations.insert(
                address,
                crate::session::Annotation {
                    label: "label".into(),
                    ..Default::default()
                },
            );
        }
        let index =
            ListingEvidence::build(&info, None, [witness(64, 1)], &[], None, Some(&session))
                .unwrap();
        assert!(index.items.is_empty());
        assert_eq!(index.split_marks(0, 200).collect::<Vec<_>>(), [63, 64, 127]);
        assert_eq!(index.next_split_after(63), Some(64));
        assert_eq!(index.prev_split_before(64), Some(63));
        assert_eq!(index.next_split_after(u64::MAX), None);
        let mut relative = witness(8, 1);
        relative.encoding = PointerEncoding::Relative;
        let mut direct = witness(16, 1);
        direct.reason = AdmissionReason::InitMetadata;
        info.sections.push(SectionInfo {
            executable: true,
            ..section(128, 32, 32)
        });
        let index = ListingEvidence::build(
            &info,
            None,
            [relative, direct, witness(9, 1), witness(128, 1)],
            &[],
            None,
            None,
        )
        .unwrap();
        assert!(index.items.is_empty());
    }

    #[test]
    fn interior_marks_preserve_items_and_annotation_edits_preserve_other_sources() {
        let mut info = info();
        info.sections = vec![section(0, 128, 128)];
        let strings = [string(8, Some(16), "tail merged text")];
        let mut calls = CallIndex::new(Default::default());
        calls.data_incoming.insert(14, vec![0]);
        calls.address_incoming.insert(16, vec![0]);
        let mut index =
            ListingEvidence::build(&info, None, [], &strings, Some(&calls), None).unwrap();
        assert!(index.add_mark(14));
        assert!(index.add_mark(18));
        let item = *index.covering(14).unwrap();
        assert_eq!((item.start, item.end), (8, 24));
        assert_eq!(index.marks_within(&item).collect::<Vec<_>>(), [14, 16, 18]);
        index.remove_mark(14); // data reference still exists
        index.remove_mark(18);
        assert_eq!(index.marks_within(&item).collect::<Vec<_>>(), [14, 16]);
        assert_eq!(index.covering(18), Some(&item));
        assert!(!index.add_mark(128));
        assert!(index.add_mark(18));
        assert!(index.add_mark(18));
        index.remove_mark(18);
        assert_eq!(index.annotation_marks, 0);
    }

    #[test]
    fn longer_strings_win_then_earlier_start_and_incremental_stays_equivalent() {
        let mut info = info();
        info.sections = vec![section(0, 128, 128)];
        let mut wide = string(3, Some(10), "Hello");
        wide.encoding = "UTF-16LE".into();
        let strings = [
            string(0, Some(4), "xyzH"),
            wide,
            string(32, Some(8), "earliest"),
            string(34, Some(8), "tielater"),
            string(64, Some(32), "hi"),
            string(70, Some(4), "real"),
        ];
        let mut index = ListingEvidence::build(&info, None, [], &strings, None, None).unwrap();
        assert!(index.covering(0).is_none());
        assert_eq!(index.covering(3).unwrap().kind, EvidenceKind::String(1));
        assert_eq!(index.covering(34).unwrap().start, 32);
        assert!(index.covering(64).is_none());
        assert_eq!(index.covering(70).unwrap().kind, EvidenceKind::String(5));
        index.add_witnesses([witness(8, 100)]);
        let full =
            ListingEvidence::build(&info, None, [witness(8, 100)], &strings, None, None).unwrap();
        assert_eq!(index.items, full.items);
    }

    #[test]
    fn bounds_queries_and_truncated_previews() {
        let mut info = info();
        info.sections = vec![section(0, 100, 80), section(u64::MAX - 16, 16, 16)];
        let strings = vec![
            string(8, Some(32), "abc…"),
            string(70, Some(11), "outsidehere"),
            string(50, None, "ascii"),
            string(60, None, "truncated…"),
            string(u64::MAX - 8, Some(8), "topbytes"),
            string(u64::MAX - 2, Some(8), "overflow"),
        ];
        let index = ListingEvidence::build(&info, None, [], &strings, None, None).unwrap();
        assert_eq!(index.covering(39).unwrap().end, 40);
        assert!(index.covering(40).is_none());
        assert!(index.covering(70).is_none());
        assert_eq!(index.next_start_after(8), Some(50));
        assert_eq!(index.prev_end_before(40), None);
        assert_eq!(index.prev_end_before(41), Some(40));
        assert_eq!(index.covering(u64::MAX - 1).unwrap().end, u64::MAX);
        assert!(index.covering(u64::MAX).is_none());
        assert_eq!(index.next_start_after(u64::MAX), None);
        assert_eq!(index.within(8, 50).count(), 1);
        assert_eq!(index.within(50, 8).count(), 0);
        assert_eq!(index.split_marks(0, 100).collect::<Vec<_>>(), vec![60]);
    }
}
