//! Exact cross-reference targets and queries over validated reference evidence.
//!
//! Targets come only from decoded call sites, confirmed call, data-access or
//! address-taking evidence owned by an exact instruction, or an address the
//! user explicitly chose.
//! Names are for display and filtering; they never establish a target, and
//! no target is derived from matching text or a nearby address. The rules are
//! independent of the desktop so a later scripting surface can reuse them.
use std::collections::BTreeSet;

use crate::call_analysis::CallIndex;
use crate::model::*;

/// Distinct targets offered for one selection; more are reported as omitted.
pub const MAX_TARGET_CHOICES: usize = 32;

/// Why an address was offered. Every kind is queried as the same exact address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetKind {
    /// A displayed function's entry, or an inventory entry chosen by the user.
    Function,
    /// The decoded direct target of a call instruction.
    CallTarget,
    /// The start of a confirmed direct memory access by an instruction.
    DataAccess,
    /// An address an instruction materializes into a register or store.
    TakenAddress,
    /// The first byte of a scanned string.
    StringStart,
    /// An exact address the user selected or entered.
    Address,
}

impl TargetKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Function => "function",
            Self::CallTarget => "call target",
            Self::DataAccess => "data access target",
            Self::TakenAddress => "taken address",
            Self::StringStart => "string start",
            Self::Address => "address",
        }
    }

    /// Whether data references are the natural first view for this target.
    pub fn prefers_data(self) -> bool {
        matches!(
            self,
            Self::DataAccess | Self::TakenAddress | Self::StringStart
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XrefTarget {
    pub address: u64,
    pub kind: TargetKind,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TargetSet {
    /// Distinct addresses in ascending order.
    pub targets: Vec<XrefTarget>,
    /// Further distinct addresses beyond [`MAX_TARGET_CHOICES`]. Bounded by
    /// the caller's instruction and per-instruction evidence limits.
    omitted: BTreeSet<u64>,
}

impl TargetSet {
    pub fn single(target: XrefTarget) -> Self {
        Self {
            targets: vec![target],
            omitted: BTreeSet::new(),
        }
    }

    /// Distinct targets not offered because the choice list is full.
    pub fn omitted(&self) -> usize {
        self.omitted.len()
    }

    fn push(&mut self, target: XrefTarget) {
        match self
            .targets
            .binary_search_by_key(&target.address, |t| t.address)
        {
            // One address answers one query; keep the first evidence kind.
            Ok(_) => {}
            Err(_) if self.targets.len() >= MAX_TARGET_CHOICES => {
                self.omitted.insert(target.address);
            }
            Err(at) => self.targets.insert(at, target),
        }
    }
}

/// Indices of `owner`'s references decoded at exactly `pc`. Evidence is
/// validated as strictly ordered, so each owner's slice is ordered by address.
fn at_pc<'a, R>(
    references: &'a [R],
    owned: Option<&'a Vec<usize>>,
    pc: u64,
    address: impl Fn(&R) -> u64,
) -> impl Iterator<Item = &'a R> {
    let owned = owned.map(Vec::as_slice).unwrap_or(&[]);
    let start = owned.partition_point(|&i| address(&references[i]) < pc);
    owned[start..]
        .iter()
        .map(|&i| &references[i])
        .take_while(move |reference| address(reference) == pc)
}

/// Exact call and data targets of instructions `pcs` in function `owner`.
/// Call targets come from the displayed graph when it is `owner`'s, and from
/// confirmed call evidence; data targets only from confirmed data-access or
/// address-taking evidence.
/// Graph call sites are only bounded by view validation (projects may supply
/// them), so their targets must also be aligned, file-backed code in `info`,
/// the rule reference evidence and semantic call tokens already satisfy.
pub fn instruction_targets(
    view: Option<(&BinaryInfo, &FunctionView)>,
    index: Option<&CallIndex>,
    owner: u64,
    pcs: impl IntoIterator<Item = u64>,
) -> TargetSet {
    let mut set = TargetSet::default();
    let (info, calls) = match view {
        Some((info, view)) if view.address == owner => (Some(info), view.calls.as_slice()),
        _ => (None, &[][..]),
    };
    for pc in pcs {
        for call in calls.iter().filter(|call| call.address == pc) {
            if let Some(target) = call.target
                && info.is_some_and(|info| crate::call_analysis::code_address(info, target))
            {
                set.push(XrefTarget {
                    address: target,
                    kind: TargetKind::CallTarget,
                });
            }
        }
        let Some(index) = index else { continue };
        let report = &index.report;
        for reference in at_pc(&report.references, index.outgoing.get(&owner), pc, |r| {
            r.address
        }) {
            set.push(XrefTarget {
                address: reference.target,
                kind: TargetKind::CallTarget,
            });
        }
        if let Some(data) = &report.data {
            for reference in at_pc(&data.references, index.data_outgoing.get(&owner), pc, |r| {
                r.address
            }) {
                set.push(XrefTarget {
                    address: reference.target,
                    kind: TargetKind::DataAccess,
                });
            }
        }
        if let Some(addresses) = &report.addresses {
            for reference in at_pc(
                &addresses.references,
                index.address_outgoing.get(&owner),
                pc,
                |r| r.address,
            ) {
                set.push(XrefTarget {
                    address: reference.target,
                    kind: TargetKind::TakenAddress,
                });
            }
        }
    }
    set
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CallDirection {
    #[default]
    All,
    /// Calls whose decoded target is the inspected address.
    Incoming,
    /// Calls decoded inside the inspected function.
    Outgoing,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AccessFilter {
    #[default]
    All,
    Read,
    Write,
    /// Address-taking evidence only.
    Address,
}

impl AccessFilter {
    fn admits(self, access: DataAccess) -> bool {
        match self {
            Self::All => true,
            Self::Read => access == DataAccess::Read,
            Self::Write => access == DataAccess::Write,
            Self::Address => false,
        }
    }
}

/// One displayed data-reference row: an index into the access or the
/// address-taking evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataRow {
    Access(usize),
    Address(usize),
}

/// One displayed call row: an index into the report's call evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallRow {
    pub reference: usize,
    pub incoming: bool,
}

/// Bounded, case-insensitive text matching over known names and hexadecimal
/// addresses of a row. Address matching ignores an optional `0x` prefix.
#[derive(Clone, Debug, Default)]
pub struct TextFilter {
    text: String,
    hex: Option<String>,
}

impl TextFilter {
    pub fn new(query: &str) -> Self {
        let text = query.trim().to_lowercase();
        let digits = text.strip_prefix("0x").unwrap_or(&text);
        let hex = (!digits.is_empty() && digits.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| digits.trim_start_matches('0').to_owned())
            .map(|digits| {
                if digits.is_empty() {
                    "0".into()
                } else {
                    digits
                }
            });
        Self { text, hex }
    }

    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    fn matches(&self, addresses: &[u64], names: &[Option<&str>], scratch: &mut String) -> bool {
        if self.text.is_empty() {
            return true;
        }
        if let Some(hex) = &self.hex {
            use std::fmt::Write;
            for address in addresses {
                scratch.clear();
                let _ = write!(scratch, "{address:x}");
                if scratch.contains(hex.as_str()) {
                    return true;
                }
            }
        }
        names
            .iter()
            .flatten()
            .any(|name| name.to_lowercase().contains(&self.text))
    }
}

/// Call rows for `address`: calls targeting it, then calls decoded inside the
/// function it starts, filtered by direction and by `filter` over the
/// counterpart's known name and the caller, instruction and target addresses.
pub fn call_rows<'a>(
    index: &CallIndex,
    address: u64,
    direction: CallDirection,
    filter: &TextFilter,
    name: impl Fn(u64) -> Option<&'a str>,
) -> Vec<CallRow> {
    let mut rows = Vec::new();
    let mut scratch = String::with_capacity(16);
    let mut add = |indices: Option<&Vec<usize>>, incoming: bool| {
        for &reference in indices.map(Vec::as_slice).unwrap_or(&[]) {
            let call = &index.report.references[reference];
            let counterpart = if incoming { call.caller } else { call.target };
            if filter.matches(
                &[call.caller, call.address, call.target],
                &[name(counterpart)],
                &mut scratch,
            ) {
                rows.push(CallRow {
                    reference,
                    incoming,
                });
            }
        }
    };
    if direction != CallDirection::Outgoing {
        add(index.incoming.get(&address), true);
    }
    if direction != CallDirection::Incoming {
        add(index.outgoing.get(&address), false);
    }
    rows
}

/// Data-reference rows beginning exactly at `target`, or made by `function`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataScope {
    StartingAt(u64),
    From(u64),
}

/// Data accesses and address-taking evidence in `scope`, filtered by kind
/// and `filter` over the owning function's known name and the function,
/// instruction and target addresses, ordered by function and instruction.
/// Evidence that merely lies inside a range starting at `target` is excluded.
pub fn data_rows<'a>(
    index: &CallIndex,
    scope: DataScope,
    access: AccessFilter,
    filter: &TextFilter,
    name: impl Fn(u64) -> Option<&'a str>,
) -> Vec<DataRow> {
    let (accesses, addresses) = match scope {
        DataScope::StartingAt(target) => (
            index.data_incoming.get(&target),
            index.address_incoming.get(&target),
        ),
        DataScope::From(function) => (
            index.data_outgoing.get(&function),
            index.address_outgoing.get(&function),
        ),
    };
    fn slice(rows: Option<&Vec<usize>>) -> &[usize] {
        rows.map(Vec::as_slice).unwrap_or(&[])
    }
    let mut scratch = String::with_capacity(16);
    let mut matches =
        |addresses: [u64; 3]| filter.matches(&addresses, &[name(addresses[0])], &mut scratch);
    let mut rows = Vec::new();
    if let Some(data) = &index.report.data
        && access != AccessFilter::Address
    {
        for &i in slice(accesses) {
            let reference = &data.references[i];
            if access.admits(reference.access)
                && matches([reference.function, reference.address, reference.target])
            {
                rows.push(((reference.function, reference.address), DataRow::Access(i)));
            }
        }
    }
    if let Some(taken) = &index.report.addresses
        && matches!(access, AccessFilter::All | AccessFilter::Address)
    {
        for &i in slice(addresses) {
            let reference = &taken.references[i];
            if matches([reference.function, reference.address, reference.target]) {
                rows.push(((reference.function, reference.address), DataRow::Address(i)));
            }
        }
    }
    // Both inputs are already ordered; a stable sort keeps accesses first.
    rows.sort_by_key(|&(key, _)| key);
    rows.into_iter().map(|(_, row)| row).collect()
}

/// Exact-address evidence counts, for choosing and labelling a view.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub calls: usize,
    pub accesses: usize,
    pub addresses: usize,
}

impl Counts {
    pub fn data(self) -> usize {
        self.accesses + self.addresses
    }
}

pub fn counts(index: &CallIndex, address: u64) -> Counts {
    let count =
        |rows: &std::collections::BTreeMap<u64, Vec<usize>>| rows.get(&address).map_or(0, Vec::len);
    Counts {
        calls: count(&index.incoming),
        accesses: count(&index.data_incoming),
        addresses: count(&index.address_incoming),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index() -> CallIndex {
        let data = |function, address, target, access| DataReference {
            function,
            address,
            target,
            size: 4,
            access,
            provenance: DataProvenance::InstructionLocal,
        };
        CallIndex::new(CallAnalysis {
            references: vec![
                CallReference {
                    caller: 0x1000,
                    address: 0x1004,
                    target: 0x1040,
                },
                CallReference {
                    caller: 0x1000,
                    address: 0x1010,
                    target: 0x1080,
                },
                CallReference {
                    caller: 0x1040,
                    address: 0x1044,
                    target: 0x1080,
                },
            ],
            data: Some(DataAnalysis {
                references: vec![
                    data(0x1000, 0x1008, 0x2000, DataAccess::Read),
                    data(0x1000, 0x1008, 0x2010, DataAccess::Write),
                    data(0x1000, 0x100c, 0x2000, DataAccess::Write),
                    data(0x1040, 0x1048, 0x2002, DataAccess::Read),
                ],
                ..Default::default()
            }),
            addresses: Some(Box::new(AddressAnalysis {
                references: [
                    (0x1000, 0x1006, 0x2000),
                    (0x1040, 0x1046, 0x2000),
                    (0x1040, 0x104c, 0x1040),
                ]
                .into_iter()
                .map(|(function, address, target)| AddressReference {
                    function,
                    address,
                    target,
                    provenance: DataProvenance::InstructionLocal,
                })
                .collect(),
                ..Default::default()
            })),
            ..Default::default()
        })
    }

    fn addresses(set: &TargetSet) -> Vec<(u64, TargetKind)> {
        set.targets.iter().map(|t| (t.address, t.kind)).collect()
    }

    #[test]
    fn instruction_targets_use_exact_owner_and_pc_evidence_only() {
        let index = index();
        // A multi-target instruction offers every exact target, ordered.
        let set = instruction_targets(None, Some(&index), 0x1000, [0x1008]);
        assert_eq!(
            addresses(&set),
            [
                (0x2000, TargetKind::DataAccess),
                (0x2010, TargetKind::DataAccess)
            ]
        );
        // Neighbouring PCs and other owners' evidence are never borrowed.
        for (owner, pc) in [(0x1000, 0x1009), (0x1000, 0x1007), (0x1040, 0x1008)] {
            assert!(
                instruction_targets(None, Some(&index), owner, [pc])
                    .targets
                    .is_empty()
            );
        }
        // Address-taking evidence is offered as its own target kind.
        assert_eq!(
            addresses(&instruction_targets(None, Some(&index), 0x1040, [0x104c])),
            [(0x1040, TargetKind::TakenAddress)]
        );
        // Several mapped PCs merge distinct targets without duplicates.
        let set = instruction_targets(None, Some(&index), 0x1000, [0x1004, 0x1008, 0x100c]);
        assert_eq!(
            addresses(&set),
            [
                (0x1040, TargetKind::CallTarget),
                (0x2000, TargetKind::DataAccess),
                (0x2010, TargetKind::DataAccess)
            ]
        );
        assert_eq!(set.omitted(), 0);
    }

    #[test]
    fn displayed_call_sites_count_only_for_their_own_function() {
        let info = BinaryInfo {
            path: "fixture".into(),
            architecture: "x86-64".into(),
            format: "ELF".into(),
            entry: 0x1000,
            file_len: 0x200,
            sha256: "a".repeat(64),
            source_identity: None,
            sections: vec![
                SectionInfo {
                    name: ".text".into(),
                    address: 0x1000,
                    size: 0x100,
                    file_offset: 0,
                    file_size: 0x100,
                    executable: true,
                },
                SectionInfo {
                    name: ".data".into(),
                    address: 0x2000,
                    size: 0x100,
                    file_offset: 0x100,
                    file_size: 0x100,
                    executable: false,
                },
            ],
            functions: vec![],
            functions_truncated: false,
            warnings: vec![],
        };
        let view = FunctionView {
            address: 0x1000,
            blocks: vec![],
            edges: vec![],
            calls: vec![
                CallSite {
                    address: 0x1020,
                    target: Some(0x10c0),
                    no_return: None,
                },
                CallSite {
                    address: 0x1024,
                    target: None,
                    no_return: None,
                },
                // A saved view can name mapped data or unmapped addresses.
                CallSite {
                    address: 0x1028,
                    target: Some(0x2000),
                    no_return: None,
                },
                CallSite {
                    address: 0x102c,
                    target: Some(0x9000),
                    no_return: None,
                },
            ],
            warnings: vec![],
        };
        let pcs = [0x1020, 0x1024, 0x1028, 0x102c];
        let set = instruction_targets(Some((&info, &view)), None, 0x1000, pcs);
        assert_eq!(addresses(&set), [(0x10c0, TargetKind::CallTarget)]);
        assert!(
            instruction_targets(Some((&info, &view)), None, 0x1040, [0x1020])
                .targets
                .is_empty()
        );
    }

    #[test]
    fn target_choices_are_bounded_and_report_omissions() {
        let mut set = TargetSet::default();
        for address in 0..(MAX_TARGET_CHOICES as u64 + 3) {
            set.push(XrefTarget {
                address,
                kind: TargetKind::Address,
            });
        }
        // Repeated evidence for kept or omitted addresses is counted once.
        for address in [0, MAX_TARGET_CHOICES as u64 + 1] {
            set.push(XrefTarget {
                address,
                kind: TargetKind::CallTarget,
            });
        }
        assert_eq!(set.targets.len(), MAX_TARGET_CHOICES);
        assert_eq!(set.omitted(), 3);
        assert_eq!(set.targets[0].kind, TargetKind::Address);
    }

    #[test]
    fn call_rows_filter_direction_names_and_addresses_without_inference() {
        let index = index();
        let names = |address| match address {
            0x1000 => Some("main"),
            0x1040 => Some("Helper"),
            _ => None,
        };
        let all = TextFilter::default();
        let rows = call_rows(&index, 0x1040, CallDirection::All, &all, names);
        assert_eq!(
            rows,
            [
                CallRow {
                    reference: 0,
                    incoming: true
                },
                CallRow {
                    reference: 2,
                    incoming: false
                }
            ]
        );
        let incoming = call_rows(&index, 0x1040, CallDirection::Incoming, &all, names);
        assert_eq!(incoming.len(), 1);
        let outgoing = call_rows(&index, 0x1040, CallDirection::Outgoing, &all, names);
        assert_eq!(outgoing, [rows[1]]);
        // Names match case-insensitively for the counterpart only.
        let main = TextFilter::new("MAI");
        assert_eq!(
            call_rows(&index, 0x1040, CallDirection::All, &main, names),
            [rows[0]]
        );
        // Hex queries match caller, instruction or target, with or without 0x.
        for query in ["0x1044", "1044", "0X01044"] {
            assert_eq!(
                call_rows(
                    &index,
                    0x1040,
                    CallDirection::All,
                    &TextFilter::new(query),
                    names
                ),
                [rows[1]],
                "{query}"
            );
        }
        // A name that only appears elsewhere does not create rows.
        assert!(
            call_rows(
                &index,
                0x1080,
                CallDirection::All,
                &TextFilter::new("zzz"),
                names
            )
            .is_empty()
        );
        // No evidence at a nearby address.
        assert!(call_rows(&index, 0x1041, CallDirection::All, &all, names).is_empty());
    }

    #[test]
    fn duplicate_names_never_merge_distinct_targets() {
        let index = index();
        let names = |_| Some("dup");
        let to_1040 = call_rows(
            &index,
            0x1040,
            CallDirection::Incoming,
            &TextFilter::new("dup"),
            names,
        );
        let to_1080 = call_rows(
            &index,
            0x1080,
            CallDirection::Incoming,
            &TextFilter::new("dup"),
            names,
        );
        assert_eq!(to_1040.len(), 1);
        assert_eq!(to_1080.len(), 2);
        assert!(
            to_1040
                .iter()
                .all(|row| index.report.references[row.reference].target == 0x1040)
        );
    }

    #[test]
    fn data_rows_use_exact_start_and_access_filters() {
        let index = index();
        let names = |_| None;
        let all = TextFilter::default();
        let at = |access| data_rows(&index, DataScope::StartingAt(0x2000), access, &all, names);
        use DataRow::{Access, Address};
        // Both classes, ordered by owner and instruction.
        assert_eq!(
            at(AccessFilter::All),
            [Address(0), Access(0), Access(2), Address(1)]
        );
        assert_eq!(at(AccessFilter::Read), [Access(0)]);
        assert_eq!(at(AccessFilter::Write), [Access(2)]);
        assert_eq!(at(AccessFilter::Address), [Address(0), Address(1)]);
        // An access starting inside a range is not an access starting at it.
        assert_eq!(
            data_rows(
                &index,
                DataScope::StartingAt(0x2001),
                AccessFilter::All,
                &all,
                names
            ),
            Vec::<DataRow>::new()
        );
        assert_eq!(
            data_rows(
                &index,
                DataScope::From(0x1000),
                AccessFilter::All,
                &TextFilter::new("2010"),
                names
            ),
            [Access(1)]
        );
        let counted = |calls, accesses, addresses| Counts {
            calls,
            accesses,
            addresses,
        };
        assert_eq!(counts(&index, 0x2000), counted(0, 2, 2));
        assert_eq!(counts(&index, 0x1080), counted(2, 0, 0));
        // A function whose entry is also taken as an address.
        assert_eq!(counts(&index, 0x1040), counted(1, 0, 1));
        assert_eq!(
            data_rows(
                &index,
                DataScope::StartingAt(0x1040),
                AccessFilter::All,
                &all,
                names
            ),
            [Address(2)]
        );
        let legacy = CallIndex::new(CallAnalysis::default());
        assert!(
            data_rows(
                &legacy,
                DataScope::StartingAt(0x2000),
                AccessFilter::All,
                &all,
                names
            )
            .is_empty()
        );
    }

    #[test]
    fn text_filters_treat_hex_and_names_separately() {
        let filter = TextFilter::new("  Fe ");
        assert!(filter.matches(&[0x10fe], &[None], &mut String::new()));
        assert!(filter.matches(&[0], &[Some("safe")], &mut String::new()));
        // A non-hex query never matches addresses, only names.
        let name_only = TextFilter::new("0xzz");
        assert!(!name_only.matches(&[0x0, 0xff], &[Some("other")], &mut String::new()));
        assert!(name_only.matches(&[0], &[Some("A_0XZZ")], &mut String::new()));
        assert!(TextFilter::new("0x0").matches(&[0x100], &[None], &mut String::new()));
        assert!(TextFilter::new("").is_empty());
    }
}
