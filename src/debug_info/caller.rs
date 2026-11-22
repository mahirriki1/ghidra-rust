//! Caller evidence. A render without any DWARF lock (the reference) records
//! which entry inputs the function really uses and where each call operand's
//! value comes from. Lifted machine code then corroborates which of those
//! operands are actual setup rather than parameter trials. A candidate render
//! with callee prototypes installed must preserve every corroborated fact;
//! otherwise the reference is published unchanged.
//!
//! Facts hold only owned scalars: no engine arena identifier leaves the
//! capture, since operation and varnode IDs are not stable across renders.

use ghidra_decompiler::funcdata::Funcdata;
use ghidra_decompiler::opcodes::OpCode;
use ghidra_decompiler::space::SpaceType;
use ghidra_decompiler::varnode::Varnode;
use ghidra_decompiler::varnode::VarnodeId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Total def-use edges one capture may follow (origins and uses together).
const MAX_EDGES: usize = 16_384;
/// Longest value-preserving chain followed from one operand or input.
const MAX_DEPTH: usize = 16;
/// Retained operand facts per capture.
const MAX_OPERANDS: usize = 4_096;
/// Input varnodes visited per capture.
const MAX_INPUTS: usize = 16_384;
/// Machine instructions lifted per scan window, and in total per comparison.
const MAX_SITE_INSTRUCTIONS: usize = 512;
const MAX_LIFTED_INSTRUCTIONS: usize = 16_384;
/// A site's setup scan starts at most this many engine-known instruction
/// starts before it, within its basic-block range.
const SCAN_WINDOW: usize = 64;
/// Instruction starts retained per capture for choosing scan windows.
const MAX_RETAINED_STARTS: usize = 65_536;

/// The address space of a storage location: only register and entry-relative
/// stack storage take part in comparisons.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum Space {
    Register,
    Stack,
}

/// A checked half-open byte interval in one space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct Storage {
    pub space: Space,
    pub offset: u64,
    pub size: u32,
}

impl Storage {
    fn end(&self) -> Option<u64> {
        self.offset.checked_add(u64::from(self.size))
    }
    /// Whether every byte of `other` lies in `self`.
    pub(crate) fn contains(&self, other: &Storage) -> bool {
        self.space == other.space
            && other.offset >= self.offset
            && other
                .end()
                .zip(self.end())
                .is_some_and(|(inner, outer)| inner <= outer)
    }
    fn overlaps(&self, other: &Storage) -> bool {
        self.space == other.space
            && other.end().is_some_and(|end| self.offset < end)
            && self.end().is_some_and(|end| other.offset < end)
    }
    /// The low `size` bytes at byte `shift` (little-endian), if inside.
    fn slice(&self, shift: u64, size: u32) -> Option<Storage> {
        let slice = Storage {
            space: self.space,
            offset: self.offset.checked_add(shift)?,
            size,
        };
        self.contains(&slice).then_some(slice)
    }
}

/// Where a value comes from, after byte-preserving copies, casts, constant
/// slices and extensions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Origin {
    /// The function's own entry value of this storage.
    Entry(Storage),
    Constant {
        bits: u64,
        size: u32,
    },
    /// The value one machine instruction computed (or a call returned).
    Definition {
        pc: u64,
    },
    Unknown,
}

impl Origin {
    /// Normalized equality: same entry storage start, constant bytes or
    /// defining instruction, comparing the bytes both sides carry.
    fn agrees(&self, other: &Origin) -> bool {
        match (self, other) {
            (Origin::Entry(a), Origin::Entry(b)) => {
                a.space == b.space && a.offset == b.offset && a.size.min(b.size) > 0
            }
            (Origin::Constant { bits: a, size: x }, Origin::Constant { bits: b, size: y }) => {
                let bytes = (*x).min(*y).min(8);
                let mask = if bytes == 8 {
                    u64::MAX
                } else {
                    (1u64 << (bytes * 8)) - 1
                };
                bytes > 0 && a & mask == b & mask
            }
            (Origin::Definition { pc: a }, Origin::Definition { pc: b }) => a == b,
            _ => false,
        }
    }
}

/// One visible operand of a call (or the value of a return).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Operand {
    /// Visible position, from zero.
    pub slot: u16,
    /// The ABI storage the engine assigned to this slot, when unambiguous.
    pub storage: Option<Storage>,
    pub origin: Origin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum SiteKind {
    Call,
    Return,
}

/// One call or return, keyed by its exact machine PC.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Site {
    pub pc: u64,
    pub kind: SiteKind,
    /// Where the setup scan for this site starts: the first instruction of
    /// the engine basic-block range holding it, or an instruction start the
    /// engine reported in that range at most `SCAN_WINDOW` instructions
    /// before the site. Setup before this point is not evidence.
    pub block_start: Option<u64>,
    /// Hidden `this`/return slots, or several operations at one PC.
    pub ambiguous: bool,
    /// Declared parameter count of an input-locked callee.
    pub locked_inputs: Option<u16>,
    pub operands: Vec<Operand>,
}

/// An ordinary formal parameter and whether a render really uses it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Formal {
    pub storage: Storage,
    /// Any live, non-artificial use of its entry value.
    pub used: bool,
}

/// What one render proves about its inputs and calls.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Facts {
    pub complete: bool,
    pub formals: Vec<Formal>,
    /// Entry inputs with an independent real use (a store, load, branch,
    /// indirect target or computation), not only a forwarded operand.
    pub independent: Vec<Storage>,
    pub sites: Vec<Site>,
}

/// Why a candidate cannot replace the reference render.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Veto {
    IncompleteReference,
    IncompleteCandidate,
    LostFormal(Storage),
    MissingSite(u64),
    AmbiguousSite(u64),
    LostOperand {
        pc: u64,
        slot: u16,
    },
    ChangedOperand {
        pc: u64,
        slot: u16,
        reference: Origin,
        candidate: Origin,
    },
}

impl std::fmt::Display for Veto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Veto::IncompleteReference => write!(f, "incomplete reference evidence"),
            Veto::IncompleteCandidate => write!(f, "incomplete candidate evidence"),
            Veto::LostFormal(s) => {
                write!(f, "lost formal {:?}:{:#x}:{}", s.space, s.offset, s.size)
            }
            Veto::MissingSite(pc) => write!(f, "missing site {pc:#x}"),
            Veto::AmbiguousSite(pc) => write!(f, "ambiguous site {pc:#x}"),
            Veto::LostOperand { pc, slot } => write!(f, "lost operand {slot} at {pc:#x}"),
            Veto::ChangedOperand {
                pc,
                slot,
                reference,
                candidate,
            } => write!(
                f,
                "changed operand {slot} at {pc:#x}: {reference:?} became {candidate:?}"
            ),
        }
    }
}

fn storage_of(address: &ghidra_decompiler::address::Address, size: i32) -> Option<Storage> {
    let space = address.get_space()?;
    let space = match space.get_type() {
        SpaceType::Processor if space.get_name() == "register" => Space::Register,
        SpaceType::Spacebase if space.get_name() == "stack" => Space::Stack,
        _ => return None,
    };
    let size = u32::try_from(size).ok().filter(|&s| s > 0 && s <= 64)?;
    let storage = Storage {
        space,
        offset: address.get_offset(),
        size,
    };
    storage.end().map(|_| storage)
}

/// Bounded def-use traversal state shared by one capture.
struct Walk {
    edges: usize,
    exhausted: bool,
    origins: BTreeMap<VarnodeId, Origin>,
}

impl Walk {
    fn charge(&mut self) -> bool {
        if self.edges >= MAX_EDGES {
            self.exhausted = true;
            return false;
        }
        self.edges += 1;
        true
    }

    /// The origin of `vn`'s value.
    fn origin(&mut self, data: &Funcdata, vn: VarnodeId, depth: usize) -> Origin {
        if let Some(origin) = self.origins.get(&vn) {
            return *origin;
        }
        let origin = self.origin_uncached(data, vn, depth);
        self.origins.insert(vn, origin);
        origin
    }

    fn origin_uncached(&mut self, data: &Funcdata, vn: VarnodeId, depth: usize) -> Origin {
        if depth > MAX_DEPTH || !self.charge() {
            return Origin::Unknown;
        }
        let varnode = data.vn(vn);
        let size = u32::try_from(varnode.get_size()).unwrap_or(0);
        if varnode.is_constant() {
            return Origin::Constant {
                bits: varnode.get_offset(),
                size,
            };
        }
        if varnode.is_input() {
            return storage_of(varnode.get_addr(), varnode.get_size())
                .map_or(Origin::Unknown, Origin::Entry);
        }
        let Some(def) = varnode.get_def() else {
            return Origin::Unknown;
        };
        let op = data.op(def);
        match op.code() {
            OpCode::Copy | OpCode::Cast | OpCode::IntZext | OpCode::IntSext
                if op.num_input() >= 1 =>
            {
                match self.origin(data, op.get_in(0), depth + 1) {
                    // An extension keeps the source bytes; a narrowing
                    // copy keeps the low bytes.
                    Origin::Entry(source) => source
                        .slice(0, size.min(source.size))
                        .map_or(Origin::Unknown, Origin::Entry),
                    other => other,
                }
            }
            OpCode::Subpiece if op.num_input() == 2 => {
                let shift = data.vn(op.get_in(1));
                if !shift.is_constant() {
                    return Origin::Unknown;
                }
                let shift = shift.get_offset();
                match self.origin(data, op.get_in(0), depth + 1) {
                    Origin::Entry(source) => source
                        .slice(shift, size)
                        .map_or(Origin::Unknown, Origin::Entry),
                    Origin::Constant { bits, .. } if shift < 8 => Origin::Constant {
                        bits: bits >> (shift * 8),
                        size,
                    },
                    Origin::Definition { pc } if shift == 0 => Origin::Definition { pc },
                    _ => Origin::Unknown,
                }
            }
            // `x & 0xff..ff` keeps exactly x's low bytes: the same value as
            // a narrower copy of x, which a candidate may print instead.
            OpCode::IntAnd if op.num_input() == 2 => {
                let mask = data.vn(op.get_in(1));
                let kept = (1..8u32).find(|&bytes| {
                    mask.is_constant() && mask.get_offset() == (1u64 << (bytes * 8)) - 1
                });
                match kept.map(|bytes| (bytes, self.origin(data, op.get_in(0), depth + 1))) {
                    Some((bytes, Origin::Entry(source))) => source
                        .slice(0, bytes.min(source.size))
                        .map_or(Origin::Unknown, Origin::Entry),
                    _ => Origin::Definition {
                        pc: op.get_addr().get_offset(),
                    },
                }
            }
            OpCode::Multiequal => {
                let mut agreed: Option<Origin> = None;
                for slot in 0..op.num_input() {
                    let incoming = self.origin(data, op.get_in(slot), depth + 1);
                    match agreed {
                        _ if incoming == Origin::Unknown => return Origin::Unknown,
                        None => agreed = Some(incoming),
                        Some(previous) if previous == incoming => {}
                        Some(_) => return Origin::Unknown,
                    }
                }
                agreed.unwrap_or(Origin::Unknown)
            }
            // An artificial clobber or unresolved merge never establishes a
            // value.
            OpCode::Indirect | OpCode::Piece => Origin::Unknown,
            _ => {
                let address = op.get_addr();
                if address.is_invalid() {
                    Origin::Unknown
                } else {
                    Origin::Definition {
                        pc: address.get_offset(),
                    }
                }
            }
        }
    }

    /// How the entry value in `vn` is used: `(independent, forwarded)`.
    /// Independent uses are stores, loads, branches, indirect targets and
    /// computations; forwarded uses reach a call operand or return value
    /// through value-preserving operations only.
    fn uses(&mut self, data: &Funcdata, start: VarnodeId) -> (bool, bool) {
        let mut forwarded = false;
        let mut stack = vec![(start, false, 0usize)];
        let mut seen = std::collections::BTreeSet::new();
        while let Some((vn, computed, depth)) = stack.pop() {
            if depth > MAX_DEPTH || !seen.insert(vn) {
                continue;
            }
            for &op_id in data.vn(vn).descend() {
                if !self.charge() {
                    return (false, forwarded);
                }
                let op = data.op(op_id);
                if op.is_dead() {
                    continue;
                }
                let slots = (0..op.num_input()).filter(|&slot| op.get_in(slot) == vn);
                match op.code() {
                    OpCode::Indirect => {}
                    OpCode::Store
                    | OpCode::Load
                    | OpCode::Cbranch
                    | OpCode::Branchind
                    | OpCode::Callother => return (true, forwarded),
                    OpCode::Callind if slots.clone().any(|slot| slot == 0) => {
                        return (true, forwarded);
                    }
                    OpCode::Call | OpCode::Callind | OpCode::Return => {
                        if computed {
                            return (true, forwarded);
                        }
                        if slots.clone().any(|slot| slot >= 1) {
                            forwarded = true;
                        }
                    }
                    OpCode::Copy
                    | OpCode::Cast
                    | OpCode::IntZext
                    | OpCode::IntSext
                    | OpCode::Subpiece
                    | OpCode::Piece
                    | OpCode::Multiequal => {
                        if let Some(out) = op.get_out() {
                            stack.push((out, computed, depth + 1));
                        }
                    }
                    _ => match op.get_out() {
                        Some(out) => stack.push((out, true, depth + 1)),
                        // Any other consumer without an output is a use.
                        None => return (true, forwarded),
                    },
                }
            }
        }
        (false, forwarded)
    }
}

/// Facts of the analyzed function, called before the printer runs and
/// before analysis is cleared. `executable` admits exact machine PCs.
pub(crate) fn capture(
    data: &mut Funcdata,
    architecture: &ghidra_decompiler::architecture::Architecture,
    executable: &crate::selection::ExecutableRanges,
) -> Facts {
    let mut facts = Facts {
        complete: true,
        ..Default::default()
    };
    let mut walk = Walk {
        edges: 0,
        exhausted: false,
        origins: BTreeMap::new(),
    };
    // Ordinary formals: hidden return storage and implicit `this` are
    // excluded by the engine's own flags.
    let proto = data.get_func_proto_mut();
    let count = proto.num_params(architecture);
    if count > crate::signatures::MAX_PARAMETERS as i32 {
        facts.complete = false;
    }
    let mut formals = Vec::new();
    for i in 0..count.clamp(0, crate::signatures::MAX_PARAMETERS as i32) {
        let Some(param) = proto.get_param(i, architecture) else {
            facts.complete = false;
            continue;
        };
        if param.is_hidden_return(architecture)
            || param.is_this_pointer(architecture)
            || param.is_indirect_storage(architecture)
        {
            continue;
        }
        match storage_of(
            &param.get_address(architecture),
            param.get_size(architecture),
        ) {
            Some(storage) => formals.push(storage),
            None => facts.complete = false,
        }
    }
    // Entry inputs: their real uses decide which formal bytes are live.
    let mut used = Vec::new();
    match (
        data.begin_def_flags(Varnode::INPUT),
        data.end_def_flags(Varnode::INPUT),
    ) {
        (Ok(mut cursor), Ok(end)) => {
            let mut visited = 0;
            while cursor != end {
                visited += 1;
                if visited > MAX_INPUTS {
                    facts.complete = false;
                    break;
                }
                let Some(id) = data.vbank.def_at(&cursor) else {
                    // The ordered input range ended before `end`.
                    facts.complete = false;
                    break;
                };
                let vn = data.vn(id);
                if vn.is_input()
                    && !vn.is_spacebase()
                    && let Some(storage) = storage_of(vn.get_addr(), vn.get_size())
                {
                    let (independent, forwarded) = walk.uses(data, id);
                    if independent {
                        facts.independent.push(storage);
                    }
                    if independent || forwarded {
                        used.push(storage);
                    }
                }
                cursor = data.vbank.def_next(&cursor);
            }
        }
        _ => facts.complete = false,
    }
    facts.formals = formals
        .into_iter()
        .map(|storage| Formal {
            storage,
            used: used.iter().any(|u| u.overlaps(&storage)),
        })
        .collect();
    let code_space = architecture.manager.get_default_code_space();
    let output = data
        .get_func_proto()
        .get_output_ref()
        .and_then(|p| storage_of(&p.get_address(architecture), p.get_size(architecture)));
    let mut sites: BTreeMap<(u64, SiteKind), Site> = BTreeMap::new();
    let mut retained = 0usize;
    // Engine instruction starts per basic-block range, for scan windows.
    let mut starts: BTreeMap<u64, std::collections::BTreeSet<u64>> = BTreeMap::new();
    let mut retained_starts = 0usize;
    let mut current = data.obank.begin_alive();
    let mut ops = 0usize;
    while let Some(id) = current {
        ops += 1;
        if ops > crate::decompile::MAX_CAPTURED_OPS {
            facts.complete = false;
            break;
        }
        current = data
            .obank
            .next_in_list(id, ghidra_decompiler::op::PcodeOp::INSERT_LIST);
        let op = data.op(id);
        let address = op.get_addr().clone();
        let parent = op.get_parent();
        let pc = address.get_offset();
        let block_start = parent.and_then(|block| {
            let space = address.get_space()?;
            data.block(block)
                .basic()
                .cover
                .get_range(space, pc)
                .map(|range| range.get_first())
        });
        if let Some(start) = block_start
            && retained_starts < MAX_RETAINED_STARTS
            && !address.is_invalid()
            && executable.contains(pc)
            && starts.entry(start).or_default().insert(pc)
        {
            retained_starts += 1;
        }
        let kind = match op.code() {
            OpCode::Call | OpCode::Callind => SiteKind::Call,
            OpCode::Return => SiteKind::Return,
            _ => continue,
        };
        let inputs = op.num_input();
        let operand_ids = (0..inputs).map(|slot| op.get_in(slot)).collect::<Vec<_>>();
        if address.is_invalid()
            || !address
                .get_space()
                .zip(code_space.as_ref())
                .is_some_and(|(a, b)| std::sync::Arc::ptr_eq(a, b))
            || !executable.contains(pc)
        {
            // A call without an exact executable PC cannot be compared.
            if kind == SiteKind::Call {
                facts.complete = false;
            }
            continue;
        }
        let mut ambiguous = false;
        let mut locked_inputs = None;
        let mut storages: Vec<Option<Storage>> = Vec::new();
        match kind {
            SiteKind::Call => {
                let visible = usize::try_from(inputs - 1).unwrap_or(0);
                match data.get_call_specs_op(id) {
                    Some(spec) => {
                        let fc = data.call_spec(spec);
                        if fc.has_this_pointer() {
                            ambiguous = true;
                        }
                        let trials = fc.get_active_input_ref();
                        let count = trials.get_num_trials();
                        let from_trials = (count >= 0 && count as usize == visible).then(|| {
                            (0..count)
                                .map(|i| {
                                    let trial = trials.get_trial(i);
                                    storage_of(trial.get_address(), trial.get_size())
                                })
                                .collect::<Vec<_>>()
                        });
                        let params = fc.num_params(architecture);
                        let mut from_params = None;
                        let fc = data.call_spec_mut(spec);
                        // Locked or prototype-derived storage, when it maps
                        // one-to-one onto the visible operands.
                        if params >= 0 && params as usize == visible {
                            let mut list = Vec::new();
                            for i in 0..params {
                                list.push(fc.get_param(i, architecture).and_then(|p| {
                                    if p.is_hidden_return(architecture) {
                                        ambiguous = true;
                                    }
                                    storage_of(
                                        &p.get_address(architecture),
                                        p.get_size(architecture),
                                    )
                                }));
                            }
                            from_params = Some(list);
                        }
                        if fc.is_input_locked(architecture) {
                            locked_inputs = u16::try_from(params).ok();
                            storages = from_params.unwrap_or_default();
                        } else {
                            storages = from_trials.or(from_params).unwrap_or_default();
                        }
                    }
                    None => ambiguous = true,
                }
            }
            SiteKind::Return => {
                // Slot zero is the return address; slot one the value.
                if inputs < 2 {
                    continue;
                }
                storages = vec![output];
            }
        }
        let first = match kind {
            SiteKind::Call => 1,
            SiteKind::Return => 1,
        };
        let mut operands = Vec::new();
        for slot in first..inputs.min(first + crate::signatures::MAX_PARAMETERS as i32) {
            if retained >= MAX_OPERANDS {
                facts.complete = false;
                break;
            }
            retained += 1;
            let visible = (slot - first) as usize;
            operands.push(Operand {
                slot: visible as u16,
                storage: storages.get(visible).copied().flatten(),
                origin: walk.origin(data, operand_ids[slot as usize], 0),
            });
        }
        if kind == SiteKind::Return && operands.len() > 1 {
            operands.truncate(1);
        }
        let site = Site {
            pc,
            kind,
            block_start,
            ambiguous,
            locked_inputs,
            operands,
        };
        match sites.entry((pc, kind)) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(site);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                // Several operations at one PC: keep them only if their
                // layouts agree (a return duplicated per path, say).
                let existing = entry.get_mut();
                if existing.operands != site.operands {
                    existing.ambiguous = true;
                }
            }
        }
        if sites.len() > crate::model::MAX_GRAPH_CALLS {
            facts.complete = false;
            break;
        }
    }
    if walk.exhausted {
        facts.complete = false;
    }
    for site in sites.values_mut() {
        if let Some(start) = site.block_start
            && let Some(window) = starts.get(&start).and_then(|known| {
                known
                    .range(start..site.pc)
                    .rev()
                    .nth(SCAN_WINDOW - 1)
                    .copied()
            })
        {
            site.block_start = Some(window);
        }
    }
    facts.sites = sites.into_values().collect();
    facts
}

/// One lifted p-code varnode, as the engine's raw instruction lift names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RawSpace {
    Register,
    Unique,
    Constant,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RawVarnode {
    pub space: RawSpace,
    pub offset: u64,
    pub size: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RawOp {
    pub opcode: OpCode,
    pub output: Option<RawVarnode>,
    pub inputs: Vec<RawVarnode>,
}

/// One decoded machine instruction and its raw p-code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RawInstruction {
    pub address: u64,
    pub length: u64,
    pub ops: Vec<RawOp>,
}

impl RawVarnode {
    pub(crate) fn from_engine(varnode: &ghidra_decompiler::program::PcodeVarnode) -> Self {
        Self {
            space: match varnode.space.as_str() {
                "register" => RawSpace::Register,
                "unique" => RawSpace::Unique,
                "const" => RawSpace::Constant,
                _ => RawSpace::Other,
            },
            offset: varnode.offset,
            size: varnode.size,
        }
    }
}

/// A register's value in a forward scan of one basic block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Raw {
    /// The register's value on entry to the block.
    In(Storage),
    Constant {
        bits: u64,
        size: u32,
    },
    /// Produced by the instruction at this PC (a computation, a load, or the
    /// result of the call there).
    Definition(u64),
    Unknown,
}

impl Raw {
    fn narrow(self, size: u32) -> Raw {
        match self {
            Raw::In(storage) => storage.slice(0, size).map_or(Raw::Unknown, Raw::In),
            Raw::Constant { bits, .. } => Raw::Constant { bits, size },
            other => other,
        }
    }
    /// Whether this explicit write to the operand's slot, inside the scan
    /// window, is setup for the value the reference proved. The reference's
    /// SSA gives the value (traced through spills and reloads, copies from
    /// registers defined outside the window and the like); the machine write
    /// shows the slot was really prepared for this call. Only an immediate
    /// that contradicts the reference's value is not.
    fn supplies(&self, origin: &Origin) -> bool {
        match (self, origin) {
            (Raw::Constant { bits, size }, Origin::Constant { .. }) => Origin::Constant {
                bits: *bits,
                size: *size,
            }
            .agrees(origin),
            // An immediate is never an entry input.
            (Raw::Constant { .. }, Origin::Entry(_)) => false,
            _ => true,
        }
    }
}

/// Forward scan state: the last write to each register slice in this block.
#[derive(Default)]
struct Scan {
    registers: Vec<(Storage, Raw)>,
    unique: Vec<(u64, u32, Raw)>,
    /// After a call or control transfer, unwritten registers no longer hold
    /// their block-entry values: `Some(pc)` after a call there.
    barrier: Option<Option<u64>>,
}

impl Scan {
    fn read(&self, varnode: &RawVarnode) -> Raw {
        match varnode.space {
            RawSpace::Constant => Raw::Constant {
                bits: varnode.offset,
                size: varnode.size,
            },
            RawSpace::Unique => self
                .unique
                .iter()
                .rev()
                .find(|(offset, size, _)| *offset == varnode.offset && *size >= varnode.size)
                .map_or(Raw::Unknown, |(_, _, value)| value.narrow(varnode.size)),
            RawSpace::Register => {
                let wanted = Storage {
                    space: Space::Register,
                    offset: varnode.offset,
                    size: varnode.size,
                };
                match self.written(&wanted) {
                    Some(value) => value,
                    None if self.registers.iter().any(|(s, _)| s.overlaps(&wanted)) => {
                        // A partial or high-half write: not a known value.
                        Raw::Unknown
                    }
                    None => match self.barrier {
                        None => Raw::In(wanted),
                        Some(Some(call)) => Raw::Definition(call),
                        Some(None) => Raw::Unknown,
                    },
                }
            }
            RawSpace::Other => Raw::Unknown,
        }
    }
    /// The value of the last write covering exactly the low bytes of `slot`.
    fn written(&self, slot: &Storage) -> Option<Raw> {
        self.registers
            .iter()
            .rev()
            .find(|(storage, _)| storage.offset == slot.offset && storage.size >= slot.size)
            .map(|(_, value)| value.narrow(slot.size))
    }
    fn write(&mut self, output: &RawVarnode, value: Raw) {
        match output.space {
            RawSpace::Register => {
                let storage = Storage {
                    space: Space::Register,
                    offset: output.offset,
                    size: output.size,
                };
                self.registers.retain(|(s, _)| !s.overlaps(&storage));
                self.registers.push((storage, value));
            }
            RawSpace::Unique => {
                self.unique
                    .retain(|(offset, _, _)| *offset != output.offset);
                self.unique.push((output.offset, output.size, value));
            }
            _ => {}
        }
    }
    fn execute(&mut self, pc: u64, ops: &[RawOp]) {
        self.unique.clear();
        for op in ops {
            match op.opcode {
                OpCode::Call | OpCode::Callind | OpCode::Callother => {
                    self.registers.clear();
                    self.barrier = Some(Some(pc));
                    continue;
                }
                OpCode::Branch | OpCode::Cbranch | OpCode::Branchind | OpCode::Return => {
                    self.registers.clear();
                    self.barrier = Some(None);
                    continue;
                }
                _ => {}
            }
            let Some(output) = op.output else { continue };
            let value = match op.opcode {
                OpCode::Copy | OpCode::IntZext if op.inputs.len() == 1 => self
                    .read(&op.inputs[0])
                    .narrow(output.size.min(op.inputs[0].size)),
                OpCode::IntSext if op.inputs.len() == 1 => match self.read(&op.inputs[0]) {
                    Raw::Constant { .. } => Raw::Definition(pc),
                    other => other,
                },
                OpCode::Subpiece
                    if op.inputs.len() == 2
                        && op.inputs[1].space == RawSpace::Constant
                        && op.inputs[1].offset == 0 =>
                {
                    self.read(&op.inputs[0]).narrow(output.size)
                }
                OpCode::IntXor if op.inputs.len() == 2 && op.inputs[0] == op.inputs[1] => {
                    Raw::Constant {
                        bits: 0,
                        size: output.size,
                    }
                }
                _ => Raw::Definition(pc),
            };
            self.write(&output, value);
        }
    }
}

/// One operand a candidate must preserve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Required {
    pub pc: u64,
    pub kind: SiteKind,
    pub slot: u16,
    pub storage: Option<Storage>,
    /// `Unknown` when the reference could not trace a prepared argument:
    /// then only its presence is required.
    pub origin: Origin,
    /// The reference site already had a locked callee prototype.
    pub locked: bool,
}

/// What a candidate must preserve, from the reference facts and the machine
/// code that sets up each operand.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Obligations {
    pub complete: bool,
    /// Formal bytes with an independent real use.
    pub formals: Vec<Storage>,
    /// Formal bytes used only as these required operands.
    pub forwarded: Vec<(Storage, Vec<usize>)>,
    pub operands: Vec<Required>,
}

/// Derives the obligations of `reference`, lifting each needed basic block
/// once with `lift` (an instruction at an exact address, or `None`).
pub(crate) fn obligations(
    reference: &Facts,
    lift: &mut dyn FnMut(u64) -> Option<RawInstruction>,
) -> Obligations {
    let mut result = Obligations {
        complete: reference.complete,
        ..Default::default()
    };
    // Sites with an operand whose value is known, grouped by block.
    let mut blocks: BTreeMap<u64, Vec<&Site>> = BTreeMap::new();
    for site in &reference.sites {
        if site.ambiguous {
            continue;
        }
        if site.locked_inputs.is_some() {
            // A prototype already locked in the reference stays locked:
            // its operands are an independent interface.
            for operand in &site.operands {
                if operand.origin != Origin::Unknown {
                    result.operands.push(required(site, operand, true));
                }
            }
            continue;
        }
        if !site.operands.is_empty()
            && let Some(start) = site.block_start
            && start <= site.pc
        {
            blocks.entry(start).or_default().push(site);
        }
    }
    let mut lifted = 0usize;
    'blocks: for (start, mut sites) in blocks {
        sites.sort_by_key(|site| site.pc);
        let mut scan = Scan::default();
        let mut address = start;
        let mut scanned = 0usize;
        for site in sites {
            while address < site.pc {
                lifted += 1;
                scanned += 1;
                if lifted > MAX_LIFTED_INSTRUCTIONS || scanned > MAX_SITE_INSTRUCTIONS {
                    // Unexamined setup may hold required operands.
                    result.complete = false;
                    break 'blocks;
                }
                let Some(instruction) = lift(address) else {
                    result.complete = false;
                    continue 'blocks;
                };
                let Some(next) = (instruction.address == address && instruction.length > 0)
                    .then(|| address.checked_add(instruction.length))
                    .flatten()
                else {
                    result.complete = false;
                    continue 'blocks;
                };
                scan.execute(address, &instruction.ops);
                address = next;
            }
            if address != site.pc {
                // The site is not an instruction start of this range.
                result.complete = false;
                continue 'blocks;
            }
            for operand in &site.operands {
                let Some(storage) = operand.storage.filter(|s| s.space == Space::Register) else {
                    continue;
                };
                let setup = scan
                    .written(&storage)
                    .is_some_and(|value| value.supplies(&operand.origin));
                // A formal forwarded in place is evidence only if the
                // formal also has an independent use.
                let in_place = matches!(operand.origin, Origin::Entry(entry)
                    if entry.space == storage.space
                        && entry.offset == storage.offset
                        && reference.independent.iter().any(|u| u.overlaps(&entry)));
                // A returned value is a stale register unless it forwards an
                // entry input: no caller use of the result is known here.
                let stale_return =
                    site.kind == SiteKind::Return && !matches!(operand.origin, Origin::Entry(_));
                if (setup || in_place) && !stale_return {
                    result.operands.push(required(site, operand, false));
                }
            }
        }
    }
    for formal in &reference.formals {
        for used in &reference.independent {
            if let Some(bytes) = intersection(&formal.storage, used) {
                result.formals.push(bytes);
            }
        }
    }
    for formal in &reference.formals {
        if result.formals.iter().any(|f| f.overlaps(&formal.storage)) {
            continue;
        }
        let reasons = result
            .operands
            .iter()
            .enumerate()
            .filter(|(_, r)| matches!(r.origin, Origin::Entry(e) if e.overlaps(&formal.storage)))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if !reasons.is_empty() {
            let bytes = result.operands[reasons[0]].origin;
            if let Origin::Entry(entry) = bytes
                && let Some(bytes) = intersection(&formal.storage, &entry)
            {
                result.forwarded.push((bytes, reasons));
            }
        }
    }
    result
}

fn required(site: &Site, operand: &Operand, locked: bool) -> Required {
    Required {
        pc: site.pc,
        kind: site.kind,
        slot: operand.slot,
        storage: operand.storage,
        origin: operand.origin,
        locked,
    }
}

fn intersection(a: &Storage, b: &Storage) -> Option<Storage> {
    if !a.overlaps(b) {
        return None;
    }
    let start = a.offset.max(b.offset);
    let end = a.end()?.min(b.end()?);
    Some(Storage {
        space: a.space,
        offset: start,
        size: u32::try_from(end - start).ok()?,
    })
}

/// Whether `candidate` preserves every obligation of the reference. A
/// required operand beyond a newly locked callee's declared parameters is
/// a speculative trailing value: the callee's own verified interface does
/// not read it. With `complete`, incomplete evidence on either side also
/// selects the reference; without it, only a confirmed loss among the
/// recorded obligations does.
pub(crate) fn compare(
    obligations: &Obligations,
    candidate: &Facts,
    complete: bool,
) -> Result<(), Veto> {
    if complete && !obligations.complete {
        return Err(Veto::IncompleteReference);
    }
    if complete && !candidate.complete {
        return Err(Veto::IncompleteCandidate);
    }
    let sites = candidate
        .sites
        .iter()
        .map(|site| ((site.pc, site.kind), site))
        .collect::<BTreeMap<_, _>>();
    let mut waived = vec![false; obligations.operands.len()];
    for (index, required) in obligations.operands.iter().enumerate() {
        let Some(site) = sites.get(&(required.pc, required.kind)) else {
            return Err(Veto::MissingSite(required.pc));
        };
        if !required.locked
            && site
                .locked_inputs
                .is_some_and(|declared| required.slot >= declared)
        {
            waived[index] = true;
            continue;
        }
        if site.ambiguous {
            return Err(Veto::AmbiguousSite(required.pc));
        }
        let Some(operand) = site.operands.iter().find(|o| o.slot == required.slot) else {
            return Err(Veto::LostOperand {
                pc: required.pc,
                slot: required.slot,
            });
        };
        let storage_moved = matches!((operand.storage, required.storage),
            (Some(a), Some(b)) if a.space == b.space && a.offset != b.offset);
        // A returned value must stay returned. Unless it forwards an entry
        // input, a candidate may compute it differently: a return type can
        // let the engine fold a reloaded local into its constant.
        let returned = required.kind == SiteKind::Return
            && !matches!(required.origin, Origin::Entry(_))
            && operand.origin != Origin::Unknown;
        // A prepared argument whose value the reference could not trace must
        // still be passed; its value cannot be compared.
        let untraced = required.origin == Origin::Unknown;
        if storage_moved || !(untraced || returned || operand.origin.agrees(&required.origin)) {
            return Err(Veto::ChangedOperand {
                pc: required.pc,
                slot: required.slot,
                reference: required.origin,
                candidate: operand.origin,
            });
        }
    }
    let covered = |bytes: &Storage| {
        candidate
            .formals
            .iter()
            .any(|formal| formal.used && formal.storage.contains(bytes))
    };
    for bytes in &obligations.formals {
        if !covered(bytes) {
            return Err(Veto::LostFormal(*bytes));
        }
    }
    for (bytes, reasons) in &obligations.forwarded {
        if reasons.iter().any(|&r| !waived[r]) && !covered(bytes) {
            return Err(Veto::LostFormal(*bytes));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // SysV x86-64 register-space offsets as the engine numbers them.
    const RSI: u64 = 0x30;
    const RDX: u64 = 0x10;
    const RCX: u64 = 0x8;
    const RDI: u64 = 0x38;
    const R8: u64 = 0x80;

    fn register(offset: u64, size: u32) -> Storage {
        Storage {
            space: Space::Register,
            offset,
            size,
        }
    }
    fn raw(offset: u64, size: u32) -> RawVarnode {
        RawVarnode {
            space: RawSpace::Register,
            offset,
            size,
        }
    }
    fn constant(value: u64, size: u32) -> RawVarnode {
        RawVarnode {
            space: RawSpace::Constant,
            offset: value,
            size,
        }
    }
    fn copy(output: RawVarnode, input: RawVarnode) -> RawOp {
        RawOp {
            opcode: OpCode::Copy,
            output: Some(output),
            inputs: vec![input],
        }
    }
    fn formal(offset: u64) -> Formal {
        Formal {
            storage: register(offset, 8),
            used: true,
        }
    }
    fn operand(slot: u16, storage: u64, origin: Origin) -> Operand {
        Operand {
            slot,
            storage: Some(register(storage, 8)),
            origin,
        }
    }
    fn call(pc: u64, operands: Vec<Operand>) -> Site {
        Site {
            pc,
            kind: SiteKind::Call,
            block_start: Some(0x1000),
            ambiguous: false,
            locked_inputs: None,
            operands,
        }
    }
    fn entry(offset: u64) -> Origin {
        Origin::Entry(register(offset, 8))
    }
    /// The caller of the original libfprint loss: five formals, the fifth
    /// copied into the fourth argument of an indirect call at 0x1010.
    fn reference() -> Facts {
        Facts {
            complete: true,
            formals: [RDI, RSI, RDX, RCX, R8].map(formal).to_vec(),
            independent: vec![register(RDI, 8)],
            sites: vec![call(
                0x1010,
                vec![
                    operand(0, RDI, entry(RDI)),
                    operand(1, RSI, entry(RDX)),
                    operand(2, RDX, entry(RCX)),
                    operand(3, RCX, entry(R8)),
                ],
            )],
        }
    }
    /// One block from 0x1000: `mov rsi,rdx; mov rdx,rcx; mov rcx,r8`, a
    /// constant setup at 0x100c, then the call at 0x1010.
    fn machine(pc: u64) -> Option<RawInstruction> {
        let ops = match pc {
            0x1000 => vec![copy(raw(RSI, 8), raw(RDX, 8))],
            0x1004 => vec![copy(raw(RDX, 8), raw(RCX, 8))],
            0x1008 => vec![copy(raw(RCX, 8), raw(R8, 8))],
            0x100c => vec![
                copy(raw(RSI, 4), constant(9, 4)),
                RawOp {
                    opcode: OpCode::IntZext,
                    output: Some(raw(RSI, 8)),
                    inputs: vec![raw(RSI, 4)],
                },
            ],
            _ => return None,
        };
        Some(RawInstruction {
            address: pc,
            length: 4,
            ops,
        })
    }
    fn obligations_of(facts: &Facts) -> Obligations {
        obligations(facts, &mut machine)
    }
    fn without_operand(mut facts: Facts, slot: u16) -> Facts {
        facts.sites[0].operands.retain(|o| o.slot != slot);
        facts
    }

    #[test]
    fn forwarded_fifth_input_is_an_obligation_at_its_indirect_call() {
        let reference = reference();
        let obligations = obligations_of(&reference);
        assert!(obligations.complete);
        assert!(obligations.operands.iter().any(|r| r.pc == 0x1010
            && r.slot == 3
            && r.storage == Some(register(RCX, 8))
            && r.origin == entry(R8)));
        assert_eq!(compare(&obligations, &reference, true), Ok(()));
        // The fifth formal and the argument disappear together.
        let mut lost = without_operand(reference.clone(), 3);
        lost.formals.pop();
        assert_eq!(
            compare(&obligations, &lost, true),
            Err(Veto::LostOperand {
                pc: 0x1010,
                slot: 3
            })
        );
        // The formal stays but the argument is lost or replaced.
        let retained = without_operand(reference.clone(), 3);
        assert!(compare(&obligations, &retained, true).is_err());
        let mut replaced = reference.clone();
        replaced.sites[0].operands[3].origin = Origin::Constant { bits: 0, size: 8 };
        assert!(matches!(
            compare(&obligations, &replaced, true),
            Err(Veto::ChangedOperand {
                pc: 0x1010,
                slot: 3,
                ..
            })
        ));
        let mut substituted = reference.clone();
        substituted.sites[0].operands[3].origin = entry(RCX);
        assert!(compare(&obligations, &substituted, true).is_err());
        // Only the fifth formal missing (its argument kept) is a lost formal.
        let mut formal_only = reference.clone();
        formal_only.formals.pop();
        assert_eq!(
            compare(&obligations, &formal_only, true),
            Err(Veto::LostFormal(register(R8, 8)))
        );
    }

    #[test]
    fn prepared_constants_and_each_site_are_compared_separately() {
        let mut reference = reference();
        reference.sites[0].pc = 0x1010;
        reference.sites[0].operands[1] = operand(1, RSI, Origin::Constant { bits: 9, size: 4 });
        // A second indirect call to the same target at its own PC.
        let mut second = reference.sites[0].clone();
        second.pc = 0x1010 + 0x100;
        second.block_start = Some(0x1000);
        reference.sites.push(second);
        let obligations = obligations(&reference, &mut |pc| {
            machine(pc).or_else(|| {
                (0x1010..0x1110).contains(&pc).then(|| RawInstruction {
                    address: pc,
                    length: if pc == 0x1010 { 0x100 } else { 1 },
                    // The first call clobbers every register.
                    ops: vec![RawOp {
                        opcode: OpCode::Callind,
                        output: None,
                        inputs: vec![],
                    }],
                })
            })
        });
        assert!(obligations.complete);
        // The constant at the first site is corroborated; nothing at the
        // second site is (its setup did not survive the first call).
        assert!(obligations.operands.iter().any(|r| r.pc == 0x1010
            && r.slot == 1
            && r.origin == Origin::Constant { bits: 9, size: 4 }));
        // After the first call only the in-place, independently used first
        // argument remains evidenced at the second site.
        assert!(
            obligations
                .operands
                .iter()
                .all(|r| r.pc == 0x1010 || r.slot == 0)
        );
        let mut lost_constant = reference.clone();
        lost_constant.sites[0].operands[1].origin = Origin::Constant { bits: 0, size: 4 };
        assert!(compare(&obligations, &lost_constant, true).is_err());
        let mut second_only = reference.clone();
        second_only.sites[1].operands.truncate(1);
        assert_eq!(compare(&obligations, &second_only, true), Ok(()));
        let mut missing = reference.clone();
        missing.sites.remove(0);
        assert_eq!(
            compare(&obligations, &missing, true),
            Err(Veto::MissingSite(0x1010))
        );
    }

    #[test]
    fn a_register_copy_corroborates_a_value_defined_outside_the_window() {
        // `mov rdi, rbx` right before the call; the reference traced RBX to
        // a call result outside the scan window.
        let reference = Facts {
            complete: true,
            formals: Vec::new(),
            independent: Vec::new(),
            sites: vec![call(
                0x1004,
                vec![operand(0, RDI, Origin::Definition { pc: 0x0f00 })],
            )],
        };
        let obligations = obligations(&reference, &mut |pc| {
            (pc == 0x1000).then(|| RawInstruction {
                address: pc,
                length: 4,
                ops: vec![copy(raw(RDI, 8), raw(0x18, 8))],
            })
        });
        assert_eq!(obligations.operands.len(), 1);
        let mut dropped = reference.clone();
        dropped.sites[0].operands.clear();
        assert!(compare(&obligations, &dropped, true).is_err());
        // An immediate contradicts an entry-input origin.
        assert!(!Raw::Constant { bits: 9, size: 4 }.supplies(&entry(RDX)));
        // A reload of a spilled value is setup for whatever the reference
        // traced it to; an untraced but prepared argument must stay present.
        assert!(Raw::Definition(0x10).supplies(&Origin::Definition { pc: 0x0f00 }));
        let mut untraced = reference.clone();
        untraced.sites[0].operands[0].origin = Origin::Unknown;
        let obligations = super::obligations(&untraced, &mut |pc| {
            (pc == 0x1000).then(|| RawInstruction {
                address: pc,
                length: 4,
                ops: vec![copy(raw(RDI, 8), raw(0x18, 8))],
            })
        });
        assert_eq!(obligations.operands.len(), 1);
        let mut changed = untraced.clone();
        changed.sites[0].operands[0].origin = Origin::Constant { bits: 1, size: 8 };
        assert_eq!(compare(&obligations, &changed, true), Ok(()));
        assert!(compare(&obligations, &dropped, true).is_err());
    }

    #[test]
    fn storage_intervals_allow_narrowing_but_not_another_half() {
        let mut reference = reference();
        // Only the low four bytes of RDI are really used.
        reference.independent = vec![register(RDI, 4)];
        let obligations = obligations_of(&reference);
        assert!(obligations.formals.contains(&register(RDI, 4)));
        let mut narrowed = reference.clone();
        narrowed.formals[0] = Formal {
            storage: register(RDI, 4),
            used: true,
        };
        assert_eq!(compare(&obligations, &narrowed, true), Ok(()));
        let mut high = reference.clone();
        high.independent = vec![register(RDI + 4, 4)];
        let obligations = obligations_of(&high);
        let mut low_only = high.clone();
        low_only.formals[0] = Formal {
            storage: register(RDI, 4),
            used: true,
        };
        assert_eq!(
            compare(&obligations, &low_only, true),
            Err(Veto::LostFormal(register(RDI + 4, 4)))
        );
        // A formal that stays but loses its use does not cover the bytes.
        let mut unused = reference.clone();
        unused.formals[0].used = false;
        assert!(compare(&obligations_of(&reference), &unused, true).is_err());
    }

    #[test]
    fn aliased_widths_agree_and_hidden_slots_are_never_guessed() {
        // AArch64: w4 and x4 share the register's low bytes.
        assert!(Origin::Entry(register(0x4020, 8)).agrees(&Origin::Entry(register(0x4020, 4))));
        assert!(!Origin::Entry(register(0x4020, 8)).agrees(&Origin::Entry(register(0x4028, 8))));
        let reference = reference();
        let obligations = obligations_of(&reference);
        let mut hidden = reference.clone();
        hidden.sites[0].ambiguous = true;
        assert_eq!(
            compare(&obligations, &hidden, true),
            Err(Veto::AmbiguousSite(0x1010))
        );
        // An ambiguous reference site creates no operand obligation.
        let mut ambiguous_reference = reference.clone();
        ambiguous_reference.sites[0].ambiguous = true;
        assert!(obligations_of(&ambiguous_reference).operands.is_empty());
    }

    #[test]
    fn unprepared_trials_and_stack_slots_are_not_obligations() {
        // RCX forwarded in place with no setup and no other use: a
        // parameter trial, so a callee lock may drop it.
        let mut reference = reference();
        reference.sites[0].operands[3] = operand(3, RCX, entry(RCX));
        reference.sites[0].block_start = Some(0x1000);
        let obligations = obligations(&reference, &mut |pc| {
            machine(pc).map(|mut instruction| {
                if pc == 0x1008 {
                    instruction.ops.clear();
                }
                instruction
            })
        });
        assert!(!obligations.operands.iter().any(|r| r.slot == 3));
        assert_eq!(
            compare(&obligations, &without_operand(reference.clone(), 3), true),
            Ok(())
        );
        // x86-32 stack arguments are not corroborated by register setup.
        let mut stack = reference.clone();
        stack.sites[0].operands[3].storage = Some(Storage {
            space: Space::Stack,
            offset: 4,
            size: 4,
        });
        assert!(!obligations_of(&stack).operands.iter().any(|r| r.slot == 3));
        // An independently used stack formal is still required.
        let mut stack_formal = reference.clone();
        let slot = Storage {
            space: Space::Stack,
            offset: 8,
            size: 4,
        };
        stack_formal.formals.push(Formal {
            storage: slot,
            used: true,
        });
        stack_formal.independent.push(slot);
        let obligations = obligations_of(&stack_formal);
        let mut lost = stack_formal.clone();
        lost.formals.pop();
        assert_eq!(
            compare(&obligations, &lost, true),
            Err(Veto::LostFormal(slot))
        );
    }

    #[test]
    fn a_newly_locked_callee_may_drop_trailing_values_it_never_reads() {
        let reference = reference();
        let obligations = obligations_of(&reference);
        let mut locked = without_operand(reference.clone(), 3);
        locked.sites[0].locked_inputs = Some(3);
        locked.formals.pop();
        assert_eq!(compare(&obligations, &locked, true), Ok(()));
        // Within the declared parameters the argument must survive.
        let mut short = locked.clone();
        short.sites[0].locked_inputs = Some(4);
        assert!(compare(&obligations, &short, true).is_err());
    }

    #[test]
    fn returned_values_must_stay_returned() {
        let mut reference = reference();
        reference.sites.push(Site {
            pc: 0x1014,
            kind: SiteKind::Return,
            block_start: None,
            ambiguous: false,
            locked_inputs: None,
            operands: vec![operand(0, 0x0, Origin::Definition { pc: 0x1010 })],
        });
        let mut obligations = obligations_of(&reference);
        obligations.operands.push(required(
            &reference.sites[1],
            &reference.sites[1].operands[0],
            false,
        ));
        let mut folded = reference.clone();
        folded.sites[1].operands[0].origin = Origin::Constant { bits: 0, size: 4 };
        assert_eq!(compare(&obligations, &folded, true), Ok(()));
        let mut dropped = reference.clone();
        dropped.sites[1].operands.clear();
        assert!(compare(&obligations, &dropped, true).is_err());
        // A forwarded entry input must still be the one returned.
        let mut forwarded = reference.clone();
        forwarded.sites[1].operands[0].origin = entry(RDI);
        let mut obligations = obligations_of(&forwarded);
        obligations.operands.push(required(
            &forwarded.sites[1],
            &forwarded.sites[1].operands[0],
            false,
        ));
        assert!(compare(&obligations, &folded, true).is_err());
        // A value written to the return register is not by itself an
        // obligation (it may be a stale register of a void function); a
        // forwarded entry input is.
        let lift = |pc| match pc {
            0x1010 => Some(RawInstruction {
                address: pc,
                length: 4,
                ops: vec![copy(raw(0x0, 8), raw(RDI, 8))],
            }),
            _ => machine(pc),
        };
        let mut stale = reference.clone();
        stale.sites[1].block_start = Some(0x1000);
        let returns = |facts: &Facts| {
            super::obligations(facts, &mut |pc| lift(pc))
                .operands
                .iter()
                .filter(|r| r.kind == SiteKind::Return)
                .count()
        };
        assert_eq!(returns(&stale), 0);
        stale.sites[1].operands[0].origin = entry(RDI);
        assert_eq!(returns(&stale), 1);
    }

    #[test]
    fn incomplete_evidence_selects_the_reference() {
        let reference = reference();
        let mut candidate = reference.clone();
        candidate.complete = false;
        assert_eq!(
            compare(&obligations_of(&reference), &candidate, true),
            Err(Veto::IncompleteCandidate)
        );
        let mut capped = reference.clone();
        capped.complete = false;
        assert_eq!(
            compare(&obligations_of(&capped), &reference, true),
            Err(Veto::IncompleteReference)
        );
        // Without required completeness only confirmed losses count.
        assert_eq!(compare(&obligations_of(&capped), &reference, false), Ok(()));
        let mut partial = obligations_of(&reference);
        partial.complete = false;
        assert!(compare(&partial, &without_operand(reference.clone(), 3), false).is_err());
        // Setup that cannot be lifted leaves the reference incomplete.
        let unlifted = obligations(&reference, &mut |_| None);
        assert!(!unlifted.complete);
        // Win64's fourth register argument is just another storage slot.
        let mut win64 = reference.clone();
        win64.sites[0].operands[3].storage = Some(register(0x88, 8));
        assert!(obligations_of(&win64).operands.iter().all(|r| r.slot != 3));
    }
}
