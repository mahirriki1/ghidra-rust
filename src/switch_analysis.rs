//! Switch (jump-table) destinations recovered by the engine's own flow
//! analysis, as Ghidra's switch analyzer does. Only bounded numeric evidence
//! leaves the engine; callers validate every destination before use.
use ghidra_decompiler::address::Address;
use ghidra_decompiler::architecture::Architecture;
use ghidra_decompiler::program::Program;

/// Instructions the engine may follow while recovering one function's tables.
const MAX_FLOW_INSTRUCTIONS: u32 = 2_048;
/// Entries the engine may read from one table.
pub(crate) const MAX_TABLE_ENTRIES: usize = 256;
/// Tables and total entries copied out of one recovery, before deduplication.
pub(crate) const MAX_TABLES: usize = 32;
pub(crate) const MAX_TOTAL_ENTRIES: usize = 1_024;

/// One computed jump and the destinations the engine established for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Table {
    /// The address of the indirect branch instruction.
    pub branch: u64,
    /// Destinations in table order, possibly repeated.
    pub targets: Vec<u64>,
    /// The engine or these limits left the table incomplete.
    pub partial: bool,
}

/// The engine's recovered tables for the function at `entry`.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Recovered {
    pub tables: Vec<Table>,
    /// Tables or entries were left out by the extraction limits.
    pub truncated: bool,
}

/// Restores the architecture limits changed for recovery, also on unwind.
struct Limits<'a> {
    architecture: &'a mut Architecture,
    saved: (u32, u32, u32),
}

impl Drop for Limits<'_> {
    fn drop(&mut self) {
        let (instructions, entries, options) = self.saved;
        self.architecture.max_instructions = instructions;
        self.architecture.max_jumptable_size = entries;
        self.architecture.flowoptions = options;
    }
}

/// Runs engine flow analysis, with jump-table recovery, for the existing
/// engine function at `entry`. Decompilation actions are not run.
pub(crate) fn recover(program: &mut Program, entry: u64) -> Result<Recovered, String> {
    let _span = crate::performance::span("switch_recovery");
    let architecture = program.architecture();
    let space = architecture
        .manager
        .get_default_code_space()
        .ok_or("Missing default code space for switch recovery")?;
    let start = Address::new(space.clone(), entry);
    let symbol = {
        let symbols = architecture.symboltab_ref().map_err(|e| e.to_string())?;
        let scope = symbols
            .get_global_scope()
            .ok_or("Missing global scope for switch recovery")?;
        symbols
            .scope_query_function(scope, &start)
            .ok_or("Switch recovery requires an established function")?
    };
    let saved = (
        architecture.max_instructions,
        architecture.max_jumptable_size,
        architecture.flowoptions,
    );
    let limits = Limits {
        architecture,
        saved,
    };
    let architecture = &mut *limits.architecture;
    architecture.max_instructions = MAX_FLOW_INSTRUCTIONS;
    architecture.max_jumptable_size = MAX_TABLE_ENTRIES as u32;
    architecture.flowoptions = ghidra_decompiler::flow::ERROR_TOOMANYINSTRUCTIONS;
    architecture
        .with_function(symbol, |function, architecture| {
            if function.has_no_code() {
                return Err(ghidra_decompiler::error::Error::Lowlevel(
                    "The function has no code".into(),
                ));
            }
            architecture.clear_analysis(function);
            let code = |address: &Address| {
                address
                    .get_space()
                    .is_some_and(|other| other.get_index() == space.get_index())
            };
            let first = Address::from_parts(Some(space.clone()), 0);
            let last = Address::from_parts(Some(space.clone()), space.get_highest());
            let flowed = function.follow_flow(&first, &last, architecture);
            let mut recovered = Recovered::default();
            if flowed.is_ok() {
                let mut entries = 0usize;
                for &id in &function.jumpvec {
                    if recovered.tables.len() == MAX_TABLES {
                        recovered.truncated = true;
                        break;
                    }
                    let table = function.jump_table(id);
                    let branch = table.get_op_address();
                    if !code(branch) {
                        continue;
                    }
                    let available = MAX_TABLE_ENTRIES.min(MAX_TOTAL_ENTRIES - entries);
                    let mut targets = Vec::new();
                    let mut foreign = false;
                    for target in table.addresstable.iter().take(available) {
                        if code(target) {
                            targets.push(target.get_offset());
                        } else {
                            foreign = true;
                        }
                    }
                    let cut = table.addresstable.len() > available;
                    recovered.truncated |= cut;
                    entries += targets.len();
                    recovered.tables.push(Table {
                        branch: branch.get_offset(),
                        targets,
                        // The engine stops at its own entry limit without
                        // marking the table partial; treat a full table so.
                        partial: table.is_partial()
                            || !table.is_recovered()
                            || foreign
                            || cut
                            || table.addresstable.len() >= MAX_TABLE_ENTRIES,
                    });
                    if entries == MAX_TOTAL_ENTRIES {
                        recovered.truncated |= recovered.tables.len() < function.jumpvec.len();
                        break;
                    }
                }
            }
            architecture.clear_analysis(function);
            flowed.map(|()| recovered)
        })
        .map_err(|error| format!("Switch recovery failed: {error}"))
}
