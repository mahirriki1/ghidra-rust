//! Reclaim scratch storage without replacing function symbols or local scopes.
use ghidra_decompiler::{architecture::Architecture, funcdata::Funcdata};
use ghidra_decompiler::{heritage::Heritage, op::PcodeOpBank, varnode::VarnodeBank};

/// Only call with no live printer/action/capture using this function's IDs.
/// Normal clearing destroys the CFG children, calls, highs, unions and active
/// output. Arena::clear leaves tombstones; fresh banks release those allocations.
/// Override jump models can retain old IDs even after clear: preserve both banks
/// in that case, rather than allowing old indices to alias new objects (ABA).
/// Debug modification records and callbacks likewise lack a reset contract.
/// Symbols, scope IDs, locked locals, prototypes, flags and address overrides
/// remain owned by the original Funcdata. Root BlockIds are never replaced.
pub(crate) fn clear(function: &mut Funcdata, architecture: &mut Architecture) {
    architecture.clear_analysis(function);
    if !function.jumpvec.is_empty()
        || function.jtcallback.is_some()
        || !function.modify_list.is_empty()
        || function.opactdbg_on
        || function.opactdbg_active
    {
        return;
    }
    // Heritage::clear does not clear load_copy_ops on interrupted analysis.
    // Rebuild its scratch state, preserving per-space dead-code delay settings.
    Heritage::build_info_list(function, architecture);
    let delays: Vec<_> = (0..architecture.manager.num_spaces())
        .filter_map(|index| architecture.manager.get_space(index))
        .map(|space| {
            let delay = function.heritage.get_dead_code_delay(&space);
            (space, delay)
        })
        .collect();
    function.heritage = Heritage::new();
    Heritage::build_info_list(function, architecture);
    for (space, delay) in delays {
        function
            .heritage
            .set_dead_code_delay(&space, delay)
            .expect("previously valid heritage space");
    }
    function.obank = PcodeOpBank::new();
    function.vbank = VarnodeBank::new(
        &architecture.manager,
        architecture
            .translate
            .as_deref()
            .expect("loaded translator"),
    );
}
