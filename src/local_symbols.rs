//! Resolve storage-backed locals after analysis, before the engine prints.
//! Arena IDs are used only during this one rendering, never persisted.
use crate::semantic::*;
use ghidra_decompiler::{
    architecture::Architecture,
    database::{SymbolEntryKind, SymbolId, SymbolKind},
    funcdata::Funcdata,
    space::SpaceType,
    varnode::VarnodeId,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const MAX_MEMBERS: usize = 131_072;
const MAX_VARIABLE_MEMBERS: usize = 2048;

#[derive(Default)]
pub(crate) struct Locals {
    pub variables: Vec<LocalVariable>,
    pub nodes: BTreeMap<VarnodeId, usize>,
    pub symbols: BTreeMap<SymbolId, usize>,
    pub warnings: Vec<String>,
}

pub(crate) fn capture(
    data: &mut Funcdata,
    arch: &mut Architecture,
    renames: &[LocalRename],
    signature_context: &str,
    signature_owned: bool,
) -> ghidra_decompiler::error::Result<Locals> {
    let mut result = Locals::default();
    let Some(scope) = data.localmap else {
        return Ok(result);
    };
    if data.highs.len() > MAX_MEMBERS {
        return Ok(result);
    }
    let highs: Vec<_> = data.highs.iter().map(|(id, _)| id).collect();
    let mut members: BTreeMap<SymbolId, BTreeSet<VarnodeId>> = BTreeMap::new();
    let mut charged = 0;
    for high in highs {
        let Some(symbol) = data.high_get_symbol(high, arch) else {
            continue;
        };
        let count = data.high(high).num_instances() as usize;
        charged += count;
        if charged > MAX_MEMBERS {
            return Ok(Locals::default());
        }
        let set = members.entry(symbol).or_default();
        for i in 0..count {
            set.insert(data.high(high).get_instance(i as i32));
        }
    }
    let db = arch.symboltab_ref()?;
    let symbols: Vec<_> = db
        .scope(scope)
        .nametree
        .values()
        .copied()
        .take(MAX_LOCALS + 1)
        .collect();
    if symbols.len() > MAX_LOCALS {
        return Ok(result);
    }
    // Storage and full structural verification must select exactly one symbol.
    let mut candidates = Vec::new();
    for symbol in symbols {
        let sym = db.symbol(symbol);
        if sym.scope != scope
            || !matches!(sym.kind, SymbolKind::Base)
            || sym.has_merge_problems()
            || sym.mapentry.len() != 1
        {
            continue;
        }
        let entry = db.entry(sym.mapentry[0]);
        if entry.is_piece
            || entry.offset != 0
            || entry.size <= 0
            || entry.size > 256
            || entry.uselimit.num_ranges() > 64
        {
            continue;
        }
        let SymbolEntryKind::Map { addr, .. } = &entry.kind else {
            continue;
        };
        let Some(space) = addr.get_space() else {
            continue;
        };
        let storage = match (space.get_type(), space.get_name()) {
            (SpaceType::Spacebase, "stack") => LocalStorage::Stack,
            (SpaceType::Processor, "register") => LocalStorage::Register,
            _ => continue,
        };
        let Some(nodes) = members
            .get(&symbol)
            .filter(|nodes| !nodes.is_empty() && nodes.len() <= MAX_VARIABLE_MEMBERS)
        else {
            continue;
        };
        let Some(verification) = verify(data, arch, symbol, nodes, signature_context) else {
            continue;
        };
        candidates.push((
            symbol,
            LocalIdentity {
                function: data.baseaddr.get_offset(),
                engine: local_fingerprint(signature_context).into(),
                storage,
                offset: addr.get_offset(),
                size: entry.size as u32,
                verification,
            },
        ));
    }
    let mut counts = BTreeMap::new();
    for (_, identity) in &candidates {
        *counts.entry(identity.clone()).or_insert(0) += 1;
    }
    for (symbol, identity) in candidates {
        if counts[&identity] != 1 {
            continue;
        }
        let index = result.variables.len();
        for node in &members[&symbol] {
            result.nodes.insert(*node, index);
        }
        result.symbols.insert(symbol, index);
        result.variables.push(LocalVariable {
            identity,
            name: arch.symboltab_ref()?.symbol(symbol).display_name.clone(),
            signature_parameter: {
                let sym = arch.symboltab_ref()?.symbol(symbol);
                (signature_owned && sym.category == 0).then_some(sym.catindex as usize)
            },
        });
    }
    // Verify each override before applying it. Stale overrides stay saved and
    // visibly unapplied. Collisions include unsupported locals in this scope.
    for rename in renames {
        let matching: Vec<_> = result
            .variables
            .iter()
            .enumerate()
            .filter(|(_, v)| v.identity == rename.identity)
            .map(|(i, _)| i)
            .collect();
        let Some(&index) = matching.first().filter(|_| matching.len() == 1) else {
            result.warnings.push(format!(
                "Local rename '{}' not applied: absent, ambiguous, or incompatible identity",
                rename.name
            ));
            continue;
        };
        if result.variables[index].signature_parameter.is_some() {
            result.warnings.push(format!(
                "Local rename '{}' not applied: parameter name is owned by its function signature",
                rename.name
            ));
            continue;
        }
        let symbol = *result
            .symbols
            .iter()
            .find(|(_, i)| **i == index)
            .expect("Captured local")
            .0;
        let db = arch.symboltab_ref()?;
        let collision = db.scope(scope).nametree.values().any(|&id| {
            id != symbol
                && (db.symbol(id).name == rename.name || db.symbol(id).display_name == rename.name)
        });
        let override_collision = renames
            .iter()
            .any(|other| other.identity != rename.identity && other.name == rename.name);
        if collision || override_collision {
            result.warnings.push(format!(
                "Local rename '{}' not applied: name collides with another variable",
                rename.name
            ));
            continue;
        }
        arch.symboltab_mut()?
            .scope_rename_symbol(scope, symbol, &rename.name)?;
        result.variables[index].name.clone_from(&rename.name);
    }
    Ok(result)
}

fn verify(
    data: &Funcdata,
    arch: &Architecture,
    symbol: SymbolId,
    nodes: &BTreeSet<VarnodeId>,
    signature_context: &str,
) -> Option<String> {
    let db = arch.symboltab_ref().ok()?;
    let sym = db.symbol(symbol);
    let entry = db.entry(*sym.mapentry.first()?);
    let mut digest = Sha256::new();
    digest.update(local_fingerprint(signature_context));
    if !signature_context.is_empty() {
        // Bind all overrides, including callers, to the complete canonical state.
        digest.update(Sha256::digest(signature_context.as_bytes()));
    }
    digest.update(sym.category.to_le_bytes());
    digest.update(sym.catindex.to_le_bytes());
    let tp = arch.types.as_ref()?.get(sym.tp?);
    digest.update(tp.get_size().to_le_bytes());
    digest.update((tp.get_metatype() as u32).to_le_bytes());
    digest.update(tp.get_name().as_bytes());
    for range in entry.uselimit.iter() {
        digest.update(range.get_space().get_name().as_bytes());
        digest.update(range.get_first().to_le_bytes());
        digest.update(range.get_last().to_le_bytes());
    }
    let code = arch.manager.get_default_code_space()?;
    let mut records = Vec::new();
    let mut charged = 0;
    for &node in nodes {
        let vn = data.vn(node);
        if vn.is_persist() || vn.descend().len() > MAX_VARIABLE_MEMBERS {
            return None;
        }
        let mut record = Vec::new();
        record.extend(vn.get_size().to_le_bytes());
        record.push(u8::from(vn.is_input()));
        let space = vn.get_space()?;
        record.extend(space.get_name().as_bytes());
        // Unique-space offsets are allocator details, never persistent identity.
        if space.get_type() != SpaceType::Internal {
            record.extend(vn.get_offset().to_le_bytes());
        }
        let mut uses = Vec::new();
        for (op_id, definition) in vn
            .get_def()
            .into_iter()
            .map(|op| (op, true))
            .chain(vn.descend().iter().copied().map(|op| (op, false)))
        {
            charged += 1;
            if charged > MAX_VARIABLE_MEMBERS * 4 {
                return None;
            }
            let op = data.op(op_id);
            let addr = op.get_addr();
            if !std::sync::Arc::ptr_eq(addr.get_space()?, &code)
                || addr.is_invalid()
                || op.num_input() > 64
            {
                return None;
            }
            let mut slots = Vec::new();
            if !definition {
                for slot in 0..op.num_input() {
                    if op.get_in_option(slot) == Some(node) {
                        slots.push(slot);
                    }
                }
            }
            uses.push((addr.get_offset(), op.code() as u32, definition, slots));
        }
        uses.sort();
        record.extend(serde_json::to_vec(&uses).ok()?);
        records.push(record);
    }
    records.sort();
    for record in records {
        digest.update((record.len() as u64).to_le_bytes());
        digest.update(record);
    }
    Some(format!("{:x}", digest.finalize()))
}
