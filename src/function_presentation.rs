//! Validated function results with their prepared, reusable presentation data:
//! the ordered listing index, graph geometry, line ranges, and highlighting.
//! Camera, selection, scroll requests and egui ids are deliberately absent.

use std::sync::Arc;

use crate::graph::GraphGeometry;
use crate::highlight::HighlightedCode;
use crate::model::{CodeMapping, FunctionView, Instruction, MAX_DECOMPILED_BYTES, SectionInfo};
use crate::result_store::{Bytes, Retained};
use crate::semantic::SemanticInfo;

/// Decompiler display rows; longer output stays copyable but is not listed.
const MAX_CODE_LINES: usize = 20_000;

/// Address-ordered, de-duplicated `(block, instruction)` positions into the
/// view's own blocks. The first block containing an address wins.
pub struct ListingIndex(Box<[(u32, u32)]>);

impl ListingIndex {
    pub fn new(view: &FunctionView) -> Self {
        let mut rows: Vec<(u64, u32, u32)> = Vec::new();
        for (block, instructions) in view.blocks.iter().enumerate() {
            let Ok(block) = u32::try_from(block) else {
                break;
            };
            for (index, instruction) in instructions.instructions.iter().enumerate() {
                let Ok(index) = u32::try_from(index) else {
                    break;
                };
                rows.push((instruction.address, block, index));
            }
        }
        // Stable: equal addresses keep block order, so the first one wins.
        rows.sort_by_key(|row| row.0);
        rows.dedup_by_key(|row| row.0);
        Self(rows.into_iter().map(|(_, b, i)| (b, i)).collect())
    }
}

/// The listing of one prepared graph.
#[derive(Clone, Copy)]
pub struct Listing<'a> {
    view: &'a FunctionView,
    index: &'a [(u32, u32)],
}

impl<'a> Listing<'a> {
    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    pub fn get(&self, row: usize) -> Option<&'a Instruction> {
        let &(block, index) = self.index.get(row)?;
        self.view
            .blocks
            .get(block as usize)?
            .instructions
            .get(index as usize)
    }

    pub fn last(&self) -> Option<&'a Instruction> {
        self.len().checked_sub(1).and_then(|row| self.get(row))
    }

    /// The row of exactly `address`, by binary search.
    pub fn position(&self, address: u64) -> Option<usize> {
        let row = self.partition(address);
        (self.get(row)?.address == address).then_some(row)
    }

    pub fn contains(&self, address: u64) -> bool {
        self.position(address).is_some()
    }

    pub fn iter(&self) -> impl Iterator<Item = &'a Instruction> + 'a {
        let listing = *self;
        (0..listing.len()).filter_map(move |row| listing.get(row))
    }

    fn partition(&self, address: u64) -> usize {
        let (mut low, mut high) = (0, self.len());
        while low < high {
            let middle = low + (high - low) / 2;
            if self.get(middle).is_some_and(|i| i.address < address) {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        low
    }
}

/// A validated graph reply with its listing index and base geometry.
pub struct PreparedGraph {
    view: FunctionView,
    listing: ListingIndex,
    geometry: Arc<GraphGeometry>,
}

impl PreparedGraph {
    /// `view` must already have passed reply or project validation.
    pub fn new(view: FunctionView) -> Self {
        let geometry = crate::performance::span("gui_graph_geometry");
        let prepared = Self {
            listing: ListingIndex::new(&view),
            geometry: Arc::new(GraphGeometry::new(&view)),
            view,
        };
        geometry.finish(prepared.view.blocks.len() as u64);
        prepared
    }

    pub fn view(&self) -> &FunctionView {
        &self.view
    }

    pub fn address(&self) -> u64 {
        self.view.address
    }

    pub fn listing(&self) -> Listing<'_> {
        Listing {
            view: &self.view,
            index: &self.listing.0,
        }
    }

    pub fn geometry(&self) -> Arc<GraphGeometry> {
        self.geometry.clone()
    }
}

impl Retained for PreparedGraph {
    fn retained_bytes(&self) -> Option<usize> {
        let view = &self.view;
        let mut bytes = Bytes::of::<Self>()
            .slots::<crate::model::BasicBlock>(view.blocks.capacity())
            .slots::<crate::model::Edge>(view.edges.capacity())
            .slots::<crate::model::CallSite>(view.calls.capacity())
            .slots::<String>(view.warnings.capacity())
            .slots::<(u32, u32)>(self.listing.0.len())
            .add_total(self.geometry.retained_bytes());
        for block in &view.blocks {
            bytes = bytes.slots::<Instruction>(block.instructions.capacity());
            for instruction in &block.instructions {
                bytes = bytes
                    .plus(instruction.bytes.capacity())
                    .plus(instruction.mnemonic.capacity())
                    .plus(instruction.operands.capacity());
            }
        }
        for warning in &view.warnings {
            bytes = bytes.plus(warning.capacity());
        }
        bytes.total()
    }
}

/// One indivisible decompilation: text, mappings, semantic tokens/locals,
/// inferred prototype and warnings, with derived line ranges and highlighting.
/// Text and mappings are never combined from different replies.
pub struct PreparedDecompilation {
    address: u64,
    text: String,
    mappings: Arc<[CodeMapping]>,
    semantics: SemanticInfo,
    lines: Box<[(usize, usize)]>,
    highlighted: HighlightedCode,
}

impl PreparedDecompilation {
    /// Checks the size budget and exact mapping bounds before preparing.
    /// Semantic metadata is validated by the worker reader and project loader.
    pub fn validate(
        address: u64,
        text: String,
        mappings: Vec<CodeMapping>,
        semantics: SemanticInfo,
        sections: &[SectionInfo],
    ) -> Result<Self, DecompilationError> {
        if text.len() > MAX_DECOMPILED_BYTES {
            return Err(DecompilationError::Oversized);
        }
        crate::selection::validate_mappings(&text, &mappings, sections)
            .map_err(DecompilationError::Mappings)?;
        Ok(Self::prepare(address, text, mappings, semantics))
    }

    fn prepare(
        address: u64,
        text: String,
        mappings: Vec<CodeMapping>,
        semantics: SemanticInfo,
    ) -> Self {
        let highlighting = crate::performance::span("gui_highlighting");
        let highlighted = HighlightedCode::new(&text);
        highlighting.finish(text.len() as u64);
        let mut offset = 0;
        let lines = text
            .split_inclusive('\n')
            .take(MAX_CODE_LINES)
            .map(|line| {
                let range = (offset, offset + line.len());
                offset += line.len();
                range
            })
            .collect();
        Self {
            address,
            text,
            mappings: mappings.into(),
            semantics,
            lines,
            highlighted,
        }
    }

    pub fn address(&self) -> u64 {
        self.address
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn mappings(&self) -> &Arc<[CodeMapping]> {
        &self.mappings
    }

    pub fn semantics(&self) -> &SemanticInfo {
        &self.semantics
    }

    pub fn lines(&self) -> &[(usize, usize)] {
        &self.lines
    }

    pub fn highlighted(&self) -> &HighlightedCode {
        &self.highlighted
    }
}

impl Retained for PreparedDecompilation {
    fn retained_bytes(&self) -> Option<usize> {
        let semantics = &self.semantics;
        let mut bytes = Bytes::of::<Self>()
            .plus(self.text.capacity())
            .slots::<CodeMapping>(self.mappings.len())
            .slots::<(usize, usize)>(self.lines.len())
            .add_total(self.highlighted.retained_bytes())
            .slots::<crate::semantic::SemanticToken>(semantics.tokens.capacity())
            .slots::<crate::semantic::LocalVariable>(semantics.locals.capacity())
            .slots::<String>(semantics.warnings.capacity());
        for mapping in self.mappings.iter() {
            bytes = bytes.slots::<u64>(mapping.addresses.capacity());
        }
        for local in &semantics.locals {
            bytes = bytes
                .plus(local.name.capacity())
                .plus(local.identity.engine.capacity())
                .plus(local.identity.verification.capacity());
        }
        for warning in &semantics.warnings {
            bytes = bytes.plus(warning.capacity());
        }
        if let Some(prototype) = &semantics.prototype {
            bytes = bytes
                .slots::<crate::signatures::InferredSignature>(1)
                .slots::<crate::signatures::InferredParameter>(prototype.parameters.capacity())
                .slots::<String>(prototype.unsupported.capacity())
                .plus(prototype.abi.capacity());
            for parameter in &prototype.parameters {
                bytes = bytes.plus(parameter.name.capacity());
            }
            for note in &prototype.unsupported {
                bytes = bytes.plus(note.capacity());
            }
        }
        bytes.total()
    }
}

#[derive(Debug)]
pub enum DecompilationError {
    /// The text exceeds the 2 MiB reply limit.
    Oversized,
    Mappings(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::BasicBlock;

    fn instruction(address: u64, mnemonic: &str) -> Instruction {
        Instruction {
            address,
            bytes: vec![0x90],
            mnemonic: mnemonic.into(),
            operands: String::new(),
        }
    }

    #[test]
    fn listing_index_orders_blocks_and_keeps_the_first_duplicate() {
        let view = FunctionView {
            address: 0x1000,
            blocks: vec![
                BasicBlock {
                    address: 0x1008,
                    instructions: vec![instruction(0x1008, "first"), instruction(0x100c, "ret")],
                },
                BasicBlock {
                    address: 0x1000,
                    instructions: vec![instruction(0x1000, "push"), instruction(0x1008, "second")],
                },
            ],
            edges: vec![],
            calls: vec![],
            warnings: vec![],
        };
        let graph = PreparedGraph::new(view);
        let listing = graph.listing();
        let rows: Vec<_> = listing
            .iter()
            .map(|i| (i.address, i.mnemonic.as_str()))
            .collect();
        assert_eq!(rows, [(0x1000, "push"), (0x1008, "first"), (0x100c, "ret")]);
        assert_eq!(listing.position(0x1008), Some(1));
        assert_eq!(listing.position(0x1004), None);
        assert_eq!(listing.position(0x2000), None);
        assert_eq!(listing.last().unwrap().address, 0x100c);
        assert!(graph.retained_bytes().unwrap() > size_of::<PreparedGraph>());
    }

    #[test]
    fn decompilation_is_validated_as_one_unit() {
        let sections = [SectionInfo {
            name: ".text".into(),
            address: 0x1000,
            size: 0x100,
            file_size: 0x100,
            file_offset: 0,
            executable: true,
        }];
        let text = "int f() {\n  return 1;\n}\n".to_string();
        let mapping = |address| CodeMapping {
            start: 12,
            end: 21,
            addresses: vec![address],
        };
        let code = PreparedDecompilation::validate(
            0x1000,
            text.clone(),
            vec![mapping(0x1004)],
            SemanticInfo::default(),
            &sections,
        )
        .unwrap();
        assert_eq!(code.lines().len(), 3);
        assert_eq!(code.mappings().len(), 1);
        assert!(code.retained_bytes().unwrap() >= text.len());
        assert!(matches!(
            PreparedDecompilation::validate(
                0x1000,
                text.clone(),
                vec![mapping(0x9000)],
                SemanticInfo::default(),
                &sections,
            ),
            Err(DecompilationError::Mappings(_))
        ));
        assert!(matches!(
            PreparedDecompilation::validate(
                0x1000,
                "x".repeat(MAX_DECOMPILED_BYTES + 1),
                vec![],
                SemanticInfo::default(),
                &sections,
            ),
            Err(DecompilationError::Oversized)
        ));
        // A successful empty result is distinct from a missing one.
        let empty =
            PreparedDecompilation::validate(0x1000, String::new(), vec![], Default::default(), &[])
                .unwrap();
        assert!(empty.text().is_empty() && empty.lines().is_empty());
    }
}
