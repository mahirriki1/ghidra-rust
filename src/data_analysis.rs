//! Bounded, instruction-local memory-access evidence from public engine p-code.
//!
//! Adapts direct-memory reference rules from Ghidra's SymbolicPropogator.java
//! (9a723ce99952771b8368329503aa589ae233e916), Apache-2.0. See NOTICE.
use std::collections::BTreeSet;

use ghidra_decompiler::opcodes::OpCode;
use ghidra_decompiler::program::{InstructionPcode, PcodeOperation, PcodeVarnode};

use crate::model::*;

pub(crate) struct DataCollector<'a> {
    sections: &'a [SectionInfo],
    data_space: &'a str,
    pointer_bytes: u32,
    references: BTreeSet<DataReference>,
    report: DataAnalysis,
}

impl<'a> DataCollector<'a> {
    pub fn new(sections: &'a [SectionInfo], data_space: &'a str, pointer_bytes: u32) -> Self {
        Self {
            sections,
            data_space,
            pointer_bytes,
            references: BTreeSet::new(),
            report: DataAnalysis::default(),
        }
    }

    pub fn inspect(&mut self, function: u64, code: &InstructionPcode) {
        // Preflight the whole instruction before admitting evidence: internal
        // p-code branches make even preceding operations conditional.
        let charged = code
            .operations
            .len()
            .min(MAX_DATA_OPERATIONS_PER_INSTRUCTION)
            .min(MAX_DATA_OPERATIONS - self.report.operations_charged);
        self.report.operations_charged += charged;
        if charged
            < code
                .operations
                .len()
                .min(MAX_DATA_OPERATIONS_PER_INSTRUCTION)
        {
            self.report.partial = true;
            return;
        }
        if code.operations.len() > MAX_DATA_OPERATIONS_PER_INSTRUCTION
            || code
                .operations
                .iter()
                .any(|operation| !supported(operation))
        {
            self.report.unsupported_instructions += 1;
            self.report.partial = true;
            return;
        }
        for operation in &code.operations {
            use OpCode::*;
            match operation.opcode {
                Call | Callind | Branch | Branchind | Cbranch | Return => continue,
                Load | Store => {
                    let (size, access) = if operation.opcode == Load {
                        (operation.output.as_ref().unwrap().size, DataAccess::Read)
                    } else {
                        (operation.inputs[2].size, DataAccess::Write)
                    };
                    if self.candidate() {
                        let pointer = &operation.inputs[1];
                        if operation.space.as_deref() != Some(self.data_space) || !valid_size(size)
                        {
                            self.report.omitted_accesses += 1;
                        } else if pointer.space != "const" {
                            self.report.unresolved_accesses += 1;
                        } else if !fits_width(pointer.offset, pointer.size)
                            || pointer.size > self.pointer_bytes
                        {
                            self.report.omitted_accesses += 1;
                        } else {
                            self.record(function, code.address, pointer.offset, size, access);
                        }
                    }
                    // Input zero is address-space metadata, never a value read.
                    for input in operation.inputs.iter().skip(1) {
                        self.value(function, code.address, input, DataAccess::Read);
                    }
                }
                _ => {
                    for input in &operation.inputs {
                        self.value(function, code.address, input, DataAccess::Read);
                    }
                }
            }
            if let Some(output) = &operation.output {
                self.value(function, code.address, output, DataAccess::Write);
            }
        }
    }

    fn candidate(&mut self) -> bool {
        if self.report.accesses_examined == MAX_DATA_REFERENCES {
            self.report.partial = true;
            false
        } else {
            self.report.accesses_examined += 1;
            true
        }
    }

    fn value(&mut self, function: u64, address: u64, value: &PcodeVarnode, access: DataAccess) {
        if matches!(value.space.as_str(), "const" | "register" | "unique") {
            return;
        }
        if self.candidate() {
            if value.space == self.data_space {
                self.record(function, address, value.offset, value.size, access);
            } else {
                self.report.omitted_accesses += 1;
            }
        }
    }

    fn record(&mut self, function: u64, address: u64, target: u64, size: u32, access: DataAccess) {
        if mapped_range(self.sections, target, size, self.pointer_bytes, false) {
            self.references.insert(DataReference {
                function,
                address,
                target,
                size,
                access,
            });
        } else {
            self.report.omitted_accesses += 1;
        }
    }

    pub fn finish(mut self) -> DataAnalysis {
        self.report.references = self.references.into_iter().collect();
        self.report
    }
}

fn supported(operation: &PcodeOperation) -> bool {
    use OpCode::*;
    if operation.inputs.len() > MAX_DATA_OPERATION_INPUTS {
        return false;
    }
    match operation.opcode {
        Load => operation.inputs.len() == 2 && operation.output.is_some(),
        Store => operation.inputs.len() == 3 && operation.output.is_none(),
        Branch | Cbranch => operation
            .inputs
            .first()
            .is_some_and(|target| target.space != "const"),
        Call | Callind | Branchind | Return => true,
        Copy | IntEqual | IntNotequal | IntSless | IntSlessequal | IntLess | IntLessequal
        | IntZext | IntSext | IntAdd | IntSub | IntCarry | IntScarry | IntSborrow | Int2comp
        | IntNegate | IntXor | IntAnd | IntOr | IntLeft | IntRight | IntSright | IntMult
        | IntDiv | IntSdiv | IntRem | IntSrem | BoolNegate | BoolXor | BoolAnd | BoolOr
        | FloatEqual | FloatNotequal | FloatLess | FloatLessequal | FloatNan | FloatAdd
        | FloatDiv | FloatMult | FloatSub | FloatNeg | FloatAbs | FloatSqrt | FloatInt2float
        | FloatFloat2float | FloatTrunc | FloatCeil | FloatFloor | FloatRound | Piece
        | Subpiece | Popcount | Lzcount => true,
        // High-level, processor-specific, and unknown operations need separate
        // semantics; accepting their operands would invent unconditional reads.
        _ => false,
    }
}

fn valid_size(size: u32) -> bool {
    (1..=MAX_DATA_ACCESS_BYTES).contains(&size)
}

fn fits_width(address: u64, bytes: u32) -> bool {
    (1..=8).contains(&bytes) && (bytes == 8 || address < (1u64 << (bytes * 8)))
}

fn mapped_range(
    sections: &[SectionInfo],
    address: u64,
    size: u32,
    pointer_bytes: u32,
    executable: bool,
) -> bool {
    if !valid_size(size) || !fits_width(address, pointer_bytes) {
        return false;
    }
    let Some(end) = address.checked_add(u64::from(size)) else {
        return false;
    };
    if !fits_width(end - 1, pointer_bytes) {
        return false;
    }
    sections
        .partition_point(|section| section.address <= address)
        .checked_sub(1)
        .and_then(|index| sections.get(index))
        .is_some_and(|section| {
            (!executable || section.executable)
                && section
                    .address
                    .checked_add(section.size.min(section.file_size))
                    .is_some_and(|section_end| end <= section_end)
        })
}

impl DataAnalysis {
    pub fn validate(
        &self,
        info: &BinaryInfo,
        functions: &[FunctionInfo],
        decode_attempts: usize,
    ) -> Result<(), String> {
        let counted = self
            .references
            .len()
            .checked_add(self.unresolved_accesses)
            .and_then(|count| count.checked_add(self.omitted_accesses));
        let operation_limit = decode_attempts.checked_mul(MAX_DATA_OPERATIONS_PER_INSTRUCTION);
        let access_limit = self
            .operations_charged
            .checked_mul(MAX_DATA_OPERATION_INPUTS + 2);
        if decode_attempts > MAX_ANALYSIS_INSTRUCTIONS
            || self.operations_charged > MAX_DATA_OPERATIONS
            || self.accesses_examined > MAX_DATA_REFERENCES
            || self.references.len() > MAX_DATA_REFERENCES
            || self.unsupported_instructions > decode_attempts
            || counted.is_none_or(|count| count > self.accesses_examined)
            || operation_limit.is_none_or(|limit| self.operations_charged > limit)
            || access_limit.is_none_or(|limit| self.accesses_examined > limit)
            || (!self.partial && self.unsupported_instructions != 0)
            || functions.len() > crate::pe::MAX_FUNCTIONS
            || info.sections.len() > 4096
        {
            return Err("Data analysis exceeds its work or result bounds".into());
        }
        let mut previous_end = None;
        for section in &info.sections {
            let end = section.address.checked_add(section.size);
            let file_end = section
                .file_offset
                .checked_add(section.size.min(section.file_size));
            if section.size == 0
                || end.is_none()
                || file_end.is_none_or(|end| end > info.file_len)
                || previous_end.is_some_and(|end| end > section.address)
            {
                return Err("Invalid data analysis section bounds or ordering".into());
            }
            previous_end = end;
        }
        let (pointer_bytes, alignment) = match info.architecture.as_str() {
            "x86" => (4, 1),
            "x86-64" => (8, 1),
            "AArch64" => (8, 4),
            _ => return Err("Unsupported data analysis architecture".into()),
        };
        let valid_pc = |address: u64| {
            address.is_multiple_of(u64::from(alignment))
                && mapped_range(&info.sections, address, alignment, pointer_bytes, true)
        };
        for (index, function) in functions.iter().enumerate() {
            if !valid_pc(function.address)
                || function.name.len() > 256
                || (index > 0 && functions[index - 1].address >= function.address)
            {
                return Err("Invalid data analysis function inventory".into());
            }
        }
        for (index, reference) in self.references.iter().enumerate() {
            if !valid_pc(reference.function)
                || !valid_pc(reference.address)
                || functions
                    .binary_search_by_key(&reference.function, |function| function.address)
                    .is_err()
                || !mapped_range(
                    &info.sections,
                    reference.target,
                    reference.size,
                    pointer_bytes,
                    false,
                )
                || (index > 0 && self.references[index - 1] >= *reference)
            {
                return Err("Invalid data evidence addresses, ordering, or duplicates".into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_decompiler::program::Program;

    fn sections() -> Vec<SectionInfo> {
        vec![
            SectionInfo {
                name: ".text".into(),
                address: 0x1000,
                size: 0x200,
                file_offset: 0,
                file_size: 0x200,
                executable: true,
            },
            SectionInfo {
                name: ".data".into(),
                address: 0x2000,
                size: 0x200,
                file_offset: 0x200,
                file_size: 0x100,
                executable: false,
            },
        ]
    }

    fn value(space: &str, offset: u64, size: u32) -> PcodeVarnode {
        PcodeVarnode {
            space: space.into(),
            offset,
            size,
        }
    }

    fn copy(input: PcodeVarnode) -> PcodeOperation {
        PcodeOperation {
            opcode: OpCode::Copy,
            output: Some(value("register", 0, input.size)),
            inputs: vec![input],
            space: None,
        }
    }

    fn load(pointer: PcodeVarnode, size: u32) -> PcodeOperation {
        PcodeOperation {
            opcode: OpCode::Load,
            output: Some(value("register", 0, size)),
            inputs: vec![value("const", 0x1100, 8), pointer],
            space: Some("ram".into()),
        }
    }

    fn instruction(operations: Vec<PcodeOperation>) -> InstructionPcode {
        InstructionPcode {
            address: 0x1000,
            length: 4,
            operations,
        }
    }

    fn collect(operations: Vec<PcodeOperation>, pointer_bytes: u32) -> DataAnalysis {
        let sections = sections();
        let mut collector = DataCollector::new(&sections, "ram", pointer_bytes);
        collector.inspect(0x1000, &instruction(operations));
        collector.finish()
    }

    fn real(language: &str, bytes: Vec<u8>, count: usize) -> DataAnalysis {
        let pointer_bytes = if language.starts_with("x86:LE:32:") {
            4
        } else {
            8
        };
        let program = Program::from_raw_bytes(bytes, language, 0x1000).unwrap();
        let sections = sections();
        let mut collector = DataCollector::new(&sections, "ram", pointer_bytes);
        for code in program.pcode(0x1000, count).unwrap() {
            collector.inspect(0x1000, &code);
        }
        collector.finish()
    }

    #[test]
    fn engine_absolute_rip_and_literal_memory_accesses() {
        for (language, bytes, expected) in [
            (
                "x86:LE:32:default:gcc",
                vec![0xa1, 0x00, 0x11, 0, 0],
                vec![(4, DataAccess::Read)],
            ),
            (
                "x86:LE:64:default:gcc",
                vec![0x48, 0x8b, 0x05, 0xf9, 0, 0, 0],
                vec![(8, DataAccess::Read)],
            ),
            (
                "x86:LE:64:default:gcc",
                vec![0x48, 0x89, 0x05, 0xf9, 0, 0, 0],
                vec![(8, DataAccess::Write)],
            ),
            (
                "x86:LE:64:default:gcc",
                vec![0x48, 0x83, 0x05, 0xf8, 0, 0, 0, 1],
                vec![(8, DataAccess::Read), (8, DataAccess::Write)],
            ),
            (
                "AARCH64:LE:64:v8A:default",
                0x58000800u32.to_le_bytes().to_vec(),
                vec![(8, DataAccess::Read)],
            ),
        ] {
            let report = real(language, bytes, 1);
            assert!(!report.partial, "{language}: {report:?}");
            let actual: Vec<_> = report
                .references
                .iter()
                .map(|reference| {
                    assert_eq!(reference.function, 0x1000);
                    assert_eq!(reference.address, 0x1000);
                    assert_eq!(reference.target, 0x1100);
                    (reference.size, reference.access)
                })
                .collect();
            assert_eq!(actual, expected, "{language}");
        }
    }

    #[test]
    fn engine_constants_and_dynamic_addresses_do_not_invent_references() {
        for (language, bytes, count, unresolved) in [
            (
                "x86:LE:64:default:gcc",
                vec![0x48, 0x8d, 0x05, 0xf9, 0, 0, 0],
                1,
                false,
            ),
            (
                "x86:LE:64:default:gcc",
                vec![0xb8, 0x00, 0x11, 0, 0],
                1,
                false,
            ),
            ("x86:LE:64:default:gcc", vec![0x48, 0x8b, 0x00], 1, true),
            (
                "x86:LE:64:default:gcc",
                vec![0x48, 0x8b, 0x04, 0x24],
                1,
                true,
            ),
            ("x86:LE:64:default:gcc", vec![0xe8, 0xfb, 0, 0, 0], 1, true),
            (
                "AARCH64:LE:64:v8A:default",
                0x10000800u32.to_le_bytes().to_vec(),
                1,
                false,
            ),
            (
                "AARCH64:LE:64:v8A:default",
                [0x90000010u32, 0xf9408211]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect(),
                2,
                true,
            ),
        ] {
            let report = real(language, bytes, count);
            assert!(report.references.is_empty(), "{language}: {report:?}");
            assert_eq!(
                report.unresolved_accesses > 0,
                unresolved,
                "{language}: {report:?}"
            );
        }
    }

    #[test]
    fn load_store_use_pointer_slot_and_value_width_and_account_for_memory_values() {
        let store = PcodeOperation {
            opcode: OpCode::Store,
            output: None,
            inputs: vec![
                value("const", 0x1100, 8),
                value("const", 0x2000, 8),
                value("ram", 0x1104, 4),
            ],
            space: Some("ram".into()),
        };
        let mut read = load(value("const", 0x2000, 8), 8);
        read.output = Some(value("ram", 0x1108, 8));
        let report = collect(vec![store, read], 8);
        assert_eq!(report.accesses_examined, 4);
        assert_eq!(
            report
                .references
                .iter()
                .map(|r| (r.target, r.size, r.access))
                .collect::<Vec<_>>(),
            vec![
                (0x1104, 4, DataAccess::Read),
                (0x1108, 8, DataAccess::Write),
                (0x2000, 4, DataAccess::Write),
                (0x2000, 8, DataAccess::Read),
            ]
        );
        let indirect = collect(vec![load(value("ram", 0x2000, 8), 4)], 8);
        assert_eq!(indirect.accesses_examined, 2);
        assert_eq!(indirect.unresolved_accesses, 1);
        assert_eq!(indirect.references.len(), 1);
        assert_eq!(indirect.references[0].target, 0x2000);
        assert_eq!(indirect.references[0].size, 8);
        assert_eq!(indirect.references[0].access, DataAccess::Read);
    }

    #[test]
    fn no_register_unique_or_cross_instruction_propagation() {
        let sections = sections();
        let mut collector = DataCollector::new(&sections, "ram", 8);
        for space in ["register", "unique"] {
            let mut establish = copy(value("const", 0x2000, 8));
            establish.output = Some(value(space, 0, 8));
            collector.inspect(0x1000, &instruction(vec![establish]));
            collector.inspect(0x1000, &instruction(vec![load(value(space, 0, 8), 8)]));
        }
        let report = collector.finish();
        assert!(report.references.is_empty());
        assert_eq!(report.unresolved_accesses, 2);
        assert!(!report.partial);
    }

    #[test]
    fn refuses_conditional_internal_flow_and_unsupported_instructions_atomically() {
        for opcode in [
            OpCode::Branch,
            OpCode::Cbranch,
            OpCode::Callother,
            OpCode::Multiequal,
            OpCode::Indirect,
            OpCode::Ptradd,
            OpCode::New,
        ] {
            let unsupported = PcodeOperation {
                opcode,
                output: None,
                inputs: vec![value("const", 1, 8)],
                space: None,
            };
            let report = collect(vec![copy(value("ram", 0x1100, 8)), unsupported], 8);
            assert!(report.references.is_empty());
            assert_eq!(report.accesses_examined, 0);
            assert_eq!(report.operations_charged, 2);
            assert_eq!(report.unsupported_instructions, 1);
            assert!(report.partial);
        }
        for opcode in [
            OpCode::Branch,
            OpCode::Cbranch,
            OpCode::Call,
            OpCode::Callind,
            OpCode::Branchind,
            OpCode::Return,
        ] {
            let report = collect(
                vec![PcodeOperation {
                    opcode,
                    output: Some(value("ram", 0x1108, 8)),
                    inputs: vec![value("ram", 0x1100, 8)],
                    space: None,
                }],
                8,
            );
            assert!(report.references.is_empty());
            assert_eq!(report.accesses_examined, 0);
        }
    }

    #[test]
    fn omits_unmapped_bss_crossing_overflow_bad_width_and_other_spaces() {
        for (target, size) in [
            (0x3000, 8),
            (0x2100, 8),
            (0x20fc, 8),
            (u64::MAX, 8),
            (0x2000, 0),
            (0x2000, 65),
        ] {
            let report = collect(vec![copy(value("ram", target, size))], 8);
            assert!(report.references.is_empty());
            assert_eq!(report.omitted_accesses, 1);
            assert_eq!(report.accesses_examined, 1);
        }
        let mut wrong_space = load(value("const", 0x2000, 8), 8);
        wrong_space.space = Some("other".into());
        let report = collect(vec![wrong_space, copy(value("other", 0x1100, 8))], 8);
        assert!(report.references.is_empty());
        assert_eq!(report.omitted_accesses, 2);
        // The space-ID metadata happens to look mapped, but creates no read.
        let report = collect(vec![load(value("const", 0x3000, 8), 8)], 8);
        assert!(report.references.is_empty());
        assert_eq!(report.accesses_examined, 1);
    }

    #[test]
    fn rejects_pointer_truncation_and_target_width_overflow() {
        for (pointer, pointer_bytes) in [
            (value("const", 0x1_0000_2000, 4), 8),
            (value("const", 0x2000, 8), 4),
            (value("const", 0x2000, 0), 8),
            (value("const", 0x2000, 9), 8),
        ] {
            let report = collect(vec![load(pointer, 8)], pointer_bytes);
            assert!(report.references.is_empty());
            assert_eq!(report.omitted_accesses, 1);
        }
        let high = vec![SectionInfo {
            name: "high".into(),
            address: 0xffff_fff0,
            size: 64,
            file_offset: 0,
            file_size: 64,
            executable: false,
        }];
        let mut collector = DataCollector::new(&high, "ram", 4);
        collector.inspect(
            0x1000,
            &instruction(vec![copy(value("ram", 0xffff_fffc, 8))]),
        );
        assert_eq!(collector.finish().omitted_accesses, 1);
    }

    #[test]
    fn charges_duplicates_before_dedup_and_bounds_candidates_and_operations() {
        let sections = sections();
        let mut collector = DataCollector::new(&sections, "ram", 8);
        let code = instruction(vec![
            copy(value("ram", 0x1100, 8));
            MAX_DATA_OPERATIONS_PER_INSTRUCTION
        ]);
        for _ in 0..MAX_DATA_REFERENCES / MAX_DATA_OPERATIONS_PER_INSTRUCTION + 1 {
            collector.inspect(0x1000, &code);
        }
        let report = collector.finish();
        assert_eq!(report.references.len(), 1);
        assert_eq!(report.accesses_examined, MAX_DATA_REFERENCES);
        assert_eq!(
            report.operations_charged,
            MAX_DATA_REFERENCES + MAX_DATA_OPERATIONS_PER_INSTRUCTION
        );
        assert!(report.partial);

        let mut collector = DataCollector::new(&sections, "ram", 8);
        let no_access = instruction(vec![
            copy(value("const", 0x1100, 8));
            MAX_DATA_OPERATIONS_PER_INSTRUCTION
        ]);
        for _ in 0..MAX_DATA_OPERATIONS / MAX_DATA_OPERATIONS_PER_INSTRUCTION + 1 {
            collector.inspect(0x1000, &no_access);
        }
        let report = collector.finish();
        assert_eq!(report.operations_charged, MAX_DATA_OPERATIONS);
        assert_eq!(report.accesses_examined, 0);
        assert!(report.partial);

        let report = collect(
            vec![copy(value("ram", 0x1100, 8)); MAX_DATA_OPERATIONS_PER_INSTRUCTION + 1],
            8,
        );
        assert_eq!(
            report.operations_charged,
            MAX_DATA_OPERATIONS_PER_INSTRUCTION
        );
        assert_eq!(report.unsupported_instructions, 1);
        assert!(report.references.is_empty());
        let mut operation = copy(value("ram", 0x1100, 8));
        operation.inputs = vec![value("ram", 0x1100, 8); MAX_DATA_OPERATION_INPUTS + 1];
        let report = collect(vec![operation], 8);
        assert_eq!(report.unsupported_instructions, 1);
        assert_eq!(report.accesses_examined, 0);
    }

    fn binary() -> BinaryInfo {
        BinaryInfo {
            path: "fixture".into(),
            architecture: "AArch64".into(),
            format: "ELF".into(),
            entry: 0x1000,
            file_len: 0x300,
            sha256: "a".repeat(64),
            source_identity: None,
            sections: sections(),
            functions: vec![FunctionInfo {
                address: 0x1000,
                name: "caller".into(),
            }],
            functions_truncated: false,
            warnings: vec![],
        }
    }

    #[test]
    fn validates_transport_bounds_addresses_owner_order_and_accounting() {
        let info = binary();
        let report = collect(vec![copy(value("ram", 0x2000, 8))], 8);
        report.validate(&info, &info.functions, 1).unwrap();
        for (function, address, target, size) in [
            (0x1004, 0x1000, 0x2000, 8), // unknown owner
            (0x1000, 0x1002, 0x2000, 8), // unaligned instruction
            (0x1000, 0x2000, 0x2000, 8), // nonexecutable instruction
            (0x1000, 0x1000, 0x2100, 8), // BSS
            (0x1000, 0x1000, 0x20fc, 8), // crosses backed end
            (0x1000, 0x1000, u64::MAX, 8),
            (0x1000, 0x1000, 0x2000, 0),
            (0x1000, 0x1000, 0x2000, 65),
        ] {
            let mut invalid = report.clone();
            invalid.references[0] = DataReference {
                function,
                address,
                target,
                size,
                access: DataAccess::Read,
            };
            assert!(invalid.validate(&info, &info.functions, 1).is_err());
        }
        let mut invalid = report.clone();
        invalid.references.push(invalid.references[0].clone());
        invalid.accesses_examined = 2;
        assert!(invalid.validate(&info, &info.functions, 1).is_err());
        for invalid in [
            DataAnalysis {
                operations_charged: usize::MAX,
                ..report.clone()
            },
            DataAnalysis {
                accesses_examined: usize::MAX,
                ..report.clone()
            },
            DataAnalysis {
                unresolved_accesses: usize::MAX,
                ..report.clone()
            },
            DataAnalysis {
                omitted_accesses: usize::MAX,
                ..report.clone()
            },
            DataAnalysis {
                unsupported_instructions: 2,
                partial: true,
                ..report.clone()
            },
            DataAnalysis {
                operations_charged: 0,
                ..report.clone()
            },
            DataAnalysis {
                accesses_examined: 0,
                ..report.clone()
            },
            DataAnalysis {
                operations_charged: MAX_DATA_OPERATIONS_PER_INSTRUCTION + 1,
                ..report.clone()
            },
        ] {
            assert!(invalid.validate(&info, &info.functions, 1).is_err());
        }
        assert!(report.validate(&info, &info.functions, 0).is_err());
        assert!(report.validate(&info, &info.functions, usize::MAX).is_err());
        let mut invalid = info.clone();
        invalid.functions.push(invalid.functions[0].clone());
        assert!(report.validate(&invalid, &invalid.functions, 1).is_err());
        let mut invalid = info.clone();
        invalid.architecture = "x86".into();
        invalid.sections.push(SectionInfo {
            name: "high".into(),
            address: 0x1_0000_2000,
            size: 64,
            file_offset: 0,
            file_size: 64,
            executable: false,
        });
        let mut high = report.clone();
        high.references[0].target = 0x1_0000_2000;
        assert!(high.validate(&invalid, &invalid.functions, 1).is_err());
    }

    #[test]
    fn rejects_spoofed_section_backing_order_overlap_and_overflow() {
        let info = binary();
        let report = collect(vec![copy(value("ram", 0x2000, 8))], 8);
        let mut invalid = info.clone();
        invalid.sections[1].file_size = invalid.sections[1].size;
        assert!(report.validate(&invalid, &invalid.functions, 1).is_err());
        let mut invalid = info.clone();
        invalid.sections[1].file_offset = u64::MAX;
        assert!(report.validate(&invalid, &invalid.functions, 1).is_err());
        let mut invalid = info.clone();
        invalid.sections.reverse();
        assert!(report.validate(&invalid, &invalid.functions, 1).is_err());
        let mut invalid = info.clone();
        invalid.sections[1].address = 0x1100;
        assert!(report.validate(&invalid, &invalid.functions, 1).is_err());
        let mut invalid = info.clone();
        invalid.sections[1].address = u64::MAX - 1;
        assert!(report.validate(&invalid, &invalid.functions, 1).is_err());
        let mut invalid = info.clone();
        invalid.sections = vec![info.sections[0].clone(); 4097];
        assert!(report.validate(&invalid, &invalid.functions, 1).is_err());
    }
}
