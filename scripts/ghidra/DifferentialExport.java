// Exports bounded headless-analysis results for the ghidra-rust differential
// benchmark (tests/ghidra_differential.rs). This is optional measurement
// tooling run by a separately installed Ghidra; the desktop never loads it.
//
// Usage: -preScript DifferentialExport.java before <request.json>
//        -postScript DifferentialExport.java after <request.json>
// @category ghidra-rust

import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.framework.Application;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.symbol.FlowType;
import java.io.IOException;
import java.io.Writer;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.TreeSet;

public class DifferentialExport extends HeadlessScript {
	private static final String BEFORE_NANOS = "ghidra_rust_before_nanos";
	private static final String BEFORE_UPTIME = "ghidra_rust_before_uptime_ms";
	private static final String BEFORE_ERROR = "ghidra_rust_before_error";
	private static final long MAX_REQUEST_BYTES = 1024 * 1024;
	private static final int SCHEMA_VERSION = 1;

	private JsonObject request;
	private JsonObject limits;
	private long loadBase;
	private long delta;
	private AddressSpace space;

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 2) {
			throw new IllegalArgumentException("Expected <before|after> <request.json>");
		}
		Path requestPath = Path.of(args[1]);
		if (Files.size(requestPath) > MAX_REQUEST_BYTES) {
			throw new IOException("Run request exceeds its size limit");
		}
		request = JsonParser.parseString(Files.readString(requestPath, StandardCharsets.UTF_8))
				.getAsJsonObject();
		if (request.get("schema_version").getAsInt() != SCHEMA_VERSION ||
			!request.get("document_type").getAsString().equals("run_request") ||
			!request.get("tool").getAsString().equals("ghidra")) {
			throw new IllegalArgumentException("Unsupported run request");
		}
		limits = request.getAsJsonObject("limits");
		switch (args[0]) {
			case "before" -> before();
			case "after" -> after();
			default -> throw new IllegalArgumentException("Unknown phase " + args[0]);
		}
	}

	/** Runs after import and before auto-analysis. */
	private void before() throws Exception {
		long uptime = ManagementFactory.getRuntimeMXBean().getUptime();
		String expected = request.get("input_sha256").getAsString();
		String actual = currentProgram.getExecutableSHA256();
		if (!expected.equalsIgnoreCase(actual)) {
			storeHeadlessValue(BEFORE_ERROR, "Imported program hash does not match the request");
		}
		storeHeadlessValue(BEFORE_UPTIME, uptime);
		storeHeadlessValue(BEFORE_NANOS, System.nanoTime());
	}

	/** Runs after auto-analysis; freezes inventories before decompiling. */
	private void after() throws Exception {
		long afterNanos = System.nanoTime();
		long postStart = afterNanos;
		JsonObject export = new JsonObject();
		export.addProperty("schema_version", SCHEMA_VERSION);
		export.addProperty("document_type", "tool_export");
		export.addProperty("run_id", request.get("run_id").getAsString());
		export.addProperty("case_id", request.get("case_id").getAsString());
		export.addProperty("repetition", request.get("repetition").getAsInt());
		export.addProperty("tool", "ghidra");
		JsonObject input = new JsonObject();
		input.addProperty("sha256", request.get("input_sha256").getAsString());
		export.add("input", input);
		JsonObject timings = new JsonObject();
		export.add("timings", timings);
		String stage = "pre_script";
		try {
			if (!headlessStorageContainsKey(BEFORE_NANOS)) {
				throw new IllegalStateException("The pre-analysis phase did not run");
			}
			if (headlessStorageContainsKey(BEFORE_ERROR)) {
				throw new IllegalStateException((String) getStoredHeadlessValue(BEFORE_ERROR));
			}
			long beforeNanos = (Long) getStoredHeadlessValue(BEFORE_NANOS);
			timings.addProperty("jvm_uptime_at_pre_script_ms",
				(Long) getStoredHeadlessValue(BEFORE_UPTIME));
			timings.addProperty("analysis_ms", (afterNanos - beforeNanos) / 1e6);
			stage = "addressing";
			export.add("tool_info", toolInfo());
			export.add("addressing", addressing());
			export.add("settings", settings());
			export.add("executable_blocks", executableBlocks());
			stage = "inventory";
			long inventoryStart = System.nanoTime();
			JsonObject coverage = new JsonObject();
			coverage.addProperty("analysis_timed_out", analysisTimeoutOccurred());
			export.add("functions", functions(coverage));
			export.add("calls", calls(coverage));
			export.add("coverage", coverage);
			timings.addProperty("inventory_export_ms", (System.nanoTime() - inventoryStart) / 1e6);
			stage = "decompile";
			export.add("decompilations", decompile(timings));
			boolean partial = coverage.get("analysis_timed_out").getAsBoolean() ||
				coverage.get("functions_capped").getAsBoolean() ||
				coverage.get("calls_capped").getAsBoolean();
			export.addProperty("status", partial ? "partial" : "ok");
			export.add("failure_stage", null);
			export.add("error", null);
		}
		catch (Exception e) {
			export.addProperty("status", "failed");
			export.addProperty("failure_stage", stage);
			export.addProperty("error", bounded(String.valueOf(e), "max_error_bytes"));
		}
		timings.addProperty("post_script_ms", (System.nanoTime() - postStart) / 1e6);
		write(export);
	}

	private JsonObject toolInfo() {
		JsonObject info = new JsonObject();
		info.addProperty("version", Application.getApplicationVersion());
		info.addProperty("java", System.getProperty("java.version"));
		info.addProperty("language_id", currentProgram.getLanguageID().getIdAsString());
		info.addProperty("compiler_spec_id",
			currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());
		return info;
	}

	/**
	 * Ghidra rebases ELF images (64-bit PIE defaults to 0x100000). Canonical
	 * addresses undo that rebasing; RVAs are relative to the minimum PT_LOAD.
	 */
	private JsonObject addressing() {
		loadBase = Long.parseUnsignedLong(request.get("load_base").getAsString().substring(2), 16);
		Long original = ElfLoader.getElfOriginalImageBase(currentProgram);
		if (original == null) {
			throw new IllegalStateException("The program lacks an ELF original image base");
		}
		if (original != loadBase) {
			throw new IllegalStateException("ELF original image base " + hex(original) +
				" differs from the first PT_LOAD " + hex(loadBase));
		}
		long imageBase = currentProgram.getImageBase().getOffset();
		delta = Math.subtractExact(imageBase, original);
		space = currentProgram.getAddressFactory().getDefaultAddressSpace();
		JsonObject addressing = new JsonObject();
		addressing.addProperty("load_base", hex(loadBase));
		addressing.addProperty("original_base", hex(original));
		addressing.addProperty("tool_base", hex(imageBase));
		addressing.addProperty("normalization", "raw - (tool_base - original_base)");
		return addressing;
	}

	private JsonObject settings() {
		JsonObject settings = new JsonObject();
		settings.addProperty("profile", "ghidra-default-analyzers-cpu1");
		JsonObject analyzers = new JsonObject();
		Options options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
		TreeSet<String> names = new TreeSet<>(options.getOptionNames());
		int max = limits.get("max_analyzer_options").getAsInt();
		settings.addProperty("analyzer_options_capped", names.size() > max);
		for (String name : names) {
			if (analyzers.size() >= max) {
				break;
			}
			analyzers.addProperty(name, String.valueOf(options.getValueAsString(name)));
		}
		settings.add("analyzer_options", analyzers);
		settings.add("limits", limits);
		return settings;
	}

	/** Executable, initialized blocks backed by original file bytes. */
	private boolean fileBackedCode(Address address) {
		if (address.getAddressSpace() != space) {
			return false;
		}
		MemoryBlock block = currentProgram.getMemory().getBlock(address);
		return block != null && block.isExecute() && block.isInitialized() &&
			!block.getSourceInfos().isEmpty() &&
			block.getSourceInfos().get(0).getFileBytes().isPresent();
	}

	private JsonArray executableBlocks() {
		JsonArray blocks = new JsonArray();
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			if (!block.isExecute() || !block.isInitialized() ||
				block.getStart().getAddressSpace() != space) {
				continue;
			}
			JsonObject record = new JsonObject();
			record.addProperty("name", block.getName());
			record.addProperty("rva", rva(block.getStart()));
			record.addProperty("size", block.getSize());
			List<MemoryBlockSourceInfo> sources = block.getSourceInfos();
			if (sources.size() == 1 && sources.get(0).getFileBytes().isPresent()) {
				record.addProperty("file_offset", sources.get(0).getFileBytesOffset());
			}
			else {
				record.add("file_offset", null);
			}
			blocks.add(record);
		}
		return blocks;
	}

	private JsonArray functions(JsonObject coverage) {
		JsonArray functions = new JsonArray();
		int max = limits.get("max_functions").getAsInt();
		int outside = 0;
		boolean capped = false;
		FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
		while (iterator.hasNext()) {
			Function function = iterator.next();
			Address entry = function.getEntryPoint();
			if (!fileBackedCode(entry)) {
				outside++;
				continue;
			}
			if (functions.size() >= max) {
				capped = true;
				break;
			}
			JsonObject record = new JsonObject();
			record.addProperty("rva", rva(entry));
			record.addProperty("raw", hex(entry.getOffset()));
			record.addProperty("name", bounded(function.getName(), "max_function_name_bytes"));
			record.addProperty("body_bytes", function.getBody().getNumAddresses());
			record.addProperty("thunk", function.isThunk());
			record.addProperty("noreturn", function.hasNoReturn());
			functions.add(record);
		}
		coverage.addProperty("functions_capped", capped);
		coverage.addProperty("functions_outside_file_backed_code", outside);
		return functions;
	}

	/**
	 * Non-computed call instructions with their literal flow destinations,
	 * plus jumps whose flow analysis overrode into calls, labelled separately.
	 */
	private JsonArray calls(JsonObject coverage) {
		JsonArray calls = new JsonArray();
		int max = limits.get("max_calls").getAsInt();
		long maxInstructions = limits.get("max_call_instructions").getAsLong();
		long inspected = 0;
		boolean capped = false;
		InstructionIterator iterator = currentProgram.getListing().getInstructions(true);
		outer: while (iterator.hasNext()) {
			if (++inspected > maxInstructions) {
				capped = true;
				break;
			}
			Instruction instruction = iterator.next();
			FlowType flow = instruction.getFlowType();
			// Analysis can override a jump's flow into a call (tail calls, PLT
			// jumps). Literal calls are judged by the unmodified prototype.
			FlowType original =
				instruction.getPrototype().getFlowType(instruction.getInstructionContext());
			boolean literal = original.isCall() && !original.isComputed();
			if (!(literal || (flow.isCall() && !flow.isComputed())) ||
				!fileBackedCode(instruction.getAddress())) {
				continue;
			}
			for (Address target : instruction.getFlows()) {
				if (target.getAddressSpace() != space) {
					continue;
				}
				if (calls.size() >= max) {
					capped = true;
					break outer;
				}
				JsonObject record = new JsonObject();
				record.addProperty("kind", literal ? "call" : "flow_override");
				record.addProperty("from_rva", rva(instruction.getAddress()));
				record.addProperty("target_rva", rva(target));
				Function caller = getFunctionContaining(instruction.getAddress());
				if (caller != null) {
					record.addProperty("caller_rva", rva(caller.getEntryPoint()));
				}
				else {
					record.add("caller_rva", null);
				}
				record.addProperty("raw_from", hex(instruction.getAddress().getOffset()));
				record.addProperty("raw_target", hex(target.getOffset()));
				calls.add(record);
			}
		}
		coverage.addProperty("calls_capped", capped);
		coverage.addProperty("call_instructions_inspected", Math.min(inspected, maxInstructions));
		return calls;
	}

	private JsonArray decompile(JsonObject timings) {
		JsonArray results = new JsonArray();
		int timeout = limits.get("decompile_timeout_seconds").getAsInt();
		long retained = 0;
		long setStart = System.nanoTime();
		DecompInterface decompiler = new DecompInterface();
		try {
			DecompileOptions options = new DecompileOptions();
			options.grabFromProgram(currentProgram);
			decompiler.setOptions(options);
			decompiler.toggleCCode(true);
			decompiler.toggleSyntaxTree(true);
			decompiler.setSimplificationStyle("decompile");
			long initStart = System.nanoTime();
			boolean opened = decompiler.openProgram(currentProgram);
			timings.addProperty("decompiler_init_ms", (System.nanoTime() - initStart) / 1e6);
			for (var element : request.getAsJsonArray("requested")) {
				JsonObject requested = element.getAsJsonObject();
				String va = requested.get("va").getAsString();
				long raw = Math.addExact(Long.parseUnsignedLong(va.substring(2), 16), delta);
				Address address = space.getAddress(raw);
				JsonObject record = new JsonObject();
				record.addProperty("rva", requested.get("rva").getAsString());
				record.addProperty("raw", hex(raw));
				record.add("c", null);
				record.add("c_bytes", null);
				record.add("elapsed_ms", null);
				record.add("error", null);
				record.addProperty("engine_truncation", false);
				record.addProperty("export_truncation", false);
				Function function = currentProgram.getFunctionManager().getFunctionAt(address);
				if (!opened) {
					record.addProperty("status", "error");
					record.addProperty("error", bounded(decompiler.getLastMessage(), "max_error_bytes"));
				}
				else if (function == null) {
					record.addProperty("status", "not_discovered");
				}
				else {
					long start = System.nanoTime();
					DecompileResults result = decompiler.decompileFunction(function, timeout, monitor);
					record.addProperty("elapsed_ms", (System.nanoTime() - start) / 1e6);
					if (result.isTimedOut()) {
						record.addProperty("status", "timeout");
					}
					else if (result.isCancelled()) {
						record.addProperty("status", "cancelled");
					}
					else if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
						record.addProperty("status", "error");
						record.addProperty("error",
							bounded(String.valueOf(result.getErrorMessage()), "max_error_bytes"));
					}
					else {
						String c = result.getDecompiledFunction().getC();
						byte[] bytes = c.getBytes(StandardCharsets.UTF_8);
						long limit = Math.min(limits.get("max_c_bytes_per_function").getAsLong(),
							limits.get("max_c_bytes_total").getAsLong() - retained);
						String kept = truncate(c, (int) Math.max(0, limit));
						retained += kept.getBytes(StandardCharsets.UTF_8).length;
						record.addProperty("status", "success");
						record.addProperty("c", kept);
						record.addProperty("c_bytes", bytes.length);
						record.addProperty("export_truncation", kept.length() < c.length());
					}
				}
				results.add(record);
			}
		}
		finally {
			decompiler.dispose();
		}
		timings.addProperty("decompile_set_ms", (System.nanoTime() - setStart) / 1e6);
		return results;
	}

	private String rva(Address address) {
		long canonical = Math.subtractExact(address.getOffset(), delta);
		long rva = Math.subtractExact(canonical, loadBase);
		if (rva < 0) {
			throw new IllegalStateException("Address precedes the load base: " + address);
		}
		return hex(rva);
	}

	private static String hex(long value) {
		return "0x" + Long.toHexString(value);
	}

	private String bounded(String text, String limit) {
		return truncate(text == null ? "" : text, limits.get(limit).getAsInt());
	}

	/** Truncates to at most `maxBytes` UTF-8 bytes on a code point boundary. */
	private static String truncate(String text, int maxBytes) {
		if (text.getBytes(StandardCharsets.UTF_8).length <= maxBytes) {
			return text;
		}
		int bytes = 0;
		int end = 0;
		while (end < text.length()) {
			int codePoint = text.codePointAt(end);
			int length = new String(Character.toChars(codePoint)).getBytes(StandardCharsets.UTF_8).length;
			if (bytes + length > maxBytes) {
				break;
			}
			bytes += length;
			end += Character.charCount(codePoint);
		}
		return text.substring(0, end);
	}

	/** Publishes a complete document; never replaces an existing export. */
	private void write(JsonObject export) throws IOException {
		Path output = Path.of(request.get("output").getAsString());
		if (Files.exists(output)) {
			throw new IOException("Export already exists: " + output);
		}
		Path temporary = Files.createTempFile(output.getParent(), "export-", ".tmp");
		try (Writer writer = Files.newBufferedWriter(temporary, StandardCharsets.UTF_8)) {
			new GsonBuilder().serializeNulls().setPrettyPrinting().create().toJson(export, writer);
		}
		Files.move(temporary, output, StandardCopyOption.ATOMIC_MOVE);
	}
}
