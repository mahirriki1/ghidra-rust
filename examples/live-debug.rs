//! Inspect a trusted executable at one function breakpoint from the console.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use ghidra_rust::debugger::{Debugger, State};
    use ghidra_rust::headless::{Analyzer, Command, Input, Options, Output};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    let mut args = std::env::args_os().skip(1);
    let usage = "Usage: live-debug EXECUTABLE FUNCTION_OR_HEX_ADDRESS";
    let path = PathBuf::from(args.next().ok_or(usage)?);
    let location = args.next().ok_or(usage)?;
    let location = location
        .to_str()
        .ok_or("Function or address must be UTF-8")?;
    if args.next().is_some() {
        return Err(usage.into());
    }
    let mut analysis = Analyzer::open(
        Input::Binary(path.clone()),
        &std::env::current_exe()?,
        Options::default(),
    )?;
    let Output::Info { info, .. } = analysis.execute(Command::Info {})? else {
        unreachable!("decoded an info response")
    };
    let address = if let Some(hex) = location.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)?
    } else {
        let mut matches = info.functions.iter().filter(|f| f.name == location);
        let function = matches
            .next()
            .ok_or("Function is absent from the static inventory")?;
        if matches.next().is_some() {
            return Err("Function name is ambiguous. Supply a hexadecimal address.".into());
        }
        function.address
    };
    drop(analysis);
    let mut debugger = Debugger::launch(&path, &info, Path::new("/usr/bin/gdb"))?;
    debugger.insert_breakpoint(address)?;
    debugger.resume()?;
    let state = debugger.wait(Duration::from_secs(5))?;
    let State::Stopped(stop) = state else {
        return Err(format!("Target did not stop at the breakpoint: {state:?}").into());
    };
    if stop.reason != "breakpoint-hit" || stop.location.static_address != Some(address) {
        return Err(
            format!("Target stopped before reaching the requested breakpoint: {stop:?}").into(),
        );
    }
    let runtime = stop.location.runtime;
    println!(
        "Breakpoint at {runtime:#x} (static {address:#x}) on thread {}",
        stop.thread
    );
    for register in debugger.registers()? {
        println!("{:8} {:#018x}", register.name, register.value);
    }
    println!("Stack");
    for frame in debugger.stack()? {
        print!(
            "{:#018x}  {}",
            frame.location.runtime,
            frame.function.as_deref().unwrap_or("?")
        );
        if let Some(address) = frame.location.static_address {
            print!(" (static {address:#x})");
        }
        println!();
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() -> std::process::ExitCode {
    let result = if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == "--analysis-worker")
    {
        ghidra_rust::worker::run_worker().map_err(Into::into)
    } else {
        run()
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() -> std::process::ExitCode {
    eprintln!("The live debugger example requires Linux x86-64.");
    std::process::ExitCode::FAILURE
}
