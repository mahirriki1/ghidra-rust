# Native GUI + all workers of this exact executable. Inputs are never executed.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Executable,
    [Parameter(Mandatory=$true)][string]$InputBinary,
    [string]$OutputDirectory = 'target\analysis-baseline',
    [ValidateRange(1,3600)][int]$Seconds = 180,
    [ValidateRange(10,10000)][int]$SampleMilliseconds = 100,
    [switch]$Trace
)
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'Run on native Windows.' }
$executablePath = (Resolve-Path -LiteralPath $Executable).Path
$inputPath = (Resolve-Path -LiteralPath $InputBinary).Path
$processName = [IO.Path]::GetFileNameWithoutExtension($executablePath)
foreach ($existing in @(Get-Process -Name $processName -ErrorAction SilentlyContinue)) {
    if ($existing.Path -eq $executablePath) { throw 'Close other instances of this exact test executable before measuring.' }
}
$before = Get-FileHash -LiteralPath $inputPath -Algorithm SHA256
$inputItem = Get-Item -LiteralPath $inputPath
$run = Join-Path $OutputDirectory ('desktop-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $run | Out-Null
$run = (Resolve-Path -LiteralPath $run).Path
$previousTrace = $env:GHIDRA_RUST_PERF_DIR
$stream = $null
try {
    if ($Trace) { $env:GHIDRA_RUST_PERF_DIR = $run }
    else { Remove-Item Env:GHIDRA_RUST_PERF_DIR -ErrorAction SilentlyContinue }
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $gui = Start-Process -FilePath $executablePath -ArgumentList ('"' + $inputPath + '"') -PassThru
    $owned = @{}
    $owned[$gui.Id] = $gui.StartTime.ToUniversalTime().ToFileTimeUtc()
    $spawnMs = $clock.Elapsed.TotalMilliseconds
    Write-Host "GUI PID $($gui.Id); run $run"
    $stream = [IO.StreamWriter]::new((Join-Path $run 'memory.jsonl'), $false)
    $missed = 0
    $samples = 0
    $overheadMs = 0.0
    $maxGapMs = 0.0
    $previousMs = 0.0
    while ($clock.Elapsed.TotalSeconds -lt $Seconds) {
        $sampleStart = $clock.Elapsed.TotalMilliseconds
        $maxGapMs = [Math]::Max($maxGapMs, $sampleStart - $previousMs)
        $previousMs = $sampleStart
        $rows = @()
        $unrelated = $false
        foreach ($process in @(Get-Process -Name $processName -ErrorAction SilentlyContinue)) {
            try {
                if ($process.Path -ne $executablePath) { continue }
                $birth = $process.StartTime.ToUniversalTime().ToFileTimeUtc()
                if (!$owned.ContainsKey($process.Id) -or $owned[$process.Id] -ne $birth) {
                    $details = Get-CimInstance Win32_Process -Filter ("ProcessId=" + $process.Id)
                    if (!$details -or !$owned.ContainsKey([int]$details.ParentProcessId) -or
                        $birth -lt $owned[[int]$details.ParentProcessId]) {
                        $unrelated = $true
                        continue
                    }
                    $owned[$process.Id] = $birth
                }
                $process.Refresh()
                $rows += [ordered]@{ pid=$process.Id; birth=$birth; working_set_bytes=$process.WorkingSet64;
                    private_bytes=$process.PrivateMemorySize64; cpu_seconds=$process.TotalProcessorTime.TotalSeconds }
            } catch { $missed++ }
        }
        if ($unrelated) { throw 'Another unrelated instance appeared during measurement; reject this run.' }
        $workingSet = 0L
        $privateBytes = 0L
        foreach ($row in $rows) { $workingSet += $row.working_set_bytes; $privateBytes += $row.private_bytes }
        $record = [ordered]@{ elapsed_ms=$sampleStart; processes=$rows; sum_working_set_bytes=$workingSet;
            sum_private_bytes=$privateBytes; missed_process_reads=$missed }
        $stream.WriteLine(($record | ConvertTo-Json -Compress -Depth 5))
        $samples++
        $overheadMs += $clock.Elapsed.TotalMilliseconds - $sampleStart
        $gui.Refresh()
        if ($gui.HasExited -and $rows.Count -eq 0) { break }
        Start-Sleep -Milliseconds $SampleMilliseconds
    }
    $stream.Dispose()
    $stream = $null
    $after = Get-FileHash -LiteralPath $inputPath -Algorithm SHA256
    if ($before.Hash -ne $after.Hash) { throw 'Input hash changed during measurement.' }
    [ordered]@{
        executable=$executablePath; executable_sha256=(Get-FileHash -LiteralPath $executablePath -Algorithm SHA256).Hash;
        input=$inputPath; input_sha256=$before.Hash; input_bytes=$inputItem.Length;
        input_last_write_utc=$inputItem.LastWriteTimeUtc.ToString('o'); input_version=$inputItem.VersionInfo.FileVersion;
        gui_pid=$gui.Id; gui_spawn_ms=$spawnMs; trace_requested=[bool]$Trace;
        gui_exit_code=$(if ($gui.HasExited) { $gui.ExitCode } else { $null });
        os=[Environment]::OSVersion.VersionString; processor=$env:PROCESSOR_IDENTIFIER;
        logical_cpus=[Environment]::ProcessorCount; requested_sample_ms=$SampleMilliseconds;
        actual_max_sample_gap_ms=$maxGapMs; sampler_work_ms=$overheadMs; samples=$samples; missed_process_reads=$missed;
        duration_ms=$clock.Elapsed.TotalMilliseconds;
        limitations=@('Working sets can double-count shared pages; private bytes are committed private virtual memory, not resident memory.',
            'Process reads are sequential and can miss short-lived workers and peaks; PID/creation time and observed parentage identify owned processes.',
            'Sampler overhead and filesystem caches affect timing; fresh launches are not cold-cache measurements.',
            'The GUI remains open if the sampling duration expires. Interact with the owned app during sampling.',
            'Trace files are bounded asynchronous observations. Reject incomplete or dropped traces for phase attribution.')
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $run 'metadata.json') -Encoding UTF8
    Write-Host "Measurement saved: $run"
} finally {
    if ($stream) { $stream.Dispose() }
    $env:GHIDRA_RUST_PERF_DIR = $previousTrace
}
