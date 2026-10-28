# Internal failure janitor. Only duplicated handles arrive on the private pipe;
# no incoming path, expression, or script is evaluated.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class UpdaterCleanup {
    [StructLayout(LayoutKind.Sequential)]
    public struct Disposition { public byte DeleteFile; }
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetFileInformationByHandle(IntPtr file, int kind, ref Disposition info, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr process, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);
}
'@
$plan = [Console]::In.ReadLine() | ConvertFrom-Json
$process = [IntPtr]([long]$plan.wait)
$files = @($plan.files | ForEach-Object { [IntPtr]([long]$_) })
try {
    [Console]::Out.WriteLine('"ready"')
    [Console]::Out.Flush()
    # Allow time for the user to dismiss the helper's error dialog. An
    # interrupted/hung helper never authorizes deletion of a running image.
    if ([UpdaterCleanup]::WaitForSingleObject($process, 300000) -eq 0) {
        for ($index = 0; $index -lt $files.Count; $index++) {
            $info = New-Object UpdaterCleanup+Disposition
            $info.DeleteFile = 1
            # Regular artifacts come first; the last handle is the staging
            # directory. Disposition refuses a nonempty directory: no recursion.
            [void][UpdaterCleanup]::SetFileInformationByHandle($files[$index], 4, [ref]$info, 1)
            [void][UpdaterCleanup]::CloseHandle($files[$index])
            $files[$index] = [IntPtr]::Zero
        }
    }
} finally {
    foreach ($file in $files) {
        if ($file -ne [IntPtr]::Zero) { [void][UpdaterCleanup]::CloseHandle($file) }
    }
    [void][UpdaterCleanup]::CloseHandle($process)
}
