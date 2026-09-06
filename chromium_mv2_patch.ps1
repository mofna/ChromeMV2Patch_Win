<#
.SYNOPSIS
Analyzes or patches a Windows x64 Chromium browser DLL to retain MV2 support.

.DESCRIPTION
With no arguments, displays the Windows GUI. With -Target, the script only
analyzes the target unless -Apply or -Output is specified. Use -Apply for an
in-place patch and extension backup, -RestoreExt with
a receipt to restore extension data and reopen Chrome Web Store pages,
-RestoreExtSettings to reopen protected per-extension settings,
-AutoPatch to register Google Updater history monitoring and an hourly fallback,
-RemoveAutoPatch to remove it, -RamLaunch to apply the verified patch only to a
new Chromium-browser process, or -Restore to restore a DLL backup.

.PARAMETER Target
Path to chrome.dll or the corresponding DLL from a Chromium-derived browser.

.PARAMETER Apply
Patch Target in place after creating a verified backup. When Target is omitted,
detect Google Chrome and use the latest complete versioned chrome.dll.

.PARAMETER Output
Write a patched copy instead of modifying Target.

.PARAMETER BackupRoot
Backup base directory. Defaults to chromium_mv2_backups beside this script.

.PARAMETER SignatureCatalog
Path to the signature profile catalog.

.PARAMETER AutoPatch
Register Google Updater history and Chrome DLL notification monitoring plus an
hourly fallback, then patch the latest writable Chrome version immediately.

.PARAMETER RemoveAutoPatch
Remove the registered automatic patch tasks.

.PARAMETER Restore
Restore an original DLL. When Receipt is omitted, use the newest completed
receipt under BackupRoot.

.PARAMETER RestoreExt
Restore backed-up extension settings and open each extension's Chrome Web Store
page for reinstallation. Chrome's protected preferences are never overwritten.

.PARAMETER RestoreExtSettings
After extensions are reinstalled, open their Chrome settings pages and report
the backed-up incognito and file-URL access values. Chrome must apply these
protected settings itself so that its preference MAC remains valid.

.PARAMETER Receipt
Path to receipt.json created by an in-place patch. Optional with Restore.

.PARAMETER BrowserRoot
Chrome Application directory used by auto-detected Apply, Restore, and automatic
patch modes. Detected when omitted.

.PARAMETER RamLaunch
Start the matching Chromium browser with the verified patch applied only to process
memory. The target DLL must be an unmodified supported build and the browser must
be closed.

.PARAMETER BrowserExecutable
Browser executable used by RamLaunch. When omitted, select the sole non-proxy EXE
beside the target version whose product name and version match the target DLL.

.PARAMETER BackupProfile
Before RamLaunch, back up browser profile settings, extension bodies, and related
extension storage below BackupRoot. Unknown browsers must specify --user-data-dir.

.PARAMETER ChromeArguments
Windows command-line text appended to the browser by RamLaunch. Whitespace
separates arguments; use Windows quoting for values that contain spaces. The
alias BrowserArguments is also accepted.

.EXAMPLE
.\chromium_mv2_patch.ps1 -Target 'C:\path\to\chrome.dll'

.EXAMPLE
.\chromium_mv2_patch.ps1 -Target 'C:\path\to\chrome.dll' -Apply

.EXAMPLE
.\chromium_mv2_patch.ps1 -Apply

.EXAMPLE
.\chromium_mv2_patch.ps1 -Target 'C:\path\to\chrome.dll' -Output '.\chrome.mv2-patched.dll'

.EXAMPLE
.\chromium_mv2_patch.ps1 -AutoPatch

.EXAMPLE
.\chromium_mv2_patch.ps1 -RemoveAutoPatch

.EXAMPLE
.\chromium_mv2_patch.ps1 -Restore

.EXAMPLE
.\chromium_mv2_patch.ps1 -Restore -Receipt '.\chromium_mv2_backups\...\receipt.json'

.EXAMPLE
.\chromium_mv2_patch.ps1 -RestoreExt -Receipt '.\chromium_mv2_backups\...\receipt.json'

.EXAMPLE
.\chromium_mv2_patch.ps1 -RestoreExtSettings -Receipt '.\chromium_mv2_backups\...\receipt.json'

.EXAMPLE
.\chromium_mv2_patch.ps1 -RamLaunch -BackupProfile

.EXAMPLE
.\chromium_mv2_patch.ps1 -RamLaunch `
    -ChromeArguments '--user-data-dir="C:\Chrome MV2 Profile" --no-first-run'

.EXAMPLE
.\chromium_mv2_patch.ps1 -RamLaunch `
    -Target 'C:\path\to\browser\1.2.3.4\chrome.dll' `
    -BrowserExecutable 'C:\path\to\browser\browser.exe' `
    -BrowserArguments '--user-data-dir="C:\Browser MV2 Profile"'
#>
[CmdletBinding()]
param(
    [string]$Target,

    [switch]$Apply,

    [string]$Output,

    [string]$BackupRoot,

    [string]$SignatureCatalog,

    [switch]$AutoPatch,

    [switch]$RemoveAutoPatch,

    [switch]$Restore,

    [switch]$RestoreExt,

    [switch]$RestoreExtSettings,

    [string]$Receipt,

    [string]$BrowserRoot,

    [switch]$RamLaunch,

    [string]$BrowserExecutable,

    [switch]$BackupProfile,

    [Alias('BrowserArguments')]
    [string]$ChromeArguments,

    [Parameter(DontShow = $true)]
    [string]$ChromeArgumentsBase64,

    [Parameter(DontShow = $true)]
    [switch]$HandleUpdateEvent,

    [Parameter(DontShow = $true)]
    [switch]$WatchUpdates,

    [Parameter(DontShow = $true)]
    [switch]$PatchLatestOnce,

    [Parameter(DontShow = $true)]
    [string]$UpdaterRoot,

    [Parameter(DontShow = $true)]
    [ValidateRange(1, 3600)]
    [int]$ReadinessTimeoutSeconds = 120,

    [Parameter(DontShow = $true)]
    [ValidateRange(1, 86400)]
    [int]$ReconcileIntervalSeconds = 3600,

    [Parameter(DontShow = $true)]
    [string]$AutoPatchLog,

    [Parameter(DontShow = $true)]
    [switch]$Gui
)

if (-not $PSBoundParameters.ContainsKey('BackupRoot')) {
    $BackupRoot = Join-Path $PSScriptRoot 'chromium_mv2_backups'
}
if (-not $PSBoundParameters.ContainsKey('SignatureCatalog')) {
    $SignatureCatalog = Join-Path $PSScriptRoot 'chromium_mv2_signatures.psd1'
}
if (-not $PSBoundParameters.ContainsKey('AutoPatchLog')) {
    $AutoPatchLog = Join-Path $PSScriptRoot 'chromium_mv2_autopatch.log'
}
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
if (-not [string]::IsNullOrWhiteSpace($ChromeArgumentsBase64)) {
    if (-not [string]::IsNullOrWhiteSpace($ChromeArguments)) {
        throw 'Specify browser arguments directly or through the GUI, not both.'
    }
    try {
        $ChromeArguments = [Text.Encoding]::UTF8.GetString(
            [Convert]::FromBase64String($ChromeArgumentsBase64))
    } catch {
        throw 'The encoded browser argument text is invalid.'
    }
}
$showGui = $Gui -or $PSBoundParameters.Count -eq 0
$modeCount = @($AutoPatch, $RemoveAutoPatch, $Restore, $RestoreExt, $RamLaunch,
    $RestoreExtSettings,
    $HandleUpdateEvent, $WatchUpdates, $PatchLatestOnce, $Gui |
    Where-Object { $_ }).Count
if ($modeCount -gt 1) {
    throw 'Specify only one public mode or one internal automatic-patch mode.'
}
if ($modeCount -gt 0 -and ($Apply -or $Output -or ($Target -and -not $RamLaunch))) {
    throw 'Explicit modes cannot be combined with -Target, -Apply, or -Output, except that -RamLaunch accepts -Target.'
}
if ($BackupProfile -and -not $RamLaunch) {
    throw '-BackupProfile is valid only with -RamLaunch.'
}
if (-not [string]::IsNullOrWhiteSpace($BrowserExecutable) -and -not $RamLaunch) {
    throw '-BrowserExecutable is valid only with -RamLaunch.'
}
if (-not [string]::IsNullOrWhiteSpace($ChromeArguments) -and -not $RamLaunch) {
    throw '-ChromeArguments is valid only with -RamLaunch.'
}
if ($null -ne $ChromeArguments -and $ChromeArguments.IndexOf([char]0) -ge 0) {
    throw 'Browser arguments must not contain NUL characters.'
}
if (-not $showGui -and $modeCount -eq 0 -and
    [string]::IsNullOrWhiteSpace($Target) -and -not $Apply) {
    throw 'Specify -Target or an explicit mode. Use -? to display CLI help.'
}
if ($Apply -and $Output) {
    throw '-Apply and -Output cannot be used together.'
}
if (($RestoreExt -or $RestoreExtSettings) -and
    [string]::IsNullOrWhiteSpace($Receipt)) {
    throw '-RestoreExt and -RestoreExtSettings require -Receipt.'
}

Add-Type -TypeDefinition @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public static class BinaryPatternScanner {
    public static List<long> Find(byte[] data, int[] pattern, long start, long length) {
        var result = new List<long>();
        if (pattern == null || pattern.Length == 0 || length < pattern.Length)
            return result;

        long end = Math.Min((long)data.Length, start + length) - pattern.Length;
        int anchor = 0;
        while (anchor < pattern.Length && pattern[anchor] < 0)
            anchor++;
        if (anchor == pattern.Length)
            throw new ArgumentException("A pattern cannot consist entirely of wildcards.");

        byte anchorByte = (byte)pattern[anchor];
        for (long pos = start; pos <= end; pos++) {
            if (data[pos + anchor] != anchorByte)
                continue;
            bool matched = true;
            for (int i = 0; i < pattern.Length; i++) {
                if (pattern[i] >= 0 && data[pos + i] != (byte)pattern[i]) {
                    matched = false;
                    break;
                }
            }
            if (matched)
                result.Add(pos);
        }
        return result;
    }

    public static List<long> FindMasked(
        byte[] data, byte[] values, byte[] masks, long start, long length) {
        var result = new List<long>();
        if (values == null || masks == null || values.Length == 0 ||
            values.Length != masks.Length || length < values.Length)
            return result;

        var anchor = 0;
        while (anchor < masks.Length && masks[anchor] == 0)
            anchor++;
        if (anchor == masks.Length)
            throw new ArgumentException("A masked pattern cannot be entirely unconstrained.");

        long end = Math.Min((long)data.Length, start + length) - values.Length;
        for (long pos = start; pos <= end; pos++) {
            if ((data[pos + anchor] & masks[anchor]) != values[anchor])
                continue;
            var matched = true;
            for (var i = 0; i < values.Length; i++) {
                if ((data[pos + i] & masks[i]) != values[i]) {
                    matched = false;
                    break;
                }
            }
            if (matched)
                result.Add(pos);
        }
        return result;
    }
}

public sealed class RamPatchResult {
    public int ProcessId { get; set; }
    public string ModulePath { get; set; }
    public int PatchCount { get; set; }
}

public static class RamPatchLauncher {
    private const uint DebugOnlyThisProcess = 0x00000002;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint ExceptionDebugEvent = 1;
    private const uint CreateProcessDebugEvent = 3;
    private const uint ExitProcessDebugEvent = 5;
    private const uint LoadDllDebugEvent = 6;
    private const uint DbgContinue = 0x00010002;
    private const uint DbgExceptionNotHandled = 0x80010001;
    private const uint ExceptionBreakpoint = 0x80000003;
    private const uint PageExecuteReadWrite = 0x40;
    private const int ErrorSemTimeout = 121;
    private const int DebugEventSizeX64 = 176;
    private const int DebugInfoOffsetX64 = 16;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessW(
        string applicationName, StringBuilder commandLine, IntPtr processAttributes,
        IntPtr threadAttributes, bool inheritHandles, uint creationFlags,
        IntPtr environment, string currentDirectory, ref StartupInfo startupInfo,
        out ProcessInformation processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WaitForDebugEventEx(IntPtr debugEvent, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ContinueDebugEvent(int processId, int threadId, uint continueStatus);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DebugSetProcessKillOnExit(bool killOnExit);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DebugActiveProcessStop(int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(
        IntPtr process, IntPtr address, [Out] byte[] buffer, UIntPtr size,
        out UIntPtr bytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(
        IntPtr process, IntPtr address, byte[] buffer, UIntPtr size,
        out UIntPtr bytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtectEx(
        IntPtr process, IntPtr address, UIntPtr size, uint newProtection,
        out uint oldProtection);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FlushInstructionCache(
        IntPtr process, IntPtr address, UIntPtr size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        IntPtr file, StringBuilder path, uint characterCount, uint flags);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CommandLineToArgvW(string commandLine, out int argumentCount);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    public static string[] ParseArguments(string commandLine) {
        if (String.IsNullOrWhiteSpace(commandLine))
            return new string[0];
        if (commandLine.IndexOf('\0') >= 0)
            throw new ArgumentException("Browser arguments must not contain NUL characters.");

        int argumentCount;
        var pointer = CommandLineToArgvW(Quote("chrome.exe") + " " + commandLine,
            out argumentCount);
        if (pointer == IntPtr.Zero)
            throw Error("Could not parse the browser command line");
        try {
            var arguments = new string[Math.Max(0, argumentCount - 1)];
            for (var i = 1; i < argumentCount; i++) {
                var argument = Marshal.ReadIntPtr(pointer, i * IntPtr.Size);
                arguments[i - 1] = Marshal.PtrToStringUni(argument);
            }
            return arguments;
        } finally {
            LocalFree(pointer);
        }
    }

    public static RamPatchResult Launch(
        string chromePath, string dllPath, long[] patchRvas,
        byte[][] expectedBytes, byte[][] replacementBytes,
        string chromeArguments, int timeoutSeconds) {
        if (IntPtr.Size != 8)
            throw new PlatformNotSupportedException("RAM launch supports only x64 Windows.");
        if (patchRvas == null || expectedBytes == null || replacementBytes == null ||
            patchRvas.Length == 0 || patchRvas.Length != expectedBytes.Length ||
            patchRvas.Length != replacementBytes.Length)
            throw new ArgumentException("The RAM patch plan is empty or inconsistent.");

        var startup = new StartupInfo();
        startup.cb = Marshal.SizeOf(typeof(StartupInfo));
        ProcessInformation process;
        var commandLine = new StringBuilder(Quote(chromePath));
        if (chromeArguments != null && chromeArguments.IndexOf('\0') >= 0)
            throw new ArgumentException("Browser arguments must not contain NUL characters.");
        if (!String.IsNullOrWhiteSpace(chromeArguments))
            commandLine.Append(' ').Append(chromeArguments);
        if (!CreateProcessW(chromePath, commandLine, IntPtr.Zero, IntPtr.Zero, false,
            DebugOnlyThisProcess | CreateUnicodeEnvironment, IntPtr.Zero,
            Path.GetDirectoryName(chromePath), ref startup, out process))
            throw Error("Could not start the Chromium browser for RAM patching");

        var detached = false;
        var debugEvent = Marshal.AllocHGlobal(DebugEventSizeX64);
        try {
            if (!DebugSetProcessKillOnExit(false))
                throw Error("Could not configure the browser debug session");
            var timer = Stopwatch.StartNew();
            while (timer.Elapsed < TimeSpan.FromSeconds(timeoutSeconds)) {
                ZeroMemory(debugEvent, DebugEventSizeX64);
                if (!WaitForDebugEventEx(debugEvent, 500)) {
                    var error = Marshal.GetLastWin32Error();
                    if (error == ErrorSemTimeout)
                        continue;
                    throw new Win32Exception(error, "WaitForDebugEventEx failed");
                }

                var eventCode = unchecked((uint)Marshal.ReadInt32(debugEvent, 0));
                var eventProcessId = Marshal.ReadInt32(debugEvent, 4);
                var eventThreadId = Marshal.ReadInt32(debugEvent, 8);
                var continueStatus = DbgContinue;
                if (eventCode == ExceptionDebugEvent &&
                    unchecked((uint)Marshal.ReadInt32(debugEvent, DebugInfoOffsetX64)) != ExceptionBreakpoint)
                    continueStatus = DbgExceptionNotHandled;

                IntPtr eventFile = IntPtr.Zero;
                RamPatchResult result = null;
                try {
                    if (eventCode == CreateProcessDebugEvent || eventCode == LoadDllDebugEvent)
                        eventFile = Marshal.ReadIntPtr(debugEvent, DebugInfoOffsetX64);
                    if (eventCode == LoadDllDebugEvent) {
                        var modulePath = GetPath(eventFile);
                        if (modulePath != null && PathsEqual(modulePath, dllPath)) {
                            var moduleBase = Marshal.ReadIntPtr(debugEvent, DebugInfoOffsetX64 + IntPtr.Size);
                            Patch(process.hProcess, moduleBase, patchRvas, expectedBytes, replacementBytes);
                            result = new RamPatchResult {
                                ProcessId = process.dwProcessId,
                                ModulePath = modulePath,
                                PatchCount = patchRvas.Length
                            };
                        }
                    } else if (eventCode == ExitProcessDebugEvent) {
                        throw new InvalidOperationException("The browser exited before the target DLL could be RAM-patched.");
                    }
                } finally {
                    if (eventFile != IntPtr.Zero && eventFile != new IntPtr(-1))
                        CloseHandle(eventFile);
                    if (!ContinueDebugEvent(eventProcessId, eventThreadId, continueStatus))
                        throw Error("ContinueDebugEvent failed");
                }

                if (result != null) {
                    if (!DebugActiveProcessStop(process.dwProcessId))
                        throw Error("Could not detach the RAM patcher from the browser");
                    detached = true;
                    return result;
                }
            }
            throw new TimeoutException("Timed out waiting for the browser to load the target DLL.");
        } catch {
            if (!detached)
                TerminateProcess(process.hProcess, 0x4D5632);
            throw;
        } finally {
            Marshal.FreeHGlobal(debugEvent);
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
        }
    }

    private static void Patch(IntPtr process, IntPtr moduleBase, long[] rvas,
        byte[][] expected, byte[][] replacements) {
        var addresses = new IntPtr[rvas.Length];
        for (var i = 0; i < rvas.Length; i++) {
            if (expected[i] == null || replacements[i] == null ||
                expected[i].Length == 0 || expected[i].Length != replacements[i].Length)
                throw new ArgumentException("A RAM patch edit has invalid byte lengths.");
            addresses[i] = new IntPtr(checked(moduleBase.ToInt64() + rvas[i]));
            var observed = Read(process, addresses[i], expected[i].Length);
            if (!StructuralComparisons.StructuralEqualityComparer.Equals(observed, expected[i]))
                throw new InvalidOperationException("Browser memory did not match the verified on-disk patch plan.");
        }

        for (var i = 0; i < addresses.Length; i++) {
            for (var j = 0; j < replacements[i].Length; j++) {
                if (expected[i][j] == replacements[i][j])
                    continue;
                var address = new IntPtr(checked(addresses[i].ToInt64() + j));
                var replacement = new byte[] { replacements[i][j] };
                var size = new UIntPtr(1);
                uint oldProtection;
                if (!VirtualProtectEx(process, address, size, PageExecuteReadWrite, out oldProtection))
                    throw Error("VirtualProtectEx failed at an MV2 target");
                try {
                    UIntPtr written;
                    if (!WriteProcessMemory(process, address, replacement, size, out written) ||
                        written.ToUInt64() != 1)
                        throw Error("WriteProcessMemory failed at an MV2 target");
                    var verified = Read(process, address, 1);
                    if (verified[0] != replacement[0])
                        throw new InvalidOperationException("RAM patch read-back verification failed.");
                    if (!FlushInstructionCache(process, address, size))
                        throw Error("FlushInstructionCache failed");
                } finally {
                    uint ignored;
                    VirtualProtectEx(process, address, size, oldProtection, out ignored);
                }
            }
        }
    }

    private static byte[] Read(IntPtr process, IntPtr address, int count) {
        var bytes = new byte[count];
        UIntPtr read;
        if (!ReadProcessMemory(process, address, bytes, new UIntPtr(unchecked((uint)count)), out read) ||
            read.ToUInt64() != unchecked((ulong)count))
            throw Error("ReadProcessMemory failed at an MV2 target");
        return bytes;
    }

    private static string GetPath(IntPtr file) {
        if (file == IntPtr.Zero || file == new IntPtr(-1))
            return null;
        var path = new StringBuilder(1024);
        var length = GetFinalPathNameByHandleW(file, path, unchecked((uint)path.Capacity), 0);
        if (length == 0)
            return null;
        if (length >= path.Capacity) {
            path.EnsureCapacity(checked((int)length + 1));
            length = GetFinalPathNameByHandleW(file, path, unchecked((uint)path.Capacity), 0);
            if (length == 0)
                return null;
        }
        return Normalize(path.ToString());
    }

    private static bool PathsEqual(string left, string right) {
        return string.Equals(Normalize(left), Normalize(right), StringComparison.OrdinalIgnoreCase);
    }

    private static string Normalize(string path) {
        const string prefix = "\\\\?\\";
        if (path.StartsWith(prefix, StringComparison.Ordinal))
            path = path.Substring(prefix.Length);
        return Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar);
    }

    private static string Quote(string value) {
        var result = new StringBuilder("\"");
        var backslashes = 0;
        foreach (var character in value) {
            if (character == '\\') {
                backslashes++;
            } else if (character == '"') {
                result.Append('\\', backslashes * 2 + 1).Append('"');
                backslashes = 0;
            } else {
                result.Append('\\', backslashes).Append(character);
                backslashes = 0;
            }
        }
        result.Append('\\', backslashes * 2).Append('"');
        return result.ToString();
    }

    private static void ZeroMemory(IntPtr address, int count) {
        for (var i = 0; i < count; i++)
            Marshal.WriteByte(address, i, 0);
    }

    private static Win32Exception Error(string message) {
        return new Win32Exception(Marshal.GetLastWin32Error(), message);
    }
}
'@

function ConvertTo-Pattern {
    param([Parameter(Mandatory = $true)][string]$Text)

    $tokens = @($Text.Trim() -split '\s+' | Where-Object { $_ })
    $result = New-Object 'int[]' $tokens.Count
    for ($i = 0; $i -lt $tokens.Count; $i++) {
        if ($tokens[$i] -eq '??') {
            $result[$i] = -1
        } else {
            $result[$i] = [Convert]::ToInt32($tokens[$i], 16)
        }
    }
    return ,$result
}

function ConvertTo-ConcreteBytes {
    param([Parameter(Mandatory = $true)][string]$Text)

    $pattern = ConvertTo-Pattern $Text
    if (@($pattern | Where-Object { $_ -lt 0 }).Count -gt 0) {
        throw "RAM patch bytes must not contain wildcards: $Text"
    }
    return ,([byte[]]$pattern)
}

function Test-BytesAt {
    param(
        [byte[]]$Bytes,
        [long]$Offset,
        [int[]]$Pattern
    )

    if ($Offset -lt 0 -or ($Offset + $Pattern.Length) -gt $Bytes.LongLength) {
        return $false
    }
    for ($i = 0; $i -lt $Pattern.Length; $i++) {
        if ($Pattern[$i] -ge 0 -and $Bytes[$Offset + $i] -ne $Pattern[$i]) {
            return $false
        }
    }
    return $true
}

function Get-HexBytes {
    param([byte[]]$Bytes)
    return (($Bytes | ForEach-Object { $_.ToString('X2') }) -join ' ')
}

function Get-PeInfo {
    param([byte[]]$Bytes)

    if ($Bytes.Length -lt 0x100 -or $Bytes[0] -ne 0x4D -or $Bytes[1] -ne 0x5A) {
        throw 'Target is not a valid PE file (missing MZ header).'
    }
    $peOffset = [BitConverter]::ToInt32($Bytes, 0x3C)
    if ($peOffset -lt 0 -or ($peOffset + 24) -gt $Bytes.Length -or
        $Bytes[$peOffset] -ne 0x50 -or $Bytes[$peOffset + 1] -ne 0x45 -or
        $Bytes[$peOffset + 2] -ne 0 -or $Bytes[$peOffset + 3] -ne 0) {
        throw 'Target is not a valid PE file (missing PE header).'
    }

    $machine = [BitConverter]::ToUInt16($Bytes, $peOffset + 4)
    $sectionCount = [BitConverter]::ToUInt16($Bytes, $peOffset + 6)
    $optionalSize = [BitConverter]::ToUInt16($Bytes, $peOffset + 20)
    $sectionTable = $peOffset + 24 + $optionalSize
    $ranges = @()
    for ($i = 0; $i -lt $sectionCount; $i++) {
        $entry = $sectionTable + (40 * $i)
        if (($entry + 40) -gt $Bytes.Length) {
            throw 'PE section table is truncated.'
        }
        $virtualAddress = [BitConverter]::ToUInt32($Bytes, $entry + 12)
        $rawSize = [BitConverter]::ToUInt32($Bytes, $entry + 16)
        $rawOffset = [BitConverter]::ToUInt32($Bytes, $entry + 20)
        $characteristics = [BitConverter]::ToUInt32($Bytes, $entry + 36)
        if (($characteristics -band 0x20000000) -ne 0 -and $rawSize -gt 0 -and
            ([long]$rawOffset + $rawSize) -le $Bytes.LongLength) {
            $ranges += [pscustomobject]@{
                Start = [long]$rawOffset
                Length = [long]$rawSize
                VirtualAddress = [long]$virtualAddress
            }
        }
    }
    if ($ranges.Count -eq 0) {
        throw 'PE file has no executable sections.'
    }
    return [pscustomobject]@{ Machine = [int]$machine; ExecutableRanges = $ranges }
}

function ConvertTo-PeRva {
    param(
        $PeInfo,
        [long]$FileOffset,
        [int]$Length
    )

    $ranges = @($PeInfo.ExecutableRanges | Where-Object {
        $FileOffset -ge $_.Start -and
        ($FileOffset + $Length) -le ($_.Start + $_.Length)
    })
    if ($ranges.Count -ne 1) {
        throw "Patch offset 0x$($FileOffset.ToString('X')) is not in exactly one executable PE section."
    }
    return [long]$ranges[0].VirtualAddress + $FileOffset - $ranges[0].Start
}

function Read-StreamRange {
    param(
        [IO.FileStream]$Stream,
        [long]$Offset,
        [int]$Count
    )

    if ($Offset -lt 0 -or $Count -lt 0 -or ($Offset + $Count) -gt $Stream.Length) {
        return $null
    }
    $result = New-Object 'byte[]' $Count
    $Stream.Position = $Offset
    $read = 0
    while ($read -lt $Count) {
        $countRead = $Stream.Read($result, $read, $Count - $read)
        if ($countRead -le 0) { return $null }
        $read += $countRead
    }
    return ,$result
}

function Get-PeStreamInfo {
    param([IO.FileStream]$Stream)

    $dos = Read-StreamRange $Stream 0 64
    if (-not $dos -or $dos[0] -ne 0x4D -or $dos[1] -ne 0x5A) {
        throw 'Target is not a valid PE file (missing MZ header).'
    }
    $peOffset = [BitConverter]::ToInt32($dos, 0x3C)
    $coff = Read-StreamRange $Stream $peOffset 24
    if (-not $coff -or $coff[0] -ne 0x50 -or $coff[1] -ne 0x45 -or
        $coff[2] -ne 0 -or $coff[3] -ne 0) {
        throw 'Target is not a valid PE file (missing PE header).'
    }

    $machine = [BitConverter]::ToUInt16($coff, 4)
    $sectionCount = [BitConverter]::ToUInt16($coff, 6)
    $optionalSize = [BitConverter]::ToUInt16($coff, 20)
    if ($sectionCount -eq 0 -or $sectionCount -gt 96) {
        throw 'PE section count is invalid.'
    }
    $sectionBytes = Read-StreamRange $Stream `
        ([long]$peOffset + 24 + $optionalSize) (40 * $sectionCount)
    if (-not $sectionBytes) { throw 'PE section table is truncated.' }

    $ranges = @()
    for ($i = 0; $i -lt $sectionCount; $i++) {
        $entry = 40 * $i
        $rawSize = [BitConverter]::ToUInt32($sectionBytes, $entry + 16)
        $rawOffset = [BitConverter]::ToUInt32($sectionBytes, $entry + 20)
        $characteristics = [BitConverter]::ToUInt32($sectionBytes, $entry + 36)
        if (($characteristics -band 0x20000000) -ne 0 -and $rawSize -gt 0 -and
            ([long]$rawOffset + $rawSize) -le $Stream.Length) {
            $ranges += [pscustomobject]@{ Start = [long]$rawOffset; Length = [long]$rawSize }
        }
    }
    if ($ranges.Count -eq 0) { throw 'PE file has no executable sections.' }
    return [pscustomobject]@{ Machine = [int]$machine; ExecutableRanges = $ranges }
}

function Test-PatternCompatibility {
    param(
        [int[]]$Concrete,
        [int[]]$Pattern
    )

    if ($Concrete.Length -ne $Pattern.Length -or
        @($Concrete | Where-Object { $_ -lt 0 }).Count -gt 0) {
        return $false
    }
    for ($i = 0; $i -lt $Pattern.Length; $i++) {
        if ($Pattern[$i] -ge 0 -and $Concrete[$i] -ne $Pattern[$i]) {
            return $false
        }
    }
    return $true
}

function Test-StreamPattern {
    param(
        [IO.FileStream]$Stream,
        [long]$Offset,
        [int[]]$Pattern
    )

    $bytes = Read-StreamRange $Stream $Offset $Pattern.Length
    return ($null -ne $bytes -and (Test-BytesAt $bytes 0 $Pattern))
}

function Test-StreamMaskedPattern {
    param(
        [IO.FileStream]$Stream,
        [long]$Offset,
        $Pattern
    )

    $bytes = Read-StreamRange $Stream $Offset $Pattern.Length
    return ($null -ne $bytes -and (Test-MaskedBytesAt $bytes 0 $Pattern))
}

function Test-ConcreteMaskedPattern {
    param(
        [int[]]$Concrete,
        $Pattern
    )

    if ($Concrete.Length -ne $Pattern.Length -or
        @($Concrete | Where-Object { $_ -lt 0 }).Count -gt 0) {
        return $false
    }
    for ($i = 0; $i -lt $Pattern.Length; $i++) {
        if (($Concrete[$i] -band $Pattern.Masks[$i]) -ne $Pattern.Values[$i]) {
            return $false
        }
    }
    return $true
}

function Test-ExecutableRange {
    param(
        $PeInfo,
        [long]$Offset,
        [int]$Length
    )

    return @($PeInfo.ExecutableRanges | Where-Object {
        $Offset -ge $_.Start -and
        ($Offset + $Length) -le ($_.Start + $_.Length)
    }).Count -eq 1
}

function ConvertTo-MaskedPattern {
    param([Parameter(Mandatory = $true)][string]$Text)

    $tokens = @($Text.Trim() -split '\s+' | Where-Object { $_ })
    $values = New-Object 'byte[]' $tokens.Count
    $masks = New-Object 'byte[]' $tokens.Count
    for ($i = 0; $i -lt $tokens.Count; $i++) {
        if ($tokens[$i] -eq '??') { continue }
        if ($tokens[$i] -notmatch '^([0-9A-Fa-f]{2})(?:/([0-9A-Fa-f]{2}))?$') {
            throw "Invalid masked-pattern token: $($tokens[$i])"
        }
        $mask = if ($Matches[2]) {
            [Convert]::ToByte($Matches[2], 16)
        } else { [byte]0xFF }
        $masks[$i] = $mask
        $values[$i] = [Convert]::ToByte($Matches[1], 16) -band $mask
    }
    return [pscustomobject]@{
        Values = $values
        Masks = $masks
        Length = $values.Length
    }
}

function Test-MaskedBytesAt {
    param(
        [byte[]]$Bytes,
        [long]$Offset,
        $Pattern
    )

    if ($Offset -lt 0 -or ($Offset + $Pattern.Length) -gt $Bytes.LongLength) {
        return $false
    }
    for ($i = 0; $i -lt $Pattern.Length; $i++) {
        if (($Bytes[$Offset + $i] -band $Pattern.Masks[$i]) -ne
            $Pattern.Values[$i]) {
            return $false
        }
    }
    return $true
}

function Get-VariantPatchPatterns {
    param($Rule, $Variant)

    $originalText = if ($Variant.ContainsKey('Original')) {
        $Variant.Original
    } else { $Rule.Original }
    $replacementText = if ($Variant.ContainsKey('Replacement')) {
        $Variant.Replacement
    } else { $Rule.Replacement }
    $original = ConvertTo-MaskedPattern $originalText
    $replacement = ConvertTo-MaskedPattern $replacementText
    if ($original.Length -ne $replacement.Length -or
        @($replacement.Masks | Where-Object { $_ -ne 0xFF }).Count -gt 0) {
        throw "Rule '$($Rule.Name)' must have an equal-length concrete replacement."
    }
    return [pscustomobject]@{
        Original = $original
        Replacement = $replacement
    }
}

function Get-MaskedRuleResult {
    param(
        [byte[]]$Bytes,
        $Rule,
        $PeInfo
    )

    $classified = @()
    $seen = @{}
    $variantIndex = 0
    foreach ($variant in @($Rule.Variants)) {
        $patch = Get-VariantPatchPatterns $Rule $variant
        $original = $patch.Original
        $replacement = $patch.Replacement
        $pattern = ConvertTo-MaskedPattern $variant.Pattern
        $patchOffset = [int]$variant.PatchOffset
        if (($patchOffset + $original.Length) -gt $pattern.Length) {
            throw "Rule '$($Rule.Name)' patch range is outside variant $variantIndex."
        }
        $contextValues = New-Object 'byte[]' $pattern.Length
        $contextMasks = New-Object 'byte[]' $pattern.Length
        [Array]::Copy($pattern.Values, $contextValues, $pattern.Length)
        [Array]::Copy($pattern.Masks, $contextMasks, $pattern.Length)
        for ($i = 0; $i -lt $original.Length; $i++) {
            $contextMasks[$patchOffset + $i] = 0
            $contextValues[$patchOffset + $i] = 0
        }

        foreach ($range in $PeInfo.ExecutableRanges) {
            foreach ($match in [BinaryPatternScanner]::FindMasked(
                $Bytes, $contextValues, $contextMasks,
                $range.Start, $range.Length)) {
                $valid = $true
                if ($variant.ContainsKey('RequiredPattern')) {
                    $required = ConvertTo-MaskedPattern $variant.RequiredPattern
                    $valid = Test-MaskedBytesAt $Bytes `
                        ($match + [long]$variant.RequiredPatternOffset) $required
                }
                if ($valid -and $variant.ContainsKey('EqualBytes')) {
                    foreach ($pair in @($variant.EqualBytes)) {
                        $offsets = @([string]$pair -split ':')
                        if ($offsets.Count -ne 2 -or
                            $Bytes[$match + [int]$offsets[0]] -ne
                            $Bytes[$match + [int]$offsets[1]]) {
                            $valid = $false
                            break
                        }
                    }
                }
                if (-not $valid) { continue }

                $patchAt = $match + $patchOffset
                $key = $patchAt.ToString('X')
                if ($seen.ContainsKey($key)) { continue }
                $state = 'Unknown'
                if (Test-MaskedBytesAt $Bytes $patchAt $original) {
                    $state = 'Original'
                } elseif (Test-MaskedBytesAt $Bytes $patchAt $replacement) {
                    $state = 'Patched'
                }
                $classified += [pscustomobject]@{
                    MatchOffset = $match
                    PatchOffset = $patchAt
                    State = $state
                    Variant = $variantIndex
                    OriginalPattern = $original.Values
                    ReplacementPattern = $replacement.Values
                }
                $seen[$key] = $true
            }
        }
        $variantIndex++
    }

    return [pscustomobject]@{
        Name = $Rule.Name
        Description = $Rule.Description
        MatchCount = $classified.Count
        Candidates = $classified
        Rule = $Rule
    }
}

function Get-RuleResult {
    param(
        [byte[]]$Bytes,
        $Rule,
        $PeInfo
    )

    if ($Rule.ContainsKey('Variants')) {
        return Get-MaskedRuleResult $Bytes $Rule $PeInfo
    }

    $pattern = ConvertTo-Pattern $Rule.Pattern
    $original = ConvertTo-Pattern $Rule.Original
    $replacement = ConvertTo-Pattern $Rule.Replacement
    if ($original.Length -ne $replacement.Length) {
        throw "Rule '$($Rule.Name)' changes the instruction length."
    }
    if (($Rule.PatchOffset + $original.Length) -gt $pattern.Length) {
        throw "Rule '$($Rule.Name)' patch range is outside its signature."
    }

    $context = New-Object 'int[]' $pattern.Length
    [Array]::Copy($pattern, $context, $pattern.Length)
    for ($i = 0; $i -lt $original.Length; $i++) {
        $context[$Rule.PatchOffset + $i] = -1
    }

    $matches = New-Object System.Collections.Generic.List[long]
    foreach ($range in $PeInfo.ExecutableRanges) {
        foreach ($match in [BinaryPatternScanner]::Find(
            $Bytes, $context, $range.Start, $range.Length)) {
            $matches.Add($match)
        }
    }

    $classified = @()
    foreach ($match in $matches) {
        if ($Rule.ContainsKey('RequiredPattern')) {
            $required = ConvertTo-Pattern $Rule.RequiredPattern
            if (-not (Test-BytesAt $Bytes `
                ($match + [long]$Rule.RequiredPatternOffset) $required)) {
                continue
            }
        }
        $patchAt = $match + [long]$Rule.PatchOffset
        $state = 'Unknown'
        if (Test-BytesAt $Bytes $patchAt $original) {
            $state = 'Original'
        } elseif (Test-BytesAt $Bytes $patchAt $replacement) {
            $state = 'Patched'
        } elseif ($Rule.ContainsKey('AcceptedReplacements')) {
            foreach ($acceptedText in $Rule.AcceptedReplacements) {
                $accepted = ConvertTo-Pattern $acceptedText
                if ($accepted.Length -eq $replacement.Length -and
                    (Test-BytesAt $Bytes $patchAt $accepted)) {
                    $state = 'PatchedLegacy'
                    break
                }
            }
        }
        $classified += [pscustomobject]@{
            MatchOffset = $match
            PatchOffset = $patchAt
            State = $state
        }
    }

    return [pscustomobject]@{
        Name = $Rule.Name
        Description = $Rule.Description
        MatchCount = $classified.Count
        Candidates = $classified
        Rule = $Rule
        OriginalPattern = $original
        ReplacementPattern = $replacement
    }
}

function Get-ExpectedMatchCount {
    param($Rule)
    if ($Rule.ContainsKey('ExpectedMatches')) {
        return [int]$Rule.ExpectedMatches
    }
    return 1
}

function Get-RuleState {
    param($RuleResult)

    if ($RuleResult.MatchCount -ne (Get-ExpectedMatchCount $RuleResult.Rule)) {
        return 'Invalid'
    }
    $states = @($RuleResult.Candidates.State | Select-Object -Unique)
    if ($states.Count -ne 1 -or $states[0] -eq 'Unknown') {
        return 'Invalid'
    }
    return $states[0]
}

function Get-ByteArraySha256 {
    param([byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '')
    } finally {
        $sha.Dispose()
    }
}

function Read-ExclusiveStreamBytes {
    param([IO.FileStream]$Stream)
    if ($Stream.Length -gt [int]::MaxValue) {
        throw 'DLL is too large for this patcher.'
    }
    $result = New-Object 'byte[]' ([int]$Stream.Length)
    $Stream.Position = 0
    $read = 0
    while ($read -lt $result.Length) {
        $count = $Stream.Read($result, $read, $result.Length - $read)
        if ($count -le 0) {
            throw 'Unexpected end of file while reading the locked DLL.'
        }
        $read += $count
    }
    return ,$result
}

function Get-ProfileResult {
    param(
        [byte[]]$Bytes,
        $Profile,
        $PeInfo
    )

    $results = @()
    foreach ($rule in $Profile.Rules) {
        $results += Get-RuleResult $Bytes $rule $PeInfo
    }
    return [pscustomobject]@{
        Profile = $Profile
        Rules = $results
        IsValid = @($results | Where-Object {
            (Get-RuleState $_) -ne 'Invalid'
        }).Count -eq $results.Count
    }
}

function Resolve-TargetAnalysis {
    param(
        [string]$Path,
        [byte[]]$Bytes,
        [string]$CatalogPath
    )

    $catalog = Import-PowerShellDataFile -LiteralPath $CatalogPath
    if ($catalog.SchemaVersion -ne 1) {
        throw "Unsupported signature catalog schema: $($catalog.SchemaVersion)"
    }
    $peInfo = Get-PeInfo $Bytes
    $profiles = @($catalog.Profiles | Where-Object {
        [int]$_.Machine -eq $peInfo.Machine
    })
    $profileResults = @($profiles | ForEach-Object {
        Get-ProfileResult $Bytes $_ $peInfo
    })
    $validProfiles = @($profileResults | Where-Object IsValid)
    if ($validProfiles.Count -ne 1) {
        $details = foreach ($profileResult in $profileResults) {
            foreach ($ruleResult in $profileResult.Rules) {
                if ((Get-RuleState $ruleResult) -eq 'Invalid') {
                    '{0}/{1}: matches={2}/{3}, states={4}' -f
                        $profileResult.Profile.Id, $ruleResult.Name,
                        $ruleResult.MatchCount, (Get-ExpectedMatchCount $ruleResult.Rule),
                        (($ruleResult.Candidates | ForEach-Object { $_.State }) -join ',')
                }
            }
        }
        throw "No unique supported signature profile matched. The target was not modified.`n$($details -join "`n")"
    }

    $selected = $validProfiles[0]
    $states = @($selected.Rules | ForEach-Object { Get-RuleState $_ })
    $allOriginal = @($states | Where-Object { $_ -eq 'Original' }).Count -eq $states.Count
    $allPatched = @($states | Where-Object {
        $_ -in @('Patched', 'PatchedLegacy')
    }).Count -eq $states.Count
    $allLegacyPatched = @($selected.Rules | Where-Object {
        $legacy = if ($_.Rule.ContainsKey('LegacyState')) {
            [string]$_.Rule.LegacyState
        } else { 'Patched' }
        if ($legacy -eq 'Original') {
            (Get-RuleState $_) -eq 'Original'
        } elseif ($legacy -eq 'Patched') {
            (Get-RuleState $_) -in @('Patched', 'PatchedLegacy')
        } else {
            throw "Rule '$($_.Name)' has unsupported LegacyState '$legacy'."
        }
    }).Count -eq $selected.Rules.Count
    if (-not $allOriginal -and -not $allPatched -and -not $allLegacyPatched) {
        throw "A partial or mixed patch was detected. The target was not modified: $($states -join ', ')"
    }

    $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
    $hash = Get-ByteArraySha256 $Bytes
    $publicResult = [pscustomobject]@{
        Target = $Path
        ProductName = $version.ProductName
        ProductVersion = $version.ProductVersion
        FileVersion = $version.FileVersion
        Machine = ('0x{0:X4}' -f $peInfo.Machine)
        Profile = $selected.Profile.Id
        SHA256 = $hash
        State = $(if ($allOriginal) {
            'Patchable'
        } elseif ($allPatched) {
            'AlreadyPatched'
        } else {
            'UpgradeRequired'
        })
        Rules = @($selected.Rules | ForEach-Object {
            [pscustomobject]@{
                Name = $_.Name
                Offsets = @($_.Candidates | ForEach-Object {
                    '0x{0:X}' -f $_.PatchOffset
                })
                State = Get-RuleState $_
            }
        })
    }
    return [pscustomobject]@{
        Public = $publicResult
        Selected = $selected
        AllOriginal = $allOriginal
        AllPatched = $allPatched
        AllLegacyPatched = $allLegacyPatched
        Version = $version
        Hash = $hash
    }
}

function New-PatchedBytes {
    param(
        [byte[]]$Bytes,
        $SelectedProfile
    )
    $patched = New-Object 'byte[]' $Bytes.Length
    [Array]::Copy($Bytes, $patched, $Bytes.Length)
    $receiptPatches = @()
    foreach ($ruleResult in $SelectedProfile.Rules) {
        foreach ($candidate in $ruleResult.Candidates) {
            $offset = [long]$candidate.PatchOffset
            $original = @(if ($candidate.PSObject.Properties.Name -contains
                'OriginalPattern') {
                $candidate.OriginalPattern
            } else { $ruleResult.OriginalPattern })
            $replacement = @(if ($candidate.PSObject.Properties.Name -contains
                'ReplacementPattern') {
                $candidate.ReplacementPattern
            } else { $ruleResult.ReplacementPattern })
            $before = New-Object 'byte[]' $original.Length
            [Array]::Copy($patched, $offset, $before, 0, $before.Length)
            for ($i = 0; $i -lt $replacement.Length; $i++) {
                if ($replacement[$i] -ge 0) {
                    $patched[$offset + $i] = [byte]$replacement[$i]
                }
            }
            $after = New-Object 'byte[]' $before.Length
            [Array]::Copy($patched, $offset, $after, 0, $after.Length)
            $changed = $false
            for ($i = 0; $i -lt $before.Length; $i++) {
                if ($before[$i] -ne $after[$i]) {
                    $changed = $true
                    break
                }
            }
            if ($changed) {
                $receiptPatches += [pscustomobject]@{
                    Name = $ruleResult.Name
                    Offset = $offset
                    Before = Get-HexBytes $before
                    After = Get-HexBytes $after
                }
            }
        }
    }
    return [pscustomobject]@{ Bytes = $patched; Patches = $receiptPatches }
}

function Assert-GoogleChromeStopped {
    if (Get-Process chrome -ErrorAction SilentlyContinue) {
        throw 'Close every Google Chrome window and background process before this operation.'
    }
}

function Assert-BrowserStopped {
    param([string]$ExecutablePath)

    $name = [IO.Path]::GetFileNameWithoutExtension($ExecutablePath)
    if (Get-Process -Name $name -ErrorAction SilentlyContinue) {
        throw "Close every '$name' browser window and background process before this operation."
    }
}

function Copy-BackupDirectory {
    param(
        [string]$Source,
        [string]$Destination
    )
    New-Item -ItemType Directory -Path (Split-Path -Parent $Destination) `
        -Force | Out-Null
    Copy-Item -LiteralPath $Source -Destination $Destination -Recurse -Force
}

function Get-BrowserUserDataRoot {
    param(
        [string[]]$Arguments,
        [string]$WorkingDirectory,
        [string]$DefaultPath
    )

    $values = @()
    for ($i = 0; $i -lt @($Arguments).Count; $i++) {
        if ($Arguments[$i] -eq '--user-data-dir') {
            if (($i + 1) -ge $Arguments.Count -or
                [string]::IsNullOrWhiteSpace($Arguments[$i + 1])) {
                throw '--user-data-dir requires a path argument.'
            }
            $values += $Arguments[++$i]
        } elseif ($Arguments[$i].StartsWith(
            '--user-data-dir=', [StringComparison]::Ordinal)) {
            $values += $Arguments[$i].Substring('--user-data-dir='.Length)
        }
    }
    if ($values.Count -gt 1) {
        throw 'Specify --user-data-dir only once.'
    }
    if ($values.Count -eq 0) {
        if ([string]::IsNullOrWhiteSpace($DefaultPath)) {
            throw 'The profile path for this browser is unknown. Add --user-data-dir to the RAM launch arguments or disable -BackupProfile.'
        }
        return $DefaultPath
    }
    if ([string]::IsNullOrWhiteSpace($values[0])) {
        throw '--user-data-dir requires a non-empty path.'
    }

    $path = [Environment]::ExpandEnvironmentVariables([string]$values[0])
    if (-not [IO.Path]::IsPathRooted($path)) {
        $path = Join-Path $WorkingDirectory $path
    }
    return [IO.Path]::GetFullPath($path)
}

function New-ChromeExtensionBackup {
    param(
        [string]$BackupDirectory,
        [string]$UserDataRoot,
        [string]$BrowserExecutable
    )

    if ($BrowserExecutable) {
        Assert-BrowserStopped $BrowserExecutable
    } else {
        Assert-GoogleChromeStopped
    }
    if ([string]::IsNullOrWhiteSpace($UserDataRoot)) {
        $UserDataRoot = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data'
    }
    $extensionBackup = Join-Path $BackupDirectory 'extensions'
    New-Item -ItemType Directory -Path $extensionBackup -Force | Out-Null

    $inventory = [ordered]@{
        SchemaVersion = 1
        CreatedUtc = (Get-Date).ToUniversalTime().ToString('o')
        UserDataRoot = $UserDataRoot
        Profiles = @()
    }
    $storeRoots = @(
        'Local Extension Settings',
        'Sync Extension Settings',
        'Managed Extension Settings',
        'Storage\ext'
    )
    $totalExtensions = 0

    if (Test-Path -LiteralPath $UserDataRoot) {
        $localStatePath = Join-Path $UserDataRoot 'Local State'
        if (-not (Test-Path -LiteralPath $localStatePath)) {
            throw "Chrome Local State was not found: $localStatePath"
        }
        $localState = [IO.File]::ReadAllText(
            $localStatePath, [Text.Encoding]::UTF8) | ConvertFrom-Json
        foreach ($profileName in @(
            $localState.profile.info_cache.PSObject.Properties.Name)) {
            $profile = Get-Item -LiteralPath (Join-Path $UserDataRoot $profileName) `
                -ErrorAction SilentlyContinue
            if (-not $profile) { continue }
            $securePreferences = Join-Path $profile.FullName 'Secure Preferences'
            $extensionsRoot = Join-Path $profile.FullName 'Extensions'
            $ids = @()
            if (Test-Path -LiteralPath $extensionsRoot) {
                $ids += @(Get-ChildItem -LiteralPath $extensionsRoot -Directory |
                    Select-Object -ExpandProperty Name)
            }
            foreach ($storeRoot in $storeRoots) {
                $path = Join-Path $profile.FullName $storeRoot
                if (Test-Path -LiteralPath $path) {
                    $ids += @(Get-ChildItem -LiteralPath $path -Directory |
                        Select-Object -ExpandProperty Name)
                }
            }

            $settings = $null
            $registeredIds = @()
            if (Test-Path -LiteralPath $securePreferences) {
                try {
                    $secure = [IO.File]::ReadAllText(
                        $securePreferences, [Text.Encoding]::UTF8) | ConvertFrom-Json
                    $settings = $secure.extensions.settings
                    if ($settings) {
                        $registeredIds = @($settings.PSObject.Properties.Name)
                        $ids += $registeredIds
                    }
                } catch {
                    throw "Could not read extension inventory: $securePreferences"
                }
            }

            $extensionRecords = @()
            foreach ($id in @($ids | Where-Object { $_ -match '^[a-p]{32}$' } |
                Sort-Object -Unique)) {
                $setting = if ($settings) {
                    $property = $settings.PSObject.Properties[$id]
                    if ($property) { $property.Value }
                }
                $location = $null
                if ($setting -and $setting.PSObject.Properties['location']) {
                    $location = [int]$setting.location
                }
                if ($location -in @(5, 10)) { continue }

                $body = Join-Path $extensionsRoot $id
                $stores = @()
                if (Test-Path -LiteralPath $body) {
                    $relative = Join-Path (Join-Path 'profiles' $profile.Name) `
                        (Join-Path 'Extensions' $id)
                    Copy-BackupDirectory $body (Join-Path $extensionBackup $relative)
                    $stores += [ordered]@{
                        Kind = 'Body'
                        BackupRelativePath = $relative
                        TargetRelativePath = Join-Path $profile.Name `
                            (Join-Path 'Extensions' $id)
                    }
                }
                foreach ($storeRoot in $storeRoots) {
                    $source = Join-Path (Join-Path $profile.FullName $storeRoot) $id
                    if (-not (Test-Path -LiteralPath $source)) { continue }
                    $relative = Join-Path (Join-Path 'profiles' $profile.Name) `
                        (Join-Path $storeRoot $id)
                    Copy-BackupDirectory $source (Join-Path $extensionBackup $relative)
                    $stores += [ordered]@{
                        Kind = 'Settings'
                        BackupRelativePath = $relative
                        TargetRelativePath = Join-Path $profile.Name `
                            (Join-Path $storeRoot $id)
                    }
                }

                $manifest = $null
                $versions = @()
                if (Test-Path -LiteralPath $body) {
                    $versionDirectories = @(Get-ChildItem -LiteralPath $body -Directory |
                        Sort-Object Name -Descending)
                    $versions = @($versionDirectories.Name)
                    if ($versionDirectories.Count -gt 0) {
                        $manifestPath = Join-Path $versionDirectories[0].FullName 'manifest.json'
                        if (Test-Path -LiteralPath $manifestPath) {
                            try {
                                $manifest = [IO.File]::ReadAllText(
                                    $manifestPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
                            } catch {}
                        }
                    }
                }
                if (-not $manifest -and $setting -and
                    $setting.PSObject.Properties['manifest']) {
                    $manifest = $setting.manifest
                }
                $extensionRecords += [ordered]@{
                    Id = $id
                    Name = if ($manifest -and $manifest.PSObject.Properties['name']) {
                        [string]$manifest.name
                    } else { $id }
                    ManifestVersion = if ($manifest -and
                        $manifest.PSObject.Properties['manifest_version']) {
                        [int]$manifest.manifest_version
                    } else { $null }
                    Versions = $versions
                    ReinstallUrl = if ($registeredIds -contains $id -or
                        (Test-Path -LiteralPath $body)) {
                        "https://chromewebstore.google.com/detail/$id"
                    } else { $null }
                    IncognitoEnabled = if ($setting -and
                        $setting.PSObject.Properties['incognito']) {
                        [bool]$setting.incognito
                    } else { $false }
                    AllowFileAccess = if ($setting -and
                        $setting.PSObject.Properties['newAllowFileAccess']) {
                        [bool]$setting.newAllowFileAccess
                    } else { $false }
                    Stores = $stores
                }
            }

            if ($extensionRecords.Count -gt 0) {
                $profileBackup = Join-Path (Join-Path $extensionBackup 'profiles') `
                    $profile.Name
                if (Test-Path -LiteralPath $securePreferences) {
                    New-Item -ItemType Directory -Path $profileBackup -Force | Out-Null
                    Copy-Item -LiteralPath $securePreferences -Destination `
                        (Join-Path $profileBackup 'Secure Preferences.snapshot') -Force
                }
                $inventory.Profiles += [ordered]@{
                    Directory = $profile.Name
                    Extensions = $extensionRecords
                }
                $totalExtensions += $extensionRecords.Count
            }
        }
    }

    $inventoryPath = Join-Path $extensionBackup 'inventory.json'
    $inventory | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $inventoryPath -Encoding UTF8
    return [pscustomobject]@{
        Path = $extensionBackup
        Inventory = $inventoryPath
        ProfileCount = $inventory.Profiles.Count
        ExtensionCount = $totalExtensions
    }
}

function New-ChromeProfileBackup {
    param(
        [string]$BackupDirectory,
        [string]$UserDataRoot,
        [string]$BrowserExecutable
    )

    if ($BrowserExecutable) {
        Assert-BrowserStopped $BrowserExecutable
    } else {
        Assert-GoogleChromeStopped
    }
    if ([string]::IsNullOrWhiteSpace($UserDataRoot)) {
        $UserDataRoot = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data'
    }
    $extensionBackup = New-ChromeExtensionBackup $BackupDirectory $UserDataRoot `
        $BrowserExecutable
    $settingsRoot = Join-Path $BackupDirectory 'profile-settings'
    New-Item -ItemType Directory -Path $settingsRoot -Force | Out-Null

    $files = @()
    $localStatePath = Join-Path $UserDataRoot 'Local State'
    if (Test-Path -LiteralPath $localStatePath -PathType Leaf) {
        $localStateBackup = Join-Path $settingsRoot 'Local State'
        Copy-Item -LiteralPath $localStatePath -Destination $localStateBackup -Force
        $files += [ordered]@{
            SourceRelativePath = 'Local State'
            BackupRelativePath = 'profile-settings\Local State'
        }
        $localState = [IO.File]::ReadAllText(
            $localStatePath, [Text.Encoding]::UTF8) | ConvertFrom-Json
        $profileNames = @($localState.profile.info_cache.PSObject.Properties.Name)
    } else {
        $profileNames = @()
    }

    foreach ($profileName in $profileNames) {
        foreach ($name in @('Preferences', 'Secure Preferences')) {
            $source = Join-Path (Join-Path $UserDataRoot $profileName) $name
            if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { continue }
            $destinationDirectory = Join-Path $settingsRoot $profileName
            New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
            Copy-Item -LiteralPath $source -Destination `
                (Join-Path $destinationDirectory $name) -Force
            $files += [ordered]@{
                SourceRelativePath = Join-Path $profileName $name
                BackupRelativePath = Join-Path `
                    (Join-Path 'profile-settings' $profileName) $name
            }
        }
    }

    $manifest = [ordered]@{
        SchemaVersion = 1
        CreatedUtc = (Get-Date).ToUniversalTime().ToString('o')
        UserDataRoot = $UserDataRoot
        Files = $files
        ExtensionInventoryPath = $extensionBackup.Inventory
        ProfileCount = $profileNames.Count
        ExtensionCount = $extensionBackup.ExtensionCount
    }
    $manifestPath = Join-Path $BackupDirectory 'profile-backup.json'
    $manifest | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath $manifestPath -Encoding UTF8
    return [pscustomobject]@{
        Path = $BackupDirectory
        Manifest = $manifestPath
        ProfileCount = $profileNames.Count
        ExtensionCount = $extensionBackup.ExtensionCount
        Inventory = $extensionBackup.Inventory
    }
}

function Invoke-ExtensionRestore {
    param(
        [string]$ReceiptPath,
        [string]$CatalogPath
    )

    Assert-GoogleChromeStopped
    $resolvedReceipt = (Resolve-Path -LiteralPath $ReceiptPath).Path
    $record = Get-Content -Raw -LiteralPath $resolvedReceipt | ConvertFrom-Json
    if (-not $record.PSObject.Properties['ExtensionInventoryPath']) {
        throw 'This receipt predates extension backups. Use a receipt created by the updated script.'
    }
    $inventoryPath = (Resolve-Path -LiteralPath $record.ExtensionInventoryPath).Path
    $inventory = Get-Content -Raw -LiteralPath $inventoryPath | ConvertFrom-Json
    if ($inventory.SchemaVersion -ne 1) {
        throw "Unsupported extension backup schema: $($inventory.SchemaVersion)"
    }

    $applicationRoot = Resolve-ChromeApplicationRoot $null
    $currentDll = Get-LatestChromeDll $applicationRoot
    $analysis = Resolve-TargetAnalysis $currentDll `
        ([IO.File]::ReadAllBytes($currentDll)) $CatalogPath
    if (-not $analysis.AllPatched) {
        throw 'Apply the MV2 patch to the current Chrome version before -RestoreExt.'
    }

    $restoredStores = 0
    $existingStores = 0
    foreach ($profile in @($inventory.Profiles)) {
        foreach ($extension in @($profile.Extensions)) {
            foreach ($store in @($extension.Stores | Where-Object Kind -eq 'Settings')) {
                $source = Join-Path (Split-Path -Parent $inventoryPath) `
                    $store.BackupRelativePath
                $destination = Join-Path $inventory.UserDataRoot $store.TargetRelativePath
                if (Test-Path -LiteralPath $destination) {
                    $existingStores++
                    continue
                }
                Copy-BackupDirectory $source $destination
                $restoredStores++
            }
        }
    }

    $chromeExe = Join-Path $applicationRoot 'chrome.exe'
    $openedPages = 0
    foreach ($profile in @($inventory.Profiles)) {
        $urls = @($profile.Extensions.ReinstallUrl | Where-Object { $_ } |
            Sort-Object -Unique)
        if ($urls.Count -eq 0) { continue }
        $arguments = @(
            "--profile-directory=`"$($profile.Directory)`"",
            '--no-first-run'
        ) + $urls
        Start-Process -FilePath $chromeExe -ArgumentList $arguments
        $openedPages += $urls.Count
    }

    return [pscustomobject]@{
        Receipt = $resolvedReceipt
        RestoredSettingStores = $restoredStores
        ExistingSettingStores = $existingStores
        ReinstallPagesOpened = $openedPages
        ExtensionBodies = Split-Path -Parent $inventoryPath
    }
}

function Invoke-ExtensionProtectedSettingsRestore {
    param([string]$ReceiptPath)

    $resolvedReceipt = (Resolve-Path -LiteralPath $ReceiptPath).Path
    $record = Get-Content -Raw -LiteralPath $resolvedReceipt | ConvertFrom-Json
    if (-not $record.PSObject.Properties['ExtensionInventoryPath']) {
        throw 'This receipt predates extension backups. Use a newer receipt.'
    }
    $inventoryPath = (Resolve-Path -LiteralPath $record.ExtensionInventoryPath).Path
    $inventory = Get-Content -Raw -LiteralPath $inventoryPath | ConvertFrom-Json
    $chromeExe = Join-Path (Resolve-ChromeApplicationRoot $null) 'chrome.exe'
    $settings = @()
    $missingExtensions = 0

    foreach ($profile in @($inventory.Profiles)) {
        $snapshotSettings = $null
        $snapshotPath = Join-Path (Split-Path -Parent $inventoryPath) `
            (Join-Path 'profiles' (Join-Path $profile.Directory `
                'Secure Preferences.snapshot'))
        if (Test-Path -LiteralPath $snapshotPath) {
            try {
                $snapshot = [IO.File]::ReadAllText(
                    $snapshotPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
                $snapshotSettings = $snapshot.extensions.settings
            } catch {
                throw "Could not read protected extension settings: $snapshotPath"
            }
        }
        $urls = @()
        foreach ($extension in @($profile.Extensions)) {
            $incognitoProperty = $extension.PSObject.Properties['IncognitoEnabled']
            $fileAccessProperty = $extension.PSObject.Properties['AllowFileAccess']
            $snapshotSetting = if ($snapshotSettings) {
                $property = $snapshotSettings.PSObject.Properties[$extension.Id]
                if ($property) { $property.Value }
            }
            if (-not $incognitoProperty -and $snapshotSetting) {
                $incognitoProperty = $snapshotSetting.PSObject.Properties['incognito']
            }
            if (-not $fileAccessProperty -and $snapshotSetting) {
                $fileAccessProperty = `
                    $snapshotSetting.PSObject.Properties['newAllowFileAccess']
            }
            if (-not $incognitoProperty -and -not $fileAccessProperty) { continue }
            $incognito = $incognitoProperty -and [bool]$incognitoProperty.Value
            $fileAccess = $fileAccessProperty -and [bool]$fileAccessProperty.Value
            if (-not $incognito -and -not $fileAccess) { continue }

            $installedPath = Join-Path $inventory.UserDataRoot `
                (Join-Path $profile.Directory (Join-Path 'Extensions' $extension.Id))
            if (-not (Test-Path -LiteralPath $installedPath)) {
                $missingExtensions++
                continue
            }
            $url = "chrome://extensions/?id=$($extension.Id)"
            $urls += $url
            $settings += [pscustomobject]@{
                Profile = $profile.Directory
                Id = $extension.Id
                Name = $extension.Name
                IncognitoEnabled = [bool]$incognito
                AllowFileAccess = [bool]$fileAccess
                SettingsUrl = $url
            }
        }
        if ($urls.Count -gt 0) {
            $arguments = @(
                "--profile-directory=`"$($profile.Directory)`"",
                '--no-first-run'
            ) + @($urls | Sort-Object -Unique)
            Start-Process -FilePath $chromeExe -ArgumentList $arguments
        }
    }

    if ($settings.Count -eq 0 -and $missingExtensions -eq 0) {
        throw 'This backup contains no protected extension settings to restore.'
    }
    return [pscustomobject]@{
        Receipt = $resolvedReceipt
        SettingsPagesOpened = $settings.Count
        MissingExtensionsSkipped = $missingExtensions
        RequiredSettings = $settings
    }
}

function Get-LatestTargetReceipt {
    param(
        [string]$BackupBase,
        [string]$Path,
        [string]$FileVersion
    )

    if ([string]::IsNullOrWhiteSpace($BackupBase) -or
        -not (Test-Path -LiteralPath $BackupBase -PathType Container)) {
        return $null
    }
    $targetPath = [IO.Path]::GetFullPath($Path)
    $matches = Get-ChildItem -LiteralPath $BackupBase -Directory | ForEach-Object {
        $receiptPath = Join-Path $_.FullName 'receipt.json'
        if (-not (Test-Path -LiteralPath $receiptPath -PathType Leaf)) { return }
        try {
            $record = Get-Content -Raw -LiteralPath $receiptPath | ConvertFrom-Json
            if ($record.SchemaVersion -eq 1 -and $record.State -eq 'Applied' -and
                $record.AppliedUtc -and $record.TargetPath -and $record.Profile -and
                $record.FileVersion -eq $FileVersion -and
                [string]::Equals([IO.Path]::GetFullPath([string]$record.TargetPath),
                    $targetPath, [StringComparison]::OrdinalIgnoreCase)) {
                [pscustomobject]@{
                    Path = (Resolve-Path -LiteralPath $receiptPath).Path
                    AppliedUtc = [DateTimeOffset]$record.AppliedUtc
                    Record = $record
                }
            }
        } catch {
            Write-Verbose "Ignoring invalid target receipt: $receiptPath"
        }
    }
    return $matches | Sort-Object AppliedUtc -Descending | Select-Object -First 1
}

function Test-SemanticReceiptPatch {
    param(
        [IO.FileStream]$Stream,
        $PeInfo,
        $Rule,
        $Patch
    )

    $before = ConvertTo-Pattern ([string]$Patch.Before)
    $after = ConvertTo-Pattern ([string]$Patch.After)
    $patchAt = [long]$Patch.Offset

    $matches = 0
    foreach ($variant in @($Rule.Variants)) {
        $patch = Get-VariantPatchPatterns $Rule $variant
        $original = $patch.Original
        $replacement = $patch.Replacement
        if (-not (Test-ConcreteMaskedPattern $before $original) -or
            -not (Test-ConcreteMaskedPattern $after $replacement) -or
            -not (Test-StreamPattern $Stream $patchAt $after)) {
            continue
        }
        $pattern = ConvertTo-MaskedPattern $variant.Pattern
        $patchOffset = [int]$variant.PatchOffset
        if (($patchOffset + $original.Length) -gt $pattern.Length) { continue }
        $matchAt = $patchAt - $patchOffset
        if (-not (Test-ExecutableRange $PeInfo $matchAt $pattern.Length)) { continue }

        $contextValues = New-Object 'byte[]' $pattern.Length
        $contextMasks = New-Object 'byte[]' $pattern.Length
        [Array]::Copy($pattern.Values, $contextValues, $pattern.Length)
        [Array]::Copy($pattern.Masks, $contextMasks, $pattern.Length)
        for ($i = 0; $i -lt $original.Length; $i++) {
            $contextValues[$patchOffset + $i] = 0
            $contextMasks[$patchOffset + $i] = 0
        }
        $context = [pscustomobject]@{
            Values = $contextValues
            Masks = $contextMasks
            Length = $pattern.Length
        }
        $observed = Read-StreamRange $Stream $matchAt $pattern.Length
        if ($null -eq $observed -or
            -not (Test-MaskedBytesAt $observed 0 $context)) { continue }

        if ($variant.ContainsKey('RequiredPattern')) {
            $required = ConvertTo-MaskedPattern $variant.RequiredPattern
            $requiredAt = $matchAt + [long]$variant.RequiredPatternOffset
            if (-not (Test-ExecutableRange $PeInfo $requiredAt $required.Length) -or
                -not (Test-StreamMaskedPattern $Stream $requiredAt $required)) {
                continue
            }
        }
        $equal = $true
        if ($variant.ContainsKey('EqualBytes')) {
            foreach ($pair in @($variant.EqualBytes)) {
                $offsets = @([string]$pair -split ':')
                if ($offsets.Count -ne 2 -or
                    $observed[[int]$offsets[0]] -ne $observed[[int]$offsets[1]]) {
                    $equal = $false
                    break
                }
            }
        }
        if ($equal) { $matches++ }
    }
    return $matches -eq 1
}

function Get-ReceiptPatchedAnalysis {
    param(
        [string]$Path,
        [string]$BackupBase,
        [string]$CatalogPath
    )

    try {
        $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
        $receipt = Get-LatestTargetReceipt $BackupBase $Path $version.FileVersion
        if (-not $receipt) { return $null }
        $record = $receipt.Record
        if (-not $record.Patches -or
            [string]$record.PatchedSHA256 -notmatch '^[0-9A-Fa-f]{64}$') {
            return $null
        }

        $catalog = Import-PowerShellDataFile -LiteralPath $CatalogPath
        if ($catalog.SchemaVersion -ne 1) { return $null }
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open,
            [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try {
            $peInfo = Get-PeStreamInfo $stream
            $receiptPatches = @($record.Patches)
            $receiptOffsets = @($receiptPatches | ForEach-Object { [long]$_.Offset })
            if (@($receiptOffsets | Select-Object -Unique).Count -ne
                $receiptOffsets.Count) {
                return $null
            }
            $compatible = @()
            foreach ($profile in $catalog.Profiles) {
                if ([int]$profile.Machine -ne $peInfo.Machine) { continue }
                $expectedTotal = 0
                $ruleResults = @()
                $profileValid = $true
                foreach ($rule in $profile.Rules) {
                    $expected = Get-ExpectedMatchCount $rule
                    $expectedTotal += $expected
                    $patches = @($receiptPatches | Where-Object { $_.Name -eq $rule.Name })
                    if ($patches.Count -ne $expected) {
                        $profileValid = $false
                        break
                    }

                    if ($rule.ContainsKey('Variants')) {
                        $offsets = @()
                        foreach ($patch in $patches) {
                            if (-not (Test-SemanticReceiptPatch $stream $peInfo `
                                $rule $patch)) {
                                $profileValid = $false
                                break
                            }
                            $offsets += '0x{0:X}' -f [long]$patch.Offset
                        }
                        if (-not $profileValid) { break }
                        $ruleResults += [pscustomobject]@{
                            Name = $rule.Name
                            Offsets = $offsets
                            State = 'Patched'
                        }
                        continue
                    }

                    $pattern = ConvertTo-Pattern $rule.Pattern
                    $original = ConvertTo-Pattern $rule.Original
                    $replacement = ConvertTo-Pattern $rule.Replacement
                    if ($original.Length -ne $replacement.Length -or
                        ($rule.PatchOffset + $original.Length) -gt $pattern.Length) {
                        $profileValid = $false
                        break
                    }
                    $context = New-Object 'int[]' $pattern.Length
                    [Array]::Copy($pattern, $context, $pattern.Length)
                    for ($i = 0; $i -lt $original.Length; $i++) {
                        $context[$rule.PatchOffset + $i] = -1
                    }

                    $offsets = @()
                    foreach ($patch in $patches) {
                        $patchAt = [long]$patch.Offset
                        $matchAt = $patchAt - [long]$rule.PatchOffset
                        $before = ConvertTo-Pattern ([string]$patch.Before)
                        $after = ConvertTo-Pattern ([string]$patch.After)
                        if (-not (Test-PatternCompatibility $before $original) -or
                            -not (Test-PatternCompatibility $after $replacement) -or
                            -not (Test-ExecutableRange $peInfo $matchAt $pattern.Length) -or
                            -not (Test-StreamPattern $stream $matchAt $context) -or
                            -not (Test-StreamPattern $stream $patchAt $after)) {
                            $profileValid = $false
                            break
                        }
                        if ($rule.ContainsKey('RequiredPattern')) {
                            $required = ConvertTo-Pattern $rule.RequiredPattern
                            $requiredAt = $matchAt + [long]$rule.RequiredPatternOffset
                            if (-not (Test-ExecutableRange $peInfo $requiredAt $required.Length) -or
                                -not (Test-StreamPattern $stream $requiredAt $required)) {
                                $profileValid = $false
                                break
                            }
                        }
                        $offsets += '0x{0:X}' -f $patchAt
                    }
                    if (-not $profileValid) { break }
                    $ruleResults += [pscustomobject]@{
                        Name = $rule.Name
                        Offsets = $offsets
                        State = 'Patched'
                    }
                }
                if ($profileValid -and $receiptPatches.Count -eq $expectedTotal) {
                    $compatible += [pscustomobject]@{
                        Profile = $profile
                        Rules = $ruleResults
                    }
                }
            }
            if ($compatible.Count -ne 1 -or
                $compatible[0].Profile.Id -ne [string]$record.Profile) {
                return $null
            }

            return [pscustomobject]@{
                Target = $Path
                ProductName = $version.ProductName
                ProductVersion = $version.ProductVersion
                FileVersion = $version.FileVersion
                Machine = ('0x{0:X4}' -f $peInfo.Machine)
                Profile = $compatible[0].Profile.Id
                SHA256 = $null
                State = 'AlreadyPatched'
                Rules = $compatible[0].Rules
                Verification = 'ReceiptFastPath'
                ReceiptSHA256 = ([string]$record.PatchedSHA256).ToUpperInvariant()
            }
        } finally {
            if ($stream) { $stream.Dispose() }
        }
    } catch {
        Write-Verbose "Receipt fast path was not usable: $($_.Exception.Message)"
        return $null
    }
}

function Invoke-PatchTarget {
    param(
        [string]$Path,
        [switch]$InPlace,
        [string]$OutputPath,
        [string]$BackupBase,
        [string]$CatalogPath,
        [switch]$BackupExtensions
    )

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $resolvedCatalog = (Resolve-Path -LiteralPath $CatalogPath).Path
    $fastAnalysis = Get-ReceiptPatchedAnalysis $resolved $BackupBase $resolvedCatalog
    if ($fastAnalysis) {
        if ($OutputPath) {
            Copy-Item -LiteralPath $resolved -Destination $OutputPath
        }
        return $fastAnalysis
    }
    $bytes = [IO.File]::ReadAllBytes($resolved)
    $analysis = Resolve-TargetAnalysis $resolved $bytes $resolvedCatalog
    if (-not $InPlace -and [string]::IsNullOrWhiteSpace($OutputPath)) {
        return $analysis.Public
    }
    if ($analysis.AllPatched) {
        if ($OutputPath) {
            Copy-Item -LiteralPath $resolved -Destination $OutputPath
        }
        return $analysis.Public
    }

    $patchData = New-PatchedBytes $bytes $analysis.Selected
    $patchedHash = Get-ByteArraySha256 $patchData.Bytes
    if ($OutputPath) {
        $outputFull = [IO.Path]::GetFullPath($OutputPath)
        [IO.File]::WriteAllBytes($outputFull, $patchData.Bytes)
        if ((Get-FileHash -LiteralPath $outputFull -Algorithm SHA256).Hash -ne $patchedHash) {
            throw 'Output hash verification failed.'
        }
        return [pscustomobject]@{
            Target = $resolved
            Output = $outputFull
            Profile = $analysis.Selected.Profile.Id
            OriginalSHA256 = $analysis.Hash
            PatchedSHA256 = $patchedHash
            PatchCount = $patchData.Patches.Count
        }
    }

    $locked = $null
    try {
        try {
            $locked = [IO.File]::Open($resolved, [IO.FileMode]::Open,
                [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        } catch {
            throw "Target DLL is loaded, updating, or not writable: $resolved"
        }
        $lockedBytes = Read-ExclusiveStreamBytes $locked
        if ((Get-ByteArraySha256 $lockedBytes) -ne $analysis.Hash) {
            throw 'Target changed between analysis and exclusive lock acquisition; retry.'
        }

        $timestamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmssZ')
        $safeProduct = if ($analysis.Version.ProductName) {
            $analysis.Version.ProductName -replace '[^A-Za-z0-9._-]', '_'
        } else { 'Chromium' }
        $safeVersion = if ($analysis.Version.FileVersion) {
            $analysis.Version.FileVersion -replace '[^A-Za-z0-9._-]', '_'
        } else { 'unknown' }
        $backupDirectory = Join-Path $BackupBase (
            "{0}_{1}_{2}" -f $safeProduct, $safeVersion, $timestamp)
        New-Item -ItemType Directory -Path $backupDirectory -Force | Out-Null
        $backupPath = Join-Path $backupDirectory ([IO.Path]::GetFileName($resolved))
        [IO.File]::WriteAllBytes($backupPath, $lockedBytes)
        if ((Get-FileHash -LiteralPath $backupPath -Algorithm SHA256).Hash -ne $analysis.Hash) {
            throw 'Backup hash verification failed. The target was not modified.'
        }

        $extensionBackup = $null
        if ($BackupExtensions -and $analysis.Version.ProductName -eq 'Google Chrome') {
            $extensionBackup = New-ChromeExtensionBackup $backupDirectory
        }

        $receiptPath = Join-Path $backupDirectory 'receipt.json'
        $receipt = [ordered]@{
            SchemaVersion = 1
            State = 'Prepared'
            Tool = 'chromium_mv2_patch.ps1'
            AppliedUtc = (Get-Date).ToUniversalTime().ToString('o')
            TargetPath = $resolved
            BackupPath = $backupPath
            ProductName = $analysis.Version.ProductName
            ProductVersion = $analysis.Version.ProductVersion
            FileVersion = $analysis.Version.FileVersion
            Profile = $analysis.Selected.Profile.Id
            OriginalSHA256 = $analysis.Hash
            PatchedSHA256 = $patchedHash
            OriginalSignatureStatus = [string](
                Get-AuthenticodeSignature -LiteralPath $backupPath).Status
            ExtensionBackupPath = if ($extensionBackup) { $extensionBackup.Path } else { $null }
            ExtensionInventoryPath = if ($extensionBackup) { $extensionBackup.Inventory } else { $null }
            ExtensionBackupProfileCount = if ($extensionBackup) {
                $extensionBackup.ProfileCount
            } else { 0 }
            ExtensionBackupExtensionCount = if ($extensionBackup) {
                $extensionBackup.ExtensionCount
            } else { 0 }
            Patches = $patchData.Patches
        }
        $receipt | ConvertTo-Json -Depth 6 |
            Set-Content -LiteralPath $receiptPath -Encoding UTF8

        $writeStarted = $false
        try {
            $locked.Position = 0
            $writeStarted = $true
            $locked.Write($patchData.Bytes, 0, $patchData.Bytes.Length)
            $locked.SetLength($patchData.Bytes.Length)
            $locked.Flush($true)
            $writtenBytes = Read-ExclusiveStreamBytes $locked
            if ((Get-ByteArraySha256 $writtenBytes) -ne $patchedHash) {
                throw 'Post-write verification failed.'
            }
            $writtenAnalysis = Resolve-TargetAnalysis $resolved $writtenBytes $CatalogPath
            if (-not $writtenAnalysis.AllPatched) {
                throw 'Post-write rule verification failed.'
            }
            $receipt.State = 'Applied'
            $receipt | ConvertTo-Json -Depth 6 |
                Set-Content -LiteralPath $receiptPath -Encoding UTF8
        } catch {
            $patchFailure = $_.Exception
            if ($writeStarted) {
                try {
                    $locked.Position = 0
                    $locked.Write($lockedBytes, 0, $lockedBytes.Length)
                    $locked.SetLength($lockedBytes.Length)
                    $locked.Flush($true)
                    $restoredBytes = Read-ExclusiveStreamBytes $locked
                    if ((Get-ByteArraySha256 $restoredBytes) -ne $analysis.Hash) {
                        throw 'Rollback hash verification failed.'
                    }
                } catch {
                    throw "Patch failed: $($patchFailure.Message) Automatic rollback also failed: $($_.Exception.Message) Restore from: $backupPath"
                }
                $receipt.State = 'RolledBack'
                $receipt['Failure'] = $patchFailure.Message
                try {
                    $receipt | ConvertTo-Json -Depth 6 |
                        Set-Content -LiteralPath $receiptPath -Encoding UTF8
                } catch {}
            }
            throw $patchFailure
        }

        return [pscustomobject]@{
            Target = $resolved
            Profile = $analysis.Selected.Profile.Id
            OriginalSHA256 = $analysis.Hash
            PatchedSHA256 = $patchedHash
            Backup = $backupPath
            Receipt = $receiptPath
            PatchCount = $patchData.Patches.Count
            ExtensionBackup = if ($extensionBackup) { $extensionBackup.Path } else { $null }
            ExtensionCount = if ($extensionBackup) {
                $extensionBackup.ExtensionCount
            } else { 0 }
        }
    } finally {
        if ($locked) { $locked.Dispose() }
    }
}

function Get-LatestBackupReceipt {
    param([string]$BackupBase)

    if (-not (Test-Path -LiteralPath $BackupBase -PathType Container)) {
        throw "Backup directory was not found: $BackupBase"
    }
    $latest = Get-ChildItem -LiteralPath $BackupBase -Directory | ForEach-Object {
        $path = Join-Path $_.FullName 'receipt.json'
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            try {
                $record = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
                if ($record.SchemaVersion -eq 1 -and $record.State -eq 'Applied' -and
                    $record.AppliedUtc) {
                    [pscustomobject]@{
                        Path = (Resolve-Path -LiteralPath $path).Path
                        AppliedUtc = [DateTimeOffset]$record.AppliedUtc
                    }
                }
            } catch {
                Write-Verbose "Ignoring invalid backup receipt: $path"
            }
        }
    } | Sort-Object AppliedUtc -Descending | Select-Object -First 1
    if (-not $latest) {
        throw "No completed backup receipt was found under: $BackupBase"
    }
    return $latest.Path
}

function Invoke-ReceiptRestore {
    param(
        [string]$ReceiptPath,
        [string]$RequestedRoot
    )
    $resolvedReceipt = (Resolve-Path -LiteralPath $ReceiptPath).Path
    $record = Get-Content -Raw -LiteralPath $resolvedReceipt | ConvertFrom-Json
    if ($record.SchemaVersion -ne 1) {
        throw "Unsupported receipt schema: $($record.SchemaVersion)"
    }
    $recordedTarget = [IO.Path]::GetFullPath([string]$record.TargetPath)
    $targetPath = if ($record.ProductName -eq 'Google Chrome') {
        Get-LatestChromeDll (Resolve-ChromeApplicationRoot $RequestedRoot)
    } else {
        (Resolve-Path -LiteralPath $recordedTarget).Path
    }
    $targetPath = (Resolve-Path -LiteralPath $targetPath).Path
    $backupPath = (Resolve-Path -LiteralPath $record.BackupPath).Path
    $backupBytes = [IO.File]::ReadAllBytes($backupPath)
    if ((Get-ByteArraySha256 $backupBytes) -ne $record.OriginalSHA256) {
        throw 'Backup hash does not match the receipt.'
    }
    $backupMachine = (Get-PeInfo $backupBytes).Machine

    $locked = $null
    try {
        try {
            $locked = [IO.File]::Open($targetPath, [IO.FileMode]::Open,
                [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        } catch {
            throw "Target DLL is loaded or not writable: $targetPath"
        }
        $current = Read-ExclusiveStreamBytes $locked
        $currentMachine = (Get-PeInfo $current).Machine
        if ($currentMachine -ne $backupMachine) {
            throw ('Backup and current Chrome architectures differ ' +
                "(backup=0x$($backupMachine.ToString('X4')), " +
                "current=0x$($currentMachine.ToString('X4'))). Refusing to restore.")
        }
        if ((Get-ByteArraySha256 $current) -ne $record.PatchedSHA256) {
            throw ("Current Chrome DLL does not match this receipt; refusing to overwrite it. " +
                "Receipt target: $recordedTarget Current target: $targetPath")
        }
        $locked.Position = 0
        $locked.Write($backupBytes, 0, $backupBytes.Length)
        $locked.SetLength($backupBytes.Length)
        $locked.Flush($true)
        $verified = Read-ExclusiveStreamBytes $locked
        if ((Get-ByteArraySha256 $verified) -ne $record.OriginalSHA256) {
            throw 'Post-restore hash verification failed.'
        }
    } finally {
        if ($locked) { $locked.Dispose() }
    }
    return [pscustomobject]@{
        Target = $targetPath
        RestoredSHA256 = $record.OriginalSHA256
        Signature = (Get-AuthenticodeSignature -LiteralPath $targetPath).Status
        Receipt = $resolvedReceipt
    }
}

function Resolve-ChromeApplicationRoot {
    param([string]$RequestedRoot)
    if (-not [string]::IsNullOrWhiteSpace($RequestedRoot)) {
        return (Resolve-Path -LiteralPath $RequestedRoot).Path
    }
    $candidates = @()
    foreach ($key in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe'
    )) {
        if (Test-Path -LiteralPath $key) {
            $exe = (Get-Item -LiteralPath $key).GetValue('')
            if ($exe) { $candidates += (Split-Path -Parent $exe) }
        }
    }
    $candidates += @(
        (Join-Path $env:ProgramFiles 'Google\Chrome\Application'),
        (Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application'),
        (Join-Path $env:LOCALAPPDATA 'Google\Chrome\Application')
    )
    $existing = @($candidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } |
        Select-Object -Unique)
    if ($existing.Count -ne 1) {
        throw "Could not uniquely detect the Chrome Application directory. Specify -BrowserRoot. Candidates: $($existing -join ', ')"
    }
    return (Resolve-Path -LiteralPath $existing[0]).Path
}

function Get-LatestChromeDll {
    param(
        [string]$ApplicationRoot,
        [switch]$AllowIncomplete
    )
    $versions = foreach ($directory in Get-ChildItem -Directory -LiteralPath $ApplicationRoot) {
        [version]$parsed = '0.0'
        if ([version]::TryParse($directory.Name, [ref]$parsed)) {
            $dll = Join-Path $directory.FullName 'chrome.dll'
            if ($AllowIncomplete) {
                [pscustomobject]@{ Version = $parsed; Path = $dll }
            } elseif (Test-Path -LiteralPath $dll) {
                if ([Diagnostics.FileVersionInfo]::GetVersionInfo($dll).FileVersion -eq
                    $directory.Name) {
                    [pscustomobject]@{ Version = $parsed; Path = $dll }
                }
            }
        }
    }
    $latest = $versions | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $latest) {
        throw "No complete versioned chrome.dll was found under: $ApplicationRoot"
    }
    return $latest.Path
}

function Get-GoogleUpdaterTask {
    $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
        $_.TaskPath -eq '\GoogleSystem\GoogleUpdater\' -and
        @($_.Actions | Where-Object {
            $_.Execute -match '(?i)updater\.exe' -and $_.Arguments -match '(?i)--system'
        }).Count -gt 0
    })
    if ($tasks.Count -ne 1) {
        throw "Expected one system Google Updater task, found $($tasks.Count)."
    }
    return $tasks[0]
}

function Resolve-GoogleUpdaterDataRoot {
    param([string]$RequestedRoot)

    if (-not [string]::IsNullOrWhiteSpace($RequestedRoot)) {
        return (Resolve-Path -LiteralPath $RequestedRoot).Path
    }

    $candidates = @()
    try {
        $task = Get-GoogleUpdaterTask
        $executable = [Environment]::ExpandEnvironmentVariables(
            ([string]$task.Actions[0].Execute).Trim('"'))
        if ($executable) {
            $candidates += Split-Path -Parent (Split-Path -Parent $executable)
        }
    } catch {}
    $candidates += @(
        (Join-Path $env:ProgramFiles 'Google\GoogleUpdater'),
        (Join-Path ${env:ProgramFiles(x86)} 'Google\GoogleUpdater'),
        (Join-Path $env:LOCALAPPDATA 'Google\GoogleUpdater')
    )
    $existing = @($candidates | Where-Object {
        $_ -and (Test-Path -LiteralPath (Join-Path $_ 'updater_history.jsonl'))
    } | ForEach-Object { (Resolve-Path -LiteralPath $_).Path } | Select-Object -Unique)
    if ($existing.Count -ne 1) {
        throw "Could not uniquely detect Google Updater data. Specify -UpdaterRoot. Candidates: $($existing -join ', ')"
    }
    return $existing[0]
}

function Get-AutoPatchTaskFolder {
    param($SchedulerService)
    try {
        return $SchedulerService.GetFolder('\ChromiumMV2Patcher')
    } catch {
        return $SchedulerService.GetFolder('\').CreateFolder('ChromiumMV2Patcher', $null)
    }
}

function Get-PowerShellHostPath {
    $currentHost = (Get-Process -Id $PID).Path
    if ($currentHost -and (Test-Path -LiteralPath $currentHost -PathType Leaf)) {
        return $currentHost
    }
    $systemHost = Join-Path $env:SystemRoot `
        'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path -LiteralPath $systemHost -PathType Leaf) {
        return $systemHost
    }
    throw 'Could not resolve a PowerShell executable.'
}

function Set-CommonTaskDefinition {
    param(
        $Definition,
        [string]$Description,
        [string]$Arguments,
        [string]$ExecutionTimeLimit
    )
    $Definition.RegistrationInfo.Description = $Description
    $Definition.Principal.UserId = 'SYSTEM'
    $Definition.Principal.LogonType = 5
    $Definition.Principal.RunLevel = 1
    $Definition.Settings.Enabled = $true
    $Definition.Settings.StartWhenAvailable = $true
    $Definition.Settings.MultipleInstances = 2
    $Definition.Settings.ExecutionTimeLimit = $ExecutionTimeLimit
    $Definition.Settings.DisallowStartIfOnBatteries = $false
    $Definition.Settings.StopIfGoingOnBatteries = $false
    $action = $Definition.Actions.Create(0)
    $action.Path = Get-PowerShellHostPath
    $action.Arguments = $Arguments
    $action.WorkingDirectory = $PSScriptRoot
}

function Register-AutoPatchTasks {
    param(
        [string]$ApplicationRoot,
        [string]$BackupBase,
        [string]$CatalogPath
    )
    $updaterData = Resolve-GoogleUpdaterDataRoot $UpdaterRoot
    $hourlyArguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -PatchLatestOnce -BrowserRoot "{1}" -BackupRoot "{2}" -SignatureCatalog "{3}"' -f
        $PSCommandPath, $ApplicationRoot, $BackupBase, $CatalogPath
    $watchArguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -WatchUpdates -BrowserRoot "{1}" -UpdaterRoot "{2}" -BackupRoot "{3}" -SignatureCatalog "{4}"' -f
        $PSCommandPath, $ApplicationRoot, $updaterData, $BackupBase, $CatalogPath

    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    $folder = Get-AutoPatchTaskFolder $service

    foreach ($oldName in @('ChromiumMV2FileWatcher', 'ChromiumMV2UpdateWatcher')) {
        try {
            $oldTask = $folder.GetTask($oldName)
            $instances = $oldTask.GetInstances(0)
            for ($index = 1; $index -le $instances.Count; $index++) {
                $instances.Item($index).Stop()
            }
            $folder.DeleteTask($oldName, 0)
        } catch {
            if ($_.Exception.HResult -ne -2147024894) { throw }
        }
    }

    $hourlyDefinition = $service.NewTask(0)
    Set-CommonTaskDefinition $hourlyDefinition `
        'Checks the newest Chrome DLL every hour and applies the MV2 patch.' `
        $hourlyArguments 'PT30M'
    $hourlyTrigger = $hourlyDefinition.Triggers.Create(2)
    $hourlyTrigger.Enabled = $true
    $hourlyTrigger.StartBoundary = (Get-Date).AddMinutes(1).ToString(
        "yyyy-MM-dd'T'HH:mm:ss")
    $hourlyTrigger.DaysInterval = 1
    $hourlyTrigger.Repetition.Interval = 'PT1H'
    $hourlyTrigger.Repetition.Duration = 'P1D'
    $hourlyTrigger.Repetition.StopAtDurationEnd = $false
    [void]$folder.RegisterTaskDefinition(
        'ChromiumMV2AutoPatch', $hourlyDefinition, 6, 'SYSTEM', $null, 5, $null)

    $watchDefinition = $service.NewTask(0)
    Set-CommonTaskDefinition $watchDefinition `
        'Watches Google Updater history and Chrome files for completed updates.' `
        $watchArguments 'PT0S'
    $watchDefinition.Settings.RestartCount = 3
    $watchDefinition.Settings.RestartInterval = 'PT1M'
    $bootTrigger = $watchDefinition.Triggers.Create(8)
    $bootTrigger.Enabled = $true
    $bootTrigger.Delay = 'PT10S'
    [void]$folder.RegisterTaskDefinition(
        'ChromiumMV2UpdateWatcher', $watchDefinition, 6, 'SYSTEM', $null, 5, $null)

    return [pscustomobject]@{
        HourlyTask = '\ChromiumMV2Patcher\ChromiumMV2AutoPatch'
        UpdateWatcherTask = '\ChromiumMV2Patcher\ChromiumMV2UpdateWatcher'
        UpdaterRoot = $updaterData
        BrowserRoot = $ApplicationRoot
    }
}

function Start-AutoPatchWatcherTask {
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    $folder = $service.GetFolder('\ChromiumMV2Patcher')
    [void]$folder.GetTask('ChromiumMV2UpdateWatcher').Run($null)
    return [pscustomobject]@{
        Started = $true
        Task = '\ChromiumMV2Patcher\ChromiumMV2UpdateWatcher'
    }
}

function Remove-AutoPatchTasks {
    $taskNames = @(
        'ChromiumMV2AutoPatch',
        'ChromiumMV2UpdateWatcher',
        'ChromiumMV2FileWatcher'
    )
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    try { $folder = $service.GetFolder('\ChromiumMV2Patcher') } catch { $folder = $null }
    $results = foreach ($taskName in $taskNames) {
        $removed = $false
        if ($folder) {
            try {
                $instances = ($folder.GetTask($taskName)).GetInstances(0)
                for ($index = 1; $index -le $instances.Count; $index++) {
                    $instances.Item($index).Stop()
                }
                $folder.DeleteTask($taskName, 0)
                $removed = $true
            } catch {
                if ($_.Exception.HResult -ne -2147024894) { throw }
            }
        }
        [pscustomobject]@{
            Removed = $removed
            Task = "\ChromiumMV2Patcher\$taskName"
        }
    }
    if ($folder) {
        try { $service.GetFolder('\').DeleteFolder('ChromiumMV2Patcher', 0) } catch {}
    }
    return $results
}

function Write-AutoPatchLog {
    param([string]$Message)
    $line = '{0} {1}' -f (Get-Date).ToUniversalTime().ToString('o'), $Message
    Add-Content -LiteralPath $AutoPatchLog -Value $line -Encoding UTF8
}

function Get-PatchMutexName {
    param([string]$ApplicationRoot)

    $normalized = [IO.Path]::GetFullPath($ApplicationRoot).TrimEnd('\').ToUpperInvariant()
    $data = [Text.Encoding]::UTF8.GetBytes($normalized)
    $hash = Get-ByteArraySha256 $data
    return "Global\ChromiumMV2Patcher-$($hash.Substring(0, 16))"
}

function Invoke-WithPatchMutex {
    param(
        [string]$ApplicationRoot,
        [scriptblock]$Action,
        [int]$TimeoutSeconds = 300
    )

    $mutex = New-Object Threading.Mutex($false, (Get-PatchMutexName $ApplicationRoot))
    $ownsMutex = $false
    try {
        try {
            $ownsMutex = $mutex.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))
        } catch [Threading.AbandonedMutexException] {
            $ownsMutex = $true
            Write-AutoPatchLog "mutex recovered root=$ApplicationRoot"
        }
        if (-not $ownsMutex) {
            throw "Timed out waiting for another patch operation: $ApplicationRoot"
        }
        return & $Action
    } finally {
        if ($ownsMutex) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}

function Get-PatchLockRoot {
    param([string]$Path)

    $directory = Split-Path -Parent ([IO.Path]::GetFullPath($Path))
    $version = [version]'0.0'
    if ([version]::TryParse((Split-Path -Leaf $directory), [ref]$version)) {
        return Split-Path -Parent $directory
    }
    return $directory
}

function Resolve-RamBrowserExecutable {
    param(
        [string]$TargetPath,
        [string]$RequestedPath,
        $TargetVersion
    )

    if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
        $resolved = (Resolve-Path -LiteralPath $RequestedPath).Path
    } else {
        $root = Get-PatchLockRoot $TargetPath
        $matches = @(Get-ChildItem -LiteralPath $root -Filter '*.exe' -File |
            Where-Object {
                $_.Name -notlike '*_proxy.exe' -and
                $_.VersionInfo.OriginalFilename -notlike '*_proxy.exe' -and
                [string]::Equals($_.VersionInfo.ProductName,
                    $TargetVersion.ProductName,
                    [StringComparison]::OrdinalIgnoreCase) -and
                [string]::Equals($_.VersionInfo.FileVersion,
                    $TargetVersion.FileVersion,
                    [StringComparison]::OrdinalIgnoreCase)
            })
        if ($matches.Count -ne 1) {
            throw "Could not uniquely identify the browser executable in '$root'. Specify -BrowserExecutable explicitly. Matching executables: $($matches.Count)."
        }
        $resolved = $matches[0].FullName
    }

    $bytes = [IO.File]::ReadAllBytes($resolved)
    if ((Get-PeInfo $bytes).Machine -ne 0x8664) {
        throw "RAM launch requires an x64 browser executable: $resolved"
    }
    return $resolved
}

function Get-RamDefaultUserDataRoot {
    param([string]$BrowserPath)

    $applicationRoot = Split-Path -Parent $BrowserPath
    if ((Split-Path -Leaf $applicationRoot) -ne 'Application') { return $null }
    $browserDirectory = Split-Path -Leaf (Split-Path -Parent $applicationRoot)
    $relative = switch ($browserDirectory) {
        'Chrome' { 'Google\Chrome\User Data' }
        'Chrome Beta' { 'Google\Chrome Beta\User Data' }
        'Chrome Dev' { 'Google\Chrome Dev\User Data' }
        'Chrome SxS' { 'Google\Chrome SxS\User Data' }
        'Brave-Browser' { 'BraveSoftware\Brave-Browser\User Data' }
        'Edge' { 'Microsoft\Edge\User Data' }
        'Vivaldi' { 'Vivaldi\User Data' }
        default { $null }
    }
    if ($relative) { return Join-Path $env:LOCALAPPDATA $relative }
    return $null
}

function Invoke-RamLaunch {
    param(
        [string]$Path,
        [string]$BackupBase,
        [string]$CatalogPath,
        [switch]$BackupProfile,
        [string]$ChromeArguments,
        [string]$BrowserExecutable
    )

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $bytes = [IO.File]::ReadAllBytes($resolved)
    $analysis = Resolve-TargetAnalysis $resolved $bytes $CatalogPath
    if (-not $analysis.AllOriginal) {
        if ($analysis.AllPatched) {
            throw 'RAM launch requires an original, unpatched target DLL. Restore or update the browser before trying it.'
        }
        throw 'RAM launch requires every verified rule to be in its original state.'
    }
    $peInfo = Get-PeInfo $bytes
    if ($peInfo.Machine -ne 0x8664) {
        throw 'RAM launch currently supports x64 Chromium browsers only.'
    }

    $browserPath = Resolve-RamBrowserExecutable $resolved $BrowserExecutable `
        $analysis.Version
    $workingDirectory = Split-Path -Parent $browserPath
    Assert-BrowserStopped $browserPath
    $parsedChromeArguments = [RamPatchLauncher]::ParseArguments($ChromeArguments)

    $patchData = New-PatchedBytes $bytes $analysis.Selected
    if ($patchData.Patches.Count -eq 0) {
        throw 'The verified RAM patch plan contains no byte changes.'
    }
    $rvas = New-Object 'long[]' $patchData.Patches.Count
    $expected = New-Object 'byte[][]' $patchData.Patches.Count
    $replacements = New-Object 'byte[][]' $patchData.Patches.Count
    for ($i = 0; $i -lt $patchData.Patches.Count; $i++) {
        $patch = $patchData.Patches[$i]
        $expected[$i] = ConvertTo-ConcreteBytes $patch.Before
        $replacements[$i] = ConvertTo-ConcreteBytes $patch.After
        $rvas[$i] = ConvertTo-PeRva $peInfo ([long]$patch.Offset) $expected[$i].Length
    }

    $profileBackup = $null
    if ($BackupProfile) {
        $defaultUserDataRoot = Get-RamDefaultUserDataRoot $browserPath
        $userDataRoot = Get-BrowserUserDataRoot $parsedChromeArguments `
            $workingDirectory $defaultUserDataRoot
        $safeVersion = if ($analysis.Version.FileVersion) {
            $analysis.Version.FileVersion -replace '[^A-Za-z0-9._-]', '_'
        } else { 'unknown' }
        $timestamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmssZ')
        $backupDirectory = Join-Path $BackupBase `
            ("RamLaunch_{0}_{1}" -f $safeVersion, $timestamp)
        New-Item -ItemType Directory -Path $backupDirectory -Force | Out-Null
        $profileBackup = New-ChromeProfileBackup $backupDirectory $userDataRoot `
            $browserPath
    }

    try {
        $registeredTasks = @(Get-ScheduledTask -TaskPath '\ChromiumMV2Patcher\' `
            -ErrorAction SilentlyContinue)
        if ($registeredTasks.Count -gt 0) {
            Write-Warning 'Automatic disk patch tasks are registered. RAM launch does not remove them; a later update event may patch chrome.dll on disk.'
        }
    } catch {}

    Assert-BrowserStopped $browserPath
    $result = [RamPatchLauncher]::Launch(
        $browserPath, $resolved, $rvas, $expected, $replacements,
        $ChromeArguments, 30)
    $diskHash = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash
    if ($diskHash -ne $analysis.Hash) {
        throw 'The target DLL changed on disk during RAM launch verification.'
    }
    return [pscustomobject]@{
        ProcessId = $result.ProcessId
        BrowserExecutable = $browserPath
        Target = $resolved
        ModulePath = $result.ModulePath
        Profile = $analysis.Selected.Profile.Id
        PatchCount = $result.PatchCount
        DiskSHA256 = $diskHash
        DiskModified = $false
        BackupPath = if ($profileBackup) { $profileBackup.Path } else { $null }
        BackupManifest = if ($profileBackup) { $profileBackup.Manifest } else { $null }
        ExtensionCount = if ($profileBackup) { $profileBackup.ExtensionCount } else { $null }
        ChromeArguments = @($parsedChromeArguments)
    }
}

function Invoke-AutoPatchCore {
    param(
        [string]$ApplicationRoot,
        [string]$BackupBase,
        [string]$CatalogPath,
        [switch]$RefreshRegistration,
        [switch]$WaitForReady,
        [int]$ReadyTimeoutSeconds = 120
    )

    return Invoke-WithPatchMutex $ApplicationRoot {
        $targetDll = $null
        $deadline = [datetime]::UtcNow.AddSeconds($ReadyTimeoutSeconds)
        try {
            while ($true) {
                if ($WaitForReady) {
                    $targetDll = Wait-ForLatestPatchableFile $ApplicationRoot $deadline
                    if (-not $targetDll) {
                        $pending = Get-LatestChromeDll $ApplicationRoot -AllowIncomplete
                        $complete = Get-LatestChromeDll $ApplicationRoot
                        if ($pending -ne $complete) {
                            throw "The newest Chrome version did not become ready before the timeout: $pending"
                        }
                        $targetDll = $complete
                    }
                } else {
                    $targetDll = Get-LatestChromeDll $ApplicationRoot
                }

                try {
                    $result = Invoke-PatchTarget $targetDll -InPlace `
                        -BackupBase $BackupBase -CatalogPath $CatalogPath
                } catch {
                    $transient = $_.Exception.Message -like 'Target DLL is loaded,*' -or
                        $_.Exception.Message -like 'Target changed between analysis*'
                    if ($WaitForReady -and $transient -and [datetime]::UtcNow -lt $deadline) {
                        Write-AutoPatchLog "target=$targetDll retry=$($_.Exception.Message)"
                        Start-Sleep -Seconds 2
                        continue
                    }
                    throw
                }

                if ($WaitForReady) {
                    $newest = Get-LatestChromeDll $ApplicationRoot -AllowIncomplete
                    if (-not [string]::Equals($newest, $targetDll,
                        [StringComparison]::OrdinalIgnoreCase)) {
                        if ([datetime]::UtcNow -ge $deadline) {
                            throw "A newer Chrome version appeared before patch completion: $newest"
                        }
                        Write-AutoPatchLog "target=$targetDll superseded-by=$newest"
                        continue
                    }
                }

                $stateProperty = $result.PSObject.Properties['State']
                $state = if ($stateProperty) { $stateProperty.Value } else { 'Patched' }
                Write-AutoPatchLog ("target={0} state={1}" -f $targetDll, $state)
                return $result
            }
        } catch {
            Write-AutoPatchLog ("target={0} error={1}" -f $targetDll, $_.Exception.Message)
            throw
        } finally {
            if ($RefreshRegistration) {
                try {
                    Register-AutoPatchTasks $ApplicationRoot $BackupBase $CatalogPath | Out-Null
                } catch {
                    Write-AutoPatchLog "registration-refresh error=$($_.Exception.Message)"
                }
            }
        }
    }
}

function Wait-ForLatestPatchableFile {
    param(
        [string]$ApplicationRoot,
        [datetime]$Deadline
    )
    while ([datetime]::UtcNow -lt $Deadline) {
        $dllPath = $null
        try {
            $dllPath = Get-LatestChromeDll $ApplicationRoot -AllowIncomplete
        } catch {}
        if ($dllPath -and (Test-Path -LiteralPath $dllPath)) {
            try {
                $expectedVersion = Split-Path -Leaf (Split-Path -Parent $dllPath)
                $actualVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($dllPath).FileVersion
                if ($actualVersion -eq $expectedVersion) {
                    $probe = [IO.File]::Open($dllPath, [IO.FileMode]::Open,
                        [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
                    $probe.Dispose()
                    if ((Get-LatestChromeDll $ApplicationRoot -AllowIncomplete) -eq $dllPath) {
                        return $dllPath
                    }
                }
            } catch {}
        }
        Start-Sleep -Seconds 2
    }
    return $null
}

function Get-GoogleUpdaterCompletion {
    param(
        [string]$HistoryPath
    )

    $starts = @{}
    $latest = $null
    foreach ($path in @("$HistoryPath.old", $HistoryPath)) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        try {
            $stream = [IO.File]::Open($path, [IO.FileMode]::Open,
                [IO.FileAccess]::Read,
                [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
            try {
                $reader = New-Object IO.StreamReader($stream)
                try {
                    while (($line = $reader.ReadLine()) -ne $null) {
                        try { $event = $line | ConvertFrom-Json } catch { continue }
                        if ($event.eventType -ne 'UPDATE') { continue }
                        $key = '{0}|{1}' -f $event.processToken, $event.eventId
                        if ($event.bound -eq 'START') {
                            $starts[$key] = [string]$event.appId
                            continue
                        }
                        if ($event.bound -ne 'END' -or
                            $starts[$key] -ine '{8A69D345-D564-463c-AFF1-A69D9E530F96}') {
                            continue
                        }
                        $states = @($event.updateStates | ForEach-Object { $_.state })
                        if ($event.result -eq 'SUCCESS' -and $states -contains 'UPDATED') {
                            $latest = [pscustomobject]@{
                                Marker = $key
                                Version = [string]$event.nextVersion
                            }
                        }
                    }
                } finally {
                    $reader.Dispose()
                }
            } finally {
                $stream.Dispose()
            }
        } catch {
            Write-AutoPatchLog "updater-history read-error=$($_.Exception.Message)"
        }
    }
    return $latest
}

function Invoke-WatcherPatch {
    param(
        [string]$Reason,
        [string]$ApplicationRoot,
        [string]$BackupBase,
        [string]$CatalogPath
    )

    $arguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -PatchLatestOnce -BrowserRoot "{1}" -BackupRoot "{2}" -SignatureCatalog "{3}" -AutoPatchLog "{4}" -ReadinessTimeoutSeconds {5}' -f
        $PSCommandPath, $ApplicationRoot, $BackupBase, $CatalogPath, $AutoPatchLog,
        $ReadinessTimeoutSeconds
    try {
        $process = Start-Process (Get-PowerShellHostPath) `
            -ArgumentList $arguments -WindowStyle Hidden -Wait -PassThru
    } catch {
        Write-AutoPatchLog "watcher reason=$Reason child-error=$($_.Exception.Message)"
        return $false
    }
    if ($process.ExitCode -ne 0) {
        Write-AutoPatchLog "watcher reason=$Reason child-exit=$($process.ExitCode)"
        return $false
    }
    Write-AutoPatchLog "watcher reason=$Reason state=Completed"
    return $true
}

function Register-FileWatcherEvents {
    param(
        [IO.FileSystemWatcher]$Watcher,
        [string]$Prefix
    )
    foreach ($eventName in @('Changed', 'Created', 'Renamed', 'Error')) {
        Register-ObjectEvent -InputObject $Watcher -EventName $eventName `
            -SourceIdentifier "$Prefix.$eventName"
    }
}

function Watch-AutomaticUpdates {
    param(
        [string]$ApplicationRoot,
        [string]$UpdaterDataRoot,
        [string]$BackupBase,
        [string]$CatalogPath,
        [int]$ReconcileSeconds
    )

    $historyPath = Join-Path $UpdaterDataRoot 'updater_history.jsonl'
    $updaterWatcher = New-Object IO.FileSystemWatcher
    $updaterWatcher.Path = $UpdaterDataRoot
    $updaterWatcher.Filter = 'updater_history.jsonl*'
    $updaterWatcher.NotifyFilter = [IO.NotifyFilters]::FileName -bor
        [IO.NotifyFilters]::LastWrite -bor [IO.NotifyFilters]::Size
    $chromeWatcher = New-Object IO.FileSystemWatcher
    $chromeWatcher.Path = $ApplicationRoot
    $chromeWatcher.Filter = 'chrome.dll'
    $chromeWatcher.IncludeSubdirectories = $true
    $chromeWatcher.NotifyFilter = [IO.NotifyFilters]::FileName -bor
        [IO.NotifyFilters]::LastWrite -bor [IO.NotifyFilters]::Size
    $updaterWatcher.InternalBufferSize = 65536
    $chromeWatcher.InternalBufferSize = 65536
    $sourceIds = @(
        'ChromiumMV2.Updater.Changed', 'ChromiumMV2.Updater.Created',
        'ChromiumMV2.Updater.Renamed', 'ChromiumMV2.Updater.Error',
        'ChromiumMV2.Chrome.Changed', 'ChromiumMV2.Chrome.Created',
        'ChromiumMV2.Chrome.Renamed', 'ChromiumMV2.Chrome.Error'
    )
    try {
        Register-FileWatcherEvents $updaterWatcher 'ChromiumMV2.Updater' | Out-Null
        Register-FileWatcherEvents $chromeWatcher 'ChromiumMV2.Chrome' | Out-Null
        $updaterWatcher.EnableRaisingEvents = $true
        $chromeWatcher.EnableRaisingEvents = $true
        $completion = Get-GoogleUpdaterCompletion $historyPath
        $lastMarker = if ($completion) { $completion.Marker } else { '' }
        $lastTarget = ''
        Write-AutoPatchLog "watcher started chrome=$ApplicationRoot updater=$UpdaterDataRoot"
        if (Invoke-WatcherPatch 'startup' $ApplicationRoot $BackupBase $CatalogPath) {
            try { $lastTarget = Get-LatestChromeDll $ApplicationRoot } catch {}
        }

        while ($true) {
            $firstEvent = Wait-Event -Timeout $ReconcileSeconds
            if (-not $firstEvent) { continue }

            Start-Sleep -Milliseconds 750
            $events = @(Get-Event | Where-Object {
                $sourceIds -contains $_.SourceIdentifier
            })
            if ($events.Count -eq 0) { $events = @($firstEvent) }
            foreach ($queued in $events) {
                Remove-Event -EventIdentifier $queued.EventIdentifier -ErrorAction SilentlyContinue
            }

            $reason = @()
            $updaterEvents = @($events | Where-Object {
                $_.SourceIdentifier -like 'ChromiumMV2.Updater.*'
            })
            if ($updaterEvents.Count -gt 0) {
                $newCompletion = Get-GoogleUpdaterCompletion $historyPath
                if ($newCompletion -and $newCompletion.Marker -ne $lastMarker) {
                    $lastMarker = $newCompletion.Marker
                    $reason += "updater-history-$($newCompletion.Version)"
                }
                if (@($updaterEvents | Where-Object {
                    $_.SourceIdentifier -eq 'ChromiumMV2.Updater.Error'
                }).Count -gt 0) {
                    $reason += 'updater-watcher-error'
                }
            }

            foreach ($chromeEvent in @($events | Where-Object {
                $_.SourceIdentifier -like 'ChromiumMV2.Chrome.*'
            })) {
                if ($chromeEvent.SourceIdentifier -eq 'ChromiumMV2.Chrome.Error') {
                    $reason += 'chrome-watcher-error'
                    continue
                }
                $reason += 'chrome-file'
                break
            }
            if ($reason.Count -gt 0) {
                $currentTarget = ''
                try { $currentTarget = Get-LatestChromeDll $ApplicationRoot } catch {}
                if (-not $currentTarget -or -not [string]::Equals(
                    $currentTarget, $lastTarget, [StringComparison]::OrdinalIgnoreCase)) {
                    if (Invoke-WatcherPatch (($reason | Select-Object -Unique) -join '+') `
                        $ApplicationRoot $BackupBase $CatalogPath) {
                        try { $lastTarget = Get-LatestChromeDll $ApplicationRoot } catch {}
                    }
                } else {
                    $handledReason = ($reason | Select-Object -Unique) -join '+'
                    Write-AutoPatchLog "watcher reason=$handledReason state=AlreadyHandled"
                }
            }
        }
    } finally {
        foreach ($sourceId in $sourceIds) {
            Unregister-Event -SourceIdentifier $sourceId -ErrorAction SilentlyContinue
            Get-Event -SourceIdentifier $sourceId -ErrorAction SilentlyContinue |
                Remove-Event -ErrorAction SilentlyContinue
        }
        $updaterWatcher.Dispose()
        $chromeWatcher.Dispose()
        Write-AutoPatchLog "watcher stopped chrome=$ApplicationRoot updater=$UpdaterDataRoot"
    }
}

function ConvertTo-CommandLine {
    param([string[]]$Arguments)
    return ($Arguments | ForEach-Object {
        '"' + ([string]$_).Replace('"', '\"') + '"'
    }) -join ' '
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Show-PatcherGui {
    if ([Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
        throw 'The GUI requires an STA PowerShell process.'
    }

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [Windows.Forms.Application]::EnableVisualStyles()

    $form = New-Object Windows.Forms.Form
    $form.Text = 'Chromium MV2 Patcher'
    $form.ClientSize = New-Object Drawing.Size(760, 720)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.Font = New-Object Drawing.Font('Segoe UI', 9)

    $title = New-Object Windows.Forms.Label
    $title.Text = 'Chromium MV2 Patcher'
    $title.Font = New-Object Drawing.Font('Segoe UI Semibold', 16)
    $title.AutoSize = $true
    $title.Location = New-Object Drawing.Point(18, 14)
    $form.Controls.Add($title)

    $targetLabel = New-Object Windows.Forms.Label
    $targetLabel.Text = '対象 chrome.dll'
    $targetLabel.AutoSize = $true
    $targetLabel.Location = New-Object Drawing.Point(20, 55)
    $form.Controls.Add($targetLabel)

    $targetBox = New-Object Windows.Forms.TextBox
    $targetBox.Location = New-Object Drawing.Point(20, 76)
    $targetBox.Size = New-Object Drawing.Size(570, 24)
    $form.Controls.Add($targetBox)

    $detectButton = New-Object Windows.Forms.Button
    $detectButton.Text = '自動検出'
    $detectButton.Location = New-Object Drawing.Point(598, 74)
    $detectButton.Size = New-Object Drawing.Size(70, 28)
    $form.Controls.Add($detectButton)

    $browseButton = New-Object Windows.Forms.Button
    $browseButton.Text = '参照'
    $browseButton.Location = New-Object Drawing.Point(674, 74)
    $browseButton.Size = New-Object Drawing.Size(66, 28)
    $form.Controls.Add($browseButton)

    $targetInfo = New-Object Windows.Forms.Label
    $targetInfo.Text = 'バージョン: 未検出'
    $targetInfo.AutoSize = $true
    $targetInfo.Location = New-Object Drawing.Point(20, 106)
    $form.Controls.Add($targetInfo)

    $newButton = {
        param([string]$Text, [int]$X, [int]$Y, [int]$Width = 165)
        $button = New-Object Windows.Forms.Button
        $button.Text = $Text
        $button.Location = New-Object Drawing.Point($X, $Y)
        $button.Size = New-Object Drawing.Size($Width, 34)
        $form.Controls.Add($button)
        return $button
    }

    $analyzeButton = & $newButton '状態を解析' 20 135 165
    $applyButton = & $newButton 'パッチを適用' 195 135 165
    $ramLaunchButton = & $newButton 'RAM起動を試す' 370 135 165
    $helpButton = & $newButton 'CLIヘルプ' 575 135 165

    $backupProfileBox = New-Object Windows.Forms.CheckBox
    $backupProfileBox.Text = 'RAM起動前に拡張機能と関連設定をバックアップ'
    $backupProfileBox.Checked = $true
    $backupProfileBox.AutoSize = $true
    $backupProfileBox.Location = New-Object Drawing.Point(20, 177)
    $form.Controls.Add($backupProfileBox)

    $chromeArgumentsLabel = New-Object Windows.Forms.Label
    $chromeArgumentsLabel.Text = 'ブラウザ起動引数（Windows形式、空白区切り）'
    $chromeArgumentsLabel.AutoSize = $true
    $chromeArgumentsLabel.Location = New-Object Drawing.Point(20, 207)
    $form.Controls.Add($chromeArgumentsLabel)

    $chromeArgumentsBox = New-Object Windows.Forms.TextBox
    $chromeArgumentsBox.Location = New-Object Drawing.Point(20, 228)
    $chromeArgumentsBox.Size = New-Object Drawing.Size(720, 56)
    $chromeArgumentsBox.Multiline = $true
    $chromeArgumentsBox.ScrollBars = 'Vertical'
    $chromeArgumentsBox.AcceptsReturn = $true
    $form.Controls.Add($chromeArgumentsBox)

    $backupLabel = New-Object Windows.Forms.Label
    $backupLabel.Text = '適用済みバックアップ'
    $backupLabel.AutoSize = $true
    $backupLabel.Location = New-Object Drawing.Point(20, 296)
    $form.Controls.Add($backupLabel)

    $receiptBox = New-Object Windows.Forms.ComboBox
    $receiptBox.DropDownStyle = 'DropDownList'
    $receiptBox.DisplayMember = 'Display'
    $receiptBox.Location = New-Object Drawing.Point(20, 317)
    $receiptBox.Size = New-Object Drawing.Size(720, 25)
    $form.Controls.Add($receiptBox)

    $restoreButton = & $newButton 'DLLを復元' 20 352 165
    $restoreExtButton = & $newButton '拡張機能を復元' 195 352 165
    $restoreSettingsButton = & $newButton '保護設定ページを開く' 370 352 190

    $autoLabel = New-Object Windows.Forms.Label
    $autoLabel.Text = '自動適用: 確認中'
    $autoLabel.AutoSize = $true
    $autoLabel.Location = New-Object Drawing.Point(20, 400)
    $form.Controls.Add($autoLabel)

    $registerButton = & $newButton '自動適用を登録' 20 423 165
    $removeButton = & $newButton '自動適用を解除' 195 423 165

    $logLabel = New-Object Windows.Forms.Label
    $logLabel.Text = '実行結果'
    $logLabel.AutoSize = $true
    $logLabel.Location = New-Object Drawing.Point(20, 473)
    $form.Controls.Add($logLabel)

    $logBox = New-Object Windows.Forms.TextBox
    $logBox.Location = New-Object Drawing.Point(20, 494)
    $logBox.Size = New-Object Drawing.Size(720, 158)
    $logBox.Multiline = $true
    $logBox.ReadOnly = $true
    $logBox.ScrollBars = 'Vertical'
    $logBox.Font = New-Object Drawing.Font('Consolas', 9)
    $form.Controls.Add($logBox)

    $statusLabel = New-Object Windows.Forms.Label
    $statusLabel.Text = '待機中'
    $statusLabel.AutoSize = $true
    $statusLabel.Location = New-Object Drawing.Point(20, 664)
    $form.Controls.Add($statusLabel)

    $closeButton = & $newButton '閉じる' 640 670 100
    $operationButtons = @(
        $analyzeButton, $applyButton, $ramLaunchButton, $restoreButton, $restoreExtButton,
        $restoreSettingsButton, $registerButton, $removeButton,
        $detectButton, $browseButton
    )
    $state = [pscustomobject]@{
        Process = $null
        OutFile = $null
        ErrorFile = $null
        Captured = $false
        Action = ''
        Busy = $false
    }

    $writeLog = {
        param([string]$Text)
        if (-not [string]::IsNullOrWhiteSpace($Text)) {
            $logBox.AppendText($Text.TrimEnd() + [Environment]::NewLine)
            $logBox.SelectionStart = $logBox.TextLength
            $logBox.ScrollToCaret()
        }
    }
    $setBusy = {
        param([bool]$Busy)
        $state.Busy = $Busy
        foreach ($button in $operationButtons) { $button.Enabled = -not $Busy }
        $backupProfileBox.Enabled = -not $Busy
        $chromeArgumentsBox.Enabled = -not $Busy
        $closeButton.Enabled = -not $Busy
    }
    $refreshTarget = {
        try {
            if ([string]::IsNullOrWhiteSpace($targetBox.Text)) {
                $root = Resolve-ChromeApplicationRoot $null
                $targetBox.Text = Get-LatestChromeDll $root
            }
            if (-not (Test-Path -LiteralPath $targetBox.Text -PathType Leaf)) {
                $targetInfo.Text = 'バージョン: 対象が見つかりません'
                return
            }
            $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($targetBox.Text)
            $targetInfo.Text = "バージョン: $($version.FileVersion)    製品: $($version.ProductName)"
        } catch {
            $targetInfo.Text = 'バージョン: 自動検出できません'
            & $writeLog $_.Exception.Message
        }
    }
    $refreshReceipts = {
        $selectedPath = if ($receiptBox.SelectedItem) {
            [string]$receiptBox.SelectedItem.Path
        } else { '' }
        $receiptBox.Items.Clear()
        if (Test-Path -LiteralPath $BackupRoot -PathType Container) {
            foreach ($directory in Get-ChildItem -LiteralPath $BackupRoot -Directory |
                Sort-Object Name -Descending) {
                $path = Join-Path $directory.FullName 'receipt.json'
                if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
                try {
                    $record = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
                    if ($record.SchemaVersion -ne 1 -or $record.State -ne 'Applied') {
                        continue
                    }
                    $display = '{0}  {1}' -f $record.FileVersion,
                        ([DateTimeOffset]$record.AppliedUtc).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
                    [void]$receiptBox.Items.Add([pscustomobject]@{
                        Display = $display
                        Path = $path
                    })
                } catch {}
            }
        }
        if ($receiptBox.Items.Count -gt 0) {
            $match = 0
            for ($i = 0; $i -lt $receiptBox.Items.Count; $i++) {
                if ($receiptBox.Items[$i].Path -eq $selectedPath) { $match = $i; break }
            }
            $receiptBox.SelectedIndex = $match
        }
    }
    $refreshTasks = {
        try {
            $tasks = @(Get-ScheduledTask -TaskPath '\ChromiumMV2Patcher\' `
                -ErrorAction Stop)
            if ($tasks.Count -eq 0) {
                $autoLabel.Text = '自動適用: 未登録'
            } else {
                $autoLabel.Text = '自動適用: ' + (($tasks | ForEach-Object {
                    "$($_.TaskName)=$($_.State)"
                }) -join ' / ')
            }
        } catch {
            $autoLabel.Text = '自動適用: 未登録'
        }
    }
    $requireTarget = {
        if (Test-Path -LiteralPath $targetBox.Text -PathType Leaf) { return $true }
        [void][Windows.Forms.MessageBox]::Show($form,
            '有効な chrome.dll を指定してください。', '対象未指定',
            'OK', 'Warning')
        return $false
    }
    $selectedReceipt = {
        if ($receiptBox.SelectedItem) { return [string]$receiptBox.SelectedItem.Path }
        [void][Windows.Forms.MessageBox]::Show($form,
            '適用済みバックアップを選択してください。', 'バックアップ未選択',
            'OK', 'Warning')
        return $null
    }

    $timer = New-Object Windows.Forms.Timer
    $timer.Interval = 250
    $timer.Add_Tick({
        if (-not $state.Process -or -not $state.Process.HasExited) { return }
        $timer.Stop()
        $state.Process.WaitForExit()
        $exitCode = $state.Process.ExitCode
        if ($state.Captured) {
            $output = if (Test-Path -LiteralPath $state.OutFile) {
                Get-Content -LiteralPath $state.OutFile -Raw -ErrorAction SilentlyContinue
            } else { '' }
            $errors = if (Test-Path -LiteralPath $state.ErrorFile) {
                Get-Content -LiteralPath $state.ErrorFile -Raw -ErrorAction SilentlyContinue
            } else { '' }
            & $writeLog ($output + $errors)
        }
        & $writeLog ("[$($state.Action)] 終了コード: $exitCode")
        $statusLabel.Text = if ($exitCode -eq 0) {
            "$($state.Action)が完了しました"
        } else { "$($state.Action)に失敗しました" }
        foreach ($path in @($state.OutFile, $state.ErrorFile)) {
            if ($path -and (Test-Path -LiteralPath $path)) {
                Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
            }
        }
        $state.Process.Dispose()
        $state.Process = $null
        & $setBusy $false
        & $refreshTarget
        & $refreshReceipts
        & $refreshTasks
    })
    $startOperation = {
        param(
            [string]$Label,
            [string[]]$Arguments,
            [bool]$NeedsAdministrator
        )
        if ($state.Busy) { return }
        $allArguments = @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath
        ) + $Arguments
        $start = @{
            FilePath = Get-PowerShellHostPath
            ArgumentList = ConvertTo-CommandLine $allArguments
            PassThru = $true
            WindowStyle = 'Hidden'
        }
        $capture = -not $NeedsAdministrator -or (Test-Administrator)
        if ($capture) {
            $state.OutFile = Join-Path ([IO.Path]::GetTempPath()) `
                ("ChromiumMV2Gui-{0}.out" -f [guid]::NewGuid())
            $state.ErrorFile = Join-Path ([IO.Path]::GetTempPath()) `
                ("ChromiumMV2Gui-{0}.err" -f [guid]::NewGuid())
            $start.RedirectStandardOutput = $state.OutFile
            $start.RedirectStandardError = $state.ErrorFile
        } else {
            $state.OutFile = $null
            $state.ErrorFile = $null
            $start.Verb = 'RunAs'
        }
        try {
            $state.Process = Start-Process @start
            $state.Captured = $capture
            $state.Action = $Label
            $statusLabel.Text = "$Label を実行中"
            & $writeLog "[$Label] 開始"
            & $setBusy $true
            $timer.Start()
        } catch {
            $statusLabel.Text = "$Label を開始できませんでした"
            & $writeLog $_.Exception.Message
        }
    }

    $detectButton.Add_Click({
        $targetBox.Clear()
        & $refreshTarget
    })
    $browseButton.Add_Click({
        $dialog = New-Object Windows.Forms.OpenFileDialog
        $dialog.Filter = 'Chrome DLL (chrome.dll)|chrome.dll|DLL (*.dll)|*.dll'
        $dialog.CheckFileExists = $true
        if ($dialog.ShowDialog($form) -eq 'OK') {
            $targetBox.Text = $dialog.FileName
            & $refreshTarget
        }
        $dialog.Dispose()
    })
    $analyzeButton.Add_Click({
        if (-not (& $requireTarget)) { return }
        & $startOperation -Label '状態解析' -Arguments @(
            '-Target', $targetBox.Text, '-BackupRoot', $BackupRoot,
            '-SignatureCatalog', $SignatureCatalog
        ) -NeedsAdministrator $false
    })
    $applyButton.Add_Click({
        if (-not (& $requireTarget)) { return }
        if ([Windows.Forms.MessageBox]::Show($form,
            'Chromeを終了してから適用してください。バックアップ作成後にDLLを書き換えます。続行しますか。',
            'パッチを適用', 'YesNo', 'Warning') -ne 'Yes') { return }
        & $startOperation -Label 'パッチ適用' -Arguments @(
            '-Target', $targetBox.Text, '-Apply', '-BackupRoot', $BackupRoot,
            '-SignatureCatalog', $SignatureCatalog
        ) -NeedsAdministrator $true
    })
    $ramLaunchButton.Add_Click({
        if (-not (& $requireTarget)) { return }
        if ([Windows.Forms.MessageBox]::Show($form,
            '対象ブラウザを完全に終了してから実行してください。検証済みパッチを起動したブラウザのメモリだけに適用し、DLLは変更しません。続行しますか。',
            'RAM起動', 'YesNo', 'Information') -ne 'Yes') { return }
        $arguments = @(
            '-RamLaunch', '-Target', $targetBox.Text, '-BackupRoot', $BackupRoot,
            '-SignatureCatalog', $SignatureCatalog
        )
        if ($backupProfileBox.Checked) { $arguments += '-BackupProfile' }
        $chromeArguments = $chromeArgumentsBox.Text.Trim()
        if ($chromeArguments) {
            $encoded = [Convert]::ToBase64String(
                [Text.Encoding]::UTF8.GetBytes($chromeArguments))
            $arguments += @('-ChromeArgumentsBase64', $encoded)
        }
        & $startOperation -Label 'RAM起動' -Arguments $arguments `
            -NeedsAdministrator $false
    })
    $restoreButton.Add_Click({
        $receipt = & $selectedReceipt
        if (-not $receipt) { return }
        if ([Windows.Forms.MessageBox]::Show($form,
            'Chromeを終了してから復元してください。選択したバックアップを最新のChromeへ復元します。続行しますか。',
            'DLLを復元', 'YesNo', 'Warning') -ne 'Yes') { return }
        $arguments = @('-Restore', '-Receipt', $receipt, '-BackupRoot', $BackupRoot)
        if (Test-Path -LiteralPath $targetBox.Text -PathType Leaf) {
            $arguments += @('-BrowserRoot', (Get-PatchLockRoot $targetBox.Text))
        }
        & $startOperation -Label 'DLL復元' -Arguments $arguments `
            -NeedsAdministrator $true
    })
    $restoreExtButton.Add_Click({
        $receipt = & $selectedReceipt
        if (-not $receipt) { return }
        & $startOperation -Label '拡張機能復元' -Arguments @(
            '-RestoreExt', '-Receipt', $receipt,
            '-SignatureCatalog', $SignatureCatalog
        ) -NeedsAdministrator $false
    })
    $restoreSettingsButton.Add_Click({
        $receipt = & $selectedReceipt
        if (-not $receipt) { return }
        & $startOperation -Label '保護設定ページ' -Arguments @(
            '-RestoreExtSettings', '-Receipt', $receipt,
            '-SignatureCatalog', $SignatureCatalog
        ) -NeedsAdministrator $false
    })
    $registerButton.Add_Click({
        if (-not (& $requireTarget)) { return }
        & $startOperation -Label '自動適用登録' -Arguments @(
            '-AutoPatch', '-BrowserRoot', (Get-PatchLockRoot $targetBox.Text),
            '-BackupRoot', $BackupRoot, '-SignatureCatalog', $SignatureCatalog
        ) -NeedsAdministrator $true
    })
    $removeButton.Add_Click({
        if ([Windows.Forms.MessageBox]::Show($form,
            '自動適用タスクを停止して削除します。続行しますか。',
            '自動適用を解除', 'YesNo', 'Warning') -ne 'Yes') { return }
        & $startOperation -Label '自動適用解除' `
            -Arguments @('-RemoveAutoPatch') -NeedsAdministrator $true
    })
    $helpButton.Add_Click({
        [void][Windows.Forms.MessageBox]::Show($form,
            "引数付きのCLI操作は従来どおり利用できます。`n`n詳細: Get-Help .\chromium_mv2_patch.ps1 -Detailed",
            'CLIヘルプ', 'OK', 'Information')
    })
    $closeButton.Add_Click({ $form.Close() })
    $form.Add_FormClosing({
        param($sender, $eventArgs)
        if ($state.Busy) {
            $eventArgs.Cancel = $true
            [void][Windows.Forms.MessageBox]::Show($form,
                '処理が完了するまで待ってください。', '処理中', 'OK', 'Information')
        }
    })

    & $refreshTarget
    & $refreshReceipts
    & $refreshTasks
    [void]$form.ShowDialog()
    $timer.Dispose()
    $form.Dispose()
}

if ($showGui) {
    if (-not $Gui) {
        $guiArguments = ConvertTo-CommandLine @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Sta', '-WindowStyle', 'Hidden',
            '-File', $PSCommandPath, '-Gui'
        )
        Start-Process (Get-PowerShellHostPath) -ArgumentList $guiArguments | Out-Null
    } else {
        Show-PatcherGui
    }
    return
}

if ($RemoveAutoPatch) {
    Remove-AutoPatchTasks
    return
}
if ($Restore) {
    if ([string]::IsNullOrWhiteSpace($Receipt)) {
        $Receipt = Get-LatestBackupReceipt $BackupRoot
    }
    Invoke-ReceiptRestore $Receipt $BrowserRoot
    return
}
if ($RestoreExtSettings) {
    Invoke-ExtensionProtectedSettingsRestore $Receipt
    return
}
$resolvedCatalog = (Resolve-Path -LiteralPath $SignatureCatalog).Path
if ($RestoreExt) {
    Invoke-ExtensionRestore $Receipt $resolvedCatalog
    return
}
if ($RamLaunch) {
    if ([string]::IsNullOrWhiteSpace($Target)) {
        $applicationRoot = Resolve-ChromeApplicationRoot $BrowserRoot
        $Target = Get-LatestChromeDll $applicationRoot
    }
    $lockRoot = Get-PatchLockRoot $Target
    Invoke-WithPatchMutex $lockRoot {
        Invoke-RamLaunch $Target $BackupRoot $resolvedCatalog `
            -BackupProfile:$BackupProfile -ChromeArguments $ChromeArguments `
            -BrowserExecutable $BrowserExecutable
    }
    return
}
if ($AutoPatch -or $HandleUpdateEvent -or $WatchUpdates -or $PatchLatestOnce) {
    $applicationRoot = Resolve-ChromeApplicationRoot $BrowserRoot
    if ($AutoPatch) {
        Register-AutoPatchTasks $applicationRoot $BackupRoot $resolvedCatalog
        try {
            Invoke-AutoPatchCore $applicationRoot $BackupRoot $resolvedCatalog
        } finally {
            Start-AutoPatchWatcherTask
        }
    } elseif ($HandleUpdateEvent) {
        Invoke-AutoPatchCore $applicationRoot $BackupRoot $resolvedCatalog `
            -RefreshRegistration -WaitForReady `
            -ReadyTimeoutSeconds $ReadinessTimeoutSeconds
    } elseif ($WatchUpdates) {
        $updaterData = Resolve-GoogleUpdaterDataRoot $UpdaterRoot
        Watch-AutomaticUpdates $applicationRoot $updaterData $BackupRoot `
            $resolvedCatalog $ReconcileIntervalSeconds
    } else {
        Invoke-AutoPatchCore $applicationRoot $BackupRoot $resolvedCatalog `
            -WaitForReady -ReadyTimeoutSeconds $ReadinessTimeoutSeconds
    }
    return
}

if ($Apply -and [string]::IsNullOrWhiteSpace($Target)) {
    $applicationRoot = Resolve-ChromeApplicationRoot $BrowserRoot
    $Target = Get-LatestChromeDll $applicationRoot
}

if ($Apply) {
    $lockRoot = Get-PatchLockRoot $Target
    Invoke-WithPatchMutex $lockRoot {
        Invoke-PatchTarget $Target -InPlace -BackupBase $BackupRoot `
            -CatalogPath $resolvedCatalog -BackupExtensions
    }
} else {
    Invoke-PatchTarget $Target -OutputPath $Output -BackupBase $BackupRoot `
        -CatalogPath $resolvedCatalog
}
