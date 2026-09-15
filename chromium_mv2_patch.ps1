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
            $ranges += [pscustomobject]@{ Start = [long]$rawOffset; Length = [long]$rawSize; VirtualAddress = [long][BitConverter]::ToUInt32($sectionBytes, $entry + 12) }
        }
    }
    if ($ranges.Count -eq 0) { throw 'PE file has no executable sections.' }
    $imageBase = [uint64]0
    if ($machine -eq 0x8664) {
        $optional = Read-StreamRange $Stream ($peOffset + 24) $optionalSize
        if ($null -eq $optional -or $optional.Length -lt 32 -or [BitConverter]::ToUInt16($optional, 0) -ne 0x20b) { throw 'Invalid x64 optional header.' }
        $imageBase = [BitConverter]::ToUInt64($optional, 24)
    }
    return [pscustomobject]@{ Machine = [int]$machine; ExecutableRanges = $ranges; ImageBase = $imageBase }
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

    return Complete-TargetAnalysis $Path $peInfo $validProfiles[0] (Get-ByteArraySha256 $Bytes)
}

function Complete-TargetAnalysis {
    param([string]$Path,$peInfo,$selected,[string]$hash)
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

# Streamed detection and bounded x64 control-flow recognition.
if (-not ('Mv2SmallScan' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class Mv2SmallScan {
    static int Immediate(byte[] b, int p, int end) {
        if (p+8 >= end || b[p] != 0x83 || (b[p+1]&0x38) != 0x38) return -1;
        int mod=b[p+1]>>6, rm=b[p+1]&7, q=p+2;
        if(mod!=3 && rm==4) { int sib=b[q++]; if(mod==0 && (sib&7)==5) q+=4; }
        if(mod==0 && rm==5) q+=4;
        if(mod==1) q++; else if(mod==2) q+=4;
        return q;
    }
    // Same conservative byte prefilter as V4, with sparse searches and early success.
    public static long[] Seeds(byte[] b, int start, int length) {
        var hits=new List<long>(); int end=checked(start+length), p=start;
        while(p<end-264) {
            p=Array.IndexOf(b,(byte)0x83,p,end-264-p); if(p<0) break;
            int q=Immediate(b,p,end);
            if(q>=0 && b[q]==2) {
                int bits=0; bool typeMask=false;
                for(int k=q+1;k<q+257;k++) {
                    if(k+3<end && b[k]==10 && b[k+1]==1 && b[k+2]==0 && b[k+3]==0) typeMask=true; int v=Immediate(b,k,end); if(v<0) continue;
                    if(b[v]==1) bits|=1; else if(b[v]==5) bits|=2; else if(b[v]==10) bits|=4;
                    if(bits==7 || (bits==6 && typeMask)) break;
                }
                if(bits==7 || (bits==6 && typeMask)) {
                    int seed=p;
                    if(p>start && b[p-1]>=0x40 && b[p-1]<=0x4f) seed--;
                    if(seed>=2 && b[seed-2]==0x31 && b[seed-1]==0xc0) seed-=2; hits.Add(seed);
                    if(hits.Count>64) throw new InvalidOperationException("Broad candidate budget exceeded");
                }
            }
            p++;
        }
        return hits.ToArray();
    }
    public static long[] Masked(byte[] b, byte[] values, byte[] masks, int length) {
        if(values.Length==0 || values.Length!=masks.Length || length>b.Length) throw new ArgumentException("Pattern/buffer shape");
        int anchor=-1, best=0, run=0;
        for(int i=0;i<masks.Length;i++) {
            run=masks[i]==255 ? run+1 : 0;
            if(run>best) { best=run; anchor=i-run+1; }
        }
        if(anchor<0) throw new ArgumentException("A fully fixed anchor is required");
        var hits=new List<long>(); int at=0, limit=length-values.Length;
        while(at<=limit) {
            int found=Array.IndexOf(b,values[anchor],at+anchor,limit-at+1);
            if(found<0) break;
            at=found-anchor;
            bool ok=true;
            for(int i=0;i<values.Length;i++) if((b[at+i]&masks[i])!=values[i]) {ok=false;break;}
            if(ok) {hits.Add(at); if(hits.Count>1024) throw new InvalidOperationException("Pattern candidate budget exceeded");}
            at++;
        }
        return hits.ToArray();
    }
    public static long[] Reasons(byte[] b, int length) {
        var hits=new List<long>();
        for(int p=0;p+8<=length;p++) {
            p=Array.IndexOf(b,(byte)0xc7,p,length-7-p);
            if(p<0) break;
            if(b[p+1]!=0x44 || b[p+2]!=0x24 || b[p+4]!=0 || b[p+5]!=0 || b[p+6]!=0 || b[p+7]!=2) continue;
            for(int q=Math.Max(0,p-32);q+2<p;q++) {
                if(!((b[q]==0x89 && (b[q+1]&0xc7)==0xc1) || (b[q]==0x8b && (b[q+1]&0xf8)==0xc8))) continue;
                int at=q+2; while(at<p && b[at]==0x90) at++;
                if(at+5>p || b[at]!=0xe8) continue;
                int seed=q; if(q>0 && b[q-1]>=0x40 && b[q-1]<=0x47) seed--;
                hits.Add(seed); if(hits.Count>64) throw new InvalidOperationException("Reason candidate budget exceeded");
            }
        }
        return hits.ToArray();
    }}



// Windows DbgEng COM slots from the published IDebugClient/Control/Symbols ABI.
// Only file-backed targets are opened. No process attach or execution API is exposed.
public sealed class Mv2NativeDisassembler : IDisposable {
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int QueryInterfaceCall(IntPtr self, ref Guid iid, out IntPtr result);
    [DllImport("dbgeng.dll", ExactSpelling=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int DebugCreate(ref Guid iid, out IntPtr client);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int TextCall(IntPtr self, [MarshalAs(UnmanagedType.LPStr)] string text);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int UIntCall(IntPtr self, uint value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int WaitCall(IntPtr self, uint flags, uint timeout);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int ModuleCall(IntPtr self, uint index, out ulong address);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int DisassembleCall(IntPtr self, ulong address, uint flags,
        [Out, MarshalAs(UnmanagedType.LPStr)] StringBuilder text, uint capacity,
        out uint used, out ulong end);
    private IntPtr client, control, symbols;
    private DisassembleCall disassemble;
    private readonly StringBuilder instructionText = new StringBuilder(512);
    private static readonly System.Text.RegularExpressions.Regex instructionPattern =
        new System.Text.RegularExpressions.Regex(@"^\S+\s+([0-9a-f]+)\s+(\S+)\s*(.*)$",
            System.Text.RegularExpressions.RegexOptions.CultureInvariant);
    public ulong ImageBase { get; private set; }
    public Mv2NativeDisassembler(string path) {
        try {
            path = System.IO.Path.GetFullPath(path);
            Guid id = new Guid("27fe5639-8407-4f47-8364-ee118fb08ac8");
            Check(DebugCreate(ref id, out client), "DebugCreate");
            id = new Guid("5182e668-105e-416e-ad92-24ef800424ba");
            Check(Call<QueryInterfaceCall>(client, 0)(client, ref id, out control), "IDebugControl");
            id = new Guid("8c31e98c-983a-48a5-9016-6fe5d667a950");
            Check(Call<QueryInterfaceCall>(client, 0)(client, ref id, out symbols), "IDebugSymbols");
            // No network paths, shell commands, managed support or execution.
            // Image mapping needs module loading, but the symbol search path stays empty.
            Check(Call<UIntCall>(control, 54)(control, 0x00015008), "AddEngineOptions");
            Check(Call<TextCall>(symbols, 41)(symbols, ""), "SetSymbolPath");
            Check(Call<TextCall>(symbols, 44)(symbols, System.IO.Path.GetDirectoryName(path)), "SetImagePath");
            Check(Call<TextCall>(client, 19)(client, path), "OpenDumpFile");
            Check(Call<WaitCall>(control, 93)(control, 0, 10000), "WaitForEvent");
            Check(Call<UIntCall>(control, 48)(control, 0x8664), "SetEffectiveProcessorType");
            disassemble = Call<DisassembleCall>(control, 26);
            ulong imageBase;
            Check(Call<ModuleCall>(symbols, 13)(symbols, 0, out imageBase), "GetModuleByIndex");
            ImageBase = imageBase;
        } catch { Dispose(); throw; }
    }
    private static T Call<T>(IntPtr instance, int slot) where T : class {
        IntPtr entry = Marshal.ReadIntPtr(Marshal.ReadIntPtr(instance), slot * IntPtr.Size);
        return Marshal.GetDelegateForFunctionPointer(entry, typeof(T)) as T;
    }
    private static void Check(int hr, string operation) {
        if (hr < 0) throw new InvalidOperationException(operation + ": 0x" + hr.ToString("X8"));
    }
    public Mv2NativeInstruction Decode(ulong address) {
        StringBuilder text = instructionText;
        text.Length = 0;
        uint used; ulong end;
        Check(disassemble(control, address, 0, text, (uint)text.Capacity, out used, out end), "Disassemble");
        if (end <= address || end - address > 15 || used > text.Capacity || text.ToString().Contains("???"))
            throw new InvalidOperationException("Invalid or truncated instruction: " + text.ToString());
        string value = text.ToString().Trim();
        var match = instructionPattern.Match(value);
        if (!match.Success) throw new InvalidOperationException("Unparsed: " + value);
        string op = match.Groups[2].Value, raw = match.Groups[1].Value;
        long? target = null;
        if (op == "call" || op.StartsWith("j", StringComparison.Ordinal)) {
            byte[] bytes = new byte[raw.Length / 2];
            for (int j = 0; j < bytes.Length; j++) bytes[j] = Convert.ToByte(raw.Substring(2*j, 2), 16);
            if (op == "call" && bytes[0] == 0xe8) target = checked((long)end + BitConverter.ToInt32(bytes, 1));
            if (op.StartsWith("j", StringComparison.Ordinal)) {
                if (bytes[0] == 0x0f && (bytes[1] & 0xf0) == 0x80) target = checked((long)end + BitConverter.ToInt32(bytes, 2));
                else if (bytes[0] == 0xe9) target = checked((long)end + BitConverter.ToInt32(bytes, 1));
                else if ((bytes[0] & 0xf0) == 0x70 || bytes[0] == 0xeb) target = checked((long)end + (bytes[1] < 128 ? bytes[1] : bytes[1] - 256));
                else throw new InvalidOperationException("Indirect branch rejected");
            }
        }
        return new Mv2NativeInstruction { Address = address, End = end, Text = value,
            Op = op, Args = match.Groups[3].Value, Target = target };
    }
    public void Dispose() {
        if (client != IntPtr.Zero) Call<UIntCall>(client, 26)(client, 0);
        if (symbols != IntPtr.Zero) { Marshal.Release(symbols); symbols = IntPtr.Zero; }
        if (control != IntPtr.Zero) { Marshal.Release(control); control = IntPtr.Zero; }
        if (client != IntPtr.Zero) { Marshal.Release(client); client = IntPtr.Zero; }
    }
}
public sealed class Mv2NativeInstruction {
    public ulong Address;
    public ulong End;
    public string Text;
    public string Op;
    public string Args;
    public long? Target;
}

public static class Mv2SnippetDump {
    // A synthetic dump of file bytes, never a snapshot of a running process.
    public static void Write(string path, byte[] source, long[] offsets, ulong[] addresses, ulong imageBase) {
        if (offsets.Length == 0 || offsets.Length != addresses.Length || offsets.Length > 64)
            throw new ArgumentException("Invalid snippet count");
        const int size = 4096, data = 4096;
        using (var f = File.Create(path)) using (var w = new BinaryWriter(f)) {
            f.SetLength(data + offsets.Length * size);
            w.Write(0x504d444dU); w.Write(0xa793U); w.Write(4U); w.Write(32U);
            f.Position = 32;
            foreach (uint n in new uint[] {7,56,80,3,52,136,5,(uint)(4+16*offsets.Length),2048,4,112,208}) w.Write(n);
            f.Position=80; w.Write((ushort)9);
            f.Position=86; w.Write((byte)1); w.Write((byte)1); w.Write(10U); w.Write(0U); w.Write(26100U); w.Write(2U);
            f.Position=136; w.Write(1U); w.Write(1U);
            f.Position=180; w.Write(1232U); w.Write(512U);
            f.Position=208; w.Write(1U); w.Write(imageBase); w.Write(0x20000000U);
            f.Position=232; w.Write(320U);
            f.Position=320; byte[] name=System.Text.Encoding.Unicode.GetBytes("branch-snippet.dll"); w.Write(name.Length); w.Write(name);
            f.Position=560; w.Write(0x100003U);
            f.Position=568; w.Write((ushort)0x33);
            f.Position=578; w.Write((ushort)0x2b); w.Write(0x202U);
            f.Position=664; w.Write(addresses[0]+1024);
            f.Position=760; w.Write(addresses[0]);
            f.Position=2048; w.Write((uint)offsets.Length);
            for(int i=0;i<offsets.Length;i++) {
                if (offsets[i]<0 || offsets[i]+size>source.LongLength) throw new ArgumentException("Truncated snippet");
                w.Write(addresses[i]); w.Write((uint)size); w.Write((uint)(data+i*size));
            }
            for(int i=0;i<offsets.Length;i++) { f.Position=data+i*size; w.Write(source,(int)offsets[i],size); }
        }
    }
}
'@
}

function Get-Mv2NativeRules {
    param([IO.FileStream]$Stream,$PeInfo,[string[]]$RuleNames)
    Set-StrictMode -Off
    $supported=@('skip-startup-disable','allow-install-policy-inline','allow-enable-and-report','allow-enable-policy-inline','allow-install','ignore-mv2-disable-reason-at-runtime')
    if(!$RuleNames.Count) {$RuleNames=$supported}
    if(@($RuleNames | Where-Object {$_ -notin $supported}).Count -or @($RuleNames | Sort-Object -Unique).Count -ne $RuleNames.Count) {throw 'Invalid native rule selection'}
    $traceReasons='ignore-mv2-disable-reason-at-runtime' -in $RuleNames
    $traceOriginal=@($RuleNames | Where-Object {$_ -in @('skip-startup-disable','allow-install-policy-inline')}).Count -gt 0
    $traceAdditional=@($RuleNames | Where-Object {$_ -in @('allow-enable-and-report','allow-enable-policy-inline','allow-install')}).Count -gt 0
    $traceManifests=$traceOriginal -or $traceAdditional
    $calleeCache=@{}
    $pe=$PeInfo; $imageBase=[uint64]$PeInfo.ImageBase; $Inspect=$false
    $nativeState=@{offset=0L;lo=[uint64]0;hi=[uint64]0;cache=@{};decodeCount=0;engine=$null}
    $dumpRoot=Join-Path ([IO.Path]::GetTempPath()) ('ChromiumMV2Trace-'+[guid]::NewGuid())
    New-Item -ItemType Directory -Path $dumpRoot | Out-Null
function Native-Next([uint64]$at,[hashtable]$state) {
    for($n=0;$n -lt 16;$n++) {
        $ins=Next-Real $at
        if($ins.Op -in @('mov','lea') -and $ins.Args -match '^(r\w+|e\w+),') {Apply-Copy $ins $state; $at=$ins.End; continue}
        if($ins.Op -eq 'xor' -and $ins.Args -match '^(e\w+|r[0-9]+d),\1$') {$state[(Canonical-Register $Matches[1])]='0'; $at=$ins.End; continue}
        return $ins
    }
    throw 'Extra copy budget exceeded'
}
function Native-ByteRegister([string]$reg) {
    $map=@{al='rax';cl='rcx';dl='rdx';bl='rbx';sil='rsi';dil='rdi';bpl='rbp';spl='rsp'}
    if($map.ContainsKey($reg)) {return $map[$reg]}
    if($reg -match '^(r[0-9]+)b$') {return $Matches[1]}
    throw 'Unsupported byte register'
}
function Native-FalseReturn([uint64]$at,[hashtable]$state) {
    $local=$state.Clone(); $ins=Native-Next $at $local
    if($ins.Op -ne 'ret' -or (Resolve-Value 'eax' $local) -ne '0') {throw 'No side-effect-free false return'}
    return $ins.Address
}
function Native-BranchPatch($guard) {
    $size=[int]($guard.End-$guard.Address); $raw=[byte[]]::new($size)
    if($guard.Op -eq 'jle') {for($i=0;$i -lt $size;$i++) {$raw[$i]=0x90}}
    elseif($guard.Op -eq 'jg' -and $size -eq 2) {$raw[0]=0xeb; $raw[1]=[byte](($guard.Target-$guard.End) -band 255)}
    elseif($guard.Op -eq 'jg' -and $size -eq 6) {
        $raw[0]=0x90; $raw[1]=0xe9
        [Array]::Copy([BitConverter]::GetBytes([int]($guard.Target-$guard.End)),0,$raw,2,4)
    } else {throw 'Unsupported extra branch encoding'}
    return ,$raw
}
function Native-TypeSet($first,[hashtable]$state,[uint64]$normal) {
    $branch=Next-Real $first.End
    if($first.Args -match '^(.+),8$' -and $branch.Op -eq 'ja') {
        $origin=Resolve-Value $Matches[1] $state
        if((Next-Real $branch.Target).Address -ne $normal) {throw 'Type range does not reject to normal path'}
        $mask=Next-Real $branch.End
        if($mask.Op -ne 'mov' -or $mask.Args -notmatch '^(e\w+|r[0-9]+d),10Ah$' -or (Canonical-Register $Matches[1]) -eq 'rax') {throw 'Unknown type bit mask'}
        $maskReg=Canonical-Register $Matches[1]; Apply-Copy $mask $state
        $bt=Next-Real $mask.End
        if($bt.Op -ne 'bt' -or $bt.Args -notmatch '^([^,]+),([^,]+)$') {throw 'No bounded type bit test'}
        if((Canonical-Register $Matches[1]) -ne $maskReg -or (Resolve-Value $Matches[2] $state) -ne $origin) {throw 'Type bit index changed'}
        $reject=Next-Real $bt.End
        if($reject.Op -ne 'jae' -or (Next-Real $reject.Target).Address -ne $normal) {throw 'Type bit rejection changed'}
        return [pscustomobject]@{Origin=$origin;Entry=(Next-Real $reject.End).Address;Offsets=@($first.Address);BitSet=$true}
    }
    $seen=@{}; $origin=$null; $entry=$null; $at=$first.Address; $offsets=@(); $equalState=$null
    for($i=0;$i -lt 3;$i++) {
        $cmp=Native-Next $at $state
        if($cmp.Op -ne 'cmp' -or $cmp.Args -notmatch '^(.+),(1|3|8)$') {throw 'Incomplete type membership'}
        $value=$Matches[2]; $valueOrigin=Resolve-Value $Matches[1] $state
        if($seen.ContainsKey($value) -or ($origin -and $origin -ne $valueOrigin)) {throw 'Type membership value mismatch'}
        $origin=$valueOrigin; $seen[$value]=$true; $offsets+=$cmp.Address
        $j=Next-Real $cmp.End
        if($j.Op -notin @('je','jne')) {throw 'Unsupported type equality'}
        $equal=if($j.Op -eq 'je') {$j.Target} else {$j.End}
        $other=if($j.Op -eq 'jne') {$j.Target} else {$j.End}
        $equal=(Next-Real $equal).Address
        if($entry -and $entry -ne $equal) {throw 'Type alternatives enter different paths'}
        $entry=$equal; $at=$other
        if($null -eq $equalState) {$equalState=$state.Clone()}
        else {
            foreach($key in @(@($equalState.Keys)+@($state.Keys) | Sort-Object -Unique)) {
                if((Resolve-Value $key $equalState) -ne (Resolve-Value $key $state)) {throw 'Type alternatives carry different values'}
            }
        }
    }
    if((Next-Real $at).Address -ne $normal) {throw 'Excluded type does not reach the normal path'}
    return [pscustomobject]@{Origin=$origin;Entry=$entry;Offsets=$offsets;BitSet=$false}
}
function Native-PolicyEffect([uint64]$bad,[uint64]$good,[uint64]$normal,[hashtable]$state) {
    $normalState=$state.Clone(); $normalJoin=Native-Next $normal $normalState
    if($normalJoin.Address -ne $good) {throw 'Policy normal path does not join cleanup'}
    $reason=Next-Real $bad
    if($reason.Op -ne 'mov' -or $reason.Args -notmatch '^(e\w+|r[0-9]+d),800000h$') {throw 'No MV2 disable reason'}
    $reasonReg=$Matches[1]
    $nullCheck=Next-Real $reason.End
    if($nullCheck.Op -ne 'test' -or $nullCheck.Args -notmatch '^(r\w+),\1$') {throw 'No reason-output null check'}
    $pointer=$Matches[1]; $skip=Next-Real $nullCheck.End
    if($skip.Op -ne 'je') {throw 'Reason output null branch changed'}
    $write=Next-Real $skip.End
    if($write.Op -ne 'mov' -or $write.Args -ne "dword ptr [$pointer],$reasonReg") {throw 'Reason output write changed'}
    $set=Next-Real $write.End
    if((Next-Real $skip.Target).Address -ne $set.Address -or $set.Op -ne 'mov' -or $set.Args -notmatch '^([^,]+),1$') {throw 'Policy result flag changed'}
    $resultReg=Native-ByteRegister $Matches[1]
    if((Resolve-Value $resultReg $normalState) -ne '0' -or (Resolve-Value $resultReg $state) -ne '0') {throw 'Policy unaffected result is not zero'}
    if((Next-Real $set.End).Address -ne $good) {throw 'Policy effect does not rejoin cleanup'}
    # One fall-through epilogue is checked; conditional cleanup/cookie paths are retained, not proved.
    $at=$good; $returned=$false; $copyFound=$false
    for($i=0;$i -lt 24;$i++) {
        $ins=Read-Instruction $at; $at=$ins.End
        if($ins.Op -eq 'ret') {$returned=$true; break}
        if($ins.Op -eq 'call' -or $ins.Op -eq 'jmp') {throw 'Unknown policy epilogue'}
        if($ins.Op -eq 'mov' -and $ins.Args -match '^eax,([^,]+)$') {
            if((Canonical-Register $Matches[1]) -ne $resultReg) {throw 'Policy returns a different value'}
            $copyFound=$true
        }
        if($ins.Op -notin @('cmp','test','push','pop','nop') -and $ins.Op -notmatch '^j' -and $ins.Args -match '^([re][a-z0-9]+),') {
            if((Canonical-Register $Matches[1]) -eq $resultReg) {throw 'Policy result overwritten before return'}
            if($copyFound -and (Canonical-Register $Matches[1]) -eq 'rax' -and $ins.Args -notmatch '^eax,') {throw 'Policy return register overwritten'}
        }
    }
    if(!$returned -or !$copyFound) {throw 'No bounded policy result return'}
    return [pscustomobject]@{ReasonOffset=$nativeState.offset+$reason.Address-$nativeState.lo;WriteOffset=$nativeState.offset+$write.Address-$nativeState.lo;CleanupRva=$good-$imageBase}
}
function Native-Manifest([uint64]$Address) {
    $state=@{}; $first=Native-Next $Address $state
    if($first.Op -ne 'cmp' -or $first.Args -notmatch '^(.+),2$') {throw 'No extra manifest comparison'}
    $manifest=Resolve-Value $Matches[1] $state; $prefixState=$state.Clone()
    $guard=Next-Real $first.End
    if($guard.Op -eq 'jg') {$normal=(Next-Real $guard.Target).Address; $at=$guard.End}
    elseif($guard.Op -eq 'jle') {$normal=(Next-Real $guard.End).Address; $at=$guard.Target}
    else {throw 'Unsupported extra manifest guard'}
    $override=$null; $ins=Native-Next $at $state
    if($ins.Op -eq 'cmp' -and $ins.Args -match '^(byte ptr \[.+\]),0$') {
        $overrideOrigin=Resolve-Value $Matches[1] $state
        $branch=Next-Real $ins.End
        if($branch.Op -notin @('je','jne')) {throw 'Unsupported object override'}
        $override=if($branch.Op -eq 'jne') {$branch.Target} else {$branch.End}
        $at=if($branch.Op -eq 'je') {$branch.Target} else {$branch.End}
        $ins=Native-Next $at $state
    }
    $typeState=$state.Clone(); $type=Native-TypeSet $ins $typeState $normal
    # Equality arms in the supported type chain have no copies; do not carry mismatch-arm state into them.
    if($type.BitSet) {$state=$typeState}
    $locationStart=$type.Entry
    if($override -and (Next-Real $override).Address -ne $locationStart) {throw 'Override bypasses the location filter'}
    $cmp=Native-Next $locationStart $state
    $locationOrigin=$null; $locations=@{}; $byteValues=@{}; $good=$null; $bad=$null; $policy=$false
    for($i=0;$i -lt 2;$i++) {
        if($cmp.Op -ne 'cmp' -or $cmp.Args -notmatch '^(.+),(5|0Ah)$') {throw 'No extra location comparison'}
        $value=$Matches[2]; $origin=Resolve-Value $Matches[1] $state
        if($locations.ContainsKey($value) -or ($locationOrigin -and $origin -ne $locationOrigin)) {throw 'Extra location value mismatch'}
        $locationOrigin=$origin; $locations[$value]=$cmp.Address
        $next=Next-Real $cmp.End
        if($next.Op -eq 'setne') {
            if($i -gt 0 -and $policy) {throw 'Mixed location encodings'}
            $byteValues[$next.Args]=$value
            $state[(Native-ByteRegister $next.Args)]='partial-byte-write'
            $at=$next.End
        } elseif($next.Op -in @('je','jne')) {
            if($byteValues.Count) {throw 'Mixed location encodings'}
            $policy=$true
            $equal=if($next.Op -eq 'je') {$next.Target} else {$next.End}
            $other=if($next.Op -eq 'jne') {$next.Target} else {$next.End}
            $equal=(Next-Real $equal).Address
            if($good -and $good -ne $equal) {throw 'Policy location exclusions disagree'}
            $good=$equal; $at=$other
        } else {throw 'Unsupported extra location result'}
        if($i -eq 0) {$cmp=Native-Next $at $state}
    }
    if($locationOrigin -eq $manifest -or $locationOrigin -eq $type.Origin -or $manifest -eq $type.Origin) {throw 'Aliased predicate inputs'}
    $memoryLocation=$locationOrigin -like 'dword ptr *'
    if($manifest -like 'dword ptr *') {
        if($type.Origin -notmatch '^dword ptr \[\{(.+)\}\+[0-9a-f]+h\]$') {throw 'Unknown type object'}
        $object=$Matches[1]
        if($locationOrigin -notmatch '^dword ptr \[\{(.+)\}\+[0-9a-f]+h\]$' -or $Matches[1] -ne $object) {throw 'Extra fields come from different objects'}
    } elseif(!$memoryLocation -and ($manifest -notmatch '^low32\(r\w+\)$' -or $type.Origin -notmatch '^low32\(r\w+\)$' -or $locationOrigin -notmatch '^low32\(r\w+\)$')) {throw 'Unknown direct predicate inputs'}
    $evidence=$null
    if($policy) {
        if(!$memoryLocation) {throw 'Policy location has no object origin'}
        $bad=(Next-Real $at).Address
        $evidence=Native-PolicyEffect $bad $good $normal $state
        $name='allow-enable-policy-inline'
    } else {
        $combine=Next-Real $at
        if($combine.Op -ne 'and' -or $combine.Args -notmatch '^([^,]+),([^,]+)$') {throw 'Location booleans are not intersected'}
        $dest=$Matches[1]; $src=$Matches[2]
        if(!$byteValues.ContainsKey($dest) -or !$byteValues.ContainsKey($src) -or $byteValues[$dest] -eq $byteValues[$src]) {throw 'Location conjunction lost an input'}
        $ret=Next-Real $combine.End
        if($dest -ne 'al') {
            if($ret.Op -ne 'mov' -or $ret.Args -ne "al,$dest") {throw 'Location conjunction is not returned'}
            $ret=Next-Real $ret.End
        }
        if($ret.Op -ne 'ret') {throw 'Boolean predicate has extra effects'}
        $normalRet=Native-FalseReturn $normal $prefixState
        if($normalRet -ne $ret.Address) {throw 'Boolean outcomes do not share their return'}
        $name=if($memoryLocation) {'allow-enable-and-report'} else {'allow-install'}
        $evidence=[pscustomobject]@{ReturnRva=$ret.Address-$imageBase;TypeBitSet=$type.BitSet}
    }
    return [pscustomobject]@{Name=$name;Offset=$nativeState.offset;PatchOffset=$nativeState.offset+$guard.Address-$nativeState.lo;
        Replacement=(Native-BranchPatch $guard);ExtraEvidence=$evidence;Manifest=$manifest;Type=$type.Origin;Location=$locationOrigin;
        FiveOffset=$nativeState.offset+$locations['5']-$nativeState.lo;TenOffset=$nativeState.offset+$locations['0Ah']-$nativeState.lo;
        TypeOffsets=@($type.Offsets | ForEach-Object {$nativeState.offset+$_-$nativeState.lo});CallRva=$null;NormalCallRva=$null}
}
function Native-Integer([string]$text) {
    if($text -match '^([0-9a-f]+)h$') {return [long][Convert]::ToUInt64($Matches[1],16)}
    if($text -match '^\d+$') {return [long]$text}
    throw 'Unknown integer'
}
function Native-Scalar([string]$text,[hashtable]$registers) {
    if($text -eq 'al') {if(!$registers.ContainsKey('rax')) {throw 'Undefined scalar return'}; return [long]$registers.rax -band 255}
    if($text -match '^(r\w+|e\w+)$') {
        $reg=Canonical-Register $text
        if(!$registers.ContainsKey($reg)) {throw 'Undefined scalar input'}
        $value=[long]$registers[$reg]
        if($text -match '^(e\w+|r[0-9]+d)$') {$value=$value -band 0xffffffffL}
        return $value
    }
    return Native-Integer $text
}
function Native-EvaluateValidator([uint64]$entry,[long]$value) {
    $registers=@{rcx=($value -band 0xffffffffL)}; $at=$entry; $seen=@{}; $equal=$null; $less=$null; $unsignedLess=$null; $carry=$null
    for($step=0;$step -lt 64;$step++) {
        if($seen.ContainsKey($at)) {throw 'Validator execution cycle'}; $seen[$at]=$true
        $ins=Read-Instruction $at; $at=$ins.End; $parts=$ins.Args.Split(',')
        switch($ins.Op) {
            'ret' {return Native-Scalar 'al' $registers}
            'nop' {}
            'jmp' {$at=$ins.Target}
            'mov' {
                $scalar=Native-Scalar $parts[1] $registers
                $dest=if($parts[0] -eq 'al') {'rax'} else {Canonical-Register $parts[0]}
                $registers[$dest]=$scalar
            }
            'xor' {$registers[(Canonical-Register $parts[0])]=0L; $equal=$true; $less=$false; $unsignedLess=$false; $carry=$false}
            'cmp' {
                $left=(Native-Scalar $parts[0] $registers) -band 0xffffffffL
                $right=(Native-Scalar $parts[1] $registers) -band 0xffffffffL
                $signedLeft=if($left -ge 0x80000000L) {$left-0x100000000L} else {$left}
                $signedRight=if($right -ge 0x80000000L) {$right-0x100000000L} else {$right}
                $equal=$left -eq $right; $less=$signedLeft -lt $signedRight; $unsignedLess=$left -lt $right; $carry=$unsignedLess
            }
            'bt' {
                $bits=Native-Scalar $parts[0] $registers
                $width=if($parts[0] -match '^(e\w+|r[0-9]+d)$') {32} else {64}
                $bit=(Native-Scalar $parts[1] $registers) -band ($width-1)
                $carry=($bits -band (1L -shl $bit)) -ne 0
            }
            default {
                $take=switch($ins.Op) {
                    'je' {$equal} 'jne' {!$equal} 'jg' {!$equal -and !$less} 'jle' {$equal -or $less}
                    'ja' {!$equal -and !$unsignedLess} 'jbe' {$equal -or $unsignedLess} 'jae' {!$carry} 'jb' {$carry}
                    default {throw 'Unknown scalar validator instruction'}
                }
                if($null -eq $take) {throw 'Undefined validator flags'}
                if($take) {$at=$ins.Target}
            }
        }
    }
    throw 'Validator execution budget exceeded'
}
function Native-Validator([uint64]$entry) {
    # Accept only a finite, side-effect-free integer decision graph. Sentinel checks supplement its shape.
    $colors=@{}; $pending=[Collections.Generic.Stack[object]]::new(); $pending.Push(@($entry,$false))
    $hasMv2=$false; $hasTrue=$false; $hasFalse=$false; $returns=0
    while($pending.Count) {
        $item=$pending.Pop(); $at=[uint64]$item[0]
        if($item[1]) {$colors[$at]=2; continue}
        if($colors[$at] -eq 1) {throw 'Validator graph has a cycle'}
        if($colors[$at] -eq 2) {continue}
        if($colors.Count -ge 96) {throw 'Validator graph budget exceeded'}
        $colors[$at]=1; $ins=Read-Instruction $at; $edges=@($ins.End)
        $pending.Push(@($at,$true))
        switch($ins.Op) {
            'ret' {$returns++; $edges=@()}
            'nop' {}
            'mov' {
                if($ins.Args -match '^al,([01])$') {if($Matches[1] -eq '1') {$hasTrue=$true} else {$hasFalse=$true}}
                elseif($ins.Args -eq 'ecx,ecx') {}
                elseif($ins.Args -match '^(rdx|edx|r8|r8d|r9|r9d),[0-9a-f]+h?$') {}
                else {throw 'Validator has an unknown move'}
            }
            'xor' {if($ins.Args -ne 'eax,eax') {throw 'Validator has an unknown write'}; $hasFalse=$true}
            'cmp' {if($ins.Args -notmatch '^ecx,([0-9a-f]+h?)$') {throw 'Validator compares an unknown input'}; if((Native-Integer $Matches[1]) -eq 0x800000) {$hasMv2=$true}}
            'bt' {if($ins.Args -notmatch '^(rdx|edx|r8|r8d|r9|r9d),(rcx|ecx)$') {throw 'Validator has an unknown bit test'}}
            'jmp' {$edges=@($ins.Target)}
            default {if($ins.Op -notin @('je','jne','jg','jle','ja','jbe','jae','jb')) {throw 'Validator has effects or unsupported instructions'}; $edges+=,$ins.Target}
        }
        foreach($edge in $edges) {$pending.Push(@([uint64]$edge,$false))}
    }
    if(!$hasMv2 -or !$hasTrue -or !$hasFalse -or !$returns) {throw 'Not a reason validator shape'}
    $samples=@()
    foreach($sample in @(0L,1L,3L,6L,0x800000L,0x2000000L,0x7fffffffL,0x80000000L,0xffffffffL)) {
        $wanted=if($sample -in @(0L,1L,0x800000L,0x2000000L)) {1} else {0}
        $got=Native-EvaluateValidator $entry $sample
        if($got -ne $wanted) {throw "Reason validator sentinel mismatch: $sample"}
        $samples+=[pscustomobject]@{Input=$sample;Return=$got}
    }
    return [pscustomobject]@{Kind='reason-validator';Instructions=$colors.Count;Samples=$samples}
}
function Native-Callee([uint64]$rva,[string]$kind) {
    $cacheKey=$kind+':'+$rva
    if($calleeCache.ContainsKey($cacheKey)) {return $calleeCache[$cacheKey]}
    $saved=$nativeState.Clone()
    try {
        $section=@($pe.ExecutableRanges | Where-Object {$rva -ge $_.VirtualAddress -and $rva -lt $_.VirtualAddress+$_.Length})
        if($section.Count -ne 1) {throw 'Extra callee is not executable'}
        $calleeOffset=$section[0].Start+$rva-$section[0].VirtualAddress
        if($kind -eq 'reason-insert') {
            if((Native-FunctionSpan $calleeOffset).Begin -ne $imageBase+$rva) {throw 'Reason callee does not start at a runtime function boundary'}
            $calleeCache[$cacheKey]=Test-Callee $rva $kind
            return $calleeCache[$cacheKey]
        }
        # The pure validator is a leaf function and has no x64 runtime-function entry.
        $range=@($pe.ExecutableRanges | Where-Object {$rva -ge $_.VirtualAddress -and $rva+4096 -le $_.VirtualAddress+$_.Length})
        if($range.Count -ne 1) {throw 'Extra callee is outside executable sections'}
        $nativeState.offset=[long]($range[0].Start+$rva-$range[0].VirtualAddress)
        $nativeState.lo=$imageBase+$rva; $nativeState.hi=$nativeState.lo+4096; $nativeState.cache=@{}
        $path=Join-Path $dumpRoot 'validator.dmp'
        Write-NativeDump $path ([long[]]@($nativeState.offset)) ([uint64[]]@($nativeState.lo))
        $nativeState.engine=[Mv2NativeDisassembler]::new($path)
        try {$calleeCache[$cacheKey]=Native-Validator $nativeState.lo; return $calleeCache[$cacheKey]} finally {$nativeState.engine.Dispose()}
    } finally {foreach($key in $saved.Keys) {$nativeState[$key]=$saved[$key]}}
}
function Native-FunctionSpan([long]$offset) {
    if(!$nativeState.runtimeFunctions) {
        $dos=Read-StreamRange $Stream 0 64; $peAt=[BitConverter]::ToInt32($dos,60)
        $header=Read-StreamRange $Stream $peAt 264
        $count=[BitConverter]::ToUInt16($header,6); $optional=[BitConverter]::ToUInt16($header,20)
        if($count -lt 1 -or $count -gt 96 -or $optional -lt 144) {throw 'Invalid runtime directory header'}
        $sections=Read-StreamRange $Stream ($peAt+24+$optional) (40*$count)
        $rva=[BitConverter]::ToUInt32($header,160); $size=[BitConverter]::ToUInt32($header,164)
        if(!$rva -or !$size -or $size%12 -or $size -gt 32MB) {throw 'Invalid runtime directory size'}
        $matches=@(for($i=0;$i -lt $sections.Length;$i+=40) {
            $begin=[BitConverter]::ToUInt32($sections,$i+12); $length=[BitConverter]::ToUInt32($sections,$i+16)
            if($rva -ge $begin -and [long]$rva+$size -le [long]$begin+$length) {[long][BitConverter]::ToUInt32($sections,$i+20)+$rva-$begin}
        })
        if($matches.Count -ne 1) {throw 'Runtime directory is not file-backed'}
        $nativeState.runtimeFunctions=Read-StreamRange $Stream $matches[0] $size
        if(!$nativeState.runtimeFunctions) {throw 'Truncated runtime directory'}
    }
    $data=$nativeState.runtimeFunctions; $rva=ConvertTo-PeRva $pe $offset 1
    $lo=0; $hi=[int]($data.Length/12)-1
    while($lo -le $hi) {
        $mid=[int][Math]::Floor(($lo+$hi)/2); $begin=[BitConverter]::ToUInt32($data,12*$mid); $end=[BitConverter]::ToUInt32($data,12*$mid+4)
        if($rva -lt $begin) {$hi=$mid-1} elseif($rva -ge $end) {$lo=$mid+1} else {
            if($end -le $begin -or $end-$begin -gt 4096) {throw 'Reason function exceeds bounded window'}
            $range=@($pe.ExecutableRanges | Where-Object {$begin -ge $_.VirtualAddress -and $begin+4096 -le $_.VirtualAddress+$_.Length})
            if($range.Count -ne 1) {throw 'Reason function is not executable'}
            return [pscustomobject]@{Offset=[long]($range[0].Start+$begin-$range[0].VirtualAddress);Begin=$imageBase+$begin;End=$imageBase+$end}
        }
    }
    throw 'Reason candidate has no runtime function boundary'
}
function Native-ReasonOutput($span,[string]$output) {
    if($output -notin @('rbx','rbp','rsi','rdi','r12','r13','r14','r15')) {throw 'Reason output is not preserved across calls'}
    $state=@{rcx='arg1';rdx='arg2';r8='arg3';r9='arg4'}; $xmm=@{}; $zeros16=@{}; $zeros8=@{}; $lengthReads=@{}; $prefixCalls=@()
    $at=$span.Begin; $binding=$null; $origin=$null
    for($i=0;$i -lt 64;$i++) {
        $ins=Read-Instruction $at; $at=$ins.End
        if($ins.Op -match '^j' -or $ins.Op -eq 'ret') {break}
        if($ins.Op -eq 'call') {
            $prefixCalls+=[pscustomobject]@{Rva=$ins.Target-$imageBase;This=$state['rcx'];Output=$state['rdx'];Key=$state['r8']}
            foreach($r in @('rax','rcx','rdx','r8','r9','r10','r11')) {$state[$r]='unknown-call'}; continue
        }
        if($ins.Op -eq 'xorps' -and $ins.Args -match '^(xmm\d+),\1$') {$xmm[$Matches[1]]=$true; continue}
        if($ins.Op -in @('movups','movaps') -and $ins.Args -match '^xmmword ptr (\[[^\]]+\]),(xmm\d+)$') {
            $where=Resolve-Value $Matches[1] $state; if($xmm[$Matches[2]]) {$zeros16[$where]=$ins.Address}; continue
        }
        if($ins.Op -eq 'mov' -and $ins.Args -match '^qword ptr (\[[^\]]+\]),([^,]+)$') {
            $where=Resolve-Value $Matches[1] $state; $value=Resolve-Value $Matches[2] $state
            if($value -eq '0') {$zeros8[$where]=$ins.Address}; continue
        }
        if($ins.Op -in @('mov','lea') -and $ins.Args -match '^(r\w+|e\w+),') {
            if($ins.Op -eq 'mov') {$value=Resolve-Value $ins.Args.Split(',')[1] $state; if($value -like 'qword ptr *+8]') {$lengthReads[$value]=$ins.Address}}
            $dest=Canonical-Register $Matches[1]; Apply-Copy $ins $state
            if($dest -eq $output) {if($binding) {throw 'Reason output is rebound'}; $binding=$ins.Address; $origin=$state[$output]}
        } elseif($ins.Op -eq 'xor' -and $ins.Args -match '^([^,]+),\1$') {$state[(Canonical-Register $Matches[1])]='0'}
        elseif($ins.Op -notin @('push','cmp','test','nop') -and $ins.Args -match '^([re][a-z0-9]+),') {
            $dest=Canonical-Register $Matches[1]
            if($dest -ne 'rsp') {$state[$dest]='unknown-write'}
        }
    }
    if(!$binding -or $origin -notin @('arg1','arg2') -or $state[$output] -ne $origin -or
        !$zeros16.ContainsKey('[{'+$origin+'}]') -or !$zeros8.ContainsKey('[{'+$origin+'}+10h]')) {throw 'Reason output is not an initialized caller-owned set'}
    $role=$null
    if($prefixCalls.Count -eq 0 -and $origin -eq 'arg1' -and $lengthReads.ContainsKey('qword ptr [{arg2}+8]')) {$role='set-to-set'}
    elseif($prefixCalls.Count -eq 1 -and $origin -eq 'arg2') {
        $source=$prefixCalls[0]; $local=$source.Output
        if($source.This -eq 'arg1' -and $source.Key -eq 'arg3' -and $local -match '^\[rsp\+[0-9a-f]+h\]$' -and
            $zeros16.ContainsKey('[{'+$local+'}]') -and $zeros8.ContainsKey('[{'+$local+'}+10h]') -and $lengthReads.ContainsKey('qword ptr [{'+$local+'}+8]')) {$role='read-then-collapse'}
    }
    if(!$role) {throw 'Reason caller input/output roles disagree'}
    # Decode the bounded function, requiring the same preserved output and a pointer-return epilogue.
    $at=$span.Begin; $returnCopy=$null; $ret=$null; $afterCopy=$false
    while($at -lt $span.End) {
        $ins=Read-Instruction $at; $at=$ins.End
        if($ins.Op -eq 'mov' -and $ins.Args -eq "rax,$output") {
            if($returnCopy) {throw 'Multiple reason return copies'}; $returnCopy=$ins.Address; $afterCopy=$true; continue
        }
        if($ins.Op -eq 'ret') {
            if(!$afterCopy -or $ret) {throw 'Reason function does not return its output pointer'}
            $ret=$ins.Address; $afterCopy=$false; continue
        }
        if($afterCopy -and !($ins.Op -in @('pop','nop') -or ($ins.Op -eq 'add' -and $ins.Args -match '^rsp,') -or ($ins.Op -in @('movaps','movups') -and $ins.Args -match '^xmm\d+,xmmword ptr \[rsp'))) {throw 'Reason pointer return has unknown effects'}
        if($ins.Address -ne $binding -and $ins.Op -notin @('push','pop','cmp','test','nop') -and $ins.Op -notmatch '^j' -and $ins.Args -match '^([re][a-z0-9]+),') {
            if((Canonical-Register $Matches[1]) -eq $output) {throw 'Caller-owned reason output was overwritten'}
        }
    }
    if(!$returnCopy -or !$ret) {throw 'No caller-owned set return'}
    return [pscustomobject]@{Kind='caller-owned-set-return';Role=$role;Argument=$origin;OutputRegister=$output;FunctionRva=$span.Begin-$imageBase;SourceCalls=$prefixCalls;
        BindingOffset=$span.Offset+$binding-$span.Begin;ReturnOffset=$span.Offset+$returnCopy-$span.Begin;
        Zero16Offset=$span.Offset+$zeros16['[{'+$origin+'}]']-$span.Begin;Zero8Offset=$span.Offset+$zeros8['[{'+$origin+'}+10h]']-$span.Begin}
}
function Native-Reason([uint64]$Address) {
    $span=Native-FunctionSpan $nativeState.offset
    $saved=$nativeState.Clone(); $window=[long]$span.Offset
    try {
        $nativeState.offset=$window; $nativeState.lo=$span.Begin; $nativeState.hi=$span.End; $nativeState.cache=@{}
        $path=Join-Path $dumpRoot 'reason.dmp'
        Write-NativeDump $path ([long[]]@($window)) ([uint64[]]@($nativeState.lo))
        $nativeState.engine=[Mv2NativeDisassembler]::new($path)
        try {
            $entry=Read-Instruction $Address
            if($entry.Op -ne 'mov' -or $entry.Args -notmatch '^ecx,(e\w+|r[0-9]+d)$') {throw 'No reason-validation argument'}
            $reasonReg=$Matches[1]; $reasonCanonical=Canonical-Register $reasonReg
            $call=Next-Real $entry.End
            if($call.Op -ne 'call' -or !$call.Target) {throw 'No direct reason validator'}
            $test=Next-Real $call.End; $j=Next-Real $test.End
            if($test.Op -ne 'test' -or $test.Args -ne 'al,al' -or $j.Op -notin @('je','jne')) {throw 'Reason validation result is not tested'}
            $valid=if($j.Op -eq 'jne') {$j.Target} else {$j.End}
            $invalid=if($j.Op -eq 'je') {$j.Target} else {$j.End}
            $bad=Next-Real $invalid
            if($bad.Op -ne 'mov' -or $bad.Args -notmatch '^(dword ptr \[rsp\+[0-9a-f]+h\]),2000000h$') {throw 'Unknown reason is not stored in a stack slot'}
            $slot=$Matches[1]
            $good=Next-Real $valid
            if($good.Op -ne 'mov' -or $good.Args -ne "$slot,$reasonReg") {throw 'Valid reason does not use the same slot and value'}
            $join=(Next-Real $bad.End).Address
            if((Next-Real $good.End).Address -ne $join) {throw 'Reason stores do not converge'}
            $setup=Read-CallSetup $join
            foreach($reg in @('rcx','rdx','r8','r9')) {if($setup.State[$reg] -notmatch '^r\w+$') {throw 'Unknown reason insertion argument'}}
            if($setup.State['r8'] -ne $setup.State['r9'] -or $setup.State['rcx'] -eq $setup.State['rdx']) {throw 'Reason insertion arguments disagree'}
            $outputEvidence=Native-ReasonOutput $span $setup.State['rcx']
            $advance=Next-Real $setup.Call.End
            if($advance.Op -ne 'add' -or $advance.Args -notmatch '^(r\w+),4$') {throw 'Reason iterator stride changed'}
            $iterator=$Matches[1]; $limit=Next-Real $advance.End; $repeat=Next-Real $limit.End
            if($limit.Op -ne 'cmp' -or $limit.Args -notmatch '^([^,]+),([^,]+)$' -or $iterator -notin @($Matches[1],$Matches[2]) -or $Matches[1] -eq $Matches[2] -or $repeat.Op -ne 'jne') {throw 'No bounded reason iterator comparison'}
            $load=Next-Real $repeat.Target
            if($load.Op -ne 'mov' -or $load.Args -notmatch ('^'+[regex]::Escape($reasonReg)+',dword ptr \[([^\]]+)\]$')) {throw 'Reason loop has no element load'}
            $addressRegs=$Matches[1].Split('+')
            if($addressRegs.Count -gt 2 -or $iterator -notin $addressRegs -or @($addressRegs | Where-Object {$_ -notin @('rbx','rbp','rsi','rdi','r12','r13','r14','r15')}).Count -or (Next-Real $load.End).Address -ne $entry.Address) {throw 'Reason loop does not reload the validated element'}
            # Require a visible, unmodified LEA tying the insertion key pointer to the written slot.
            $pointer=$setup.State['r8']; $slotAddress=$slot.Substring('dword ptr '.Length); $bound=$false
            for($at=$nativeState.lo;$at -lt $load.Address;$at++) {
                try {
                    $decoded=$nativeState.engine.Decode($at)
                    if($decoded.Text -notmatch '\slea\s+' -or !$decoded.Text.EndsWith("$pointer,$slotAddress")) {continue}
                    $lea=Read-Instruction $at
                } catch {continue}
                if($lea.Op -ne 'lea' -or $lea.Args -ne "$pointer,$slotAddress") {continue}
                $p=$lea.End; $safe=$true
                for($n=0;$n -lt 48 -and $p -lt $load.Address;$n++) {
                    $ins=Read-Instruction $p
                    if($ins.Op -eq 'call' -or $ins.Op -eq 'jmp' -or $ins.Op -match '^(ret|int)$') {$safe=$false; break}
                    if($ins.Op -notin @('cmp','test','push','nop') -and $ins.Op -notmatch '^j' -and $ins.Args -match '^([re][a-z0-9]+)(?:,|$)') {
                        if((Canonical-Register $Matches[1]) -eq $pointer) {$safe=$false; break}
                    }
                    $p=$ins.End
                }
                if($safe -and $p -eq $load.Address) {$bound=$true; break}
            }
            if(!$bound) {throw 'Reason stack key pointer is not bound in the local context'}
            $regs=@('rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15')
            $id=[Array]::IndexOf($regs,$reasonCanonical)
            if($id -lt 0 -or $reasonCanonical -in @('rax','rcx','rdx','r8','r9','r10','r11','rsp')) {throw 'Reason value is not in a preserved register'}
            $replacement=[Collections.Generic.List[byte]]::new()
            if($id -ge 8) {$replacement.Add(0x41)}
            $replacement.Add(0x81); $replacement.Add([byte](0xf8+($id-band 7)))
            $replacement.AddRange([BitConverter]::GetBytes([int]0x800000)); $replacement.AddRange([byte[]]@(0x0f,0x95,0xc0))
            $relValid=[long]$good.Address-([long]$Address+$replacement.Count+2)
            if($relValid -lt -128 -or $relValid -gt 127) {throw 'Reason valid branch exceeds short range'}
            $replacement.Add(0x75); $replacement.Add([byte]($relValid-band 255))
            $relSkip=[long]$advance.Address-([long]$Address+$replacement.Count+2)
            if($relSkip -lt -128 -or $relSkip -gt 127) {throw 'Reason skip branch exceeds short range'}
            $replacement.Add(0xeb); $replacement.Add([byte]($relSkip-band 255))
            if($Address+$replacement.Count -ge [Math]::Min($good.Address,$join)) {throw 'Reason patch overlaps a live destination'}
            $record=[pscustomobject]@{Name='ignore-mv2-disable-reason-at-runtime';Offset=[long]$saved.offset;PatchOffset=[long]$saved.offset;
                Replacement=$replacement.ToArray();CallRva=$null;NormalCallRva=$null;
                ExtraEvidence=[pscustomobject]@{ReasonRegister=$reasonReg;Slot=$slot;ValidatorRva=$call.Target-$imageBase;InsertRva=$setup.Call.Target-$imageBase;
                    LoopRva=$load.Address-$imageBase;ContinueRva=$advance.Address-$imageBase;Validator=$null;Insert=$null;Output=$outputEvidence};
                UnknownStoreOffset=$window+$bad.Address-$nativeState.lo;ValidStoreOffset=$window+$good.Address-$nativeState.lo;
                CallOffset=$window+$call.Address-$nativeState.lo;AdvanceOffset=$window+$advance.Address-$nativeState.lo;
                InsertSetupOffset=$window+$join-$nativeState.lo;LoopOffset=$window+$load.Address-$nativeState.lo}
        } finally {$nativeState.engine.Dispose(); $nativeState.engine=$null}
        $record.ExtraEvidence.Validator=Native-Callee $record.ExtraEvidence.ValidatorRva 'reason-validator'
        $record.ExtraEvidence.Insert=Native-Callee $record.ExtraEvidence.InsertRva 'reason-insert'
        return $record
    } finally {foreach($key in $saved.Keys) {$nativeState[$key]=$saved[$key]}}
}
function Read-Instruction([uint64]$Address) {
    if($Address -lt $nativeState.lo -or $Address -ge $nativeState.hi) { throw 'Trace leaves bounded snippet' }
    if($nativeState.cache.ContainsKey($Address)) { return $nativeState.cache[$Address] }
    if($nativeState.cache.Count -ge 128) { throw 'Instruction budget exceeded' }
    $decoded=$nativeState.engine.Decode($Address)
    if($decoded.End -gt $nativeState.hi) { throw 'Truncated instruction' }
    $nativeState.cache[$Address]=$decoded; $nativeState.decodeCount++
    return $decoded
}

function Read-Linear([uint64]$Address,[int]$Count) {
    $seen=@{}
    for($n=0;$n -lt $Count;$n++) {
        if($seen.ContainsKey($Address)) { throw 'Loop rejected' }; $seen[$Address]=$true
        $ins=Read-Instruction $Address
        if($ins.Op -eq 'jmp') { $Address=[uint64]$ins.Target; continue }
        $ins
        if($ins.Op -match '^(ret|int)') { break }
        $Address=$ins.End
    }
}

function Canonical-Register([string]$reg) {
    switch -Regex ($reg) {
        '^e(ax|bx|cx|dx|si|di|bp|sp)$' { return 'r'+$reg.Substring(1) }
        '^(r[0-9]+)d$' { return $Matches[1] }
        '^r(ax|bx|cx|dx|si|di|bp|sp|[0-9]+)$' { return $reg }
        default { throw "Unsupported register: $reg" }
    }
}
function Resolve-Value([string]$arg,[hashtable]$state) {
    if($arg -match '^(r\w+|e\w+)$') {
        $r=Canonical-Register $arg
        $value=if($state.ContainsKey($r)) {$state[$r]} else {$r}
        if($arg -match '^(e\w+|r[0-9]+d)$' -and $value -notmatch '^(dword ptr |low32\(|[0-9a-f]+h?$)') {return "low32($value)"}
        return $value
    }
    if($arg -match '^(?:(?:qword|dword|byte) ptr )?\[.*\]$') {
        return [regex]::Replace($arg,'\br(?:[0-9]+|ax|bx|cx|dx|si|di|bp|sp)\b',{
            param($m) if($state.ContainsKey($m.Value)) {'{'+$state[$m.Value]+'}'} else {$m.Value}
        })
    }
    if($arg -match '^[0-9a-f]+h?$') {return $arg}
    throw "Unsupported value: $arg"
}
function Apply-Copy($ins,[hashtable]$state) {
    if($ins.Op -eq 'nop') {return}
    if($ins.Op -notin @('mov','lea') -or $ins.Args -notmatch '^(r\w+|e\w+),(.+)$') {throw "Unsupported copy: $($ins.Text)"}
    $dest=Canonical-Register $Matches[1]; $src=$Matches[2]
    $value=Resolve-Value $src $state
    if($ins.Op -eq 'lea' -and $src -notmatch '^\[') {throw 'Unsupported LEA'}
    if($ins.Args.Split(',')[0] -match '^(e\w+|r[0-9]+d)$' -and $value -notmatch '^(dword ptr |low32\(|[0-9a-f]+h?$)') {$value="low32($value)"}
    $state[$dest]=$value
}
function Next-Real([uint64]$at) {
    $seen=@{}
    for($i=0;$i -lt 12;$i++) {
        if($seen.ContainsKey($at)) {throw 'Jump cycle'}; $seen[$at]=$true
        $ins=Read-Instruction $at
        if($ins.Op -eq 'jmp') {$at=[uint64]$ins.Target}
        elseif($ins.Op -eq 'nop') {$at=$ins.End}
        else {return $ins}
    }
    throw 'Jump budget exceeded'
}
function Flow-StackOperand([string]$arg,[int]$sp) {
    if($arg -notmatch '^(?:(qword|dword) ptr )?\[rsp(?:\+([0-9a-f]+)(h)?)?\]$') {return $null}
    $width=switch($Matches[1]) {'qword' {8} 'dword' {4} default {0}}
    $disp=0
    if($Matches[2]) {$disp=if($Matches[3]) {[Convert]::ToInt32($Matches[2],16)} else {[int]$Matches[2]}}
    return [pscustomobject]@{Offset=$sp+$disp;Width=$width}
}
function Flow-Copy($ins,$frame) {
    $parts=$ins.Args.Split(','); if($parts.Count -ne 2) {throw 'Unsupported flow copy'}
    $dest=$parts[0]; $src=$parts[1]
    $slot=Flow-StackOperand $dest $frame.SP
    if($slot -and $slot.Width -gt 0) {
        if($ins.Op -ne 'mov' -or $slot.Offset -lt $frame.SP -or $slot.Offset+$slot.Width -gt 0) {throw 'Store is not in freshly allocated scratch stack'}
        if($src -notmatch '^(r\w+|e\w+|[0-9a-f]+h?)$') {throw 'Unsupported stack store source'}
        $value=Resolve-Value $src $frame.State
        foreach($key in @($frame.Slots.Keys)) {
            $old=$frame.Slots[$key]
            if($slot.Offset -lt $key+$old.Width -and $key -lt $slot.Offset+$slot.Width) {$frame.Slots.Remove($key)}
        }
        $frame.Slots[$slot.Offset]=[pscustomobject]@{Width=$slot.Width;Value=$value}
        $frame.Spills++
        return
    }
    if($dest -notmatch '^(r\w+|e\w+)$' -or (Canonical-Register $dest) -eq 'rsp') {throw 'Unknown memory write or stack-pointer overwrite'}
    $sourceSlot=Flow-StackOperand $src $frame.SP
    if($sourceSlot -and $ins.Op -eq 'mov' -and $sourceSlot.Width -gt 0) {
        if(!$frame.Slots.ContainsKey($sourceSlot.Offset) -or $frame.Slots[$sourceSlot.Offset].Width -ne $sourceSlot.Width) {throw 'Stack reload has no intact matching store'}
        $value=$frame.Slots[$sourceSlot.Offset].Value
        if($dest -match '^(e\w+|r[0-9]+d)$' -and $value -notmatch '^(dword ptr |low32\(|[0-9a-f]+h?$)') {$value="low32($value)"}
        $frame.State[(Canonical-Register $dest)]=$value
        return
    }
    if($src -match '\brsp\b') {
        if(!$sourceSlot -or $ins.Op -ne 'lea') {throw 'Unknown stack read or stack address escape'}
        if($sourceSlot.Offset -lt 0) {throw 'Scratch stack address escapes into a register'}
        $canonical='[rsp+'+$sourceSlot.Offset.ToString('X')+'h]'
        $copy=[pscustomobject]@{Op='lea';Args="$dest,$canonical";Text=$ins.Text}
        Apply-Copy $copy $frame.State
        return
    }
    # A pointer to scratch storage cannot be created, and indirect writes are rejected above.
    Apply-Copy $ins $frame.State
}
function Read-CallSetup([uint64]$at) {
    # ponytail: finite call-setup CFG only, no loops, no calls before scratch is released.
    # Existing-frame spills and escaped/aliased stack slots need liveness/alias analysis later.
    $pending=[Collections.Generic.Stack[object]]::new()
    $pending.Push([pscustomobject]@{At=$at;State=@{};Slots=@{};SP=0;Seen=@{};Items=@();Spills=0;Steps=0})
    $leaves=@(); $forks=0; $steps=0
    while($pending.Count) {
        $f=$pending.Pop()
        while($true) {
            if(++$steps -gt 128 -or ++$f.Steps -gt 48) {throw 'Call-setup instruction budget exceeded'}
            if($f.Seen.ContainsKey($f.At)) {throw 'Call-setup cycle'}
            $f.Seen[$f.At]=$true
            $ins=Read-Instruction $f.At; $f.Items+=,$ins
            if($ins.Op -eq 'jmp') {$f.At=[uint64]$ins.Target; continue}
            if($ins.Op -eq 'nop') {$f.At=$ins.End; continue}
            if($ins.Op -match '^j') {
                if(++$forks -gt 7) {throw 'Call-setup path budget exceeded'}
                $pending.Push([pscustomobject]@{At=[uint64]$ins.Target;State=$f.State.Clone();Slots=$f.Slots.Clone();SP=$f.SP;Seen=$f.Seen.Clone();Items=@($f.Items);Spills=$f.Spills;Steps=$f.Steps})
                $f.At=$ins.End; continue
            }
            if($ins.Op -eq 'call') {
                if(!$ins.Target) {throw 'Indirect call rejected'}
                if($f.SP -ne 0 -or $f.Slots.Count) {throw 'Scratch stack live across call'}
                $leaves+=,[pscustomobject]@{Call=$ins;State=$f.State;Items=$f.Items;After=(Next-Real $ins.End);Spills=$f.Spills}
                break
            }
            if($ins.Op -in @('sub','add') -and $ins.Args -match '^rsp,([0-9a-f]+)(h)?$') {
                $amount=if($Matches[2]) {[Convert]::ToInt32($Matches[1],16)} else {[int]$Matches[1]}
                if($amount -le 0 -or $amount%16) {throw 'Unsupported scratch allocation alignment'}
                $f.SP+=if($ins.Op -eq 'sub') {-$amount} else {$amount}
                if($f.SP -gt 0 -or $f.SP -lt -256) {throw 'Scratch stack allocation budget exceeded'}
                foreach($key in @($f.Slots.Keys)) {if($key -lt $f.SP) {$f.Slots.Remove($key)}}
            } elseif($ins.Op -in @('cmp','test') -and $ins.Args -match '^[re][a-z0-9]+,(?:[re][a-z0-9]+|[0-9a-f]+h?)$') {
                # Both outcomes are explored; no assumption about the value of this condition.
            } elseif($ins.Op -in @('mov','lea')) {Flow-Copy $ins $f}
            else {throw "Unsupported call-setup instruction: $($ins.Text)"}
            $f.At=$ins.End
        }
    }
    if(!$leaves.Count) {throw 'No bounded direct call'}
    $first=$leaves[0]
    foreach($leaf in $leaves) {
        if($leaf.Call.Address -ne $first.Call.Address) {throw 'Paths reach different calls'}
        foreach($key in @(@($first.State.Keys)+@($leaf.State.Keys) | Sort-Object -Unique)) {
            if((Resolve-Value $key $first.State) -ne (Resolve-Value $key $leaf.State)) {throw "Path-dependent register value: $key"}
        }
    }
    $first | Add-Member NoteProperty Paths $leaves.Count
    $first | Add-Member NoteProperty TotalSpills (($leaves | Measure-Object Spills -Sum).Sum)
    return $first
}
function Classify-Candidate([uint64]$Address) {
    $state=@{}; $first=Next-Real $Address
    if($first.Op -ne 'cmp' -or $first.Args -notmatch '^(.+),2$') {throw 'No manifest comparison'}
    $manifest=Resolve-Value $Matches[1] $state
    $guard=Next-Real $first.End
    if($guard.Op -eq 'jg') {$normal=Next-Real ([uint64]$guard.Target); $at=$guard.End}
    elseif($guard.Op -eq 'jle') {$normal=Next-Real $guard.End; $at=[uint64]$guard.Target}
    else {throw 'Unsupported manifest guard'}
    $location=@{}; $typeValue=$null; $typeOther=$null; $overrideTarget=$null; $locationEntry=$null; $seen=@{}
    for($i=0;$i -lt 32;$i++) {
        $ins=Next-Real $at
        if($seen.ContainsKey($ins.Address)) {throw 'Predicate cycle'}; $seen[$ins.Address]=$true
        if($ins.Op -in @('mov','lea')) {Apply-Copy $ins $state; $at=$ins.End; continue}
        if($ins.Op -ne 'cmp' -or $ins.Args -notmatch '^(.+),(0|1|5|0Ah)$') {throw 'Unsupported predicate'}
        $operand=$Matches[1]; $value=$Matches[2]; $origin=Resolve-Value $operand $state
        $branch=Next-Real $ins.End
        if($branch.Op -notin @('je','jne')) {throw 'Predicate is not equality'}
        $equal=if($branch.Op -eq 'je') {[uint64]$branch.Target} else {$branch.End}
        $other=if($branch.Op -eq 'jne') {[uint64]$branch.Target} else {$branch.End}
        if($value -eq '0') {
            if($overrideTarget -or $operand -notlike 'byte ptr *' -or $typeValue -or $location.Count) {throw 'Unexpected override'}
            $overrideTarget=$other; $at=$equal; continue
        }
        if($value -eq '1') {
            if($typeValue -or $location.Count) {throw 'Duplicate or late type predicate'}
            $typeValue=$origin; $typeOther=(Next-Real $other).Address; $at=$equal; $afterType=(Next-Real $equal).Address; continue
        }
        if(!$typeValue -or $location.ContainsKey($value)) {throw 'Missing type or duplicate location'}
        if(!$locationEntry) {$locationEntry=$ins.Address}
        if((Next-Real $equal).Address -ne $normal.Address) {throw 'Unaffected destinations differ'}
        $location[$value]=[pscustomobject]@{Origin=$origin;Compare=$ins;Branch=$branch}
        $at=$other
        if($location.Count -eq 2) {break}
    }
    if($location.Count -ne 2 -or $location['5'].Origin -ne $location['0Ah'].Origin -or
        $location['5'].Origin -eq $typeValue -or $typeValue -eq $manifest) {throw 'Predicate value flow mismatch'}
    # The two enum fields must originate from the same object, even after register copies.
    if($manifest -like 'dword ptr *') {
        if($location['5'].Origin -notmatch '^dword ptr \[\{(.+)\}\+[0-9a-f]+h\]$') {throw 'Unknown location object'}
        $locationObject=$Matches[1]
        if($typeValue -notmatch '^dword ptr \[\{(.+)\}\+[0-9a-f]+h\]$' -or $Matches[1] -ne $locationObject) {throw 'Type and location come from different objects'}
    } elseif($location['5'].Origin -notmatch '^dword ptr \[r\w+\+[0-9a-f]+h\]$' -or $typeValue -notmatch '^low32\(r\w+\)$') {
        throw 'Unknown live-in predicate values'
    }
    # Register-form predicates have live-in values whose definitions precede this window.
    # Keep their distinct-value checks and require the same caller/callee evidence below.
    if($overrideTarget -and (Next-Real $overrideTarget).Address -ne $afterType) {throw 'Override does not join location check'}
    $effect=Read-CallSetup $at
    if($typeOther -eq $effect.Items[0].Address) {throw 'Type exclusion enters MV2 effect'}
    $unaffected=@(Read-Linear $normal.Address 10)
    $kind=$null; $normalCall=$null
    # Keep tree-node and result-use checks; argument instruction order is no longer fixed.
    if($unaffected[0].Op -eq 'mov' -and $unaffected[0].Args -match '^(r\w+),qword ptr \[(r\w+)\+8\]$') {
        $loaded=$Matches[1]; $node=$Matches[2]
        if($unaffected[1].Op -ne 'test' -or $unaffected[1].Args -ne "$loaded,$loaded" -or
            @($unaffected | Where-Object {$_.Op -eq 'jne' -and $_.Target -lt $_.Address}).Count -eq 0 -or
            $effect.State['r8'] -ne "[$node+38h]" -or
            $effect.State['rcx'] -notmatch '^r\w+$' -or $effect.State['rdx'] -notmatch '^r\w+$' -or
            $effect.State['rcx'] -eq $effect.State['rdx'] -or $effect.After.Address -ne $normal.Address) {throw 'Startup argument or continuation mismatch'}
        $kind='skip-startup-disable'
    } else {
        $normalCall=Read-CallSetup $normal.Address
        if($effect.State['rcx'] -notmatch '^\[rsp\+[0-9a-f]+h\]$' -or
            $effect.State['rdx'] -notmatch '^[0-9a-f]+h$' -or
            $normalCall.State['r8'] -ne $effect.State['rcx'] -or
            $normalCall.State['rcx'] -notmatch '^r\w+$' -or $normalCall.State['rdx'] -notmatch '^r\w+$' -or
            $normalCall.Call.Target -eq $effect.Call.Target) {throw 'Install argument flow mismatch'}
        $postBad=@(Read-Linear $effect.Call.End 3)
        $postGood=@(Read-Linear $normalCall.Call.End 3)
        if($postBad[0].Op -ne 'lea' -or $postGood[0].Op -ne 'lea' -or
            $postBad[0].Args -notmatch '^(r\w+),\[rsp\+[0-9a-f]+h\]$') {throw 'No bounded false result storage'}
        $badreg=$Matches[1]
        if($postGood[0].Args -notmatch '^(r\w+),\[rsp\+[0-9a-f]+h\]$') {throw 'No bounded returned result storage'}
        $goodreg=$Matches[1]
        if($postBad[1].Op -ne 'mov' -or $postBad[1].Args -ne "byte ptr [$badreg-8],0" -or
            $postGood[1].Op -ne 'mov' -or $postGood[1].Args -ne "byte ptr [$goodreg-8],al") {throw 'Return value/false result mismatch'}
        $kind='allow-install-policy-inline'
    }
    if($Inspect) {@($nativeState.cache.Values | Sort-Object Address) | ForEach-Object {$_.Text} | Out-Host}
    $patchAt=$nativeState.offset+$guard.Address-$Address
    $length=[int]($guard.End-$guard.Address)
    $replacement=[byte[]]::new($length)
    if($guard.Op -eq 'jle') {for($i=0;$i -lt $length;$i++) {$replacement[$i]=0x90}}
    elseif($length -eq 2) {$replacement[0]=0xeb; $replacement[1]=[byte](($guard.Target-$guard.End) -band 255)}
    elseif($length -eq 6) {
        $replacement[0]=0xe9; [Array]::Copy([BitConverter]::GetBytes([int]($guard.Target-($guard.Address+5))),0,$replacement,1,4); $replacement[5]=0x90
    } else {throw 'Unsupported patch encoding'}
    [pscustomobject]@{
        Name=$kind;Offset=$nativeState.offset;PatchOffset=$patchAt;Replacement=@($replacement);
        UnaffectedRva=($normal.Address-$imageBase);AffectedRva=($effect.Items[0].Address-$imageBase);
        CallRva=($effect.Call.Target-$imageBase);CallOffset=($nativeState.offset+$effect.Call.Address-$Address);
        NormalCallRva=if($normalCall) {$normalCall.Call.Target-$imageBase} else {$null};
        FlowPaths=$effect.Paths;FlowSpills=$effect.TotalSpills;Arguments=$effect.State;PredicateLocation=$location['5'].Origin;PredicateType=$typeValue;
        FiveOffset=($nativeState.offset+$location['5'].Compare.Address-$Address);
        TenOffset=($nativeState.offset+$location['0Ah'].Compare.Address-$Address);
        Decoded=$nativeState.cache.Count
    }
}
function Test-Callee([uint64]$rva,[string]$kind) {
    $range=@($pe.ExecutableRanges | Where-Object {$rva -ge $_.VirtualAddress -and $rva+4096 -le $_.VirtualAddress+$_.Length})
    if($range.Count -ne 1) {throw 'Call target outside executable section'}
    $nativeState.offset=[long]($range[0].Start+$rva-$range[0].VirtualAddress)
    $nativeState.lo=$imageBase+$rva; $nativeState.hi=$nativeState.lo+4096; $nativeState.cache=@{}
    $path=Join-Path $dumpRoot 'callee.dmp'
    Write-NativeDump $path ([long[]]@($nativeState.offset)) ([uint64[]]@($nativeState.lo))
    $nativeState.engine=[Mv2NativeDisassembler]::new($path)
    $state=@{}; $at=$nativeState.lo; $facts=@{}; $items=@(); $returned=$false
    try {
        # ponytail: inspect one linear prefix through its first RET, max 64 instructions.
        # This is extra structural evidence, not a proof of all callee paths or identity.
        for($i=0;$i -lt 64;$i++) {
            $ins=Read-Instruction $at; $items+=$ins.Text; $at=$ins.End
            if($ins.Op -eq 'ret') {$returned=$true; break}
            if($ins.Op -eq 'call') {
                if($ins.Target -and $state['r8'] -eq 'low32(rdx)' -and $state['rdx'] -eq 'rcx') {$facts.ForwardResource=$true}
                foreach($r in @('rax','rcx','rdx','r8','r9','r10','r11')) {$state[$r]='unknown-call'}
                continue
            }
            if($ins.Op -eq 'mov' -and $ins.Args -match '^(.+),(.+)$') {
                $dest=$Matches[1]; $src=$Matches[2]
                try {$origin=Resolve-Value $src $state} catch {$origin='unknown'}
                if($origin -eq 'qword ptr [rcx]') {$facts.VectorBegin=$true}; if($origin -eq 'qword ptr [rcx+8]') {$facts.VectorLength=$true}; if($origin -in @('dword ptr [r8]','dword ptr [{r8}]')) {$facts.IntKey=$true}; if($origin -eq 'qword ptr [rdx+8]' -or $origin -eq 'qword ptr [{rdx}+8]') {$facts.TreeRoot=$true}
                if($origin -eq 'qword ptr [r8]' -or $origin -eq 'qword ptr [{r8}]') {$facts.Key=$true}
                if($origin -match '^qword ptr \[rdx\+') {$facts.PolicyObject=$true}
                if($dest -match '^(r\w+|e\w+)$') {
                    try {$state[(Canonical-Register $dest)]=$origin} catch {}
                } else {
                    try {$where=Resolve-Value $dest $state} catch {$where='unknown'}
                    if($where -eq 'qword ptr [{rdx}]') {$facts.VectorResult=$true}; if($where -eq 'byte ptr [{rdx}+8]' -and $src -eq 'al' -and $state['rax'] -eq '0') {$facts.VectorFlag=$true}; if($where -eq 'qword ptr [{rcx}]') {$facts.WriteNode=$true}
                    if($where -eq 'byte ptr [{rcx}+8]' -and $src -eq 'al' -and $state['rax'] -eq '0') {$facts.WriteInserted=$true}
                    if($where -eq 'qword ptr [{rcx}+10h]' -and $src -eq '0') {$facts.ClearString=$true}
                }
                continue
            }
            if($ins.Op -eq 'xor' -and $ins.Args -match '^([^,]+),\1$') {
                try {$state[(Canonical-Register $Matches[1])]='0'} catch {}
            } elseif($ins.Op -notin @('push','pop','cmp','test','nop') -and $ins.Op -notmatch '^j' -and $ins.Args -match '^([re][a-z0-9]+),') {
                try {$state[(Canonical-Register $Matches[1])]='unknown-write'} catch {}
            }
            if($ins.Op -eq 'lea' -and $ins.Args -match '\*4\]') {$facts.Scale4=$true}; if($ins.Op -eq 'cmp' -and $ins.Args -match '^dword ptr \[.+\],(r\w+d)$' -and (Resolve-Value $Matches[1] $state) -in @('dword ptr [r8]','dword ptr [{r8}]')) {$facts.CompareKey=$true}; if($ins.Op -eq 'cmp' -and $ins.Args -match ',5$') {$facts.ComponentPolicy=$true}
        }
        $facts.ReturnsOutput=$state['rax'] -eq 'rcx'
        if(!$returned) {throw 'Callee return outside instruction budget'}
        $accepted=switch($kind) {
            'skip-startup-disable' {$facts.TreeRoot -and $facts.Key -and $facts.WriteNode -and $facts.WriteInserted -and $facts.ReturnsOutput}
            'allow-install-policy-inline' {$facts.ForwardResource -and $facts.ClearString -and $facts.ReturnsOutput}
            'normal-policy' {$facts.PolicyObject -and $facts.ComponentPolicy}
'reason-insert' {$facts.VectorBegin -and $facts.VectorLength -and $facts.IntKey -and $facts.Scale4 -and $facts.CompareKey -and $facts.VectorResult -and $facts.VectorFlag -and $state['rax'] -eq 'rdx'}
        }
        if(!$accepted) {throw "Callee shape mismatch: $kind / $($facts | ConvertTo-Json -Compress)"}
        return [pscustomobject]@{Rva=$rva;Kind=$kind;Facts=$facts;Instructions=$items}
    } finally {$nativeState.engine.Dispose()}
}

    function Write-NativeDump([string]$path,[long[]]$offsets,[uint64[]]$addresses) {
        $packed=[byte[]]::new(4096*$offsets.Count); $local=[long[]]::new($offsets.Count)
        for($i=0;$i -lt $offsets.Count;$i++) {
            $part=Read-StreamRange $Stream $offsets[$i] 4096
            if($null -eq $part) {throw 'Truncated native snippet'}
            $local[$i]=4096*$i; [Array]::Copy($part,0,$packed,4096*$i,4096)
        }
        [Mv2SnippetDump]::Write($path,$packed,$local,$addresses,$imageBase)
    }
    try {
        $seeds=[Collections.Generic.HashSet[long]]::new(); $block=4MB
        $buffer=[byte[]]::new($block+4097)
        foreach($range in $pe.ExecutableRanges) {
            $end=$range.Start+$range.Length
            for($core=$range.Start;$core -lt $end;$core+=$block) {
                $coreEnd=[Math]::Min($end,$core+$block); $begin=[Math]::Max($range.Start,$core-1)
                $count=[int]([Math]::Min($end,$coreEnd+4096)-$begin)
                $Stream.Position=$begin; $read=0
                while($read -lt $count) {$n=$Stream.Read($buffer,$read,$count-$read); if($n -le 0) {throw 'Short native scan read'}; $read+=$n}
                $hits=@()
                if($traceManifests) {$hits+=[Mv2SmallScan]::Seeds($buffer,0,$count)}
                if($traceReasons) {$hits+=[Mv2SmallScan]::Reasons($buffer,$count)}
                foreach($hit in $hits) {
                    $absolute=$begin+$hit
                    if($absolute -ge $core -and $absolute -lt $coreEnd) {[void]$seeds.Add($absolute)}
                }
                if($seeds.Count -gt 64) {throw 'Native candidate budget exceeded'}
            }
        }
        $offsets=@($seeds | Sort-Object)
        if(!$offsets.Count) {throw 'No bounded native candidates'}
        # Release streamed scan buffers before DbgEng's native allocations overlap them.
        $buffer=$null
        if($RuleNames.Count -lt $supported.Count) {[GC]::Collect()}
        $addresses=@(foreach($off in $offsets) {$imageBase+[uint64](ConvertTo-PeRva $pe $off 4096)})
        $dump=Join-Path $dumpRoot 'candidates.dmp'
        $results=@(); $rejected=@(); $reasonSeeds=@()
        if($traceManifests) {
        Write-NativeDump $dump ([long[]]$offsets) ([uint64[]]$addresses)
        $nativeState.engine=[Mv2NativeDisassembler]::new($dump)
        try {
            for($c=0;$c -lt $offsets.Count;$c++) {
                $nativeState.offset=[long]$offsets[$c]; $nativeState.lo=[uint64]$addresses[$c]; $nativeState.hi=$nativeState.lo+4096; $nativeState.cache=@{}
                try {
                    if((Read-Instruction $nativeState.lo).Op -eq 'mov') {
                        if($traceReasons) {$reasonSeeds+=@{Offset=$nativeState.offset;Address=$nativeState.lo}}
                    } else {
                        $item=$null
                        if($traceOriginal) {try {$item=Classify-Candidate $nativeState.lo} catch {}}
                        if(!$item -and $traceAdditional) {$item=Native-Manifest $nativeState.lo}
                        if($item -and $item.Name -in $RuleNames) {$results+=$item}
                    }
                }
                catch {$rejected+=[pscustomobject]@{Offset=$nativeState.offset;Reason=$_.Exception.Message}}
            }
        } finally {$nativeState.engine.Dispose(); $nativeState.engine=$null}
        } else {
            for($c=0;$c -lt $offsets.Count;$c++) {$reasonSeeds+=@{Offset=$offsets[$c];Address=$addresses[$c]}}
        }
        foreach($seed in $reasonSeeds) {
            $nativeState.offset=$seed.Offset; $nativeState.lo=$seed.Address; $nativeState.hi=$seed.Address+4096; $nativeState.cache=@{}
            try {$results+=Native-Reason $seed.Address}
            catch {$rejected+=[pscustomobject]@{Offset=$seed.Offset;Reason=$_.Exception.Message}}
        }
        # Keep diagnostics, but only caller-owned set returns now reach this list.
        $reasonResults=@($results | Where-Object Name -eq 'ignore-mv2-disable-reason-at-runtime')
        if($reasonResults.Count -eq 2) {
            $evidence=@($reasonResults.ExtraEvidence)
            if((@($evidence.Output.Role | Sort-Object) -join ',') -ne 'read-then-collapse,set-to-set' -or
                @($evidence.ValidatorRva | Sort-Object -Unique).Count -ne 1 -or @($evidence.InsertRva | Sort-Object -Unique).Count -ne 1) {throw 'Reason pair has inconsistent roles or callees'}
        }
        if($VerbosePreference -ne 'SilentlyContinue') {$rejected | ForEach-Object {Write-Verbose ("Native candidate {0}: {1}" -f $_.Offset,$_.Reason)}}
        foreach($name in $RuleNames) {
            if(@($results | Where-Object Name -eq $name).Count -ne $(if($name -in @('allow-enable-and-report','ignore-mv2-disable-reason-at-runtime')) {2} else {1})) {throw "Non-unique native result for $name"}
        }
        foreach($result in $results | Where-Object {$_.Name -in @('skip-startup-disable','allow-install-policy-inline')}) {
            $evidence=@(Test-Callee $result.CallRva $result.Name)
            if($result.NormalCallRva) {$evidence+=Test-Callee $result.NormalCallRva 'normal-policy'}
            $result | Add-Member NoteProperty CalleeEvidence $evidence
        }
        return $results
    } finally {
        foreach($name in @('candidates.dmp','callee.dmp','reason.dmp','validator.dmp')) {
            $file=Join-Path $dumpRoot $name
            if([IO.File]::Exists($file)) {[IO.File]::Delete($file)}
        }
        [IO.Directory]::Delete($dumpRoot)
    }
}

function Get-Mv2StreamRuleResults {
    param([IO.FileStream]$Stream,$Profile,$PeInfo)
    $patterns=@(); $hits=@{}; $window=4096
    foreach($rule in $Profile.Rules) {
        $hits[$rule.Name]=[Collections.Generic.HashSet[long]]::new()
        $variants=if($rule.ContainsKey('Variants')) {@($rule.Variants)} else {@($rule)}
        foreach($variant in $variants) {
            $pattern=ConvertTo-MaskedPattern $variant.Pattern
            $patch=Get-VariantPatchPatterns $rule $variant
            $at=[int]$variant.PatchOffset
            if($at -lt 0 -or $at+$patch.Original.Length -gt $pattern.Length -or $pattern.Length -gt $window) {throw 'Invalid streamed pattern window'}
            if($variant.ContainsKey('RequiredPattern') -and ($variant.RequiredPatternOffset -lt 0 -or
                $variant.RequiredPatternOffset+(ConvertTo-MaskedPattern $variant.RequiredPattern).Length -gt $window)) {throw 'Required pattern exceeds streamed window'}
            for($i=0;$i -lt $patch.Original.Length;$i++) {$pattern.Values[$at+$i]=0; $pattern.Masks[$at+$i]=0}
            $patterns+=[pscustomobject]@{Name=$rule.Name;Values=$pattern.Values;Masks=$pattern.Masks}
        }
    }
    $block=4MB; $buffer=[byte[]]::new($block+$window)
    foreach($range in $PeInfo.ExecutableRanges) {
        $end=$range.Start+$range.Length
        for($begin=$range.Start;$begin -lt $end;$begin+=$block) {
            $coreEnd=[Math]::Min($end,$begin+$block)
            $count=[int]([Math]::Min($end,$coreEnd+$window)-$begin)
            $Stream.Position=$begin; $read=0
            while($read -lt $count) {$n=$Stream.Read($buffer,$read,$count-$read); if($n -le 0) {throw 'Short pattern scan read'}; $read+=$n}
            foreach($pattern in $patterns) {
                foreach($hit in [Mv2SmallScan]::Masked($buffer,$pattern.Values,$pattern.Masks,$count)) {
                    if($begin+$hit -lt $coreEnd) {[void]$hits[$pattern.Name].Add($begin+$hit)}
                }
                if($hits[$pattern.Name].Count -gt 1024) {throw 'Pattern candidate budget exceeded'}
            }
        }
    }
    foreach($rule in $Profile.Rules) {
        $candidates=@(); $seen=@{}
        foreach($hit in ($hits[$rule.Name] | Sort-Object)) {
            $range=@($PeInfo.ExecutableRanges | Where-Object {$hit -ge $_.Start -and $hit -lt $_.Start+$_.Length})
            if($range.Count -ne 1) {throw 'Ambiguous candidate section'}
            $count=[int][Math]::Min($window,$Stream.Length-$hit)
            $part=Read-StreamRange $Stream $hit $count
            $localPe=[pscustomobject]@{ExecutableRanges=@([pscustomobject]@{Start=0L;Length=[long][Math]::Min($count,$range[0].Start+$range[0].Length-$hit)})}
            $validated=Get-RuleResult $part $rule $localPe
            foreach($candidate in $validated.Candidates | Where-Object MatchOffset -eq 0) {
                $candidate.MatchOffset+=$hit; $candidate.PatchOffset+=$hit
                if(!$seen.ContainsKey($candidate.PatchOffset) -or ($rule.ContainsKey('Variants') -and $candidate.Variant -lt $seen[$candidate.PatchOffset].Variant)) {
                    $seen[$candidate.PatchOffset]=$candidate
                }
            }
        }
        # Keep original variant precedence when different signatures share a patch site.
        $candidates=@(if($rule.ContainsKey('Variants')) {$seen.Values | Sort-Object Variant,MatchOffset} else {$seen.Values | Sort-Object MatchOffset})
        $result=[pscustomobject]@{Name=$rule.Name;Description=$rule.Description;MatchCount=$candidates.Count;Candidates=$candidates;Rule=$rule}
        if(!$rule.ContainsKey('Variants')) {
            $result | Add-Member NoteProperty OriginalPattern (ConvertTo-Pattern $rule.Original)
            $result | Add-Member NoteProperty ReplacementPattern (ConvertTo-Pattern $rule.Replacement)
        }
        $result
    }
}

function Resolve-TargetStreamAnalysis {
    param([string]$Path,[string]$CatalogPath)
    $catalog=Import-PowerShellDataFile -LiteralPath $CatalogPath
    if($catalog.SchemaVersion -ne 1) {throw 'Unsupported signature catalog schema'}
    $stream=[IO.File]::Open($Path,'Open','Read','Read')
    try {
        $pe=Get-PeStreamInfo $stream
        $profiles=@($catalog.Profiles | Where-Object {[int]$_.Machine -eq $pe.Machine})
        $profileResults=@(); $nativeEvidence=@()
        foreach($profile in $profiles) {
            $rules=@(Get-Mv2StreamRuleResults $stream $profile $pe)
            $bad=@($rules | Where-Object {(Get-RuleState $_) -eq 'Invalid'})
            $nativeNames=@('skip-startup-disable','allow-install-policy-inline','allow-enable-and-report','allow-enable-policy-inline','allow-install','ignore-mv2-disable-reason-at-runtime')
            # Never use tracing to excuse mixed bytes, duplicate signatures, or a broken unrelated rule.
            if($profile.Id -eq 'chromium-x64-manifest-v2-semantic' -and $rules.Count -eq 6 -and $bad.Count -gt 0 -and
                @($bad | Where-Object {$_.Name -notin $nativeNames -or $_.MatchCount -ne 0}).Count -eq 0 -and
                @($rules | Where-Object {$_.Name -notin $nativeNames -and (Get-RuleState $_) -ne 'Original'}).Count -eq 0 -and
                @($rules | Where-Object {$_.Name -in $nativeNames -and $_.MatchCount -gt 0 -and (Get-RuleState $_) -ne 'Original'}).Count -eq 0) {
                try {
                    $native=@(Get-Mv2NativeRules $stream $pe -RuleNames @($bad.Name))
                    foreach($group in $native | Group-Object Name) {
                        $matching=@($rules | Where-Object Name -eq $group.Name)[0]
                        if($group.Count -ne (Get-ExpectedMatchCount $matching.Rule)) {throw 'Native count disagreement'}
                        if($matching.MatchCount -gt 0 -and
                            ((@($matching.Candidates.PatchOffset | Sort-Object) -join ',') -ne (@($group.Group.PatchOffset | Sort-Object) -join ','))) {throw 'Native/signature set disagreement'}
                    }
                    foreach($group in $native | Group-Object Name) {
                        $matching=@($rules | Where-Object Name -eq $group.Name)[0]
                        if($matching.MatchCount -ne 0) {continue}
                        $candidates=@(foreach($item in $group.Group) {
                            $before=Read-StreamRange $stream $item.PatchOffset $item.Replacement.Count
                            if($null -eq $before) {throw 'Truncated native patch'}
                            [pscustomobject]@{MatchOffset=[long]$item.Offset;PatchOffset=[long]$item.PatchOffset;
                                State='Original';Variant=-1;OriginalPattern=$before;ReplacementPattern=[byte[]]$item.Replacement}
                        })
                        $matching.Candidates=$candidates; $matching.MatchCount=$candidates.Count
                        $nativeEvidence+=@($group.Group)
                    }
                } catch {Write-Verbose "Bounded trace rejected: $($_.Exception.Message)"}
            }
            $profileResults+=[pscustomobject]@{Profile=$profile;Rules=$rules;IsValid=@($rules | Where-Object {(Get-RuleState $_) -eq 'Invalid'}).Count -eq 0}
        }
        $valid=@($profileResults | Where-Object IsValid)
        if($valid.Count -ne 1) {
            $details=@($profileResults | ForEach-Object {$p=$_; foreach($r in $p.Rules) {if((Get-RuleState $r) -eq 'Invalid') {"$($p.Profile.Id)/$($r.Name): matches=$($r.MatchCount)/$(Get-ExpectedMatchCount $r.Rule)"}}})
            throw "No unique supported signature profile matched. The target was not modified.`n$($details -join "`n")"
        }
        $stream.Position=0; $sha=[Security.Cryptography.SHA256]::Create()
        try {$hash=([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','')} finally {$sha.Dispose()}
        $analysis=Complete-TargetAnalysis $Path $pe $valid[0] $hash
        $analysis | Add-Member NoteProperty PeInfo $pe
        $analysis | Add-Member NoteProperty NativeEvidence $nativeEvidence
        $analysis.Public | Add-Member NoteProperty Detector $(if($nativeEvidence.Count) {'StreamAndBoundedTrace'} else {'StreamMasked'})
        return $analysis
    } finally {$stream.Dispose()}
}

function New-StreamPatchPlan {
    param([string]$Path,$Analysis)
    $stream=[IO.File]::Open($Path,'Open','Read','Read')
    try {
        $stream.Position=0; $sha=[Security.Cryptography.SHA256]::Create()
        try {$hash=([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','')} finally {$sha.Dispose()}
        if($hash -ne $Analysis.Hash) {throw 'Target changed between analysis and planning'}
        $patches=@(); $occupied=@{}
        foreach($rule in $Analysis.Selected.Rules) {
            foreach($candidate in $rule.Candidates) {
                $replacement=@(if($candidate.PSObject.Properties.Name -contains 'ReplacementPattern') {$candidate.ReplacementPattern} else {$rule.ReplacementPattern})
                $before=Read-StreamRange $stream $candidate.PatchOffset $replacement.Count
                if($null -eq $before) {throw 'Truncated patch bytes'}
                $after=[byte[]]$before.Clone()
                for($i=0;$i -lt $replacement.Count;$i++) {
                    $at=[long]$candidate.PatchOffset+$i
                    if($occupied.ContainsKey($at)) {throw 'Overlapping patch plan'}; $occupied[$at]=$true
                    if($replacement[$i] -ge 0) {$after[$i]=[byte]$replacement[$i]}
                }
                if(($before -join ',') -ne ($after -join ',')) {
                    $patches+=[pscustomobject]@{Name=$rule.Name;Offset=[long]$candidate.PatchOffset;Before=(Get-HexBytes $before);After=(Get-HexBytes $after)}
                }
            }
        }
        return [pscustomobject]@{Patches=$patches}
    } finally {$stream.Dispose()}
}

function Get-Mv2NativeReceiptAnalysis {
    param([string]$Path,[string]$BackupBase,[string]$CatalogPath,[ref]$VerifiedRecord)
    try {
        $version=[Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
        $candidate=Get-LatestTargetReceipt $BackupBase $Path $version.FileVersion
        $record=if($candidate) {$candidate.Record} else {$null}
        if((-not $record -or $record.PSObject.Properties.Name -notcontains 'NativeTrace' -or $record.NativeTrace -ne $true) -and (Test-Path -LiteralPath ($Path+'.mv2-receipt.json'))) {
            $record=Get-Content -LiteralPath ($Path+'.mv2-receipt.json') -Raw | ConvertFrom-Json
        }
        if(-not $record -or $record.PSObject.Properties.Name -notcontains 'NativeTrace' -or $record.NativeTrace -ne $true) {return $null}
        if($record.SchemaVersion -ne 1 -or $record.State -ne 'Applied' -or $record.FileVersion -ne $version.FileVersion -or
            [IO.Path]::GetFullPath($record.TargetPath) -ne [IO.Path]::GetFullPath($Path) -or
            -not (Test-Path -LiteralPath $record.BackupPath -PathType Leaf)) {return $null}
        if((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $record.PatchedSHA256) {return $null}
        # Recompute the original's bounded evidence and patch plan; a receipt alone is not authority.
        $analysis=Resolve-TargetStreamAnalysis $record.BackupPath $CatalogPath
        if(-not $analysis.AllOriginal -or $analysis.Hash -ne $record.OriginalSHA256 -or $analysis.Selected.Profile.Id -ne $record.Profile) {return $null}
        $plan=New-StreamPatchPlan $record.BackupPath $analysis
        if($plan.Patches.Count -ne @($record.Patches).Count) {return $null}
        foreach($patch in $plan.Patches) {
            $matches=@($record.Patches | Where-Object {$_.Name -eq $patch.Name -and $_.Offset -eq $patch.Offset -and $_.Before -eq $patch.Before -and $_.After -eq $patch.After})
            if($matches.Count -ne 1) {return $null}
        }
        # Hash the complete original with only the recomputed patches projected into each block.
        $source=[IO.File]::Open($record.BackupPath,'Open','Read','Read')
        $sha=[Security.Cryptography.SHA256]::Create()
        try {
            $buffer=[byte[]]::new(4MB); $offset=0L
            while(($n=$source.Read($buffer,0,$buffer.Length)) -gt 0) {
                foreach($patch in $plan.Patches) {
                    $after=ConvertTo-ConcreteBytes $patch.After
                    $first=[Math]::Max($offset,[long]$patch.Offset)
                    $last=[Math]::Min($offset+$n,[long]$patch.Offset+$after.Length)
                    if($last -gt $first) {[Array]::Copy($after,$first-$patch.Offset,$buffer,$first-$offset,$last-$first)}
                }
                [void]$sha.TransformBlock($buffer,0,$n,$buffer,0); $offset+=$n
            }
            [void]$sha.TransformFinalBlock([byte[]]@(),0,0)
            $projected=([BitConverter]::ToString($sha.Hash)).Replace('-','')
        } finally {$sha.Dispose(); $source.Dispose()}
        if($projected -ne $record.PatchedSHA256 -or (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $projected) {return $null}
        $result=$analysis.Public
        $result.Target=[IO.Path]::GetFullPath($Path); $result.SHA256=$projected; $result.State='AlreadyPatched'
        foreach($rule in $result.Rules) {$rule.State='Patched'}
        $result | Add-Member NoteProperty Verification 'NativeReceiptVerified'
        if($null -ne $VerifiedRecord) {$VerifiedRecord.Value=$record}
        return $result
    } catch {Write-Verbose "Native receipt was not usable: $($_.Exception.Message)"; return $null}
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
    $nativeReceipt = $null
    $fastAnalysis = Get-Mv2NativeReceiptAnalysis $resolved $BackupBase $resolvedCatalog -VerifiedRecord ([ref]$nativeReceipt)
    if (-not $fastAnalysis) { $fastAnalysis = Get-ReceiptPatchedAnalysis $resolved $BackupBase $resolvedCatalog }
    if ($fastAnalysis) {
        if ($OutputPath) {
            Copy-Item -LiteralPath $resolved -Destination $OutputPath
            if ($nativeReceipt) {
                $outputFull = if (Test-Path -LiteralPath $OutputPath -PathType Container) {
                    Join-Path ([IO.Path]::GetFullPath($OutputPath)) ([IO.Path]::GetFileName($resolved))
                } else { [IO.Path]::GetFullPath($OutputPath) }
                if ((Get-FileHash -LiteralPath $outputFull -Algorithm SHA256).Hash -ne $nativeReceipt.PatchedSHA256) { throw 'Copied output hash verification failed.' }
                $nativeReceipt.TargetPath = $outputFull
                $nativeReceipt | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath ($outputFull+'.mv2-receipt.json') -Encoding UTF8
            }
        }
        return $fastAnalysis
    }
    $analysis = Resolve-TargetStreamAnalysis $resolved $resolvedCatalog
    if (-not $InPlace -and [string]::IsNullOrWhiteSpace($OutputPath)) {
        return $analysis.Public
    }
    if ($analysis.AllPatched) {
        if ($OutputPath) {
            Copy-Item -LiteralPath $resolved -Destination $OutputPath
        }
        return $analysis.Public
    }

    # Disk writes keep the existing verified backup/rollback transaction.
    $bytes = [IO.File]::ReadAllBytes($resolved)
    if ((Get-ByteArraySha256 $bytes) -ne $analysis.Hash) { throw 'Target changed after streamed analysis; retry.' }
    $patchData = New-PatchedBytes $bytes $analysis.Selected
    $patchedHash = Get-ByteArraySha256 $patchData.Bytes
    if ($OutputPath) {
        $outputFull = [IO.Path]::GetFullPath($OutputPath)
        [IO.File]::WriteAllBytes($outputFull, $patchData.Bytes)
        if ((Get-FileHash -LiteralPath $outputFull -Algorithm SHA256).Hash -ne $patchedHash) {
            throw 'Output hash verification failed.'
        }
        if ($analysis.NativeEvidence.Count -gt 0) {
            [pscustomobject]@{
                SchemaVersion=1;State='Applied';NativeTrace=$true;TargetPath=$outputFull;BackupPath=$resolved;
                FileVersion=$analysis.Version.FileVersion;Profile=$analysis.Selected.Profile.Id;
                OriginalSHA256=$analysis.Hash;PatchedSHA256=$patchedHash;Patches=$patchData.Patches
            } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath ($outputFull+'.mv2-receipt.json') -Encoding UTF8
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
            NativeTrace = ($analysis.NativeEvidence.Count -gt 0)
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
            if ($analysis.NativeEvidence.Count -gt 0) {
                # Reconstruct the verified original in the readback buffer; disk bytes are untouched.
                foreach ($patch in $patchData.Patches) {
                    $after = ConvertTo-ConcreteBytes $patch.After
                    if (-not (Test-BytesAt $writtenBytes $patch.Offset ([int[]]$after))) { throw 'Native readback differs from verified plan.' }
                    $before = ConvertTo-ConcreteBytes $patch.Before
                    [Array]::Copy($before, 0, $writtenBytes, $patch.Offset, $before.Length)
                }
                if ((Get-ByteArraySha256 $writtenBytes) -ne $analysis.Hash) { throw 'Native readback has changes outside the verified plan.' }
            } else {
                $writtenAnalysis = Resolve-TargetAnalysis $resolved $writtenBytes $CatalogPath
                if (-not $writtenAnalysis.AllPatched) { throw 'Post-write rule verification failed.' }
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

    $exeStream = [IO.File]::OpenRead($resolved)
    try {
        if ((Get-PeStreamInfo $exeStream).Machine -ne 0x8664) { throw "RAM launch requires an x64 browser executable: $resolved" }
    } finally { $exeStream.Dispose() }
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
    $analysis = Resolve-TargetStreamAnalysis $resolved $CatalogPath
    if (-not $analysis.AllOriginal) {
        if ($analysis.AllPatched) {
            throw 'RAM launch requires an original, unpatched target DLL. Restore or update the browser before trying it.'
        }
        throw 'RAM launch requires every verified rule to be in its original state.'
    }
    $peInfo = $analysis.PeInfo
    if ($peInfo.Machine -ne 0x8664) {
        throw 'RAM launch currently supports x64 Chromium browsers only.'
    }

    $browserPath = Resolve-RamBrowserExecutable $resolved $BrowserExecutable `
        $analysis.Version
    $workingDirectory = Split-Path -Parent $browserPath
    Assert-BrowserStopped $browserPath
    $parsedChromeArguments = [RamPatchLauncher]::ParseArguments($ChromeArguments)

    $patchData = New-StreamPatchPlan $resolved $analysis
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
    $chromeArgumentsLabel.Text = 'ブラウザ起動引数（RAM起動用）'
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
