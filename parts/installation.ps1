function Get-Mv2BackupEntry {
    param([string]$Directory)
    try {
        $directoryPath = (Get-Item -LiteralPath $Directory -ErrorAction Stop).FullName
        if ((Get-Item -LiteralPath $directoryPath).Attributes -band [IO.FileAttributes]::ReparsePoint) { return }
        $kind = $null; $identity = $null; $timestamp = $null
        foreach ($name in @('receipt.json', 'proxy-receipt.json', 'profile-backup.json')) {
            $path = Join-Path $directoryPath $name
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
            if ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) { return }
            $record = Get-Content -LiteralPath $path -Encoding UTF8 -Raw | ConvertFrom-Json
            if ($record.SchemaVersion -ne 1) { return }
            switch ($name) {
                'receipt.json' {
                    if ($record.Tool -ne 'chromium_mv2_patch.ps1' -or $record.State -notin @('Applied','Restored')) { return }
                    if ([IO.Path]::GetFullPath($record.BackupPath) -ne (Join-Path $directoryPath ([IO.Path]::GetFileName($record.TargetPath)))) { return }
                    $kind = 'Disk'; $identity = (Get-PatchLockRoot $record.TargetPath) + '|' + [IO.Path]::GetFileName($record.TargetPath)
                    $timestamp = $record.AppliedUtc
                }
                'proxy-receipt.json' {
                    if ($record.Kind -ne 'DllProxy' -or $record.State -ne 'Installed' -or -not $record.PSObject.Properties['TargetPath']) { return }
                    if ([IO.Path]::GetFullPath($record.BackupDirectory) -ne $directoryPath) { return }
                    $kind = 'Dll'; $identity = (Get-PatchLockRoot $record.TargetPath) + '|' + [IO.Path]::GetFileName($record.TargetPath)
                    $timestamp = $record.InstalledUtc
                }
                'profile-backup.json' {
                    if ((Split-Path -Leaf $directoryPath) -notmatch '^(RamLaunch|BrowserLaunch)_') { return }
                    if (-not [IO.Path]::GetFullPath($record.ExtensionInventoryPath).StartsWith($directoryPath + '\', [StringComparison]::OrdinalIgnoreCase)) { return }
                    $kind = 'Profile'; $identity = [IO.Path]::GetFullPath($record.UserDataRoot)
                    $timestamp = $record.CreatedUtc
                }
            }
            if (-not [IO.Path]::IsPathRooted($identity.Split('|')[0])) { return }
            return [pscustomobject]@{
                Directory = $directoryPath; Key = ($kind + '|' + $identity).ToLowerInvariant()
                CreatedUtc = [datetime]::Parse($timestamp, [Globalization.CultureInfo]::InvariantCulture).ToUniversalTime()
            }
        }
    } catch { return } # Unknown, incomplete, or malformed backups are retained.
}

function Move-Mv2BackupToRecycleBin {
    param([string]$Directory, [string]$BackupBase)
    $basePath = (Get-Item -LiteralPath $BackupBase -ErrorAction Stop).FullName.TrimEnd('\')
    $targetPath = (Get-Item -LiteralPath $Directory -ErrorAction Stop).FullName
    if ($targetPath.StartsWith('\\') -or
        ([IO.DriveInfo]::new([IO.Path]::GetPathRoot($targetPath))).DriveType -ne [IO.DriveType]::Fixed) {
        throw 'Automatic recycling is limited to local fixed drives; backup retained.'
    }
    if ((Split-Path -Parent $targetPath) -ne $basePath -or -not (Get-Mv2BackupEntry $targetPath)) {
        throw 'Backup cleanup requires an owned direct child of the selected backup directory.'
    }
    # Inspect without following directory junctions before handing the tree to Windows.
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($targetPath)
    while ($pending.Count) {
        $item = Get-Item -LiteralPath $pending.Pop() -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Backup contains a reparse point; retained.' }
        if ($item.PSIsContainer) {
            foreach ($child in Get-ChildItem -LiteralPath $item.FullName -Force -ErrorAction Stop) { $pending.Push($child.FullName) }
        }
    }
    if (-not [Environment]::UserInteractive) { throw 'Recycle Bin is unavailable in this non-interactive session; backup retained.' }
    Add-Type -AssemblyName Microsoft.VisualBasic
    [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory($targetPath,
        [Microsoft.VisualBasic.FileIO.UIOption]::OnlyErrorDialogs,
        [Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin,
        [Microsoft.VisualBasic.FileIO.UICancelOption]::ThrowException)
    Write-Information "Old backup moved to the Recycle Bin: $targetPath" -InformationAction Continue
}

function Limit-Mv2Backups {
    param([string]$BackupBase, [string]$CompletedDirectory)
    try {
        if (-not (Test-Path -LiteralPath $BackupBase -PathType Container)) { return }
        $current = Get-Mv2BackupEntry $CompletedDirectory
        if (-not $current) { return }
        $basePath = (Get-Item -LiteralPath $BackupBase -ErrorAction Stop).FullName.TrimEnd('\')
        if ((Split-Path -Parent $current.Directory) -ne $basePath) { return }
        $older = @(Get-ChildItem -LiteralPath $basePath -Directory -ErrorAction Stop |
            ForEach-Object { Get-Mv2BackupEntry $_.FullName } |
            Where-Object { $_.Key -eq $current.Key -and $_.Directory -ne $current.Directory } |
            Sort-Object CreatedUtc, Directory -Descending)
        # One completed backup plus the four newest peers. Failed work never prunes.
        foreach ($entry in @($older | Select-Object -Skip 4)) {
            try { Move-Mv2BackupToRecycleBin $entry.Directory $basePath }
            catch { Write-Warning "Backup retained: $($entry.Directory). $($_.Exception.Message)" }
        }
    } catch { Write-Warning "Backup retention skipped: $($_.Exception.Message)" }
}

function Write-Mv2Json {
    param([string]$Path, $Value)
    $directory = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $temporary = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::WriteAllText($temporary, ($Value | ConvertTo-Json -Depth 8),
            (New-Object Text.UTF8Encoding $false))
        if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temporary, $Path, ($Path + '.previous')) }
        else { [IO.File]::Move($temporary, $Path) }
    } finally {
        if (Test-Path -LiteralPath $temporary) { [IO.File]::Delete($temporary) }
    }
}

function Get-Mv2EnvironmentPaths {
    param([string]$Path)
    $targetPath = [IO.Path]::GetFullPath($Path)
    $root = Get-PatchLockRoot $targetPath
    $name = [IO.Path]::GetFileName($targetPath).ToLowerInvariant()
    if ($name -notmatch '^[a-z0-9_.-]+\.dll$') { throw 'Unsupported browser DLL filename.' }
    $sha = [Security.Cryptography.SHA1]::Create()
    try {
        $identity = ([BitConverter]::ToString($sha.ComputeHash(
            [Text.Encoding]::UTF8.GetBytes(($root.TrimEnd('\') + '|' + $name).ToLowerInvariant())))).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
    return [pscustomobject]@{
        Root = $root; Name = $name; Id = $identity
        Central = Join-Path $Mv2PackageRoot "chromium_mv2_environments\$identity.json"
        Portable = Join-Path $root ".chromium-mv2-cache\$name.environment.json"
        Cache = Join-Path $Mv2PackageRoot "chromium_mv2_cache\$identity"
    }
}

function Get-Mv2Environment {
    param([string]$Path)
    $paths = Get-Mv2EnvironmentPaths $Path
    foreach ($entry in @($paths.Portable, $paths.Central)) {
        if (-not (Test-Path -LiteralPath $entry -PathType Leaf)) { continue }
        $record = Get-Content -Raw -Encoding UTF8 -LiteralPath $entry | ConvertFrom-Json
        if ($record.SchemaVersion -ne 1 -or $record.Method -notin @('Disk','Dll') -or
            $record.DllName -ne $paths.Name -or $record.Portable -isnot [bool]) {
            throw "Invalid environment configuration: $entry"
        }
        if ($entry -eq $paths.Central -and $record.Root -ne $paths.Root) {
            throw "Environment configuration belongs to another installation: $entry"
        }
        if ($entry -eq $paths.Portable -and -not $record.Portable) { continue }
        return $record
    }
    return [pscustomobject]@{
        SchemaVersion = 1; Method = 'Disk'; Portable = $false
        Root = $paths.Root; DllName = $paths.Name; ProxyDll = $null
    }
}

function Save-Mv2Environment {
    param([string]$Path, [ValidateSet('Disk','Dll')][string]$Method,
        [ValidateSet('Script','Portable')][string]$Location = 'Script', [string]$ProxyPath)
    $paths = Get-Mv2EnvironmentPaths $Path
    if ($Method -eq 'Disk') { Assert-NoMv2Proxy $Path }
    $record = [pscustomobject]@{
        SchemaVersion = 1; Method = $Method; Portable = ($Location -eq 'Portable')
        Root = $paths.Root; DllName = $paths.Name; ProxyDll = $ProxyPath
    }
    # Portable metadata travels with the directory. A central entry is a fallback.
    if ($record.Portable) { Write-Mv2Json $paths.Portable $record }
    else {
        Write-Mv2Json $paths.Central $record
        if (Test-Path -LiteralPath $paths.Portable) {
            # Keep the old marker as an inactive record instead of deleting it.
            Write-Mv2Json $paths.Portable $record
        }
    }
    return $record
}

function Get-Mv2ProxyRecord {
    param([string]$Path)
    $receipt = [IO.Path]::GetFullPath($Path) + '.mv2-proxy.json'
    if (-not (Test-Path -LiteralPath $receipt -PathType Leaf)) { return $null }
    $record = Get-Content -Raw -Encoding UTF8 -LiteralPath $receipt | ConvertFrom-Json
    if ($record.SchemaVersion -ne 1 -or $record.Kind -ne 'DllProxy' -or
        $record.State -notin @('Prepared','Installed','Removed') -or
        $record.DllName -ne [IO.Path]::GetFileName($Path) -or
        $record.OriginalSHA256 -notmatch '^[0-9A-Fa-f]{64}$' -or
        $record.ProxySHA256 -notmatch '^[0-9A-Fa-f]{64}$') {
        throw "Invalid DLL installation receipt: $receipt"
    }
    return $record
}

function Get-Mv2EffectiveVersion {
    param([string]$Path)
    $browserDirectory = Split-Path -Parent $Path
    $record = Get-Mv2ProxyRecord $Path
    if ($record -and $record.State -ne 'Removed') {
        $Path = Join-Path (Split-Path -Parent $Path) ('original\' + $record.DllName)
    }
    $info = [Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
    if (-not $info.FileVersion -and [IO.Path]::GetFileName($Path) -eq 'opera_browser.dll') {
        $exe = Join-Path $browserDirectory 'opera.exe'
        if (Test-Path -LiteralPath $exe -PathType Leaf) {
            return [Diagnostics.FileVersionInfo]::GetVersionInfo($exe)
        }
    }
    return $info
}

function Get-Mv2AcceptedProxyHashes {
    param($Record)
    $hashes = @($Record.OriginalSHA256, $Record.ProxySHA256)
    $previous = $Record.PSObject.Properties['PreviousProxySHA256']
    if ($Record.State -eq 'Prepared' -and $previous -and $previous.Value -match '^[0-9A-Fa-f]{64}$') {
        $hashes += $previous.Value
    }
    return $hashes
}

function Assert-NoMv2Proxy {
    param([string]$Path)
    $record = Get-Mv2ProxyRecord $Path
    if ($record -and $record.State -ne 'Removed') {
        throw 'DLL proxy mode is installed or partially prepared. Use -RemoveDll before a disk patch, legacy restore, or RAM launch.'
    }
}

function Get-Mv2BrowserProcesses {
    param([string]$ExecutablePath)
    $name = [IO.Path]::GetFileNameWithoutExtension($ExecutablePath)
    foreach ($process in @(Get-Process -Name $name -ErrorAction SilentlyContinue)) {
        try { $path = $process.Path } catch { $path = $null }
        if (-not $path) { throw "Cannot verify a browser process path; no automatic termination: PID $($process.Id)" }
        if ([string]::Equals($path, $ExecutablePath, [StringComparison]::OrdinalIgnoreCase)) { $process }
    }
}

function Assert-Mv2BrowserStopped {
    param([string]$ExecutablePath)
    if (@(Get-Mv2BrowserProcesses $ExecutablePath).Count) {
        throw "Close this browser and its background processes first: $ExecutablePath"
    }
}

function Stop-Mv2BrowserBackground {
    param([string]$ExecutablePath)
    $processes = @(Get-Mv2BrowserProcesses $ExecutablePath)
    $session = [Diagnostics.Process]::GetCurrentProcess().SessionId
    foreach ($process in $processes) {
        $process.Refresh()
        if (-not $process.HasExited -and ($process.SessionId -ne $session -or $process.MainWindowHandle -ne [IntPtr]::Zero)) {
            throw "Browser windows or another user session remain; close them manually: $ExecutablePath"
        }
    }
    $deadline = [datetime]::UtcNow.AddSeconds(5)
    foreach ($process in $processes) {
        $process.Refresh()
        if ($process.HasExited) { continue }
        if ($process.SessionId -ne $session -or $process.MainWindowHandle -ne [IntPtr]::Zero -or
            -not [string]::Equals($process.Path, $ExecutablePath, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Browser process state changed; automatic termination stopped.'
        }
        Write-Verbose "Stopping selected background browser PID $($process.Id): $ExecutablePath"
        $process.Kill()
        $remaining = [Math]::Max(0, [int]($deadline - [datetime]::UtcNow).TotalMilliseconds)
        if (-not $process.WaitForExit($remaining)) { throw 'Background browser termination exceeded five seconds.' }
    }
    if (@(Get-Mv2BrowserProcesses $ExecutablePath).Count) {
        throw 'The background browser restarted; installation stopped without waiting indefinitely.'
    }
}

function Invoke-Mv2NativeAudit {
    param([string]$Library, [string]$Mode, [string]$Path)
    if (-not (Test-Path -LiteralPath $Library -PathType Leaf)) {
        throw "Native component is missing: $Library"
    }
    if (-not ('ChromiumMv2Native' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
public static class ChromiumMv2Native {
    private static readonly object Sync = new object();
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr LoadLibraryExW(string path, IntPtr file, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr module, string name);
    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern bool FreeLibrary(IntPtr module);
    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
    private delegate uint Inspect(uint abi, string mode, string path,
        [Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 4)] byte[] output, uint capacity);
    public static string Run(string library, string mode, string path) {
        if (IntPtr.Size != 8) throw new PlatformNotSupportedException("DLL inspection requires 64-bit PowerShell.");
        library = Path.GetFullPath(library);
        if (!String.Equals(Path.GetFileName(library), "chromium_mv2_proxy.dll", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Load the shipped chromium_mv2_proxy.dll, not an installed browser DLL.");
        lock (Sync) {
            IntPtr module = LoadLibraryExW(library, IntPtr.Zero, 0x100 | 0x800);
            if (module == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot load MV2 inspection library.");
            try {
                IntPtr address = GetProcAddress(module, "Mv2InspectW");
                if (address == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "MV2 inspection entry point is missing.");
                Inspect inspect = (Inspect)Marshal.GetDelegateForFunctionPointer(address, typeof(Inspect));
                byte[] output = new byte[256 * 1024];
                uint status = inspect(1, mode, Path.GetFullPath(path), output, (uint)output.Length);
                int end = Array.IndexOf(output, (byte)0);
                if (end < 0) throw new InvalidDataException("Unterminated native inspection result.");
                string result = Encoding.UTF8.GetString(output, 0, end);
                if (status != 0) throw new InvalidDataException("Native preflight rejected '" + path + "' (" + mode + ", status " + status + "). " + result);
                GC.KeepAlive(inspect);
                return result;
            } finally { FreeLibrary(module); }
        }
    }
}
'@
    }
    return ([ChromiumMv2Native]::Run($Library, $Mode, $Path) | ConvertFrom-Json)
}

function Assert-Mv2OriginalFiles {
    param([string]$Directory, $Record)
    if (-not (Test-Path -LiteralPath $Directory -PathType Container) -or
        ((Get-Item -LiteralPath $Directory).Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        @($Record.Files | Where-Object Name -eq $Record.DllName).Count -ne 1) {
        throw 'The owned original-resource directory or manifest is invalid.'
    }
    foreach ($file in $Record.Files) {
        $path = [IO.Path]::GetFullPath((Join-Path $Directory ([string]$file.Name)))
        if (-not $path.StartsWith($Directory.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $path -PathType Leaf) -or
            ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $file.SHA256) {
            throw "Original resource verification failed: $path"
        }
    }
}

function Set-Mv2DllBytes {
    param([string]$Path, [byte[]]$Bytes, [string]$ExpectedHash)
    $stream = Open-Mv2PrivateDllWrite $Path $ExpectedHash
    try {
        $before = Read-ExclusiveStreamBytes $stream
        if ((Get-ByteArraySha256 $before) -ne $ExpectedHash) { throw 'The browser DLL changed before the write lock was acquired.' }
        try {
            $stream.Position = 0; $stream.Write($Bytes, 0, $Bytes.Length)
            $stream.SetLength($Bytes.Length); $stream.Flush($true)
            if ((Get-ByteArraySha256 (Read-ExclusiveStreamBytes $stream)) -ne (Get-ByteArraySha256 $Bytes)) {
                throw 'DLL write verification failed.'
            }
        } catch {
            $failure = $_
            $stream.Position = 0; $stream.Write($before, 0, $before.Length)
            $stream.SetLength($before.Length); $stream.Flush($true)
            throw $failure
        }
    } finally { $stream.Dispose() }
}

function Set-Mv2ProxyConfig {
    param([string]$Path, [string]$Location, [bool]$Enabled)
    $cache = if ($Location -eq 'Portable') { '' } else { (Get-Mv2EnvironmentPaths $Path).Cache }
    if ($cache.IndexOfAny([char[]]"`r`n`0") -ge 0 -or $cache.Length -ge 1023) { throw 'Invalid cache directory.' }
    if ($cache) {
        try { New-Item -ItemType Directory -Path $cache -Force | Out-Null }
        catch { Write-Warning "Cache directory is not writable; DLL analysis will run without saving: $cache" }
    }
    $config = "[ChromiumMV2]`r`nEnabled=$([int]$Enabled)`r`nCacheDirectory=$cache`r`n"
    # Win32 profile APIs recognize UTF-16 BOM, including Japanese directory names.
    [IO.File]::WriteAllText(($Path + '.mv2.ini'), $config, [Text.Encoding]::Unicode)
    return $cache
}

function New-Mv2OriginalLayout {
    param([string]$Directory, [string]$Stage, [string]$Source, [string]$Browser)
    $dllName = [IO.Path]::GetFileName($Source)
    $originalName = [IO.Path]::GetFileName([Diagnostics.FileVersionInfo]::GetVersionInfo($Browser).OriginalFilename)
    $names = @($dllName, ($dllName + '.sig'), ([IO.Path]::GetFileName($Browser) + '.sig'))
    if ($originalName) { $names += $originalName + '.sig' }
    $names = @($names | Select-Object -Unique)
    $files = @()
    foreach ($name in $names) {
        $path = if ($name -eq $dllName) { $Source } else { Join-Path $Directory $name }
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $item = Get-Item -LiteralPath $path -Force
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Expected an ordinary DLL or signature file: $path" }
        $files += $item
    }
    New-Item -ItemType Directory -Path $Stage | Out-Null
    foreach ($file in $files) {
        $isOriginal = $file.FullName -eq $Source
        $relative = if ($isOriginal) { $dllName } else { $file.FullName.Substring($Directory.Length + 1) }
        $target = Join-Path $Stage $relative
        New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $target
        $hash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
        if ($hash -ne (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash) { throw 'A resource changed during preparation.' }
        [pscustomobject]@{ Name = $relative; SHA256 = $hash; Storage = 'Copy' }
    }
}

function Install-Mv2Proxy {
    param([string]$Path, [string]$BackupBase, [string]$Location,
        [string]$BrowserExecutable, [string]$ProxyPath, [switch]$Automatic)
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $directory = Split-Path -Parent $resolved
    if ((Split-Path -Leaf $directory) -eq 'original') { throw 'Select the outer browser DLL, not original\*.dll.' }
    $originalDirectory = Join-Path $directory 'original'
    $originalPath = Join-Path $originalDirectory ([IO.Path]::GetFileName($resolved))
    $recordPath = $resolved + '.mv2-proxy.json'
    $record = Get-Mv2ProxyRecord $resolved
    $environment = Get-Mv2Environment $resolved
    if (-not $Location) { $Location = if ($environment.Portable) { 'Portable' } else { 'Script' } }
    if (-not $ProxyPath) { $ProxyPath = $environment.ProxyDll }
    $source = if ($record -and $record.State -ne 'Removed') { $originalPath } else { $resolved }
    $nativeDirectory = if ([IO.Path]::GetFileName($resolved) -ieq 'msedge.dll') { 'native\edge' } else { 'native' }
    $audit = Join-Path (Join-Path $Mv2PackageRoot $nativeDirectory) 'chromium_mv2_proxy.dll'
    $resourceAudit = Invoke-Mv2NativeAudit $audit 'resources' $source
    if (-not $resourceAudit.compatible) { throw 'Resource-routing imports are missing or ambiguous. The browser was not changed.' }
    if ($ProxyPath) {
        $ProxyPath = (Resolve-Path -LiteralPath $ProxyPath).Path
        if ((Get-FileHash -LiteralPath $ProxyPath -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $audit -Algorithm SHA256).Hash) {
            throw 'Export generation only accepts the bundled template for this browser ABI. A custom proxy requires separate validation.'
        }
    }
    $selectedTemplate = $ProxyPath
    $adaptiveBrowser = Resolve-RamBrowserExecutable $resolved $BrowserExecutable ([Diagnostics.FileVersionInfo]::GetVersionInfo($source))
    $null = Invoke-Mv2NativeAudit $audit 'exe' $adaptiveBrowser
    if (-not ('Mv2AdaptiveExports' -as [type])) {
        Add-Type -Path (Join-Path $Mv2PackageRoot 'parts\adaptive-exports.cs') -ErrorAction Stop
    }
    $adaptiveExports = [Mv2AdaptiveExports]::Prepare($Mv2PackageRoot, $audit, $source, $adaptiveBrowser)
    $ProxyPath = (Resolve-Path -LiteralPath $adaptiveExports.proxyPath).Path
    if ($adaptiveExports.format -ne 'AdaptiveExports1' -or
        $adaptiveExports.templateSHA256 -ne (Get-FileHash -LiteralPath $audit -Algorithm SHA256).Hash -or
        $adaptiveExports.originalSHA256 -ne (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -or
        $adaptiveExports.browserSHA256 -ne (Get-FileHash -LiteralPath $adaptiveBrowser -Algorithm SHA256).Hash -or
        $adaptiveExports.proxySHA256 -ne (Get-FileHash -LiteralPath $ProxyPath -Algorithm SHA256).Hash) {
        throw 'Adaptive generation inputs or output changed. The browser was not changed.'
    }
    if ($ProxyPath -eq $resolved -or $ProxyPath -eq $originalPath) { throw 'The proxy source must be a separate file.' }
    if ($record) { Assert-Mv2OriginalFiles $originalDirectory $record }
    if ($Automatic -and $record -and $record.State -eq 'Installed' -and
        $record.PSObject.Properties.Name -contains 'ResourceLayout' -and $record.ResourceLayout -eq 'Routed1' -and
        (Test-Path -LiteralPath ($resolved + '.mv2.ini'))) {
        $cache = if ($Location -eq 'Portable') { '' } else { (Get-Mv2EnvironmentPaths $resolved).Cache }
        $expectedConfig = "[ChromiumMV2]`r`nEnabled=1`r`nCacheDirectory=$cache`r`n"
        if ([IO.File]::ReadAllText($resolved + '.mv2.ini') -eq $expectedConfig -and
            (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash -eq $record.ProxySHA256 -and
            (Get-FileHash -LiteralPath $ProxyPath -Algorithm SHA256).Hash -eq $record.ProxySHA256 -and
            (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -eq $record.OriginalSHA256) {
            return [pscustomobject]@{ State = 'AlreadyHandled'; Method = 'Dll'; Target = $resolved }
        }
    }
    $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($source)
    $browser = Resolve-RamBrowserExecutable $resolved $BrowserExecutable $version
    $browserDirectory = Split-Path -Parent $browser
    if ($browserDirectory -notin @((Get-PatchLockRoot $resolved), $directory)) { throw 'The executable must belong to the selected installation root or DLL directory.' }
    Stop-Mv2BrowserBackground $browser
    $null = Invoke-Mv2NativeAudit $audit 'exe' $browser
    # MV2 detection runs once in the browser and caches successes and failures.
    # A missing patch must not prevent installing or starting a compatible forwarding DLL.
    $originalHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    $proxyBytes = [IO.File]::ReadAllBytes($ProxyPath)
    $proxyHash = Get-ByteArraySha256 $proxyBytes
    if ($adaptiveExports -and ($originalHash -ne $adaptiveExports.originalSHA256 -or $proxyHash -ne $adaptiveExports.proxySHA256 -or
        $adaptiveExports.browserSHA256 -ne (Get-FileHash -LiteralPath $browser -Algorithm SHA256).Hash)) {
        throw 'Adaptive generation inputs or output changed before installation. The browser was not changed.'
    }
    $currentHash = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash
    $obsoleteOriginal = $null
    if ($record) {
        if ($originalHash -ne $record.OriginalSHA256 -or
            $currentHash -notin @(Get-Mv2AcceptedProxyHashes $record)) {
            throw 'This DLL no longer matches the proxy receipt. It may have been repaired or updated; no files were overwritten.'
        }
        if ($record.PSObject.Properties.Name -notcontains 'ResourceLayout' -or $record.ResourceLayout -ne 'Routed1') {
            if (@(Get-ChildItem -LiteralPath $originalDirectory -Directory -Recurse -Force |
                Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) { throw 'Reparse directories cannot be migrated.' }
            $actualFiles = @(Get-ChildItem -LiteralPath $originalDirectory -File -Recurse -Force)
            if ($actualFiles.Count -ne @($record.Files).Count) { throw 'Untracked original files must be reviewed before layout migration.' }
            $stage = Join-Path $directory ('.chromium-mv2-prepare-' + [guid]::NewGuid().ToString('N'))
            $files = @(New-Mv2OriginalLayout $directory $stage $source $browser)
            $obsoleteOriginal = Join-Path $directory ('.chromium-mv2-old-original-' + [guid]::NewGuid().ToString('N'))
            Write-Mv2Json ($obsoleteOriginal + '.json') $record
            # Activate routing before retiring resources. A failed DLL write
            # leaves the previous proxy and complete resource layout usable.
        }
    } else {
        if (Test-Path -LiteralPath $originalDirectory) { throw "An unowned original directory already exists: $originalDirectory" }
        if (Test-Path -LiteralPath ($resolved + '.mv2.ini')) { throw 'An unowned proxy configuration already exists.' }
        # Only the DLL and its two signature files are copied. Flat packages may
        # retain profiles alongside them; no profile or other directory is copied.
        if (@(Get-ChildItem -LiteralPath $directory -Directory -Filter '.chromium-mv2-*' |
            Where-Object Name -ne '.chromium-mv2-cache').Count) { throw 'A previous preparation directory needs inspection before retrying.' }
        $stage = Join-Path $directory ('.chromium-mv2-prepare-' + [guid]::NewGuid().ToString('N'))
        $files = @(New-Mv2OriginalLayout $directory $stage $source $browser)
        if ((Get-FileHash -LiteralPath (Join-Path $stage ([IO.Path]::GetFileName($resolved))) -Algorithm SHA256).Hash -ne $originalHash) {
            throw 'The original DLL changed during layout preparation.'
        }
        $backup = Join-Path $BackupBase ('DllProxy_' + ($version.FileVersion -replace '[^a-zA-Z0-9._-]', '_') + '_' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $backup -Force | Out-Null
        Copy-Item -LiteralPath $resolved -Destination (Join-Path $backup ([IO.Path]::GetFileName($resolved)))
        if ((Get-FileHash -LiteralPath (Join-Path $backup ([IO.Path]::GetFileName($resolved))) -Algorithm SHA256).Hash -ne $originalHash) { throw 'Original DLL backup verification failed.' }
        $record = [pscustomobject]@{
            SchemaVersion = 1; Kind = 'DllProxy'; State = 'Prepared'
            DllName = [IO.Path]::GetFileName($resolved); BrowserName = [IO.Path]::GetFileName($browser)
            BrowserInVersionDirectory = ($browserDirectory -ne (Get-PatchLockRoot $resolved))
            TargetPath = $resolved
            FileVersion = $version.FileVersion; OriginalSHA256 = $originalHash
            ProxySHA256 = $proxyHash; Files = $files; BackupDirectory = $backup
            ResourceLayout = 'Routed1'
            InstalledUtc = [datetime]::UtcNow.ToString('o')
        }
        Write-Mv2Json (Join-Path $backup 'proxy-receipt.json') $record
        # Both directories are direct children of the checked version directory.
        [IO.Directory]::Move($stage, $originalDirectory)
    }
    Assert-Mv2BrowserStopped $browser
    $record.State = 'Prepared'
    if ($adaptiveExports) { $record | Add-Member -NotePropertyName AdaptiveExports -NotePropertyValue $adaptiveExports -Force }
    $record | Add-Member -NotePropertyName PreviousProxySHA256 -NotePropertyValue $currentHash -Force
    $record.ProxySHA256 = $proxyHash
    Write-Mv2Json $recordPath $record
    $cache = Set-Mv2ProxyConfig $resolved $Location $true
    if ($currentHash -ne $proxyHash) { Set-Mv2DllBytes $resolved $proxyBytes $currentHash }
    if ($obsoleteOriginal) {
        [IO.Directory]::Move($originalDirectory, $obsoleteOriginal)
        try { [IO.Directory]::Move($stage, $originalDirectory) }
        catch { [IO.Directory]::Move($obsoleteOriginal, $originalDirectory); throw }
        $record.Files = $files
        $record | Add-Member -NotePropertyName ResourceLayout -NotePropertyValue 'Routed1' -Force
        Write-Mv2Json $recordPath $record
        Assert-Mv2OriginalFiles $originalDirectory $record
    }
    $record.State = 'Installed'
    $record.PreviousProxySHA256 = $null
    Write-Mv2Json $recordPath $record
    $null = Save-Mv2Environment $resolved 'Dll' $Location $selectedTemplate
    if ($obsoleteOriginal) {
        try {
            $retired = Get-Content -LiteralPath ($obsoleteOriginal + '.json') -Raw -Encoding UTF8 | ConvertFrom-Json
            $retired.BackupDirectory = $obsoleteOriginal; $retired.State = 'Installed'
            $retired | Add-Member -NotePropertyName TargetPath -NotePropertyValue $resolved -Force
            $retiredReceipt = Join-Path $obsoleteOriginal 'proxy-receipt.json'
            $recoveryReceipt = Join-Path $obsoleteOriginal 'original-layout-before.json'
            if ((Test-Path -LiteralPath $retiredReceipt) -or (Test-Path -LiteralPath $recoveryReceipt)) { throw 'Existing recovery metadata retained.' }
            Write-Mv2Json $retiredReceipt $retired
            Move-Item -LiteralPath ($obsoleteOriginal + '.json') -Destination $recoveryReceipt
            Move-Mv2BackupToRecycleBin $obsoleteOriginal $directory
        } catch { Write-Warning "Old original resources retained at $obsoleteOriginal. $($_.Exception.Message)" }
    }
    if ([IO.File]::Exists([IO.Path]::Combine($record.BackupDirectory, $record.DllName))) {
        try {
            $record | Add-Member -NotePropertyName TargetPath -NotePropertyValue $resolved -Force
            Write-Mv2Json (Join-Path $record.BackupDirectory 'proxy-receipt.json') $record
            Limit-Mv2Backups $BackupBase $record.BackupDirectory
        } catch { Write-Warning "Backup retention metadata was not updated: $($_.Exception.Message)" }
    }
    return [pscustomobject]@{
        State = 'DllInstalled'; Target = $resolved; Original = $originalPath
        BrowserExecutable = $browser; CacheDirectory = if ($cache) { $cache } else { Join-Path (Split-Path -Parent $browser) '.chromium-mv2-cache' }
        Receipt = $recordPath; Backup = $record.BackupDirectory; NormalShortcut = $true
    }
}

function Remove-Mv2Proxy {
    param([string]$Path)
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $record = Get-Mv2ProxyRecord $resolved
    if (-not $record) { throw 'There is no owned DLL proxy installation at this path.' }
    if ([IO.Path]::GetFileName($record.BrowserName) -ne $record.BrowserName) { throw 'Invalid browser filename in the receipt.' }
    $browserDirectory = if ($record.PSObject.Properties.Name -contains 'BrowserInVersionDirectory' -and $record.BrowserInVersionDirectory -eq $true) {
        Split-Path -Parent $resolved
    } else { Get-PatchLockRoot $resolved }
    $browser = Join-Path $browserDirectory $record.BrowserName
    $originalDirectory = Join-Path (Split-Path -Parent $resolved) 'original'
    Assert-Mv2OriginalFiles $originalDirectory $record
    $original = Join-Path $originalDirectory $record.DllName
    $browserExists = Test-Path -LiteralPath $browser -PathType Leaf
    $originalName = if ($browserExists) { [Diagnostics.FileVersionInfo]::GetVersionInfo($browser).OriginalFilename } else { $null }
    if (-not $browserExists -or ($originalName -and $originalName -ine $record.BrowserName)) {
        # The updater may have promoted a staged EXE to its canonical name.
        # An absent OriginalFilename is not evidence of a rename.
        $browser = Resolve-RamBrowserExecutable $resolved '' ([Diagnostics.FileVersionInfo]::GetVersionInfo($original))
    }
    Stop-Mv2BrowserBackground $browser
    $bytes = [IO.File]::ReadAllBytes($original)
    if ((Get-ByteArraySha256 $bytes) -ne $record.OriginalSHA256) { throw 'The original DLL does not match the receipt.' }
    $hash = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash
    if ($hash -ne $record.OriginalSHA256) {
        if ($hash -notin @(Get-Mv2AcceptedProxyHashes $record)) { throw 'The active DLL changed after installation; it will not be overwritten.' }
        Set-Mv2DllBytes $resolved $bytes $hash
    }
    $environment = Get-Mv2Environment $resolved
    $location = if ($environment.Portable) { 'Portable' } else { 'Script' }
    $null = Set-Mv2ProxyConfig $resolved $location $false
    $record.State = 'Removed'; Write-Mv2Json ($resolved + '.mv2-proxy.json') $record
    $null = Save-Mv2Environment $resolved 'Disk' $location $null
    return [pscustomobject]@{
        State = 'DllRemoved'; Target = $resolved; RestoredSHA256 = $record.OriginalSHA256
        OriginalResourcesRetained = $originalDirectory
    }
}

function Start-Mv2ConfiguredBrowser {
    param([string]$Path, [string]$BrowserExecutable, [string]$Arguments,
        [string]$BackupBase, [switch]$BackupProfile)
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $record = Get-Mv2ProxyRecord $resolved
    $environment = Get-Mv2Environment $resolved
    if ($environment.Method -eq 'Dll' -and (-not $record -or $record.State -ne 'Installed')) {
        throw 'Apply DLL mode for this version before launching it.'
    }
    $original = if ($record -and $record.State -eq 'Installed') {
        Join-Path (Split-Path -Parent $resolved) ('original\' + $record.DllName)
    } else { $resolved }
    $browser = Resolve-RamBrowserExecutable $resolved $BrowserExecutable ([Diagnostics.FileVersionInfo]::GetVersionInfo($original))
    Assert-Mv2BrowserStopped $browser
    $parsed = [RamPatchLauncher]::ParseArguments($Arguments)
    $backup = $null
    if ($BackupProfile) {
        $userData = Get-BrowserUserDataRoot $parsed (Split-Path -Parent $browser) (Get-RamDefaultUserDataRoot $browser)
        $directory = Join-Path $BackupBase ('BrowserLaunch_' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
        $backup = New-ChromeProfileBackup $directory $userData $browser
    }
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $browser; $start.WorkingDirectory = Split-Path -Parent $browser
    $start.Arguments = $Arguments; $start.UseShellExecute = $false
    # Native per-installation configuration also applies to ordinary shortcuts.
    $process = [Diagnostics.Process]::Start($start)
    $pidStarted = $process.Id
    if ($process.WaitForExit(1500) -and $process.ExitCode -ne 0) { throw "Browser startup failed with exit code $($process.ExitCode)." }
    $process.Dispose()
    return [pscustomobject]@{
        State = 'Launched'; ProcessId = $pidStarted; BrowserExecutable = $browser
        Method = $environment.Method; Backup = if ($backup) { $backup.Path } else { $null }
    }
}
