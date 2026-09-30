<#
.SYNOPSIS
Analyzes or patches a Windows x64 Chromium browser DLL to retain MV2 support.

.DESCRIPTION
With no arguments, displays the Windows GUI. With -Target, the script only
analyzes the target unless -Apply or -Output is specified. Use -Apply for an
in-place patch and extension backup, -RestoreExt with
a receipt to restore extension data and reopen Chrome Web Store pages,
-RestoreExtSettings to reopen protected per-extension settings,
-AutoPatch to register per-installation file monitoring and an hourly fallback,
-RemoveAutoPatch to remove those tasks, -RamLaunch to apply the verified patch only to a
new Chromium-browser process, or -Restore to restore a DLL backup.
Use -InstallDll for the native proxy enabled by ordinary browser shortcuts.
Saved per-installation preferences select the method used by automatic updates.

.PARAMETER InstallDll
Install or reconfigure a verified native proxy with an owned original-resource
directory. Close the target browser first. Requires native components beside this script.

.PARAMETER RemoveDll
Restore the original DLL and save the Disk preference. Retain original resources,
receipts, backups, and cache. Required before switching to a legacy patch or RAM launch.

.PARAMETER LaunchBrowser
Launch the selected installation normally. DLL mode must already be installed.

.PARAMETER SaveEnvironment
Save preferences for this installation without applying a patch.

.PARAMETER PatchMethod
Disk or Dll. Explicit Apply without this option keeps the legacy Disk behavior.
With SaveEnvironment, select the method for subsequent automatic application.

.PARAMETER CacheLocation
Script stores native generation caches under chromium_mv2_cache beside this script.
Portable stores them in .chromium-mv2-cache beside the browser executable.

.PARAMETER ProxyDll
Optional path to a copy of the qualified bundled proxy for the selected browser.
Its exact hash is required. Verified layouts have five, six, or twenty-eight
function entries, or Edge's 292 function/data entries. Other layouts are rejected.

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
Register independent tasks for BrowserRoot, monitor browser files and directories,
and check hourly. Apply the saved method immediately. Google Updater history is
used when available for Google Chrome; other browsers do not require it.

.PARAMETER RemoveAutoPatch
Remove this installation's task pair when BrowserRoot is supplied. Otherwise
remove all recognized Chromium MV2 patch tasks, preserving unrelated tasks.

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
Browser application directory containing the main DLL or version directories.
Required for non-Chrome automatic modes. Only Google Chrome is detected when omitted.

.PARAMETER RamLaunch
Start the matching Chromium browser with the verified patch applied only to process
memory. Close the browser first. If required instruction patterns are missing or
insufficient, start normally without modifying the DLL or process memory. Duplicate
matches, mixed patch states and unrelated errors are not eligible for this fallback.

.PARAMETER BrowserExecutable
Browser executable used by RamLaunch, InstallDll, or LaunchBrowser. When omitted,
inspect the application root and selected DLL directory, preferring known browser
filenames with matching product/version metadata. Opera's versionless DLL uses
the adjacent opera.exe. Edge prefers Application\msedge.exe when both root and
version-directory executables match. Other ambiguities require an explicit path.

.PARAMETER BackupProfile
Before RamLaunch or LaunchBrowser, back up browser profile settings, extension bodies, and related
extension storage below BackupRoot. Unknown browsers must specify --user-data-dir.

.PARAMETER ChromeArguments
Windows command-line text appended to the browser by RamLaunch or LaunchBrowser. Whitespace
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

    [switch]$InstallDll,

    [switch]$RemoveDll,

    [switch]$LaunchBrowser,

    [switch]$SaveEnvironment,

    [ValidateSet('Disk', 'Dll')]
    [string]$PatchMethod = 'Disk',

    [ValidateSet('Script', 'Portable')]
    [string]$CacheLocation,

    [string]$ProxyDll,

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
    $InstallDll, $RemoveDll, $LaunchBrowser, $SaveEnvironment,
    $RestoreExtSettings,
    $HandleUpdateEvent, $WatchUpdates, $PatchLatestOnce, $Gui |
    Where-Object { $_ }).Count
if ($modeCount -gt 1) {
    throw 'Specify only one public mode or one internal automatic-patch mode.'
}
if ($modeCount -gt 0 -and ($Apply -or $Output -or ($Target -and
    -not ($RamLaunch -or $InstallDll -or $RemoveDll -or $LaunchBrowser -or $SaveEnvironment -or $Gui)))) {
    throw 'This explicit mode cannot be combined with -Target, -Apply, or -Output.'
}
if ($BackupProfile -and -not ($RamLaunch -or $LaunchBrowser)) {
    throw '-BackupProfile is valid only with -RamLaunch or -LaunchBrowser.'
}
if (-not [string]::IsNullOrWhiteSpace($BrowserExecutable) -and -not ($RamLaunch -or $InstallDll -or $LaunchBrowser -or ($Apply -and $PatchMethod -eq 'Dll'))) {
    throw '-BrowserExecutable is valid only with -RamLaunch, -InstallDll, or -LaunchBrowser.'
}
if (-not [string]::IsNullOrWhiteSpace($ChromeArguments) -and -not ($RamLaunch -or $LaunchBrowser)) {
    throw '-ChromeArguments is valid only with -RamLaunch or -LaunchBrowser.'
}
if (($CacheLocation -or $ProxyDll -or $PSBoundParameters.ContainsKey('PatchMethod')) -and
    -not ($SaveEnvironment -or $InstallDll -or $Apply)) { throw 'Environment options require -SaveEnvironment, -InstallDll, or -Apply.' }
if ($ProxyDll -and $Apply -and $PatchMethod -ne 'Dll') { throw '-ProxyDll requires DLL mode.' }
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

# Keep package resources and child invocations anchored to the public entry point.
$Mv2PackageRoot=$PSScriptRoot
$Mv2EntryScriptPath=$PSCommandPath
$Mv2PartNames=@('platform.ps1','analysis.ps1','operations.ps1','installation.ps1','gui.ps1','adaptive-exports.cs')
foreach($Mv2PartName in $Mv2PartNames){
    if(-not (Test-Path -LiteralPath (Join-Path $Mv2PackageRoot ('parts\'+$Mv2PartName)) -PathType Leaf)){
        throw "Required package component is missing: $Mv2PartName"
    }
}
. (Join-Path $Mv2PackageRoot 'parts\platform.ps1')
. (Join-Path $Mv2PackageRoot 'parts\analysis.ps1')
. (Join-Path $Mv2PackageRoot 'parts\operations.ps1')
. (Join-Path $Mv2PackageRoot 'parts\installation.ps1')
. (Join-Path $Mv2PackageRoot 'parts\gui.ps1')

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
    Remove-AutoPatchTasks $BrowserRoot
    return
}
if ($InstallDll -or $RemoveDll -or $LaunchBrowser -or $SaveEnvironment) {
    if ([string]::IsNullOrWhiteSpace($Target)) {
        $Target = Get-LatestChromeDll (Resolve-ChromeApplicationRoot $BrowserRoot)
    }
    Invoke-WithPatchMutex (Get-PatchLockRoot $Target) {
        if ($InstallDll) {
            Install-Mv2Proxy $Target $BackupRoot $CacheLocation $BrowserExecutable $ProxyDll
        } elseif ($RemoveDll) {
            Remove-Mv2Proxy $Target
        } elseif ($SaveEnvironment) {
            $location = if ($CacheLocation) { $CacheLocation } else { 'Script' }
            Save-Mv2Environment $Target $PatchMethod $location $ProxyDll
        } else {
            Start-Mv2ConfiguredBrowser $Target $BrowserExecutable $ChromeArguments $BackupRoot -BackupProfile:$BackupProfile
        }
    }
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
            Start-AutoPatchWatcherTask $applicationRoot
        }
    } elseif ($HandleUpdateEvent) {
        Invoke-AutoPatchCore $applicationRoot $BackupRoot $resolvedCatalog `
            -RefreshRegistration -WaitForReady `
            -ReadyTimeoutSeconds $ReadinessTimeoutSeconds
    } elseif ($WatchUpdates) {
        $updaterData = Get-Mv2UpdaterDataRoot $applicationRoot $UpdaterRoot
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
    $rememberMethod = $PSBoundParameters.ContainsKey('PatchMethod')
    Invoke-WithPatchMutex $lockRoot {
        if ($PatchMethod -eq 'Dll') {
            Install-Mv2Proxy $Target $BackupRoot $CacheLocation $BrowserExecutable $ProxyDll
        } else {
            $result = Invoke-PatchTarget $Target -InPlace -BackupBase $BackupRoot `
                -CatalogPath $resolvedCatalog -BackupExtensions
            if ($rememberMethod) {
                $location = if ($CacheLocation) { $CacheLocation } else { 'Script' }
                $null = Save-Mv2Environment $Target 'Disk' $location
            }
            $result
        }
    }
} else {
    Invoke-PatchTarget $Target -OutputPath $Output -BackupBase $BackupRoot `
        -CatalogPath $resolvedCatalog
}
