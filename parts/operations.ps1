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

function Get-Mv2BrowserDllName {
    param([string]$ApplicationRoot)
    $names = @('chrome.dll', 'vivaldi.dll', 'opera_browser.dll', 'msedge.dll')
    $configured = @($names | Where-Object {
        (Get-Mv2Environment (Join-Path $ApplicationRoot $_)).Method -eq 'Dll'
    })
    if ($configured.Count -eq 1) { return $configured[0] }
    if ($configured.Count -gt 1) { throw 'Multiple browser DLL configurations share this root.' }
    $found = @($names | Where-Object {
        $name = $_
        (Test-Path -LiteralPath (Join-Path $ApplicationRoot $name) -PathType Leaf) -or
        @(Get-ChildItem -LiteralPath $ApplicationRoot -Directory | Where-Object {
            $v = [version]'0.0'
            [version]::TryParse($_.Name, [ref]$v) -and
                (Test-Path -LiteralPath (Join-Path $_.FullName $name) -PathType Leaf)
        }).Count -gt 0
    })
    if ($found.Count -ne 1) { throw "Could not uniquely identify a browser DLL under: $ApplicationRoot" }
    return $found[0]
}

function Get-LatestChromeDll {
    param(
        [string]$ApplicationRoot,
        [switch]$AllowIncomplete
    )
    $dllName = Get-Mv2BrowserDllName $ApplicationRoot
    $flat = Join-Path $ApplicationRoot $dllName
    $versions = @(foreach ($directory in Get-ChildItem -Directory -LiteralPath $ApplicationRoot) {
        [version]$parsed = '0.0'
        if ([version]::TryParse($directory.Name, [ref]$parsed)) {
            $dll = Join-Path $directory.FullName $dllName
            if ($AllowIncomplete) {
                [pscustomobject]@{ Version = $parsed; Path = $dll }
            } elseif (Test-Path -LiteralPath $dll) {
                if ((Get-Mv2EffectiveVersion $dll).FileVersion -eq
                    $directory.Name) {
                    [pscustomobject]@{ Version = $parsed; Path = $dll }
                }
            }
        }
    })
    if (Test-Path -LiteralPath $flat -PathType Leaf) {
        if ($versions.Count) { throw 'Both flat and versioned browser layouts exist; select an unambiguous root.' }
        return $flat
    }
    $latest = $versions | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $latest) {
        throw "No complete versioned $dllName was found under: $ApplicationRoot"
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
    $action.WorkingDirectory = $Mv2PackageRoot
}

function Get-Mv2AutoTaskNames {
    param([string]$ApplicationRoot)
    $id = (Get-Mv2EnvironmentPaths (Join-Path $ApplicationRoot 'chrome.dll')).Id
    return [pscustomobject]@{
        Hourly = 'ChromiumMV2AutoPatch-' + $id
        Watcher = 'ChromiumMV2UpdateWatcher-' + $id
    }
}

function Get-Mv2UpdaterDataRoot {
    param([string]$ApplicationRoot, [string]$RequestedRoot)
    try {
        if (-not $RequestedRoot) {
            $dll = Get-LatestChromeDll $ApplicationRoot
            if ((Get-Mv2EffectiveVersion $dll).ProductName -ne 'Google Chrome') { return '' }
        }
        return Resolve-GoogleUpdaterDataRoot $RequestedRoot
    }
    catch { return '' } # File events and the hourly task do not require an updater log.
}

function Register-AutoPatchTasks {
    param(
        [string]$ApplicationRoot,
        [string]$BackupBase,
        [string]$CatalogPath
    )
    $updaterData = Get-Mv2UpdaterDataRoot $ApplicationRoot $UpdaterRoot
    $taskNames = Get-Mv2AutoTaskNames $ApplicationRoot
    $hourlyArguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -PatchLatestOnce -BrowserRoot "{1}" -BackupRoot "{2}" -SignatureCatalog "{3}"' -f
        $Mv2EntryScriptPath, $ApplicationRoot, $BackupBase, $CatalogPath
    $watchArguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -WatchUpdates -BrowserRoot "{1}" -UpdaterRoot "{2}" -BackupRoot "{3}" -SignatureCatalog "{4}"' -f
        $Mv2EntryScriptPath, $ApplicationRoot, $updaterData, $BackupBase, $CatalogPath

    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    $folder = Get-AutoPatchTaskFolder $service

    foreach ($oldName in @($taskNames.Watcher)) {
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
        'Checks the selected Chromium installation every hour and applies its saved patch method.' `
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
        $taskNames.Hourly, $hourlyDefinition, 6, 'SYSTEM', $null, 5, $null)

    $watchDefinition = $service.NewTask(0)
    Set-CommonTaskDefinition $watchDefinition `
        'Watches the selected Chromium installation for completed updates; uses Google history when available.' `
        $watchArguments 'PT0S'
    $watchDefinition.Settings.RestartCount = 3
    $watchDefinition.Settings.RestartInterval = 'PT1M'
    $bootTrigger = $watchDefinition.Triggers.Create(8)
    $bootTrigger.Enabled = $true
    $bootTrigger.Delay = 'PT10S'
    [void]$folder.RegisterTaskDefinition(
        $taskNames.Watcher, $watchDefinition, 6, 'SYSTEM', $null, 5, $null)

    return [pscustomobject]@{
        HourlyTask = '\ChromiumMV2Patcher\' + $taskNames.Hourly
        UpdateWatcherTask = '\ChromiumMV2Patcher\' + $taskNames.Watcher
        UpdaterRoot = $updaterData
        BrowserRoot = $ApplicationRoot
    }
}

function Start-AutoPatchWatcherTask {
    param([string]$ApplicationRoot)
    $taskName = (Get-Mv2AutoTaskNames $ApplicationRoot).Watcher
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    $folder = $service.GetFolder('\ChromiumMV2Patcher')
    [void]$folder.GetTask($taskName).Run($null)
    return [pscustomobject]@{
        Started = $true
        Task = '\ChromiumMV2Patcher\' + $taskName
    }
}

function Remove-AutoPatchTasks {
    param([string]$ApplicationRoot)
    $taskNames = if ($ApplicationRoot) {
        $names = Get-Mv2AutoTaskNames $ApplicationRoot
        @($names.Hourly, $names.Watcher)
    } else { @(
        'ChromiumMV2AutoPatch',
        'ChromiumMV2UpdateWatcher',
        'ChromiumMV2FileWatcher'
    ) }
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    try { $folder = $service.GetFolder('\ChromiumMV2Patcher') } catch { $folder = $null }
    if ($folder -and -not $ApplicationRoot) {
        $taskNames += @($folder.GetTasks(0) | Where-Object {
            $_.Name -match '^ChromiumMV2(AutoPatch|UpdateWatcher)-[0-9a-f]{40}$'
        } | ForEach-Object { $_.Name })
    }
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
        $directories = @($root, (Split-Path -Parent $TargetPath)) | Select-Object -Unique
        $candidates = @(foreach ($directory in $directories) {
            Get-ChildItem -LiteralPath $directory -Filter '*.exe' -File
        })
        $knownNames = switch ([IO.Path]::GetFileName($TargetPath).ToLowerInvariant()) {
            'opera_browser.dll' { @('opera.exe') }
            'vivaldi.dll' { @('vivaldi.exe') }
            'msedge.dll' { @('msedge.exe') }
            'chrome.dll' { @('chrome.exe','brave.exe','chromium.exe') }
            default { @() }
        }
        $matches = @($candidates |
            Where-Object {
                $TargetVersion.ProductName -and $TargetVersion.FileVersion -and
                $_.Name -notlike '*_proxy.exe' -and
                $_.VersionInfo.OriginalFilename -notlike '*_proxy.exe' -and
                [string]::Equals($_.VersionInfo.ProductName,
                    $TargetVersion.ProductName,
                    [StringComparison]::OrdinalIgnoreCase) -and
                [string]::Equals($_.VersionInfo.FileVersion,
                    $TargetVersion.FileVersion,
                    [StringComparison]::OrdinalIgnoreCase)
            })
        if (-not $TargetVersion.ProductName -or -not $TargetVersion.FileVersion) {
            # Opera's browser DLL has no version resource. Do not match other
            # versionless helper EXEs; the installer still audits the selected EXE.
            $matches = @($candidates | Where-Object { $_.Name -in $knownNames })
            # A versionless DLL belongs to its adjacent browser, not an outer
            # launcher that may already point to a different installed version.
            $adjacent = @($matches | Where-Object { (Split-Path -Parent $_.FullName) -ieq (Split-Path -Parent $TargetPath) })
            if ($adjacent.Count) { $matches = $adjacent }
        }
        $knownMatches = @($matches | Where-Object { $_.Name -in $knownNames })
        if ($knownMatches.Count) { $matches = $knownMatches }
        elseif ($knownNames) {
            # Updaters may stage a renamed browser beside the older launcher.
            # Keep the product/version checks and exclude same-version helpers.
            $matches = @($matches | Where-Object { $_.VersionInfo.OriginalFilename -in $knownNames })
        }
        if ([IO.Path]::GetFileName($TargetPath) -ieq 'msedge.dll' -and $matches.Count -gt 1) {
            # Edge also keeps a same-version EXE in its version directory.
            $launcher = @($matches | Where-Object { $_.FullName -ieq (Join-Path $root 'msedge.exe') })
            if ($launcher.Count -eq 1) { $matches = $launcher }
        }
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
    Assert-NoMv2Proxy $resolved
    $beforeHash = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash
    try {
        $analysis = Resolve-TargetStreamAnalysis $resolved $CatalogPath
    } catch {
        if ($_.Exception.Data['Mv2PatternsMissing'] -ne $true) { throw }
        $reason = $_.Exception.Message
        if ((Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash -ne $beforeHash) {
            throw 'The target DLL changed during analysis. No browser was launched.'
        }
        Write-Warning 'Required MV2 instruction patterns were not found. Starting the browser without applying a patch.'
        $launch = Start-Mv2ConfiguredBrowser $resolved $BrowserExecutable $ChromeArguments $BackupBase -BackupProfile:$BackupProfile
        $launch.State = 'LaunchedUnpatched'
        $launch | Add-Member NoteProperty PatchApplied $false
        $launch | Add-Member NoteProperty PatchCount 0
        $launch | Add-Member NoteProperty PatchSkipReason $reason
        $launch | Add-Member NoteProperty DiskSHA256 $beforeHash
        $launch | Add-Member NoteProperty DiskModified $false
        return $launch
    }
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
    $launchWatch = [Diagnostics.Stopwatch]::StartNew()
    $result = [RamPatchLauncher]::Launch(
        $browserPath, $resolved, $rvas, $expected, $replacements,
        $ChromeArguments, 30)
    $launchWatch.Stop()
    $diskHash = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash
    if ($diskHash -ne $analysis.Hash) {
        throw 'The target DLL changed on disk during RAM launch verification.'
    }
    return [pscustomobject]@{
        ProcessId = $result.ProcessId
        LaunchMilliseconds = $launchWatch.ElapsedMilliseconds
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
                    $environment = Get-Mv2Environment $targetDll
                    if ($environment.Method -eq 'Dll') {
                        $result = Install-Mv2Proxy $targetDll $BackupBase -Automatic
                    } else {
                        $result = Invoke-PatchTarget $targetDll -InPlace `
                            -BackupBase $BackupBase -CatalogPath $CatalogPath
                    }
                } catch {
                    $transient = $_.Exception.Message -like 'Target DLL is loaded,*' -or
                        $_.Exception.Message -like 'Target changed between analysis*' -or
                        $_.Exception.Message -like 'Close this browser and its background processes first:*'
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
                $actualVersion = (Get-Mv2EffectiveVersion $dllPath).FileVersion
                if ((Split-Path -Parent $dllPath) -eq $ApplicationRoot -or $actualVersion -eq $expectedVersion) {
                    $probe = [IO.File]::Open($dllPath, [IO.FileMode]::Open,
                        [IO.FileAccess]::Read, ([IO.FileShare]::Read -bor [IO.FileShare]::Delete))
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
        $Mv2EntryScriptPath, $ApplicationRoot, $BackupBase, $CatalogPath, $AutoPatchLog,
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

function Get-Mv2WatchedTarget {
    param([string]$ApplicationRoot)
    $item = Get-Item -LiteralPath (Get-LatestChromeDll $ApplicationRoot)
    return '{0}|{1}|{2}' -f $item.FullName, $item.Length, $item.LastWriteTimeUtc.Ticks
}

function Watch-AutomaticUpdates {
    param(
        [string]$ApplicationRoot,
        [string]$UpdaterDataRoot,
        [string]$BackupBase,
        [string]$CatalogPath,
        [int]$ReconcileSeconds
    )

    $historyPath = $null
    $updaterWatcher = $null
    if ($UpdaterDataRoot) {
        $historyPath = Join-Path $UpdaterDataRoot 'updater_history.jsonl'
        $updaterWatcher = New-Object IO.FileSystemWatcher
        $updaterWatcher.Path = $UpdaterDataRoot
        $updaterWatcher.Filter = 'updater_history.jsonl*'
        $updaterWatcher.NotifyFilter = [IO.NotifyFilters]::FileName -bor
            [IO.NotifyFilters]::LastWrite -bor [IO.NotifyFilters]::Size
        $updaterWatcher.InternalBufferSize = 65536
    }
    $chromeWatcher = New-Object IO.FileSystemWatcher
    $chromeWatcher.Path = $ApplicationRoot
    $chromeWatcher.Filter = '*'
    $chromeWatcher.IncludeSubdirectories = $true
    $chromeWatcher.NotifyFilter = [IO.NotifyFilters]::FileName -bor
        [IO.NotifyFilters]::DirectoryName -bor [IO.NotifyFilters]::LastWrite -bor [IO.NotifyFilters]::Size
    $chromeWatcher.InternalBufferSize = 65536
    $sourceIds = @(
        'ChromiumMV2.Updater.Changed', 'ChromiumMV2.Updater.Created',
        'ChromiumMV2.Updater.Renamed', 'ChromiumMV2.Updater.Error',
        'ChromiumMV2.Chrome.Changed', 'ChromiumMV2.Chrome.Created',
        'ChromiumMV2.Chrome.Renamed', 'ChromiumMV2.Chrome.Error'
    )
    try {
        if ($updaterWatcher) {
            Register-FileWatcherEvents $updaterWatcher 'ChromiumMV2.Updater' | Out-Null
            $updaterWatcher.EnableRaisingEvents = $true
        }
        Register-FileWatcherEvents $chromeWatcher 'ChromiumMV2.Chrome' | Out-Null
        $chromeWatcher.EnableRaisingEvents = $true
        $completion = if ($historyPath) { Get-GoogleUpdaterCompletion $historyPath } else { $null }
        $lastMarker = if ($completion) { $completion.Marker } else { '' }
        $lastTarget = ''
        Write-AutoPatchLog "watcher started chrome=$ApplicationRoot updater=$UpdaterDataRoot"
        if (Invoke-WatcherPatch 'startup' $ApplicationRoot $BackupBase $CatalogPath) {
            try { $lastTarget = Get-Mv2WatchedTarget $ApplicationRoot } catch {}
        }

        while ($true) {
            $firstEvent = Wait-Event -Timeout $ReconcileSeconds
            if ($firstEvent) { Start-Sleep -Milliseconds 750 }
            $events = @(Get-Event | Where-Object {
                $sourceIds -contains $_.SourceIdentifier
            })
            if ($events.Count -eq 0 -and $firstEvent) { $events = @($firstEvent) }
            foreach ($queued in $events) {
                Remove-Event -EventIdentifier $queued.EventIdentifier -ErrorAction SilentlyContinue
            }

            $reason = @(if (-not $firstEvent) { 'reconcile' })
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
                $relative = [string]$chromeEvent.SourceEventArgs.Name
                $leaf = [IO.Path]::GetFileName($relative)
                $v = [version]'0.0'
                if ($leaf -in @('chrome.dll','vivaldi.dll','opera_browser.dll','msedge.dll','chrome.exe','brave.exe','vivaldi.exe','opera.exe','msedge.exe','chromium.exe') -or
                    ($relative -notmatch '[\\/]' -and [version]::TryParse($relative, [ref]$v))) {
                    $reason += 'browser-file'
                    break
                }
            }
            if ($reason.Count -gt 0) {
                $currentTarget = ''
                try { $currentTarget = Get-Mv2WatchedTarget $ApplicationRoot } catch {}
                if (-not $currentTarget -or -not [string]::Equals(
                    $currentTarget, $lastTarget, [StringComparison]::OrdinalIgnoreCase)) {
                    if (Invoke-WatcherPatch (($reason | Select-Object -Unique) -join '+') `
                        $ApplicationRoot $BackupBase $CatalogPath) {
                        try { $lastTarget = Get-Mv2WatchedTarget $ApplicationRoot } catch {}
                    }
                } elseif (@($reason | Where-Object { $_ -like 'updater-history-*' }).Count) {
                    Write-AutoPatchLog "watcher reason=$(($reason | Select-Object -Unique) -join '+') state=AlreadyHandled"
                }
            }
        }
    } finally {
        foreach ($sourceId in $sourceIds) {
            Unregister-Event -SourceIdentifier $sourceId -ErrorAction SilentlyContinue
            Get-Event -SourceIdentifier $sourceId -ErrorAction SilentlyContinue |
                Remove-Event -ErrorAction SilentlyContinue
        }
        if ($updaterWatcher) { $updaterWatcher.Dispose() }
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
