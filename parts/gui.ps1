function Show-PatcherGui {
    if ([Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
        throw 'The GUI requires an STA PowerShell process.'
    }

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [Windows.Forms.Application]::EnableVisualStyles()

    $form = New-Object Windows.Forms.Form
    $form.Text = 'Chromium MV2 Patcher'
    $form.ClientSize = New-Object Drawing.Size(760, 850)
    $form.AutoScroll = $true
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
    $targetLabel.Text = '対象ブラウザーDLL'
    $targetLabel.AutoSize = $true
    $targetLabel.Location = New-Object Drawing.Point(20, 55)
    $form.Controls.Add($targetLabel)

    $targetBox = New-Object Windows.Forms.TextBox
    $targetBox.Location = New-Object Drawing.Point(20, 76)
    $targetBox.Size = New-Object Drawing.Size(570, 24)
    $targetBox.Text = $Target
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

    $diskMethodRadio = New-Object Windows.Forms.RadioButton
    $diskMethodRadio.Text = '直接書換方式'
    $diskMethodRadio.Location = New-Object Drawing.Point(20, 137)
    $diskMethodRadio.Size = New-Object Drawing.Size(145, 26)
    $diskMethodRadio.Checked = $true
    $form.Controls.Add($diskMethodRadio)
    $dllMethodRadio = New-Object Windows.Forms.RadioButton
    $dllMethodRadio.Text = 'DLL置換方式'
    $dllMethodRadio.Location = New-Object Drawing.Point(185, 137)
    $dllMethodRadio.Size = New-Object Drawing.Size(145, 26)
    $form.Controls.Add($dllMethodRadio)
    $portableBox = New-Object Windows.Forms.CheckBox
    $portableBox.Text = 'ポータブル配置'
    $portableBox.AutoSize = $true
    $portableBox.Location = New-Object Drawing.Point(355, 141)
    $form.Controls.Add($portableBox)
    $saveEnvironmentButton = & $newButton 'この環境の方式を保存' 545 134 195

    $analyzeButton = & $newButton '状態を解析' 20 200 165
    $applyButton = & $newButton '選択方式を適用' 195 200 165
    $launchButton = & $newButton 'ブラウザーを起動' 370 200 165
    $ramLaunchButton = & $newButton '従来のRAM起動' 545 200 195

    $backupProfileBox = New-Object Windows.Forms.CheckBox
    $backupProfileBox.Text = 'GUIからの起動前に拡張機能と関連設定をバックアップ'
    $backupProfileBox.Checked = $true
    $backupProfileBox.AutoSize = $true
    $backupProfileBox.Location = New-Object Drawing.Point(20, 242)
    $form.Controls.Add($backupProfileBox)

    $chromeArgumentsLabel = New-Object Windows.Forms.Label
    $chromeArgumentsLabel.Text = 'GUIからのブラウザー起動引数'
    $chromeArgumentsLabel.AutoSize = $true
    $chromeArgumentsLabel.Location = New-Object Drawing.Point(20, 272)
    $form.Controls.Add($chromeArgumentsLabel)

    $chromeArgumentsBox = New-Object Windows.Forms.TextBox
    $chromeArgumentsBox.Location = New-Object Drawing.Point(20, 293)
    $chromeArgumentsBox.Size = New-Object Drawing.Size(720, 56)
    $chromeArgumentsBox.Multiline = $true
    $chromeArgumentsBox.ScrollBars = 'Vertical'
    $chromeArgumentsBox.AcceptsReturn = $true
    $form.Controls.Add($chromeArgumentsBox)

    $browserLabel = New-Object Windows.Forms.Label
    $browserLabel.Text = 'ブラウザー実行ファイル（自動判定できない場合は指定）'
    $browserLabel.AutoSize = $true
    $browserLabel.Location = New-Object Drawing.Point(20, 357)
    $form.Controls.Add($browserLabel)
    $browserBox = New-Object Windows.Forms.TextBox
    $browserBox.Location = New-Object Drawing.Point(20, 378)
    $browserBox.Size = New-Object Drawing.Size(650, 24)
    $form.Controls.Add($browserBox)
    $browserBrowseButton = & $newButton '参照' 678 373 62

    $backupLabel = New-Object Windows.Forms.Label
    $backupLabel.Text = '適用済みバックアップ'
    $backupLabel.AutoSize = $true
    $backupLabel.Location = New-Object Drawing.Point(20, 426)
    $form.Controls.Add($backupLabel)

    $receiptBox = New-Object Windows.Forms.ComboBox
    $receiptBox.DropDownStyle = 'DropDownList'
    $receiptBox.DisplayMember = 'Display'
    $receiptBox.Location = New-Object Drawing.Point(20, 447)
    $receiptBox.Size = New-Object Drawing.Size(720, 25)
    $form.Controls.Add($receiptBox)

    $restoreButton = & $newButton '直接書換パッチを復元' 20 482 165
    $restoreExtButton = & $newButton '拡張機能を復元' 195 482 165
    $restoreSettingsButton = & $newButton '保護設定ページを開く' 370 482 190
    $removeDllButton = & $newButton 'DLL置換方式を解除' 570 482 170

    $autoLabel = New-Object Windows.Forms.Label
    $autoLabel.Text = '自動適用: 確認中'
    $autoLabel.AutoSize = $true
    $autoLabel.Location = New-Object Drawing.Point(20, 530)
    $form.Controls.Add($autoLabel)

    $registerButton = & $newButton '自動適用を登録' 20 553 165
    $removeButton = & $newButton '自動適用を解除' 195 553 165
    $helpButton = & $newButton 'CLIヘルプ' 575 553 165

    $logLabel = New-Object Windows.Forms.Label
    $logLabel.Text = '実行結果'
    $logLabel.AutoSize = $true
    $logLabel.Location = New-Object Drawing.Point(20, 603)
    $form.Controls.Add($logLabel)

    $logBox = New-Object Windows.Forms.TextBox
    $logBox.Location = New-Object Drawing.Point(20, 624)
    $logBox.Size = New-Object Drawing.Size(720, 158)
    $logBox.Multiline = $true
    $logBox.ReadOnly = $true
    $logBox.ScrollBars = 'Vertical'
    $logBox.Font = New-Object Drawing.Font('Consolas', 9)
    $form.Controls.Add($logBox)

    $statusLabel = New-Object Windows.Forms.Label
    $statusLabel.Text = '待機中'
    $statusLabel.AutoSize = $true
    $statusLabel.Location = New-Object Drawing.Point(20, 794)
    $form.Controls.Add($statusLabel)

    $closeButton = & $newButton '閉じる' 640 800 100
    $form.AutoScrollMinSize = New-Object Drawing.Size(0, 850)
    $availableHeight = [Windows.Forms.Screen]::FromControl($form).WorkingArea.Height - 60
    $form.ClientSize = New-Object Drawing.Size(760, ([Math]::Min(850, $availableHeight)))
    $operationButtons = @(
        $analyzeButton, $applyButton, $ramLaunchButton, $restoreButton, $restoreExtButton,
        $restoreSettingsButton, $registerButton, $removeButton,
        $detectButton, $browseButton, $launchButton, $removeDllButton,
        $saveEnvironmentButton, $browserBrowseButton
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
        $targetBox.Enabled = -not $Busy
        $browserBox.Enabled = -not $Busy
        $diskMethodRadio.Enabled = -not $Busy
        $dllMethodRadio.Enabled = -not $Busy
        $portableBox.Enabled = -not $Busy
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
            $version = Get-Mv2EffectiveVersion $targetBox.Text
            $targetInfo.Text = "バージョン: $($version.FileVersion)    製品: $($version.ProductName)"
            $environment = Get-Mv2Environment $targetBox.Text
            $dllMethodRadio.Checked = ($environment.Method -eq 'Dll')
            $diskMethodRadio.Checked = -not $dllMethodRadio.Checked
            $portableBox.Checked = $environment.Portable
            try { $browserBox.Text = Resolve-RamBrowserExecutable $targetBox.Text '' $version }
            catch { $browserBox.Clear() }
            & $refreshTasks
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
            $names = Get-Mv2AutoTaskNames (Get-PatchLockRoot $targetBox.Text)
            $selectedTasks = @($tasks | Where-Object { $_.TaskName -in @($names.Hourly, $names.Watcher) })
            if ($selectedTasks.Count -eq 0) {
                $autoLabel.Text = '自動適用: 未登録'
            } else {
                $autoLabel.Text = '自動適用: ' + (($selectedTasks | ForEach-Object {
                    $kind = if ($_.TaskName -eq $names.Watcher) { '監視' } else { '定期確認' }
                    "$kind=$($_.State)"
                }) -join ' / ')
            }
            if (@($tasks | Where-Object { $_.TaskName -in @('ChromiumMV2AutoPatch','ChromiumMV2UpdateWatcher','ChromiumMV2FileWatcher') }).Count) {
                $autoLabel.Text += ' / 旧版の共通タスクあり'
            }
        } catch {
            $autoLabel.Text = '自動適用: 未登録'
        }
    }
    $requireTarget = {
        if (Test-Path -LiteralPath $targetBox.Text -PathType Leaf) { return $true }
        [void][Windows.Forms.MessageBox]::Show($form,
            '有効なブラウザーDLLを指定してください。', '対象未指定',
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
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Mv2EntryScriptPath
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
        $dialog.Filter = 'Browser DLL|chrome.dll;vivaldi.dll;opera_browser.dll;msedge.dll|DLL (*.dll)|*.dll'
        $dialog.CheckFileExists = $true
        if ($dialog.ShowDialog($form) -eq 'OK') {
            $targetBox.Text = $dialog.FileName
            & $refreshTarget
        }
        $dialog.Dispose()
    })
    $targetBox.Add_Leave({ & $refreshTarget })
    $browserBrowseButton.Add_Click({
        $dialog = New-Object Windows.Forms.OpenFileDialog
        $dialog.Filter = 'Browser executable (*.exe)|*.exe'
        $dialog.CheckFileExists = $true
        if ($dialog.ShowDialog($form) -eq 'OK') { $browserBox.Text = $dialog.FileName }
        $dialog.Dispose()
    })
    $saveEnvironmentButton.Add_Click({
        if (-not (& $requireTarget)) { return }
        $method = if ($dllMethodRadio.Checked) { 'Dll' } else { 'Disk' }
        $location = if ($portableBox.Checked) { 'Portable' } else { 'Script' }
        & $startOperation -Label '環境設定保存' -Arguments @(
            '-SaveEnvironment', '-Target', $targetBox.Text, '-PatchMethod', $method,
            '-CacheLocation', $location
        ) -NeedsAdministrator $false
    })
    $analyzeButton.Add_Click({
        if (-not (& $requireTarget)) { return }
        $analysisTarget = $targetBox.Text
        try {
            $record = Get-Mv2ProxyRecord $analysisTarget
            if ($record -and $record.State -ne 'Removed') {
                & $writeLog ('DLL置換方式: ' + $record.State + ' / 元DLLを解析します。')
                $analysisTarget = Join-Path (Split-Path -Parent $analysisTarget) ('original\' + $record.DllName)
            }
        } catch { & $writeLog $_.Exception.Message; return }
        & $startOperation -Label '状態解析' -Arguments @(
            '-Target', $analysisTarget, '-BackupRoot', $BackupRoot,
            '-SignatureCatalog', $SignatureCatalog
        ) -NeedsAdministrator $false
    })
    $applyButton.Add_Click({
        if (-not (& $requireTarget)) { return }
        if ($dllMethodRadio.Checked) {
            if ([Windows.Forms.MessageBox]::Show($form,
                '対象ブラウザーを終了してください。元DLLと署名ファイルを保存し、プロキシDLLを配置します。通常のアイコンからも有効になります。続行しますか。',
                'DLL置換方式を適用', 'YesNo', 'Warning') -ne 'Yes') { return }
            $arguments = @('-InstallDll', '-Target', $targetBox.Text, '-BackupRoot', $BackupRoot,
                '-CacheLocation', $(if ($portableBox.Checked) { 'Portable' } else { 'Script' }))
            if ($browserBox.Text.Trim()) { $arguments += @('-BrowserExecutable', $browserBox.Text.Trim()) }
            & $startOperation -Label 'DLL置換方式適用' -Arguments $arguments -NeedsAdministrator (-not $portableBox.Checked)
            return
        }
        if ([Windows.Forms.MessageBox]::Show($form,
            'Chromeを終了してから適用してください。バックアップ作成後にDLLを書き換えます。続行しますか。',
            'パッチを適用', 'YesNo', 'Warning') -ne 'Yes') { return }
        & $startOperation -Label 'パッチ適用' -Arguments @(
            '-Target', $targetBox.Text, '-Apply', '-BackupRoot', $BackupRoot,
            '-SignatureCatalog', $SignatureCatalog, '-PatchMethod', 'Disk',
            '-CacheLocation', $(if ($portableBox.Checked) { 'Portable' } else { 'Script' })
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
        if ($browserBox.Text.Trim()) { $arguments += @('-BrowserExecutable', $browserBox.Text.Trim()) }
        $chromeArguments = $chromeArgumentsBox.Text.Trim()
        if ($chromeArguments) {
            $encoded = [Convert]::ToBase64String(
                [Text.Encoding]::UTF8.GetBytes($chromeArguments))
            $arguments += @('-ChromeArgumentsBase64', $encoded)
        }
        & $startOperation -Label 'RAM起動' -Arguments $arguments `
            -NeedsAdministrator $false
    })
    $launchButton.Add_Click({
        if (-not (& $requireTarget)) { return }
        try {
            $saved = Get-Mv2Environment $targetBox.Text
            $selected = if ($dllMethodRadio.Checked) { 'Dll' } else { 'Disk' }
            if ($saved.Method -ne $selected) { throw '選択した方式を適用してから起動してください。' }
        } catch { & $writeLog $_.Exception.Message; return }
        $arguments = @('-LaunchBrowser', '-Target', $targetBox.Text, '-BackupRoot', $BackupRoot)
        if ($browserBox.Text.Trim()) { $arguments += @('-BrowserExecutable', $browserBox.Text.Trim()) }
        if ($backupProfileBox.Checked) { $arguments += '-BackupProfile' }
        if ($chromeArgumentsBox.Text.Trim()) {
            $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($chromeArgumentsBox.Text.Trim()))
            $arguments += @('-ChromeArgumentsBase64', $encoded)
        }
        & $startOperation -Label 'ブラウザー起動' -Arguments $arguments -NeedsAdministrator $false
    })
    $removeDllButton.Add_Click({
        if (-not (& $requireTarget)) { return }
        if ([Windows.Forms.MessageBox]::Show($form,
            '対象ブラウザーを終了してください。プロキシを元DLLに戻し、この環境の方式を従来方式に戻します。保存済みリソースとキャッシュは残します。続行しますか。',
            'DLL置換方式を解除', 'YesNo', 'Warning') -ne 'Yes') { return }
        & $startOperation -Label 'DLL置換方式解除' -Arguments @('-RemoveDll', '-Target', $targetBox.Text) `
            -NeedsAdministrator (-not $portableBox.Checked)
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
        try {
            $method = if ($dllMethodRadio.Checked) { 'Dll' } else { 'Disk' }
            $location = if ($portableBox.Checked) { 'Portable' } else { 'Script' }
            $null = Save-Mv2Environment $targetBox.Text $method $location
        } catch { & $writeLog $_.Exception.Message; return }
        & $startOperation -Label '自動適用登録' -Arguments @(
            '-AutoPatch', '-BrowserRoot', (Get-PatchLockRoot $targetBox.Text),
            '-BackupRoot', $BackupRoot, '-SignatureCatalog', $SignatureCatalog
        ) -NeedsAdministrator $true
    })
    $removeButton.Add_Click({
        if (-not (& $requireTarget)) { return }
        if ([Windows.Forms.MessageBox]::Show($form,
            '自動適用タスクを停止して削除します。続行しますか。',
            '自動適用を解除', 'YesNo', 'Warning') -ne 'Yes') { return }
        & $startOperation -Label '自動適用解除' `
            -Arguments @('-RemoveAutoPatch', '-BrowserRoot', (Get-PatchLockRoot $targetBox.Text)) -NeedsAdministrator $true
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
