# Chromium MV2 signature patcher

Windows x64版ChromiumブラウザのManifest V2制限にパッチを適用するツールです。
DLLを書き換える方法と、ディスク上のDLLを変更しないRAM起動を選べます。
GUIとCLIに対応しています。

パッチが変更する処理の詳細は、[対応箇所と変更内容](README.chromium-mv2-patch-concept.md)を参照してください。

## 実行環境と起動

Windows PowerShell 5.1またはPowerShell 7で、次の2ファイルを同じフォルダに置いて実行します。

- `chromium_mv2_patch.ps1`
- `chromium_mv2_signatures.psd1`

引数なしで実行するとGUIが開きます。

```powershell
.\chromium_mv2_patch.ps1
```

GUIで対象DLLを選び、実行する操作を選択します。
DLLへの適用と復元、自動適用の登録と解除には管理者権限が必要です。
GUIでは必要に応じてUACの確認画面が開きます。

CLIでは引数で操作を選びます。
各引数の説明は次のコマンドで確認できます。

```powershell
Get-Help .\chromium_mv2_patch.ps1 -Detailed
```

## RAM起動

RAM起動は、起動したブラウザのプロセスメモリにパッチを適用します。
効果はそのブラウザセッション中に続き、通常のユーザー権限で実行できます。
対応シグネチャを持つ未パッチのDLLを用意し、対象ブラウザを完全に終了してから実行してください。

```powershell
.\chromium_mv2_patch.ps1 -RamLaunch -BackupProfile
```

GUIでは「RAM起動を試す」を選びます。
起動前のバックアップ用チェックボックスは既定でオンです。
CLIでは`-BackupProfile`を付けると、拡張機能と関連設定を保存します。
保存内容は「バックアップと復元」を参照してください。

`-Target`を省略すると、インストール済みGoogle Chromeの最新DLLを選びます。
ブラウザへ起動引数を渡す場合は、`-BrowserArguments`に通常のWindowsコマンドライン形式で文字列を指定します。
空白を含む値は引用符で囲みます。

```powershell
.\chromium_mv2_patch.ps1 -RamLaunch -BackupProfile `
  -BrowserArguments '--user-data-dir="C:\Chrome MV2 Profile" --no-first-run'
```

Chrome以外のChromium系ブラウザでは、対象DLLと実行ファイルを指定できます。

```powershell
.\chromium_mv2_patch.ps1 -RamLaunch -BackupProfile `
  -Target 'C:\path\to\browser\1.2.3.4\chrome.dll' `
  -BrowserExecutable 'C:\path\to\browser\browser.exe' `
  -BrowserArguments '--user-data-dir="C:\Browser MV2 Profile"'
```

実行ファイルを自動検出できない場合は、`-BrowserExecutable`で指定してください。

バックアップ元はGoogle Chrome各チャネル、Brave、Edge、Vivaldiの標準配置から自動判定します。
別の配置やブラウザを使う場合は、`--user-data-dir`を指定してください。
指定したフォルダをブラウザ起動とバックアップの両方に使います。

RAM方式だけで試す場合は、登録済みの自動適用タスクを`-RemoveAutoPatch`で解除してから実行してください。

## 解析と手動パッチ

対象DLLを解析するには、`-Target`を指定します。

```powershell
.\chromium_mv2_patch.ps1 -Target 'C:\path\to\chrome.dll'
```

パッチ済みコピーを作るには、出力先を指定します。

```powershell
.\chromium_mv2_patch.ps1 `
  -Target 'C:\path\to\chrome.dll' `
  -Output '.\chrome.mv2-patched.dll'
```

出力先の隣に`.mv2-receipt.json`が作成された場合は、元の入力DLLと一緒に残してください。
適用済みかどうかを判定する際に使います。

インストール済みDLLへ直接適用するには、対象ブラウザを完全に終了して`-Apply`を実行します。
書き換え前に元DLLをバックアップします。
Program Files配下へ適用する場合は、管理者PowerShellで実行してください。

```powershell
.\chromium_mv2_patch.ps1 -Target 'C:\path\to\chrome.dll' -Apply
```

Google Chromeでは、`-Target`を省略するとインストール済みの最新DLLを自動検出します。

```powershell
.\chromium_mv2_patch.ps1 -Apply
```

Applicationフォルダを指定する場合は、`-BrowserRoot`を使います。

```powershell
.\chromium_mv2_patch.ps1 -Apply `
  -BrowserRoot 'C:\Program Files\Google\Chrome\Application'
```

## Google Chrome更新後の自動パッチ

管理者PowerShellで自動適用を登録します。
登録後、現在の最新版にも一度パッチを試行します。

```powershell
.\chromium_mv2_patch.ps1 -AutoPatch
```

自動適用はSYSTEM権限で動作します。
Windows起動時からChromeの更新を監視し、1時間ごとの定期確認も行います。
適用済みのDLLは再適用しません。

Applicationフォルダを指定して登録することもできます。

```powershell
.\chromium_mv2_patch.ps1 -AutoPatch `
  -BrowserRoot 'C:\Program Files\Google\Chrome\Application'
```

自動適用を解除するには、次を実行します。
監視プロセスを停止し、監視と定期確認のタスク登録を削除します。

```powershell
.\chromium_mv2_patch.ps1 -RemoveAutoPatch
```

処理結果はスクリプトと同じフォルダの`chromium_mv2_autopatch.log`に記録します。

## バックアップと復元

### 保存先と保存内容

既定の保存先は、スクリプトと同じフォルダの`chromium_mv2_backups`です。
`-BackupRoot`で変更できます。

```powershell
.\chromium_mv2_patch.ps1 -Apply -BackupRoot 'C:\MV2Backups'
```

DLLへの直接適用では、元DLLと適用情報を記録した`receipt.json`を保存します。
復元や適用済み判定に使うため、バックアップ内のファイルはまとめて保管してください。

手動でGoogle Chromeへ適用する場合は、`%LOCALAPPDATA%\Google\Chrome\User Data`からプロファイル別に次のデータも保存します。

- 拡張機能本体
- Local、Sync、Managed Extension Settings
- `Storage\ext`
- 拡張機能一覧、再インストール先、保護設定を記録した`inventory.json`
- `Secure Preferences.snapshot`

自動適用のバックアップ対象は、元DLLと`receipt.json`です。

RAM起動時の`-BackupProfile`では、拡張機能本体と設定ストレージ、`inventory.json`を保存します。
ブラウザ全体の`Local State`と、各プロファイルの`Preferences`、`Secure Preferences`も含まれます。
保存先はバックアップフォルダ内の`RamLaunch_<version>_<time>`で、内容を`profile-backup.json`に記録します。

### DLLの復元

対象ブラウザを完全に終了してから、`-Restore`を実行します。
`-Receipt`を省略すると、バックアップフォルダ内で適用日時が最新の完了済みレシートを使います。
保存先を変更した場合は、復元時にも同じ`-BackupRoot`を指定してください。

```powershell
.\chromium_mv2_patch.ps1 -Restore
```

バックアップを指定するには、`receipt.json`へのパスを渡します。

```powershell
.\chromium_mv2_patch.ps1 -Restore `
  -Receipt '.\chromium_mv2_backups\...\receipt.json'
```

バックアップが破損していたり、適用後に対象DLLが更新されたりしている場合は、復元せずに停止します。

### 拡張機能の復元

手動適用時に保存した拡張機能は、`-RestoreExt`で復元します。
パッチ適用済みのChromeを完全に終了し、拡張機能バックアップを含むレシートを指定してください。

```powershell
.\chromium_mv2_patch.ps1 -RestoreExt `
  -Receipt '.\chromium_mv2_backups\...\receipt.json'
```

既存の設定ストレージを保持し、失われたものをバックアップから戻します。
プロファイルごとに再インストール用のページが開くので、各ページで「Chrome に追加」を実行してください。
拡張機能本体は、バックアップ内にも保存されています。

再インストール後、シークレットモードやファイルURLへのアクセス許可を戻すには、`-RestoreExtSettings`を実行します。

```powershell
.\chromium_mv2_patch.ps1 -RestoreExtSettings `
  -Receipt '.\chromium_mv2_backups\...\receipt.json'
```

バックアップ時にいずれかの許可が有効だった拡張機能の詳細ページを開き、保存された設定値を表示します。
表示内容に従ってChromeの画面で設定してください。

## パッチ動作確認済みバージョン

次のGoogle Chrome Windows x64版でパッチ動作確認済みです。確認日：2026年9月15日。

| チャネル | バージョン |
| --- | --- |
| Stable | 151.0.7922.174 |
| Stable | 152.0.7977.76 |
| Stable | 153.0.8010.37 |
| Beta / Chrome for Testing | 153.0.8010.12 |
| Dev / Chrome for Testing | 154.0.8025.0 |
| Canary / Chrome for Testing | 154.0.8037.0 |
| Dev / Chrome for Testing | 155.0.8048.0 |
| Canary / Chrome for Testing | 155.0.8058.0 |

新しいビルドでパッチ箇所を検出できない場合や、検出数が想定と異なる場合は、パッチを適用せずに停止します。
