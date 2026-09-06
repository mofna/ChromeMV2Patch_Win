# Chromium MV2 signature patcher

Windows x64版ChromiumブラウザのDLLを命令シグネチャで解析し、Manifest V2の制限箇所にパッチを適用します。
GUIとCLIから、RAM起動、DLLへの適用、Google Chrome更新後の自動適用、バックアップと復元を操作できます。

## 実行環境と起動

Windows PowerShell 5.1またはPowerShell 7で、次の2ファイルを同じフォルダに置いて実行します。

- `chromium_mv2_patch.ps1`
- `chromium_mv2_signatures.psd1`

引数なしで実行するとGUIが開きます。

```powershell
.\chromium_mv2_patch.ps1
```

GUIでは対象DLLの自動検出と選択、状態解析、RAM起動、パッチ適用、バックアップ選択、DLL復元、拡張機能復元、保護設定ページの表示、自動適用の登録と解除を実行できます。
パッチ適用、DLL復元、自動適用の登録と解除では、UACによる管理者昇格を要求します。

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

実行ファイルの自動検出は、DLLのバージョンフォルダの一つ上にあるEXEから、製品名とファイルバージョンが一致する候補を選びます。
候補を一つに絞れない場合は、`-BrowserExecutable`で指定してください。

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

インストール済みDLLへ直接適用するには、対象ブラウザを完全に終了して`-Apply`を実行します。
書き換え前に元DLLをバックアップします。
Program Files配下へ適用する場合は、管理者PowerShellで実行してください。

```powershell
.\chromium_mv2_patch.ps1 -Target 'C:\path\to\chrome.dll' -Apply
```

Google Chromeでは、`-Target`を省略するとApplicationフォルダを自動検出し、ファイルバージョンとフォルダ名が一致する最新の`chrome.dll`を選びます。

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

SYSTEM権限で次の2タスクが動作します。

- `\ChromiumMV2Patcher\ChromiumMV2UpdateWatcher`：Windows起動時に開始し、Google Updaterの更新履歴とChrome DLLのファイル通知を監視します。
- `\ChromiumMV2Patcher\ChromiumMV2AutoPatch`：1時間ごとに最新版を確認し、適用を補完します。

自動適用は、最新版DLLの配置完了と排他書き込みの可否を確認してから実行します。
通知が配置完了前に届いた場合は、最大2分間再試行します。
適用済みDLLは検証して`AlreadyPatched`と判定します。

Applicationフォルダを指定して登録することもできます。

```powershell
.\chromium_mv2_patch.ps1 -AutoPatch `
  -BrowserRoot 'C:\Program Files\Google\Chrome\Application'
```

自動適用を解除するには、次を実行します。
両タスクと実行中の監視プロセスを停止し、タスク登録を削除します。

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
手動でGoogle Chromeへ適用する場合は、`%LOCALAPPDATA%\Google\Chrome\User Data`からプロファイル別に次のデータも保存します。

- 拡張機能本体
- Local、Sync、Managed Extension Settings
- `Storage\ext`
- 拡張機能一覧、再インストール先、保護設定を記録した`inventory.json`
- `Secure Preferences.snapshot`

自動適用のバックアップ対象は、元DLLと`receipt.json`です。

RAM起動時の`-BackupProfile`では、拡張機能本体と設定ストレージ、`inventory.json`に加え、`Local State`と各プロファイルの`Preferences`、`Secure Preferences`を保存します。
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

復元時には、バックアップのハッシュと、現在の対象DLLのパッチ済みハッシュが、それぞれレシートの記録と一致することを確認します。

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

## 対応シグネチャと検証

パッチ規則は`chromium_mv2_signatures.psd1`に定義されています。
命令種別、即値、条件分岐、前後関係を照合し、レジスタ割り当てやスタック変位などを正規化して対象を識別します。
全ルールが実行可能PEセクション内で規定数だけ一致し、各ルールの複製間で状態がそろっていることが適用条件です。

DLLへの書き込み後は、SHA-256と全パッチ箇所の再解析で結果を検証します。
検証や適用記録の確定に失敗した場合は、元バイト列へ戻してハッシュを再確認します。
RAM起動でも、対象DLLの読み込みとメモリ上の元バイト列を確認してから置換します。

2026年9月2日時点で、次のGoogle Chromeビルドについてシグネチャ一致とパッチ結果を確認しています。

| チャネル | バージョン |
| --- | --- |
| Stable | 151.0.7922.174 |
| Stable | 152.0.7977.76 |
| Beta / Chrome for Testing | 153.0.8010.12 |
| Dev / Chrome for Testing | 154.0.8025.0 |
| Canary / Chrome for Testing | 154.0.8037.0 |

5ビルドすべてで、8か所への適用、パッチ後の再解析、分岐変位の保持、コピー出力時の元DLLの保持を確認しました。
Stableでは、レシートを使う適用済み判定と、不整合のあるDLLの拒否も確認しています。
