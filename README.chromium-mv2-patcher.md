# Chromium MV2 signature patcher

Windows x64版ChromiumブラウザのManifest V2制限にパッチを適用するツールです。
直接書換方式、通常アイコンから起動するDLL置換方式、RAM起動を選べます。
GUIとCLIに対応しています。

パッチが変更する処理の詳細は、[対応箇所と変更内容](README.chromium-mv2-patch-concept.md)を参照してください。

## 実行環境と起動

64ビット版Windows PowerShell 5.1またはPowerShell 7で、次のファイルとフォルダを同じ場所に置いて実行します。

- `chromium_mv2_patch.ps1`
- `chromium_mv2_signatures.psd1`
- `parts`フォルダ。5つのPowerShellファイルと`adaptive-exports.cs`を含め、フォルダ全体を配布してください。
- `native`フォルダ。`edge`サブフォルダを含め、フォルダ全体を配布してください。

Windows PowerShell 5.1とWindows標準の.NET Frameworkだけで実行できます。
実行に必要な追加ファイルはすべて配布物に含まれています。
必要ファイルが欠けている場合は、処理を始める前に停止します。

対象DLLの関数名、序数、別名、データの構成を読み取り、対応するプロキシを生成します。
エクスポートの個数や並びを既知の構成に限定しないため、関数の追加や削除、序数の変更にも同じ生成処理を使います。
基本的には`native\chromium_mv2_proxy.dll`をひな型として使用しますが、Edgeのみ構成が大きく異なるため`native\edge\chromium_mv2_proxy.dll`を使用します。
PowerShellの`Add-Type`が`parts\adaptive-exports.cs`をコンパイルし、元DLLのファイル構造を解析します。
生成先はスクリプト横の`generated\<ひな型のSHA-256>\<元DLLのSHA-256>\<対象DLL名>`です。
対象DLL名は`chrome.dll`、`msedge.dll`、`vivaldi.dll`、`opera_browser.dll`のいずれかです。
生成済みファイルが期待する内容と異なる場合や、生成先にジャンクションなどがある場合は、既存ファイルを保持して処理を中止します。
対象に応じてインストーラーが選ぶため、ブラウザーごとに配置するプロキシDLLは1個です。
適用前のEXEとDLLの互換性検査、パッチ箇所の解析もこのDLLが担当します。
PowerShellから読み込む場合は検査用として動作します。
この切り替えにファイル名を使うため、配布元のどちらの`chromium_mv2_proxy.dll`も元の名前で配置してください。

配布用ZIPの内容は、上記の実行用ファイルと2つのREADMEです。
バックアップ、設定、キャッシュ、生成済みDLL、ログは、利用者ごとの実行データとして扱います。

引数なしで実行するとGUIが開きます。

```powershell
.\chromium_mv2_patch.ps1
```

GUIで対象DLLを選び、実行する操作を選択します。
直接書換パッチの適用と復元、自動適用の登録と解除では管理者権限を使います。
DLL置換方式も通常配置では管理者権限を使い、「ポータブル配置」では現在のユーザー権限で操作します。
管理者権限を使う操作では、GUIからUACの確認画面を開きます。

CLIでは引数で操作を選びます。
各引数の説明は次のコマンドで確認できます。

```powershell
Get-Help .\chromium_mv2_patch.ps1 -Detailed
```

## 環境ごとに方式を選ぶ

GUIで対象DLLを指定し、「直接書換方式」または「DLL置換方式」のラジオボタンを選びます。
直接書換方式は、元DLLの命令列をディスク上で書き換えます。
DLL置換方式は、元DLLを保存してプロキシDLLへ置き換え、起動時に元DLLのメモリへパッチを適用します。
どちらも適用後は通常のブラウザーアイコンから起動できます。
「選択方式を適用」で、選んだ方式を適用して保存します。
「この環境の方式を保存」は、設定の保存だけを行います。
保存単位はブラウザーのインストール先です。同じ場所のバージョン更新後も設定を使います。

DLL置換方式では、元DLLを`original`フォルダに保存し、外側のDLLをプロキシへ置き換えます。
プロキシが元DLLを読み込み、8か所すべてを検証できた場合だけ、親プロセスのメモリにMV2パッチを適用します。
検出に失敗した場合は、元DLLの命令列を保ってブラウザーの起動を続けます。
GUIの「ブラウザーを起動」からも起動できます。
起動前バックアップと起動引数は、GUIまたはCLIから起動した場合だけ有効です。

`original`には、元DLLと、存在するDLL用とEXE用の署名ファイルを保存します。
起動、言語表示、描画、DRMに必要なリソースは、読み取り時に外側の元ファイルを参照します。
この参照方式はNTFS、FAT32、exFATで共通です。
EdgeのCDMブローカーも保存済みの元DLLと署名を読み込み、ブラウザー本来の署名検証を行います。
旧版の管理情報を確認できる環境は再適用時に移行し、不要になったリソース配置をごみ箱へ移します。
未管理の追加ファイルがある場合は、移行前に確認を求めます。
ごみ箱を利用できない場所や非対話セッションでは、旧コピーを別名で残して警告します。

### DLL置換方式の適用と解除

対象ブラウザーとそのバックグラウンドプロセスを終了してから適用します。
直接書換方式が適用済みなら、先に直接書換パッチを復元してください。

```powershell
.\chromium_mv2_patch.ps1 -InstallDll `
  -Target 'C:\Browser\Application\1.2.3.4\chrome.dll' -CacheLocation Script

.\chromium_mv2_patch.ps1 -LaunchBrowser `
  -Target 'C:\Browser\Application\1.2.3.4\chrome.dll' -BackupProfile

.\chromium_mv2_patch.ps1 -RemoveDll `
  -Target 'C:\Browser\Application\1.2.3.4\chrome.dll'
```

`-Apply -PatchMethod Dll`でもDLL置換方式を適用できます。
`-Apply`だけを指定した場合は直接書換方式です。
直接書換方式やRAM起動へ切り替える前に、「DLL置換方式を解除」を実行してください。
解除すると元DLLへ戻り、保存した方式もディスクパッチへ戻ります。
元リソース、バックアップ、キャッシュは解除後も残します。
DLL置換方式のバックアップは`chromium_mv2_backups\DllProxy_*`に保存します。復元には`-RemoveDll`を使います。

登録済みの自動適用処理も、インストール先に保存した方式を使います。
DLL置換方式では更新後の新しいバージョンへプロキシを配置します。
起動中のブラウザーや検証に通らないファイルは現状を保ち、ログへ理由を記録します。
常駐している旧版の監視処理へ直ちに反映するには、GUIから自動適用を再登録してください。

### キャッシュと設定の保存先

| 配置 | 世代キャッシュ | 方式の設定 |
| --- | --- | --- |
| 通常配置 | スクリプト横の`chromium_mv2_cache\<環境ID>` | `chromium_mv2_environments\<環境ID>.json` |
| ポータブル配置 | ブラウザーEXE横の`.chromium-mv2-cache` | 同フォルダの`<DLL名>.environment.json` |

GUIの「ポータブル配置」、またはCLIの`-CacheLocation Portable`で切り替えます。
キャッシュにはDLLごとに直近3世代の検出結果を保存します。失敗した解析結果も再利用します。
元DLLのハッシュと検出ルールの版を照合し、成功した結果は命令列も再検証して使います。
DLLや検出ルールが変わった場合は再解析します。キャッシュの破損や、別ユーザーによる復号の失敗も再解析の対象です。
キャッシュを書き込めない場所では起動のたびに解析します。検出に失敗した場合も、元DLLで起動を続けます。

通常配置ではプロキシ設定にキャッシュの絶対パスを書き込むため、スクリプトを移動した後は再適用してください。
ポータブル配置のキャッシュ指定は相対配置で解決します。
別PCや別ユーザーへ移した場合は、再解析することがあります。

### DLL置換方式の対応範囲

Chrome、Vivaldi、Brave、Opera、Edgeで元DLLへの転送を確認しています。
製品ごとの確認済みビルドとMV2パッチの適用状況は、末尾の「動作確認済みビルド」を参照してください。

自動配置は、バージョン別フォルダと、検証済みのOpera同一フォルダ配置に対応します。
Edgeに同じ版のEXEが2個ある場合は、Application直下の`msedge.exe`を選びます。
導入条件は、元DLLのエクスポート構成とEXEの転送処理が互換性検査に通ることです。
MV2パッチの検出に失敗した場合も、互換性検査済みの元DLLへ転送して起動を続けます。
元DLLの欠損やロード失敗は起動エラーになります。
ブラウザーの更新・修復でファイル構造が変わった場合は、再検証が必要です。

## RAM起動

RAM起動は、起動したブラウザのプロセスメモリにパッチを適用します。
効果はそのブラウザセッション中に続き、通常のユーザー権限で実行できます。
未パッチのDLLを指定し、対象ブラウザを完全に終了してから実行してください。

必要な命令パターンが見つからない場合や、必要な個数に足りない場合は警告を出し、元DLLのまま通常起動します。
指定した起動引数と、`-BackupProfile`による起動前バックアップは、この場合も使用します。
結果の`State`は`LaunchedUnpatched`、`PatchApplied`は`false`、`PatchCount`は`0`です。
候補の重複、部分的に書き換えられたDLL、ファイルの読み取り失敗などは、起動前にエラーとして終了します。

```powershell
.\chromium_mv2_patch.ps1 -RamLaunch -BackupProfile
```

GUIでは「従来のRAM起動」を選びます。
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

## ブラウザー更新後の自動適用

管理者PowerShellで自動適用を登録します。
登録後、現在の最新版にも一度パッチを試行します。

```powershell
.\chromium_mv2_patch.ps1 -AutoPatch
```

自動適用はSYSTEM権限で動作します。
Windows起動時から指定したインストール先を監視し、1時間ごとの定期確認も行います。
登録はインストール先ごとに独立しており、複数ブラウザーを併用できます。
Google Chrome以外には`-BrowserRoot`を指定してください。省略時の自動検出はGoogle Chromeだけです。
Google Updaterの履歴はChromeで利用できる場合だけ使います。他製品はファイル監視と定期確認で処理します。
適用済みのDLLは、その状態を保持します。

Applicationフォルダを指定して登録することもできます。

```powershell
.\chromium_mv2_patch.ps1 -AutoPatch `
  -BrowserRoot 'C:\Program Files\Google\Chrome\Application'
```

DLL置換方式で自動適用するには、先に対象DLLへ`-InstallDll`を適用するか、DLL方式を保存してから登録します。
方式の既定値は直接書換方式です。

```powershell
.\chromium_mv2_patch.ps1 -SaveEnvironment -PatchMethod Dll `
  -Target 'C:\Browser\Application\1.2.3.4\msedge.dll'
.\chromium_mv2_patch.ps1 -AutoPatch -BrowserRoot 'C:\Browser\Application'
```

自動適用を解除するには、次を実行します。
`-BrowserRoot`を付けると、そのインストール先の監視と定期確認だけを解除します。
省略すると、旧版の共通タスク名も含め、このパッチャーの全登録を解除します。

```powershell
.\chromium_mv2_patch.ps1 -RemoveAutoPatch
.\chromium_mv2_patch.ps1 -RemoveAutoPatch -BrowserRoot 'C:\Browser\Application'
```

同じパスのDLLが修復などで管理情報と一致しなくなった場合は、既存ファイルを保持して処理を中止します。

処理結果はスクリプトと同じフォルダの`chromium_mv2_autopatch.log`に記録します。

## バックアップと復元

### 保持するバックアップは各5世代

新しいバックアップが正常に完了すると、同じ環境の古いバックアップをWindowsのごみ箱へ移します。
直接書換用とDLL置換用はインストール先ごと、プロファイル用はユーザーデータフォルダごとに、直近5回の完了分を残します。
ここでの1世代はバックアップ1回分です。同じブラウザーバージョンでも別の回として数えます。
RAM起動と通常起動で同じユーザーデータフォルダを使う場合、プロファイル用の5世代は共通です。

未完了、形式不明、リンクを含むバックアップは、確認用に元の場所へ残します。
ネットワーク先、取り外し可能なドライブ、ごみ箱を使えない非対話セッションでは、警告を記録して元の場所に残します。
移動に失敗した場合も同様です。その場合は5世代を超えることがあります。
インストール先に残した`original`リソースと検出キャッシュは、バックアップ整理の対象外です。
整理対象は、次回のバックアップ作成時に判定します。

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

復元には、バックアップと対象DLLのハッシュが適用記録に一致することが必要です。

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

## 動作確認済みビルド

製品・チャネルごとに、最後に動作を確認したWindows x64版のビルドを示します。
パッチの適用可否は、対象DLLの命令列と検出数から判定します。

| ブラウザー | 最終確認ビルド | 確認範囲 |
| --- | --- | --- |
| Chrome Stable | 156.0.8078.74 | パッチ適用とMV2通信 |
| Chrome Beta / Chrome for Testing | 157.0.8103.15 | パッチ動作 |
| Chrome Dev | 158.0.8117.2 | パッチ適用とMV2通信 |
| Chrome Canary / Chrome for Testing | 158.0.8127.2 | パッチ動作 |
| Edge | 156.0.4314.50 / 157.0.4341.24 / 158.0.4357.0 | 通常起動とDLL転送 |
| Vivaldi | 8.2.4133.52 | 通常起動とDLL転送 |
| Brave | 155.1.97.56 | 通常起動とDLL転送 |
| Opera | 135.0.5973.142 | 通常起動とDLL転送 |

Edge、Vivaldi、Brave、Operaの上記ビルドは元々制限されていないため、置換前DLLでもMV2通信が可能です。
これらで確認できているのは起動とDLL転送であり、MV2制限解除の可否は各製品で制限が有効になったビルドでの検証が必要です。
直接書換方式の操作はパッチ適用だけを行うため、通常起動は別に実施して確認しています。
RAM方式では操作自体が元DLLのまま起動し、DLL置換方式では元DLLへの転送を続けます。

### DRM再生

DLL置換方式でWidevineテスト動画の再生を確認した最終ビルドは、次のとおりです。
NTFS上では、元DLLと同じDRM検証結果、レンダラーの署名制限、ネットワークのAppContainer状態を確認しています。

| ブラウザー | DRM再生の最終確認ビルド |
| --- | --- |
| Chrome Stable | 153.0.8010.37 |
| Chrome Dev | 155.0.8048.0 |
| Edge | 156.0.4314.50 / 157.0.4341.24 / 158.0.4357.0 |
| Vivaldi | 8.2.4133.52 |
| Brave | 153.1.95.101 |
| Opera | 135.0.5973.142 |

Edgeは直接書換方式・RAM起動についても、元DLLでの動作と同じ検証結果と30秒以上の再生を確認しています。
FAT32とexFAT上のChromeでは、元DLL・DLL置換方式ともにネットワークのAppContainerが無効でした。
NTFSと同じ保護状態が必要な場合は、NTFS上に配置してください。
