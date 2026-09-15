# Chromium MV2パッチの対応箇所と変更内容

本パッチは、ビルド済みDLLの機械語を書き換えてChromiumのManifest V2制限を変更する。
以下のdiffは変更内容をC++で表した概念差分であり、Chromiumソースへ直接適用するパッチファイルではない。

## 対象となるChromiumの判定

対象はWindows x64版で、Chromium 151から155の複数の命令配置に対応している。
MV2廃止の影響対象かどうかは、[`manifest_v2_util::IsExtensionAffected()`](https://chromium.googlesource.com/chromium/src/+/lkgr/extensions/browser/manifest_v2_util.cc)が判定する。
条件を簡略化すると、次のようになる。

```cpp
affected =
    manifest_version < 3
    && type_is_extension
    && !is_component_extension;
```

マニフェストバージョンが3未満で、通常の拡張機能などに分類されるものが対象となる。
Chrome内部のコンポーネント拡張機能は除外される。

この判定は拡張機能の有効化やインストール、起動時の無効化に使われる。
Clang/LTOによる最適化で呼び出し元へインライン展開されたり、同じ関数から複数の機械語表現が生成されたりする場合がある。
元の関数を一か所だけ変更しても、別の場所に複製された判定は残る。

## パッチ箇所の検出

パッチ規則は`chromium_mv2_signatures.psd1`に定義されている。
通常はマスク付きバイトパターンで、MV2対象判定と周辺の命令列を照合する。
命令種別と即値、条件分岐の並びを確認し、対応するレジスタ割り当てや変位の違いはマスクで許容する。
同じ判定が複製されている場合は、規定の個数がそろい、適用状態が一致していることを求める。

6規則のいずれかをパターンで検出できない場合は、その規則の候補周辺をWindows標準のデバッグエンジンで逆アセンブルする。
命令を追って比較値の出所や分岐の合流を調べ、規則に応じて戻り値と副作用を検査する。
呼び出しを含む処理では、引数の受け渡しと呼び出し先の一部も確認する。
この範囲で比較順序の変更やレジスタ間のコピーを許容する。

起動時無効化とインストール拒否の呼び出し追跡では、一時スタックへの退避も扱う。
追跡したすべての経路が、同じ呼び出しと値に到達することが条件になる。

無効化理由の変換では、初期化した集合に入力値を取り込み、その集合を返すまでの処理を確認する。
対象は既知の変換ループであり、真偽値を返す類似ループは含めない。
設定から読み出して変換する関数と、入力集合を変換する関数が1個ずつ必要になる。
両者が同じ検証関数と挿入関数を呼んでいることも確認する。

パターンで検出済みの規則には通常のシグネチャ検査を使う。
命令追跡による補完は、全6規則が未適用状態でそろった場合だけ採用する。

### 解析範囲と新しいビルドへの対応

命令追跡の候補は最大64個、各解析範囲は4 KiB以内、命令キャッシュは最大128命令に制限する。
起動時無効化とインストール拒否の呼び出し追跡では、最大8経路と256バイト以内の一時スタック領域を扱う。
一時領域は呼び出し前に解放されている必要がある。
同じ呼び出し先の検証結果は、1回のファイル解析内で再利用する。

未知の書き込みや未対応のループ、候補の不足や過剰を検出した場合は、パッチを適用せずに停止する。
命令追跡で確認するのは限られた範囲であり、関数全体の等価性や呼び出し先のすべての動作を証明するものではない。
ただし、別の命令形で新たな制限処理が追加された場合、その処理を既存の規則で検出できるとは限らない。
既知の箇所を検出できたことだけでは、新しいビルドのすべてのMV2制限を変更できる保証にはならない。

## 分岐命令の書き換え

マニフェストバージョンの判定では、MV3が通る既存の非対象経路へMV2も進むようにする。
カタログに定義した`jg`の置換では、元の分岐先と相対変位を保つ。

| 分岐 | 変更前 | 変更後 |
| --- | --- | --- |
| 短距離 | `7F rel8` | `EB rel8` |
| 長距離 | `0F 8F rel32` | `90 E9 rel32` |

命令追跡で判定した`jg`についても、元の分岐先へ到達する変位を計算して`jmp`へ置き換える。
逆条件の`jle`として配置されている場合は、その命令をNOPで埋め、既存の非対象経路へ続ける。

## 書き込みと適用済み判定

状態解析とRAM起動のパッチ計画では、実行可能セクションを4 MiBのバッファで走査し、DLL全体をメモリーに保持しない。
DLLへ書き込む際は全体を読み込む。
直接適用では、書き換え前に元DLLをバックアップする。
書き込み後はSHA-256と全パッチ箇所の再解析で検証する。
命令追跡で補った場合は、読み戻したDLLから変更箇所だけを元に戻したデータのハッシュも照合する。
検証や適用記録の確定に失敗した場合は、元バイト列へ戻してハッシュを再確認する。
RAM起動では、対象DLLの読み込みとメモリ上の元バイト列を確認してから置換する。

命令追跡で補ったパッチの適用済み判定には、元DLLと適用記録が必要になる。
直接適用ではバックアップと`receipt.json`を使う。
コピー出力では出力先の隣に`.mv2-receipt.json`を作成し、元の入力DLLを参照する。
元DLLや記録が失われた場合、既存シグネチャに一致しない適用済みDLLは再判定できない。

## 有効化を拒否する判定

[`ManifestV2Handler::ShouldBlockExtensionEnable()`](https://chromium.googlesource.com/chromium/src/+/main/extensions/browser/manifest_v2_handler.cc)は、拡張機能がMV2廃止の影響対象なら有効化を拒否する。

本パッチの`allow-enable-and-report`規則は、マニフェストバージョン比較後の分岐を、既存の「`false`を返す」経路への無条件分岐に変更する。

```diff
diff --git a/extensions/browser/manifest_v2_handler.cc b/extensions/browser/manifest_v2_handler.cc
--- a/extensions/browser/manifest_v2_handler.cc
+++ b/extensions/browser/manifest_v2_handler.cc
@@ ManifestV2Handler::ShouldBlockExtensionEnable(...) @@
-  return manifest_v2_util::IsExtensionAffected(extension);
+  return false;
```

## ポリシー処理にインライン化された有効化判定

[`StandardManagementPolicyProvider::MustRemainDisabled()`](https://chromium.googlesource.com/chromium/src/+/main/chrome/browser/extensions/standard_management_policy_provider.cc)は、拡張機能を無効のまま維持する必要があるかを判定する。
MV2廃止のほか、最低バージョンや公開状態などの判定を含む。

本パッチの`allow-enable-policy-inline`規則は、インライン化されたMV2判定から「無効のまま維持する」という結果へ進む分岐だけを迂回する。

```diff
diff --git a/chrome/browser/extensions/standard_management_policy_provider.cc b/chrome/browser/extensions/standard_management_policy_provider.cc
--- a/chrome/browser/extensions/standard_management_policy_provider.cc
+++ b/chrome/browser/extensions/standard_management_policy_provider.cc
@@ StandardManagementPolicyProvider::MustRemainDisabled(...) @@
-  if (mv2_handler->ShouldBlockExtensionEnable(extension)) {
+  if (false) {
     reason = DISABLE_UNSUPPORTED_MANIFEST_VERSION;
     return true;
   }
```

最低バージョンなど、MV2以外の理由による無効化判定は変更しない。

## 起動時の一括無効化

[`ManifestV2Handler::DisableAffectedExtensions()`](https://chromium.googlesource.com/chromium/src/+/main/extensions/browser/manifest_v2_handler.cc)は、起動時に有効な拡張機能を走査し、MV2廃止の影響対象を無効化リストへ追加する。
走査後、Chromiumはリスト内の拡張機能へ`DISABLE_UNSUPPORTED_MANIFEST_VERSION`を付けて無効化する。

本パッチの`skip-startup-disable`規則は、対象をリストへ追加する処理へ進まず、ループの次の要素へ移る分岐へ変更する。

```diff
diff --git a/extensions/browser/manifest_v2_handler.cc b/extensions/browser/manifest_v2_handler.cc
--- a/extensions/browser/manifest_v2_handler.cc
+++ b/extensions/browser/manifest_v2_handler.cc
@@ ManifestV2Handler::DisableAffectedExtensions() @@
   for (const auto& extension : enabled_extensions) {
-    if (!manifest_v2_util::IsExtensionAffected(extension))
+    if (true)
       continue;

     extensions_to_disable.insert(extension);
   }
```

## 影響対象として報告する判定

`ManifestV2Handler::IsExtensionAffected()`は、MV2廃止の影響対象かどうかを呼び出し元へ返す。

本パッチの`allow-enable-and-report`規則は、有効化拒否の判定と影響対象を報告する判定の2か所を一括処理し、いずれも既存の「`false`を返す」経路へ分岐させる。

```diff
diff --git a/extensions/browser/manifest_v2_handler.cc b/extensions/browser/manifest_v2_handler.cc
--- a/extensions/browser/manifest_v2_handler.cc
+++ b/extensions/browser/manifest_v2_handler.cc
@@ ManifestV2Handler::IsExtensionAffected(...) @@
-  return manifest_v2_util::IsExtensionAffected(extension);
+  return false;
```

## インストールを拒否する判定

`ManifestV2Handler::ShouldBlockExtensionInstallation()`は、新規インストールを拒否するか判定する。
判定にはマニフェストバージョンと拡張機能の種別、インストール元を使う。

本パッチの`allow-install`規則は、マニフェストバージョン比較後の分岐を、既存の「`false`を返す」経路への無条件分岐に変更する。

```diff
diff --git a/extensions/browser/manifest_v2_handler.cc b/extensions/browser/manifest_v2_handler.cc
--- a/extensions/browser/manifest_v2_handler.cc
+++ b/extensions/browser/manifest_v2_handler.cc
@@ ManifestV2Handler::ShouldBlockExtensionInstallation(...) @@
-  return manifest_v2_util::IsExtensionAffected(
-      manifest_version, manifest_type, manifest_location);
+  return false;
```

## ポリシー処理にインライン化されたインストール判定

[`StandardManagementPolicyProvider::UserMayInstall()`](https://chromium.googlesource.com/chromium/src/+/main/chrome/browser/extensions/standard_management_policy_provider.cc)は、インストール後に強制無効化される拡張機能のインストールを拒否する。

この処理では`ShouldBlockExtensionEnable()`相当の判定がインライン展開されているため、元の関数を変更するだけでは拒否分岐が残る。

本パッチの`allow-install-policy-inline`規則は、MV2を理由とした拒否分岐だけを迂回する。

```diff
diff --git a/chrome/browser/extensions/standard_management_policy_provider.cc b/chrome/browser/extensions/standard_management_policy_provider.cc
--- a/chrome/browser/extensions/standard_management_policy_provider.cc
+++ b/chrome/browser/extensions/standard_management_policy_provider.cc
@@ StandardManagementPolicyProvider::UserMayInstall(...) @@
-  if (would_be_disabled_as_mv2) {
+  if (false) {
     std::move(callback).Run(false, mv2_error);
     return;
   }
```

強制インストールポリシーや一般的な読み込み可否など、MV2以外の検査は変更しない。

## 実行時の無効化理由からの除外

MV2を理由とする無効化には、[`DISABLE_UNSUPPORTED_MANIFEST_VERSION`](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/extensions/browser/disable_reason.h)が使われる。
値は`1 << 23`、すなわち`8388608`である。

[`ExtensionPrefs::GetDisableReasons()`](https://chromium.googlesource.com/chromium/src/+/master/extensions/browser/extension_prefs.cc)は、設定に保存された整数値を読み出す。
その値を`CollapseUnknownDisableReasons()`で実行時の無効化理由集合`DisableReasonSet`へ変換する。

本パッチの`ignore-mv2-disable-reason-at-runtime`規則は、この変換ループで値`8388608`だけを読み飛ばす。

```diff
diff --git a/extensions/browser/extension_prefs.cc b/extensions/browser/extension_prefs.cc
--- a/extensions/browser/extension_prefs.cc
+++ b/extensions/browser/extension_prefs.cc
@@ CollapseUnknownDisableReasons(...) @@
   for (int reason : stored_reasons) {
-    if (IsValidDisableReason(reason))
-      effective_reasons.insert(reason);
-    else
-      effective_reasons.insert(DISABLE_UNKNOWN);
+    if (reason == DISABLE_UNSUPPORTED_MANIFEST_VERSION)
+      continue;
+
+    effective_reasons.insert(reason);
   }
```

設定に保存された値は変更されず、実行時に参照される無効化理由集合からだけ`8388608`が除外される。

それ以外の無効化理由が存在する場合、その理由は引き続き有効である。

### 未知の無効化理由の扱い

実際の機械語パッチは、`8388608`との比較を収めるため、元の`IsValidDisableReason()`呼び出し部分を置換する。
その結果、`8388608`以外の整数は直接「有効な理由」として扱われる。

対象ビルドで定義済みの無効化理由について結果は変わらない。
ただし、将来追加された未知の整数が設定へ入った場合は、Chromium本来の`DISABLE_UNKNOWN`への集約処理を通らない。

## パッチ後の判定

```cpp
MV2による有効化拒否       = false;
MV2によるインストール拒否 = false;
起動時のMV2無効化対象     = empty;
MV2影響対象の公開判定      = false;

保存された無効化理由       = unchanged;
実行時の無効化理由         = stored_reasons - {8388608};
```
